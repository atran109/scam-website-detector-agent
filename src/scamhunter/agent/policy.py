"""Policy check: every proposed action is validated here, in code, before it runs (DESIGN §5.5).

The model's output and the page are both untrusted, so nothing here depends on the prompt. The
rules come from DESIGN §5.5 (decided 2026-10-05); each blocked action returns a reason that is fed
back to the model as a tool error so it can choose something else."""

import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from urllib.parse import urlparse

import tldextract

from scamhunter.agent.identity import FIELDS, PLACEHOLDER, placeholders_in
from scamhunter.agent.tools import ALLOWED_KEYS, MAX_WAIT_SECONDS
from scamhunter.browser.elements import Element
from scamhunter.browser.page_state import CARD_BANK_FIELD, PageFacts
from scamhunter.models import ActionType, AgentAction, BlockedReason, Identity

DEFAULT_DEPOSIT_AMOUNT = "100"
MAX_LITERAL_CHARS = 40
MAX_COORDINATE = 4000

_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

# Clicks that are blocked on every page: they claim a payment, move money, or sign something.
ALWAYS_BLOCKED_CLICK: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"\bi(?:'ve| have)? paid\b|\bhave paid\b|\bpayment (?:made|done|complete|sent)\b"
            r"|\bi(?:'ve| have) (?:sent|transferred)\b|已支付|已付款",
            re.I,
        ),
        "it claims a payment was made",
    ),
    (
        re.compile(
            r"upload.{0,25}(?:receipt|proof|screenshot|voucher|certificate)"
            r"|proof of payment|payment proof|\breceipt\b",
            re.I,
        ),
        "it uploads proof of payment",
    ),
    (
        re.compile(
            r"confirm(?:ation)?\s+(?:the\s+|your\s+)?payment|payment\s+confirm|\bpay now\b"
            r"|\bpay with\b|\bplace order\b|\bcheckout\b|\bpurchase\b|\bbuy\b",
            re.I,
        ),
        "it pays or buys",
    ),
    (re.compile(r"withdraw|提现", re.I), "it withdraws funds"),
    (re.compile(r"\bswap\b|\bexchange now\b", re.I), "it swaps assets"),
    (
        re.compile(
            r"\bsign\b(?![\s-]*(?:in|up|out|on)\b)|\bsignature\b|\bapprove\b|\bauthori[sz]e\b"
            r"|\bpermit\b|confirm (?:the |this )?transaction"
            r"|(?:sign|log)[\s-]*in with (?:your )?(?:wallet|ethereum|metamask)",
            re.I,
        ),
        "it signs or approves something",
    ),
]
WALLET_CONNECT = re.compile(
    r"connect\s*(?:your\s*|a\s*)?wallet|wallet\s*connect|walletconnect|\bmetamask\b"
    r"|trust wallet|coinbase wallet|link wallet|bind wallet",
    re.I,
)
# Clicks that submit a deposit order. Allowed on a deposit page only when nothing there asks for
# card or bank details or a wallet signature.
DEPOSIT_SUBMIT = re.compile(
    r"\b(?:confirm|next|continue|recharge|submit|proceed|deposit now|top up|create order"
    r"|get (?:deposit )?address|generate address)\b",
    re.I,
)
SECRET_FIELD = re.compile(
    r"seed|mnemonic|recovery.?phrase|private.?key|secret.?phrase|passphrase|keystore", re.I
)
KYC_FIELD = re.compile(
    r"id.?number|passport|\bssn\b|social.?security|driver.?licen|tax.?id|national.?id|id.?card"
    r"|身份证",
    re.I,
)
# A control that uploads an identity document: a KYC gate, never used.
KYC_UPLOAD = re.compile(
    r"upload.{0,25}(?:\bid\b|identity|passport|driver|licen[cs]e|selfie|document)"
    r"|\bselfie\b|(?:front|back) (?:side )?of (?:your |the )?(?:id|card|passport)"
    r"|上传身份证",
    re.I,
)
AMOUNT_FIELD = re.compile(r"amount|quantity|金额|\bsum\b", re.I)


def registrable(host: str) -> str:
    """Registrable domain; an IP address or localhost is its own site (mock mode)."""
    host = host.lower().strip(".")
    if host == "localhost" or ":" in host or re.fullmatch(r"[\d.]+", host):
        return host
    return _extract(host).top_domain_under_public_suffix or host


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str = ""  # shown to the model when blocked
    blocked_at: BlockedReason | None = None  # a gate the loop should stop at, not retry around


ALLOW = Decision(True)


def _block(reason: str, blocked_at: BlockedReason | None = None) -> Decision:
    return Decision(False, reason, blocked_at)


def _kyc_block() -> Decision:
    return _block(
        "this asks for identity documents, which are never provided; if the site requires "
        "them to continue, call done with blocked_at kyc",
        BlockedReason.KYC,
    )


def _label(element: Element) -> str:
    return f"{element.name} {element.hints}"


class Policy:
    def __init__(
        self,
        site_domain: str,
        identity: Identity | None = None,
        mock_wallet_active: bool = False,
    ) -> None:
        self.site_domain = site_domain
        self.identity = identity
        self.mock_wallet_active = mock_wallet_active  # connect-wallet clicks need it (§5.5)

    def check(self, action: AgentAction, elements: list[Element], facts: PageFacts) -> Decision:
        kind = action.type
        if kind in {ActionType.CLICK, ActionType.FILL, ActionType.SELECT}:
            element = next((e for e in elements if e.id == action.element_id), None)
            if element is None:
                return _block(f"there is no element [{action.element_id}] on this page")
            if element.disabled:
                return _block(f"element [{element.id}] is disabled")
            if element.input_type == "file":
                return self._file_input(element)
            if kind == ActionType.CLICK:
                return self._click(element, facts)
            if kind == ActionType.FILL:
                return self._fill(element, action.value or "", facts)
            return self._select(element, action.value or "")
        if kind == ActionType.CLICK_AT:
            return self._click_at(action, elements, facts)
        if kind == ActionType.GOTO:
            return self._goto(action.url or "")
        if kind == ActionType.PRESS:
            if action.value not in ALLOWED_KEYS:
                return _block(f"only these keys are allowed: {', '.join(ALLOWED_KEYS)}")
            return ALLOW
        if kind == ActionType.SCROLL:
            return ALLOW if action.value in {"up", "down"} else _block("scroll up or down")
        if kind == ActionType.WAIT:
            try:
                seconds = float(action.value or "")
            except ValueError:
                return _block("wait needs a number of seconds")
            ok = 0 <= seconds <= MAX_WAIT_SECONDS
            return ALLOW if ok else _block(f"wait at most {MAX_WAIT_SECONDS} seconds")
        if kind == ActionType.CHECK_EMAIL:
            return ALLOW if self.identity else _block("there is no mailbox for this run")
        return ALLOW  # back, done

    # ---------- clicks ----------

    def _file_input(self, element: Element) -> Decision:
        if KYC_FIELD.search(_label(element)) or KYC_UPLOAD.search(_label(element)):
            return _kyc_block()
        return _block("file uploads are never used")

    def _click(self, element: Element, facts: PageFacts) -> Decision:
        label = _label(element)
        for pattern, why in ALWAYS_BLOCKED_CLICK:
            if pattern.search(label):
                return _block(f'clicking "{element.name}" is not allowed: {why}')
        if KYC_UPLOAD.search(label):
            return _kyc_block()
        if element.href and not self._href_on_site(element.href):
            return _block(f"this link leaves {self.site_domain}; stay on the site")
        if WALLET_CONNECT.search(label):
            if self.mock_wallet_active:
                return ALLOW
            return _block(
                "connecting a wallet is not available; if the site needs one to continue, "
                "call done with blocked_at wallet_required",
                BlockedReason.WALLET_REQUIRED,
            )
        if DEPOSIT_SUBMIT.search(element.name):
            if facts.wallet_signature_request:
                return _block("the page asks for a wallet signature; do not confirm anything")
            if facts.is_deposit_page and facts.has_card_or_bank_fields:
                return _block(
                    "this deposit page asks for card or bank details; do not submit it",
                    BlockedReason.PAYMENT_REQUIRED,
                )
        return ALLOW

    def _click_at(self, action: AgentAction, elements: list[Element], facts: PageFacts) -> Decision:
        x, y = action.x, action.y
        if x is None or y is None or not (0 <= x <= MAX_COORDINATE and 0 <= y <= MAX_COORDINATE):
            return _block("click_at needs x and y inside the page")
        if facts.is_deposit_page:
            # What is under the point cannot be checked against the block list, and "I have paid"
            # must never be clicked, so coordinates are not accepted on deposit pages.
            return _block("click_at is not allowed on a deposit page; click a listed element")
        for e in elements:
            left, top, width, height = e.box
            if e.in_view and left <= x <= left + width and top <= y <= top + height:
                return self._click(e, facts)  # same rules as clicking that element
        return ALLOW

    # ---------- typing ----------

    def _fill(self, element: Element, value: str, facts: PageFacts) -> Decision:
        if not element.is_text_field:
            return _block(f"element [{element.id}] is not a text field; use click or select")
        label = _label(element)
        if SECRET_FIELD.search(label):
            return _block("never type wallet secrets (seed phrase or private key) anywhere")
        if CARD_BANK_FIELD.search(label):
            return _block("never enter card or bank details")
        if KYC_FIELD.search(label):
            return _kyc_block()
        if AMOUNT_FIELD.search(label):
            return self._amount(value, facts)
        return self._text(element, value)

    def _amount(self, value: str, facts: PageFacts) -> Decision:
        if not facts.is_deposit_page:
            return _block("amounts are only entered in a deposit amount field")
        allowed = facts.stated_minimum or DEFAULT_DEPOSIT_AMOUNT
        try:
            same = Decimal(value.strip()) == Decimal(allowed)
        except InvalidOperation:
            same = False
        if not same:
            return _block(f"type exactly {allowed} in the amount field (the page's minimum)")
        return ALLOW

    def _text(self, element: Element, value: str) -> Decision:
        names = placeholders_in(value)
        for name in names:
            if name not in FIELDS:
                return _block(f"unknown placeholder {{identity.{name}}}")
            if self.identity is None or not getattr(self.identity, name, None):
                return _block(f"placeholder {{identity.{name}}} is not available")
        literal = PLACEHOLDER.sub("", value)
        if "{" in literal or "}" in literal:
            return _block("only {identity.<field>} placeholders may use braces")
        is_password = element.input_type == "password"
        if is_password and value != "{identity.password}":
            return _block("password fields take only {identity.password}")
        if "password" in names and not is_password and "password" not in _label(element).lower():
            return _block("{identity.password} goes only into a password field")
        if len(literal) > MAX_LITERAL_CHARS:
            return _block(f"literal text is limited to {MAX_LITERAL_CHARS} characters")
        if "@" in literal:
            return _block("use {identity.email} for email addresses")
        digits = re.sub(r"\D", "", literal)
        if len(digits) >= 10 and len(digits) >= len(re.sub(r"\s", "", literal)) * 0.8:
            return _block("long numbers are not typed (use {identity.phone} for a phone number)")
        if len(literal.split()) >= 6:
            return _block("long phrases are not typed")
        return ALLOW

    def _select(self, element: Element, option: str) -> Decision:
        if element.role != "combobox" or not element.options:
            return _block(f"element [{element.id}] is not a dropdown; use click")
        if option.strip().lower() not in {o.lower() for o in element.options}:
            return _block(f"options are: {' | '.join(element.options)}")
        return ALLOW

    # ---------- navigation ----------

    def _href_on_site(self, href: str) -> bool:
        """True for links on this site and for non-web hrefs (javascript:, #, mailto: do not
        load another site)."""
        parts = urlparse(href)
        if parts.scheme not in {"http", "https"}:
            return True
        return bool(parts.hostname) and registrable(parts.hostname) == self.site_domain

    def _goto(self, url: str) -> Decision:
        parts = urlparse(url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            return _block("goto needs a full http(s) URL")
        if parts.username or parts.password:
            return _block("URLs with credentials are not allowed")
        if registrable(parts.hostname) != self.site_domain:
            return _block(f"goto stays on {self.site_domain}")
        return ALLOW


class LoopDetector:
    """Same URL and same action `limit` times in a row means no progress (DESIGN §5.5).
    Counts consecutive repeats, so three scrolls in a row on one page also stop the run."""

    def __init__(self, limit: int = 3) -> None:
        self.limit = limit
        self._last: tuple | None = None
        self._count = 0

    def record(self, url: str, action: AgentAction) -> bool:
        key = (url, action.type, action.element_id, action.x, action.y, action.value, action.url)
        self._count = self._count + 1 if key == self._last else 1
        self._last = key
        return self._count >= self.limit
