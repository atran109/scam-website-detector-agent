"""Content heuristics → list[Signal] (pure)."""

import re

from scamhunter.classify.domain import name_label
from scamhunter.models import Signal, SignalTier, TriageResult

WEIGHTS = {SignalTier.STRONG: 3.0, SignalTier.MODERATE: 1.5, SignalTier.WEAK: 0.5}


def _rx(*patterns: str) -> re.Pattern[str]:
    return re.compile("|".join(patterns), re.I)


# (name, tier, pattern over visible text). Multilingual where scam kits commonly are.
TEXT_RULES: list[tuple[str, SignalTier, re.Pattern[str]]] = [
    (
        "guaranteed_returns",
        SignalTier.STRONG,
        _rx(
            r"\d+(?:\.\d+)?\s?%\s*(?:daily|per day|a day|/day|every day|per hour|hourly|/h\b)",
            r"(?:daily|hourly)\s+(?:profit|return|income|interest)s?\s+(?:of\s+)?\d+(?:\.\d+)?\s?%",
            # fixed percentage per longer period: "6.5 % Weekly", "15% per month"
            r"\d+(?:\.\d+)?\s?%\s*(?:weekly|monthly|per week|per month|a week|a month"
            r"|every week|every month|/week|/month|/wk|/mo\b)",
            # investment-plan tiers: "Silver - 10% Min: $5,000 Max: $9,999 Duration: 1 Week"
            r"\d+(?:\.\d+)?\s?%[\s\S]{0,120}?(?:duration|term|period)\s*:?\s*\d+\s*"
            r"(?:hours?|days?|weeks?|months?)\b",
            r"guaranteed\s+(?:profit|return|income|payout)s?",
            r"risk[- ]free\s+(?:profit|return|invest)",
            r"日收益",
            r"每日收益",
            r"保本",
            r"稳赚",
        ),
    ),
    (
        "giveaway_send_to_receive",
        SignalTier.STRONG,
        _rx(
            r"send\s+(?:any amount|\d[\d.,]*\s*\w+)\b.{0,80}"
            r"(?:receive|get)\s+(?:back\s+)?(?:2x|double|twice)",
            r"(?:double|2x)\s+your\s+(?:btc|eth|bitcoin|crypto|coins?)",
        ),
    ),
    (
        "invite_code_required",
        SignalTier.MODERATE,
        _rx(
            r"invit(?:e|ation)\s+code",
            r"邀请码",
            r"mã giới thiệu",
            r"รหัสเชิญ",
        ),
    ),
    (
        "contract_or_quant_trading",
        SignalTier.MODERATE,
        _rx(
            r"seconds?\s+contract",
            r"秒合约",
            r"(?:ai|smart)\s+quant(?:itative)?\s+trad",
            r"arbitrage\s+(?:robot|bot)",
            r"copy\s+trading\s+(?:profit|signal)s?\s+\d",
            r"cloud\s+mining\s+(?:contract|plan)",
        ),
    ),
    (
        "withdrawal_conditions",
        SignalTier.MODERATE,
        _rx(
            r"withdrawal\s+fee",
            r"unlock\s+(?:your\s+)?(?:funds|withdrawal|account)",
            r"(?:tax|fee)\s+before\s+(?:you\s+can\s+)?withdraw",
            r"deposit\s+to\s+activate",
            r"activation\s+(?:fee|deposit|wallet|address|payment)",
        ),
    ),
    (
        "profit_plus_capital",
        SignalTier.MODERATE,
        _rx(
            r"(?:total\s+)?profit\s*\+\s*capital",
            r"capital\s*\+\s*(?:profit|interest|returns?)",
            r"principal\s*\+\s*(?:profit|interest)",
        ),
    ),
    (
        "license_claims",
        SignalTier.MODERATE,
        _rx(
            r"(?:licensed|regulated|authori[sz]ed)\s+by\s+(?:the\s+)?(?:fca|sec|asic|cysec|nfa|finra|fincen)",
            r"(?:registered with|regulated by|licen[cs]ed (?:by|with)|authori[sz]ed by"
            r"|supervised by)[^.\n]{0,80}?(?:securities and exchange commission|\(sec\)|\bsec\b"
            r"|financial conduct authority|\bfca\b|\basic\b|\bcysec\b|\bfinra\b|\bcftc\b"
            r"|\bfincen\b|\bnfa\b)",
            r"\b(?:sec|fca|asic|cysec)\s+(?:registered|regulated|licen[cs]ed|authori[sz]ed)\b",
            r"\bmsb\s+licen[cs]e",
            r"us\s+msb",
        ),
    ),
    (
        "urgency",
        SignalTier.MODERATE,
        _rx(
            r"limited\s+(?:time|spots|slots)",
            r"only\s+\d+\s+(?:spots|slots|places)\s+left",
            r"offer\s+ends\s+in",
            r"act\s+now",
        ),
    ),
    (
        "customer_service_deposit",
        SignalTier.MODERATE,
        _rx(
            r"contact\s+(?:online\s+)?customer\s+service\s+to\s+(?:deposit|recharge|top\s?up)",
            r"在线客服",
            r"联系客服充值",
        ),
    ),
]

_SEED_INPUT = _rx(
    r"<(?:input|textarea)[^>]*(?:seed|mnemonic|recovery\s?phrase|private\s?key|secret\s?phrase)",
    r"(?:seed|recovery|secret)\s+phrase.{0,200}<(?:input|textarea)",
    r"(?:12|24)[- ]word.{0,120}<(?:input|textarea)",
    r"助记词",
    r"私钥",
)
_WALLET_PROVIDERS = ("metamask.io", "trustwallet.com", "ledger.com", "trezor.io")


_COINS = re.compile(
    r"\b(?:bitcoin|btc|ethereum|eth|tether|usdt|usdc|tron|trx|bnb|binance coin|litecoin|ltc"
    r"|dogecoin|doge|ripple|xrp|solana)\b",
    re.I,
)
_PAYMENT_WORDS = re.compile(r"deposit|fund(?:s|ing)?\b|pay(?:ment)?s?\b|checkout|recharge", re.I)
_FIAT_METHODS = re.compile(
    r"visa|master\s?card|paypal|credit card|debit card|bank transfer|wire transfer|apple pay"
    r"|google pay|\bsepa\b|\bach\b",
    re.I,
)
# Products that normally take card/bank payment; a crypto exchange or wallet is not one.
_NON_CRYPTO_PRODUCT = re.compile(
    r"\bstocks?\b|stock market|brokerage|insurance|real estate|add to cart|checkout", re.I
)
_COIN_WINDOW = 250  # characters after a deposit/payment word searched for coin names
_FIAT_WINDOW = 150  # characters before it also searched for card/bank options


def crypto_only_payments(text: str) -> Signal | None:
    """Several coins offered as the way to pay/deposit for a non-crypto product (stocks,
    shop checkout, insurance…), with no card, bank or PayPal option near the payment text.
    The fiat check is local: a stock-ticker widget listing "Visa" must not count as a
    payment method."""
    product = _NON_CRYPTO_PRODUCT.search(text)
    if not product:
        return None
    for m in _PAYMENT_WORDS.finditer(text):
        around = text[max(0, m.start() - _FIAT_WINDOW) : m.start() + _COIN_WINDOW]
        coins = {c.lower() for c in _COINS.findall(text[m.start() : m.start() + _COIN_WINDOW])}
        if len(coins) >= 3 and not _FIAT_METHODS.search(around):
            return Signal(
                name="crypto_only_payments",
                tier=SignalTier.MODERATE,
                weight=WEIGHTS[SignalTier.MODERATE],
                evidence=f'"{product.group()}" product, payment only in {sorted(coins)[:4]}',
                source="content",
            )
    return None


# The cheap exchange / H5 app kits (pilot sites 057, 099, 100): an app-style menu. The words are
# the distinctive ones; "Contract", "Assets", "Team" and "Follow" also occur on ordinary token
# pages (027 has all four) and are left out. Four distinct words, not any one: 100 and 099 have
# five, 057 four; of 56 live sites no other has more than three.
MOBILE_EXCHANGE_WORDS = (
    "Recharge",
    "Withdraw",
    "Finance",
    "Loan",
    "Service",
    "AI Quant",
    "Chat Room",
    "Connect Wallet",
)
MOBILE_EXCHANGE_MIN = 4


def mobile_exchange_template(visible_text: str) -> Signal | None:
    found = [
        w
        for w in MOBILE_EXCHANGE_WORDS
        if re.search(rf"(?<![A-Za-z]){re.escape(w)}(?![A-Za-z])", visible_text, re.I)
    ]
    if len(found) < MOBILE_EXCHANGE_MIN:
        return None
    return Signal(
        name="mobile_exchange_template",
        tier=SignalTier.MODERATE,
        weight=WEIGHTS[SignalTier.MODERATE],
        evidence=f"app-style exchange menu: {', '.join(found)}",
        source="content",
    )


_TITLE = re.compile(r"<title[^>]*>(.*?)</title\s*>", re.I | re.S)
MISMATCH_MIN_WORDS = 40  # a page with little text says little about its name
MISMATCH_TEXT_CHARS = 4000


def domain_content_mismatch(host: str, title: str, visible_text: str) -> Signal | None:
    """The domain's name appears nowhere in the page's title or text (pilot site 003:
    `addmklwhisky.com` serves an immigration-consultancy site). A token of the name counts as
    present if the token, or any 4-letter piece of a token shorter than 8 letters (5 for
    longer ones), is in the page text. Weak: legitimate sites show their logo as an image, and
    a clone of a real brand's page names that brand (117: btcctw.help says BTCC)."""
    if len(visible_text.split()) < MISMATCH_MIN_WORDS:
        return None
    label = name_label(host)
    tokens = [t for t in re.split(r"[^a-z]+", label.lower()) if len(t) >= 4]
    if not tokens:
        return None
    haystack = re.sub(r"[^a-z0-9]", "", f"{title} {visible_text[:MISMATCH_TEXT_CHARS]}".lower())
    for token in tokens:
        size = 4 if len(token) < 8 else 5
        if token in haystack or any(
            token[i : i + size] in haystack for i in range(len(token) - size + 1)
        ):
            return None
    return Signal(
        name="domain_content_mismatch",
        tier=SignalTier.WEAK,
        weight=WEIGHTS[SignalTier.WEAK],
        evidence=f'the name "{label}" appears nowhere in the page title or text',
        source="content",
    )


def content_signals(visible_text: str, html: str, host: str) -> list[Signal]:
    signals: list[Signal] = []
    for name, tier, pattern in TEXT_RULES:
        if m := pattern.search(visible_text):
            signals.append(
                Signal(
                    name=name,
                    tier=tier,
                    weight=WEIGHTS[tier],
                    evidence=f'"{m.group()[:120]}"',
                    source="content",
                )
            )
    if crypto_only := crypto_only_payments(visible_text):
        signals.append(crypto_only)
    if template := mobile_exchange_template(visible_text):
        signals.append(template)
    title_match = _TITLE.search(html)
    title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else ""
    if mismatch := domain_content_mismatch(host, title, visible_text):
        signals.append(mismatch)
    if (m := _SEED_INPUT.search(html)) and not host.endswith(_WALLET_PROVIDERS):
        signals.append(
            Signal(
                name="seed_phrase_input",
                tier=SignalTier.STRONG,
                weight=WEIGHTS[SignalTier.STRONG],
                evidence=f'"{m.group()[:120]}"',
                source="content",
            )
        )
    return signals


def triage_signals(triage: TriageResult) -> list[Signal]:
    """Signals from the HTTP probe: third-party warning pages, invalid TLS."""
    signals: list[Signal] = []
    reason = (triage.reason or "").lower()
    if "suspected phishing" in reason or "potential phishing" in reason:
        signals.append(
            Signal(
                name="cloudflare_phishing_interstitial",
                tier=SignalTier.STRONG,
                weight=WEIGHTS[SignalTier.STRONG],
                evidence=triage.reason or "",
                source="status",
            )
        )
    elif triage.status.value == "suspended":
        signals.append(
            Signal(
                name="hosting_suspended",
                tier=SignalTier.MODERATE,
                weight=1.0,
                evidence=triage.reason or "",
                source="status",
            )
        )
    if triage.tls_valid is False:
        signals.append(
            Signal(
                name="invalid_tls_cert",
                tier=SignalTier.WEAK,
                weight=0.5,
                evidence="certificate failed verification",
                source="status",
            )
        )
    return signals


def address_signal(n_addresses: int) -> Signal | None:
    """A3: showing a crypto address is not evidence of a scam; recorded at ~zero weight."""
    if not n_addresses:
        return None
    return Signal(
        name="shows_crypto_address",
        tier=SignalTier.WEAK,
        weight=0.0,
        evidence=f"{n_addresses} validated address(es)",
        source="content",
    )
