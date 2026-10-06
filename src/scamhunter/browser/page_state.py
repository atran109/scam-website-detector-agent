"""What the navigation agent sees each step (DESIGN §5.5 "Observe"): a compact, token-bounded view.

Everything derived from the page is untrusted. `PageState.render()` puts it inside delimited data
blocks (llm/sanitize.py), and `PageFacts` is computed here, in code, so policy.py never has to
trust the model's reading of the page."""

import base64
import io
import re
from dataclasses import dataclass, field

from PIL import Image
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import Page

from scamhunter.browser.capture import safe_screenshot
from scamhunter.browser.elements import Element, list_elements
from scamhunter.llm.sanitize import strip_control, untrusted
from scamhunter.models import DiscoveryStage

MAX_TEXT_CHARS = 3000
MAX_ELEMENTS_CHARS = 6000
SCREENSHOT_MAX_SIDE = 1024

DEPOSIT_WORDS = re.compile(
    r"deposit|recharge|top[\s-]?up|add funds|fund (?:your )?(?:account|wallet)|充值|入金",
    re.I,
)
CARD_BANK_FIELD = re.compile(
    r"card.?(?:number|num|no\b|holder)|cc-?(?:number|num|exp|csc)|cvv|cvc|security.?code"
    r"|expir|iban|routing|account.?number|sort.?code|swift|bank.?account",
    re.I,
)
# A request to sign or approve something with a wallet, shown on the page.
WALLET_SIGNATURE = re.compile(
    r"sign (?:this |the |a )?(?:message|transaction|request)|signature request"
    r"|approve (?:this |the )?(?:transaction|spending|token)|confirm (?:this |the )?transaction"
    r" in your wallet|personal_sign|eth_sendtransaction|eth_signtypeddata|permit2? signature",
    re.I,
)
STATED_MINIMUM = re.compile(
    r"(?:min(?:imum)?\.?(?:\s+(?:deposit|recharge|amount|order))?|至少|最低)\s*[:：]?\s*"
    r"(?:of\s+)?(\d[\d,]*(?:\.\d+)?)",
    re.I,
)


@dataclass(frozen=True)
class Coverage:
    """Progress toward the goal, shown to the model so it knows what is still missing."""

    target_assets: tuple[str, ...]
    found_assets: frozenset[str]
    steps_left: int
    seconds_left: int

    @property
    def missing(self) -> list[str]:
        return [a for a in self.target_assets if a not in self.found_assets]


@dataclass(frozen=True)
class PageFacts:
    """Facts about the current page computed in code, used by the policy check."""

    url: str
    is_deposit_page: bool
    stated_minimum: str | None  # the number as printed on the page, e.g. "10"
    has_card_or_bank_fields: bool
    wallet_signature_request: bool


def compute_facts(
    url: str,
    title: str,
    headings: list[str],
    text: str,
    elements: list[Element],
    stage: DiscoveryStage,
) -> PageFacts:
    """Pure function of what the page shows. A deposit page is one that is labelled as such in
    its URL path, title or headings (or that the loop already reached as the deposit stage); a
    menu button that merely says "Recharge" does not make the page a deposit page."""
    path = re.sub(r"^[a-z]+://[^/]*", "", url.lower())
    labelled = " ".join([path, title, *headings])
    is_deposit = stage == DiscoveryStage.DEPOSIT_PAGE or bool(DEPOSIT_WORDS.search(labelled))
    minimum = STATED_MINIMUM.search(text)
    card_bank = any(
        e.role == "textbox" and CARD_BANK_FIELD.search(e.hints + " " + e.name) for e in elements
    )
    return PageFacts(
        url=url,
        is_deposit_page=is_deposit,
        stated_minimum=minimum.group(1).replace(",", "") if minimum else None,
        has_card_or_bank_fields=card_bank,
        wallet_signature_request=bool(WALLET_SIGNATURE.search(text)),
    )


@dataclass
class PageState:
    url: str
    title: str
    stage: DiscoveryStage
    elements: list[Element]
    text: str  # visible text, untruncated; render() truncates
    coverage: Coverage
    facts: PageFacts
    screenshot_png: bytes | None = field(default=None, repr=False)

    def render(self) -> str:
        """The text part of the observation. Page-derived parts are inert data blocks."""
        lines = "\n".join(e.describe() for e in self.elements) or "(no interactive elements found)"
        missing = self.coverage.missing
        done = sorted(self.coverage.found_assets)
        return "\n".join(
            [
                f"Stage: {self.stage.value}",
                f"Steps left: {self.coverage.steps_left}."
                f" Seconds left: {self.coverage.seconds_left}.",
                f"Deposit addresses found for: {', '.join(done) or 'nothing yet'}.",
                f"Still missing: {', '.join(missing) or 'nothing'}.",
                untrusted("page_header", f"URL: {self.url}\nTitle: {self.title}", 600),
                "Interactive elements (use these numbers):",
                untrusted("elements", lines, MAX_ELEMENTS_CHARS),
                "Visible text:",
                untrusted("page_text", self.text, MAX_TEXT_CHARS),
            ]
        )

    def screenshot_b64(self) -> str | None:
        return base64.b64encode(self.screenshot_png).decode() if self.screenshot_png else None


def downscale_png(png: bytes, max_side: int = SCREENSHOT_MAX_SIDE) -> bytes:
    """Shrink a screenshot so the model's image input stays small."""
    with Image.open(io.BytesIO(png)) as img:
        if max(img.size) <= max_side:
            return png
        img.thumbnail((max_side, max_side))
        out = io.BytesIO()
        img.convert("RGB").save(out, format="PNG", optimize=True)
        return out.getvalue()


async def _text_and_headings(page: Page) -> tuple[str, list[str]]:
    try:
        text = await page.inner_text("body", timeout=5000)
        headings = await page.eval_on_selector_all(
            "h1,h2,h3", "els => els.map(e => e.innerText.trim()).filter(Boolean).slice(0, 20)"
        )
    except PlaywrightError:
        return "", []
    return strip_control(text), [strip_control(h)[:100] for h in headings]


async def observe(page: Page, stage: DiscoveryStage, coverage: Coverage) -> PageState:
    """Build the observation for one step. Never raises on page trouble."""
    elements = await list_elements(page)
    text, headings = await _text_and_headings(page)
    try:
        title = await page.title()
    except PlaywrightError:
        title = ""
    png = await safe_screenshot(page, full_page=False)
    facts = compute_facts(page.url, title, headings, text, elements, stage)
    return PageState(
        url=page.url,
        title=title,
        stage=stage,
        elements=elements,
        text=text,
        coverage=coverage,
        facts=facts,
        screenshot_png=downscale_png(png) if png else None,
    )
