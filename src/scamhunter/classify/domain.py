"""Domain signals: TLD, free hosting, brand lookalikes, crypto/finance terms."""

import re
from pathlib import Path

import yaml

from scamhunter.classify.bigrams import COLS, LOGP, ROWS
from scamhunter.config import REPO_ROOT
from scamhunter.models import Signal, SignalTier

CHEAP_TLDS = {
    "xyz",
    "top",
    "cc",
    "store",
    "shop",
    "sbs",
    "click",
    "cfd",
    "vip",
    "info",
    "live",
    "fun",
    "lol",
    "work",
    "quest",
    "help",
    "xin",
    "cloud",
    "icu",
    "buzz",
    "online",
    "site",
    "cyou",
    "rest",
    "bond",
    "pro",
    "international",
    "gold",
    "art",
}
FREE_HOSTING = (
    "workers.dev",
    "netlify.app",
    "myshopify.com",
    "azurefd.net",
    "vercel.app",
    "pages.dev",
    "github.io",
    "web.app",
    "firebaseapp.com",
    "glitch.me",
)
FINANCE_TERMS = re.compile(
    r"crypto|coin|bit|btc|usdt|usdc|token|swap|wallet|exchange|trade|trading|fx|forex|invest"
    r"|capital|financ|mining|miner|profit|gold|vault|asset|equity|bank|wealth|yield|stake|defi"
    r"|web3|nft|meta|market|futures|holding"
)
MOBILE_PREFIXES = ("h5.", "m.", "wap.", "web3.")


def load_brands(path: Path = REPO_ROOT / "config" / "brands.yaml") -> list[str]:
    return yaml.safe_load(path.read_text())["brands"]


def _token(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _edit_distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def brand_signal(label: str, brands: list[str]) -> Signal | None:
    """Brand name inside the domain label, or one edit away from it (typosquat)."""
    for brand in brands:
        for part in brand.split("/"):
            token = _token(part)
            if len(token) < 4 or label == token:  # exact label: possibly the real brand
                continue
            if token in label:
                return Signal(
                    name=f"brand_in_domain:{token}",
                    tier=SignalTier.MODERATE,
                    weight=1.5,
                    evidence=f'"{token}" inside domain label "{label}"',
                    source="domain",
                )
            if len(token) >= 6:
                max_edits = 2 if len(token) >= 10 else 1  # long names tolerate two typos
                for size in range(len(token) - max_edits, len(token) + max_edits + 1):
                    for i in range(0, max(len(label) - size, 0) + 1):
                        window = label[i : i + size]
                        if _edit_distance(window, token) <= max_edits:
                            return Signal(
                                name=f"brand_typosquat:{token}",
                                tier=SignalTier.MODERATE,
                                weight=1.5,
                                evidence=f'"{window}" ≈ "{token}"',
                                source="domain",
                            )
    return None


BIGRAM_THRESHOLD = -3.9  # mean ln P(letter pair) below this: letters no English word uses
MIN_ALPHA_FOR_BIGRAMS = 5
MAX_VOWEL_RATIO = 0.15  # consonant soup ("gxecgcx", "ceffknks")
MIN_LEN_FOR_VOWELS = 6


def _bigram_score(letters: str) -> float:
    padded = "^" + letters + "$"
    total = 0.0
    for a, b in zip(padded, padded[1:], strict=False):
        total += LOGP[ROWS.index(a)][COLS.index(b)]
    return total / (len(padded) - 1)


def random_domain_reason(registrable_domain: str) -> str | None:
    """Why the domain label looks machine-generated, or None. Deliberately conservative: it
    flags digits mixed into letters and clear letter-pair outliers. Pronounceable made-up names
    ("kisngaf") score like real brands ("bitget", "claudetf") and are NOT caught."""
    label = registrable_domain.lower().split(".")[0]
    if not label:
        return None
    # digits mixed into letters: usdc661, 3455n, r7t2mj, openai9315; short two-digit tails
    # (gete84, lon28) too, but not "22betcanada" or "coinhako01"
    if re.search(r"[a-z]\d[a-z]", label) or re.search(r"[a-z]\d{3,}|\d{3,}[a-z]", label):
        return "digits mixed into the name"
    if re.fullmatch(r"\d{3,}", label):
        return "digits only"
    if re.search(r"[a-z]", label) and re.search(r"\d{2}", label) and len(label) <= 7:
        return "short name with digits"
    for part in label.split("-"):
        letters = re.sub(r"[^a-z]", "", part)
        if len(letters) >= MIN_LEN_FOR_VOWELS:
            vowels = sum(c in "aeiou" for c in letters) / len(letters)
            if vowels <= MAX_VOWEL_RATIO:
                return f'"{part}" has almost no vowels'
        if len(letters) >= MIN_ALPHA_FOR_BIGRAMS:
            score = _bigram_score(letters)
            if score < BIGRAM_THRESHOLD:
                return f'"{part}" has letter pairs no English word uses ({score:.1f})'
    return None


def domain_signals(host: str, registrable_domain: str, brands: list[str]) -> list[Signal]:
    signals: list[Signal] = []
    label, _, tld = registrable_domain.partition(".")
    free_hosting = any(host == h or host.endswith("." + h) for h in FREE_HOSTING)
    if free_hosting:
        signals.append(
            Signal(
                name="free_hosting",
                tier=SignalTier.MODERATE,
                weight=1.0,
                evidence=host,
                source="domain",
            )
        )
    elif tld.split(".")[-1] in CHEAP_TLDS:
        signals.append(
            Signal(
                name=f"cheap_tld:.{tld}",
                tier=SignalTier.WEAK,
                weight=0.5,
                evidence=registrable_domain,
                source="domain",
            )
        )
    if brand := brand_signal(_token(label) if "." in registrable_domain else _token(host), brands):
        signals.append(brand)
    if m := FINANCE_TERMS.search(host.lower()):
        signals.append(
            Signal(
                name="finance_terms_in_domain",
                tier=SignalTier.WEAK,
                weight=0.5,
                evidence=f'"{m.group()}" in {host}',
                source="domain",
            )
        )
    if not free_hosting and (why := random_domain_reason(registrable_domain)):
        signals.append(
            Signal(
                name="random_looking_domain",
                tier=SignalTier.WEAK,
                weight=0.5,
                evidence=f"{registrable_domain}: {why}",
                source="domain",
            )
        )
    if host.startswith(MOBILE_PREFIXES):
        signals.append(
            Signal(
                name="mobile_app_host",
                tier=SignalTier.WEAK,
                weight=0.5,
                evidence=host,
                source="domain",
            )
        )
    return signals
