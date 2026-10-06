"""Domain signals: TLD, free hosting, brand lookalikes, crypto/finance terms."""

import re
from dataclasses import dataclass
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


@dataclass(frozen=True)
class BrandToken:
    """One spelling of a brand and how it may match a domain name."""

    brand: str
    token: str
    mode: str  # "substring" | "anchored" | "exact" | "all_words", see _plain_match
    fuzzy: bool
    own_name: bool  # the brand's real name; an alias or known lookalike is never "the real site"
    words: tuple[str, ...] = ()  # all_words mode: each word must start or end a name part


MIN_SUBSTRING_LEN = 5  # shorter tokens ("okx", "gate") must sit at an edge of a name part
MIN_FUZZY_LEN = 6
# Words that sit one edit from a brand ("finance" ~ "binance"); never a typosquat window.
BENIGN_WORDS = frozenset(
    "finance financial bitcoin coin coins trade trading market markets global exchange capital"
    " crypto wallet".split()
)


def _token(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def load_brands(path: Path = REPO_ROOT / "config" / "brands.yaml") -> list[BrandToken]:
    """Entries are "Name/alias" strings or mappings {name, tokens, match, fuzzy, all_words}.
    `all_words` adds one more token that matches when every listed word starts or ends a
    hyphen-separated part of the same label, in any order ("interactivemining-brokers")."""
    out: list[BrandToken] = []
    for entry in yaml.safe_load(path.read_text())["brands"]:
        if isinstance(entry, str):
            entry = {"name": entry, "tokens": [_token(p) for p in entry.split("/")]}
        for token in entry["tokens"]:
            mode = entry.get("match") or (
                "substring" if len(token) >= MIN_SUBSTRING_LEN else "anchored"
            )
            fuzzy = entry.get("fuzzy", True) and len(token) >= MIN_FUZZY_LEN
            own = token in {_token(p) for p in entry["name"].split("/")}
            out.append(BrandToken(entry["name"], token, mode, fuzzy, own))
        if words := tuple(_token(w) for w in entry.get("all_words", [])):
            out.append(BrandToken(entry["name"], "+".join(words), "all_words", False, False, words))
    return out


def _edit_distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _site_names(host: str, registrable_domain: str) -> list[tuple[str, bool]]:
    """Labels that name the site, each flagged when it is the registrable label (the only place
    a label equal to a brand may be the real brand). On free hosting the provider's own labels
    are dropped: the subdomain is the site name."""
    labels = host.lower().split(".")
    for suffix in FREE_HOSTING:
        if host == suffix or host.endswith("." + suffix):
            return [(label, False) for label in labels[: -len(suffix.split("."))]]
    registrable_label = registrable_domain.lower().split(".")[0]
    return [(label, label == registrable_label) for label in labels[:-1] or labels]


def _plain_match(token: BrandToken, joined: str, parts: list[str]) -> bool:
    if token.mode == "substring":
        return token.token in joined
    if token.mode == "anchored":  # at the start or end of a hyphen-separated part
        return any(p.startswith(token.token) or p.endswith(token.token) for p in parts)
    if token.mode == "all_words":  # words split across parts; one part is the plain token's job
        homes = [
            {i for i, p in enumerate(parts) if p.startswith(w) or p.endswith(w)}
            for w in token.words
        ]
        return all(homes) and len(set.union(*homes)) > 1
    return any(p.strip("0123456789") == token.token for p in parts)  # exact: the whole part


def _fuzzy_match(token: BrandToken, joined: str, parts: list[str]) -> str | None:
    """A whole name part, or its start or end, one or two typos from the brand. The first
    letter must agree (typosquats keep it; "finance" vs "binance" does not)."""
    max_edits = 2 if len(token.token) >= 10 else 1
    for part in {joined, *parts}:
        for size in range(len(token.token) - max_edits, len(token.token) + max_edits + 1):
            if size > len(part):
                continue
            for window in {part[:size], part[-size:]}:
                if window[0] != token.token[0] or window in BENIGN_WORDS:
                    continue
                if 0 < _edit_distance(window, token.token) <= max_edits:
                    return window
    return None


def brand_signal(host: str, registrable_domain: str, brands: list[BrandToken]) -> Signal | None:
    """A brand name inside any site-name label, or a whole-part typo of it."""
    for label, is_registrable in _site_names(host, registrable_domain):
        parts = [p for p in re.split(r"-+", label) if p]
        joined = _token(label)
        for brand in brands:
            if is_registrable and brand.own_name and label == brand.token:  # maybe the real site
                continue
            if _plain_match(brand, joined, parts):
                return Signal(
                    name=f"brand_in_domain:{brand.token}",
                    tier=SignalTier.MODERATE,
                    weight=1.5,
                    evidence=f'"{brand.token}" inside domain label "{label}"',
                    source="domain",
                )
        for brand in brands:
            if not brand.fuzzy or (is_registrable and brand.own_name and label == brand.token):
                continue
            if window := _fuzzy_match(brand, joined, parts):
                return Signal(
                    name=f"brand_typosquat:{brand.token}",
                    tier=SignalTier.MODERATE,
                    weight=1.5,
                    evidence=f'"{window}" ≈ "{brand.token}" in "{label}"',
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


def domain_signals(host: str, registrable_domain: str, brands: list[BrandToken]) -> list[Signal]:
    signals: list[Signal] = []
    _, _, tld = registrable_domain.partition(".")
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
    if brand := brand_signal(host, registrable_domain, brands):
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
