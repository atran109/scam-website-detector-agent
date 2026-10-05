"""Regex candidate finders per address format."""

import re
from dataclasses import dataclass

from scamhunter.models import AddressFormat

B58 = "1-9A-HJ-NP-Za-km-z"  # Bitcoin base58 alphabet (no 0, O, I, l)
XRP58 = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
BECH = "02-9ac-hj-np-zAC-HJ-NP-Z"  # bech32 charset, either case

# Not preceded or followed by an alphanumeric, so substrings of longer tokens
# (64-hex tx hashes, longer base58 blobs) don't match.
_L, _R = r"(?<![0-9A-Za-z])", r"(?![0-9A-Za-z])"

PATTERNS: list[tuple[AddressFormat, re.Pattern[str]]] = [
    (AddressFormat.EVM, re.compile(_L + r"0x[0-9a-fA-F]{40}" + _R)),
    (AddressFormat.BTC_BECH32, re.compile(_L + rf"(?:bc1q|BC1Q)[{BECH}]{{38,58}}" + _R)),
    (AddressFormat.BTC_TAPROOT, re.compile(_L + rf"(?:bc1p|BC1P)[{BECH}]{{58}}" + _R)),
    (AddressFormat.BTC_P2PKH, re.compile(_L + rf"1[{B58}]{{25,33}}" + _R)),
    (AddressFormat.BTC_P2SH, re.compile(_L + rf"3[{B58}]{{25,33}}" + _R)),
    (AddressFormat.TRON, re.compile(_L + rf"T[{B58}]{{33}}" + _R)),
    (AddressFormat.LTC, re.compile(_L + rf"(?:[LM][{B58}]{{26,33}}|ltc1[{BECH}]{{38,58}})" + _R)),
    (AddressFormat.DOGE, re.compile(_L + rf"[DA9][{B58}]{{33}}" + _R)),
    (AddressFormat.XRP, re.compile(_L + rf"r[{XRP58}]{{24,34}}" + _R)),
    (AddressFormat.SOL, re.compile(_L + rf"[{B58}]{{32,44}}" + _R)),
]

CONTEXT_CHARS = 200  # evidence snippet, each side
NEAR_CHARS = 100  # labeling/payment context for non-line sources (JSON, attributes, scripts)
NEAR_LINES_ABOVE = 3  # labeling/payment context for visible text: own line + headings/tabs above
# A line holding another address-like token ends the walk upward: each address owns the
# lines above it only up to the previous address (sections on one page don't bleed together).
_ADDRESS_LIKE = re.compile(r"[0-9A-Za-z]{25,}")


@dataclass(frozen=True)
class Match:
    raw: str
    format_guess: AddressFormat
    start: int
    context: str  # wide window for evidence snippets, whitespace collapsed
    near: str  # tight context used to label the address and decide payment context
    label_line: str = ""  # visible text only: what the page puts right before the address


def _collapse(text: str) -> str:
    return " ".join(text.split())


def _near(text: str, start: int, end: int, by_lines: bool) -> str:
    if not by_lines:
        return _collapse(text[max(0, start - NEAR_CHARS) : end + NEAR_CHARS])
    line_start = text.rfind("\n", 0, start) + 1  # start of the address's own line
    for _ in range(NEAR_LINES_ABOVE):
        if line_start == 0:
            break
        above_start = text.rfind("\n", 0, line_start - 1) + 1
        if _ADDRESS_LIKE.search(text[above_start : line_start - 1]):
            break
        line_start = above_start
    line_end = text.find("\n", end)
    return _collapse(text[line_start : line_end if line_end >= 0 else len(text)])


def _label_line(text: str, start: int) -> str:
    """Text on the address's own line before it; if the address starts its line, the nearest
    non-empty line above ("Contract Address:⏎0x…" lays out both ways)."""
    line_start = text.rfind("\n", 0, start) + 1
    prefix = text[line_start:start].strip()
    while not prefix and line_start > 0:
        prev_start = text.rfind("\n", 0, line_start - 1) + 1
        prefix = text[prev_start : line_start - 1].strip()
        line_start = prev_start
    return prefix[-120:]


def find_candidates(text: str, by_lines: bool = False) -> list[Match]:
    """Every regex match of every format. One string may match several formats;
    the extractor keeps whichever one validates (checksummed formats win over SOL).

    by_lines: `text` is rendered visible text with line breaks, so the near context is the
    address's own line plus the lines just above it rather than a character window."""
    matches = []
    for fmt, pattern in PATTERNS:
        for m in pattern.finditer(text):
            window = text[max(0, m.start() - CONTEXT_CHARS) : m.end() + CONTEXT_CHARS]
            near = _near(text, m.start(), m.end(), by_lines)
            label_line = _label_line(text, m.start()) if by_lines else ""
            matches.append(Match(m.group(), fmt, m.start(), _collapse(window), near, label_line))
    return matches


# JSON / JS object keys around a value: `"contract_address":"0x…"`, `approve_address:{TRX:"T…"}`.
_IMMEDIATE_KEY = re.compile(r"""["']?([A-Za-z_][\w-]*)["']?\s*[:=]\s*["'][^"'\n]{0,200}$""")
_ENCLOSING_KEY = re.compile(r"""["']?([A-Za-z_][\w-]*)["']?\s*:\s*[\[{][^\[\]{}]{0,400}$""")


def json_keys(text: str, start: int) -> tuple[str, str]:
    """(key whose string value contains the match, key of the enclosing object/array);
    "" where there is none. Lets the extractor read structure instead of nearby words."""
    before = text[max(0, start - 600) : start]
    immediate = m.group(1) if (m := _IMMEDIATE_KEY.search(before)) else ""
    enclosing = m.group(1) if (m := _ENCLOSING_KEY.search(before)) else ""
    return immediate, enclosing


# Payment URIs in hrefs and QR codes: "bitcoin:ADDR?amount=1", "ethereum:0x…@1".
_URI = re.compile(r"^(?:bitcoin|ethereum|tron|litecoin|dogecoin|solana|ripple|xrp):", re.I)


def strip_payment_uri(text: str) -> str:
    if not _URI.match(text):
        return text
    return re.split(r"[?@/]", _URI.sub("", text), maxsplit=1)[0]
