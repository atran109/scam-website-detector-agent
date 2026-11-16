"""One pure parser per provider format (DESIGN §8.2 step 1). No network, no files.

Every parser takes the provider's text and returns the usable candidates plus a count of what
it skipped and why. Provider files are untrusted data: one bad entry never raises, and a file
in an unexpected shape gives an empty result with a reason."""

import csv
import ipaddress
import json
import re
from collections import Counter
from datetime import date
from html import unescape
from io import StringIO
from urllib.parse import urlsplit

import tldextract
from eval.dataset_v1.models import Candidate, Expected, ParseResult, Source

# Bundled suffix list only (no network). Private suffixes are on, so two sites on a shared
# host such as pages.dev or vercel.app count as two domains, not one.
_extract = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
)
_LABEL = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)")
_NEVER_PUBLIC = {"invalid", "localhost", "local", "internal", "lan", "home", "onion"}

_TAG = re.compile(r"<[^>]+>")
_ROW = re.compile(r"<tr\b[^>]*>(.*?)</tr>", re.S | re.I)
_CELL = re.compile(r"<td\b[^>]*class=\"column-(\d)\"[^>]*>(.*?)</td>", re.S | re.I)
_HOSTISH = re.compile(r"(?:https?://)?(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?:/[^\s,;)]*)?")
_LOOKALIKE = re.compile(r"not to be confused with([^<]{0,300})", re.I)
_ADDRESS = re.compile(
    r"\b(?:0x[0-9a-fA-F]{40}|bc1[ac-hj-np-z02-9]{20,80}|[13][1-9A-HJ-NP-Za-km-z]{25,34}"
    r"|T[1-9A-HJ-NP-Za-km-z]{33})\b"
)


def normalise_host(raw: str) -> str | None:
    """A provider's entry as a lower-case ASCII hostname, or None if it is not a public one.
    Accepts a bare host, a wildcard (`*.x.com`), or a URL; drops scheme, port and path."""
    text = raw.strip().lower()
    if not text or any(c.isspace() for c in text):
        return None
    if "://" not in text:
        text = "//" + text
    try:
        host = urlsplit(text).hostname or ""
    except ValueError:
        return None
    host = host.removeprefix("*.").rstrip(".")
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = host.split(".")
    if len(labels) < 2 or labels[-1] in _NEVER_PUBLIC or labels[-1].isdigit():
        return None
    if len(host) > 253 or not all(_LABEL.fullmatch(label) for label in labels):
        return None
    return host


def registrable(host: str) -> str:
    """The domain someone registered: `a.b.co.uk` -> `b.co.uk`, `x.pages.dev` -> `x.pages.dev`.
    A name whose suffix is not on the list falls back to its last two labels."""
    parts = _extract(host)
    if parts.suffix and parts.domain:
        return f"{parts.domain}.{parts.suffix}"
    return ".".join(host.split(".")[-2:])


def _url_for(raw: str) -> tuple[str, str] | None:
    """(url, host) for a provider entry. A bare host becomes https://host/; a path is kept."""
    host = normalise_host(raw)
    if host is None:
        return None
    text = raw.strip()
    parts = urlsplit(text if "://" in text else "//" + text)
    tail = parts.path or "/"
    if parts.query:
        tail += "?" + parts.query
    if parts.fragment:
        tail += "#" + parts.fragment
    return f"https://{host}{tail}", host


class _Collector:
    """Builds a ParseResult, keeping the first entry per registrable domain."""

    def __init__(self, source: Source, expected: Expected) -> None:
        self.source: Source = source
        self.expected: Expected = expected
        self.candidates: list[Candidate] = []
        self.skipped: Counter[str] = Counter()
        self._seen: set[str] = set()

    def add(self, raw: object, listed_on: date | None = None, note: str = "") -> None:
        if not isinstance(raw, str):
            self.skipped["not a string"] += 1
            return
        made = _url_for(raw)
        if made is None:
            self.skipped["not a public hostname"] += 1
            return
        url, host = made
        domain = registrable(host)
        if domain in self._seen:
            self.skipped["duplicate domain"] += 1
            return
        self._seen.add(domain)
        self.candidates.append(
            Candidate(
                url=url,
                registrable_domain=domain,
                source=self.source,
                expected=self.expected,
                listed_on=listed_on,
                source_note=note,
            )
        )

    def skip(self, reason: str) -> "_Collector":
        self.skipped[reason] += 1
        return self

    def result(self) -> ParseResult:
        return ParseResult(candidates=self.candidates, skipped=dict(self.skipped))


def _load_json(text: str) -> object | None:
    try:
        return json.loads(text)
    except ValueError:
        return None


def parse_scamsniffer_day(text: str, listed_on: date) -> ParseResult:
    """One file of ScamSniffer's `blacklist/archive/`: `{"domains": [...]}`."""
    out = _Collector("scamsniffer", "scam")
    data = _load_json(text)
    domains = data.get("domains") if isinstance(data, dict) else None
    if not isinstance(domains, list):
        return out.skip("unexpected file shape").result()
    for entry in domains:
        out.add(entry, listed_on)
    return out.result()


def parse_metamask_config(text: str) -> tuple[ParseResult, ParseResult]:
    """MetaMask's `src/config.json`: `blacklist` (scam) and `whitelist` (legitimate)."""
    block = _Collector("metamask_block", "scam")
    allow = _Collector("metamask_allow", "not_scam")
    data = _load_json(text)
    for key, out in (("blacklist", block), ("whitelist", allow)):
        entries = data.get(key) if isinstance(data, dict) else None
        if not isinstance(entries, list):
            out.skip("unexpected file shape")
            continue
        for entry in entries:
            out.add(entry)
    return block.result(), allow.result()


def _cell_lines(cell_html: str) -> list[str]:
    lines = unescape(_TAG.sub("\n", cell_html)).splitlines()
    return [line.strip() for line in lines if line.strip()]


def parse_dfpi(html: str) -> tuple[ParseResult, ParseResult]:
    """California DFPI's Crypto Scam Tracker table: (scam sites, legitimate look-alikes).

    Each scam candidate's note holds the row's scam types and any crypto addresses in the
    complaint narrative. Look-alikes are hosts named after "not to be confused with"."""
    scams = _Collector("dfpi", "scam")
    legit = _Collector("dfpi_lookalike", "not_scam")
    rows = [dict(_CELL.findall(row)) for row in _ROW.findall(html)]
    rows = [row for row in rows if row]
    if not rows:
        scams.skip("table not found")
        return scams.result(), legit.result()
    for row in rows:
        narrative = unescape(_TAG.sub(" ", row.get("2", "")))
        for sentence in _LOOKALIKE.findall(narrative):
            for match in _HOSTISH.findall(sentence.split(". ")[0]):
                legit.add(match.rstrip("."))
        sites = _cell_lines(row.get("4", ""))
        if not sites:
            scams.skip("row without a website")
            continue
        addresses = list(dict.fromkeys(_ADDRESS.findall(narrative)))
        note = "; ".join(_cell_lines(row.get("3", "")))
        if addresses:
            note += " | addresses: " + " ".join(addresses)
        for site in sites:
            scams.add(site, note=note)
    return scams.result(), legit.result()


def parse_tranco(csv_text: str, top: int = 100_000) -> ParseResult:
    """Tranco's `top-1m.csv`: `rank,domain` lines. Keeps ranks 1..top."""
    out = _Collector("tranco", "not_scam")
    for row in csv.reader(StringIO(csv_text)):
        if len(row) != 2 or not row[0].isdigit():
            out.skip("unexpected line")
            continue
        if int(row[0]) > top:
            break
        out.add(row[1], note=f"rank {int(row[0])}")
    return out.result()


def parse_coingecko_exchanges(json_text: str) -> ParseResult:
    """One page of CoinGecko's `/exchanges`: a list of objects with `name` and `url`."""
    out = _Collector("coingecko", "not_scam")
    data = _load_json(json_text)
    if not isinstance(data, list):
        return out.skip("unexpected file shape").result()
    for item in data:
        url = item.get("url") if isinstance(item, dict) else None
        if not url:
            out.skip("no url")
            continue
        out.add(url, note=str(item.get("name", "")))
    return out.result()
