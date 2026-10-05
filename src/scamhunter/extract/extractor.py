"""Snapshot → list[CryptoAddress]: merge candidates, dedupe, append sightings."""

import html as html_lib
import re
from collections.abc import Iterator
from dataclasses import dataclass, field

from scamhunter.extract.blocklist import is_blocked
from scamhunter.extract.context import (
    coins_in,
    has_payment_context,
    label,
    mentions_solana,
    merge_labels,
)
from scamhunter.extract.patterns import find_candidates, strip_payment_uri
from scamhunter.extract.validators import validate
from scamhunter.models import (
    AddressFormat,
    AddressSource,
    AddressTier,
    CryptoAddress,
    DiscoveryStage,
    Sighting,
)

_SCRIPT = re.compile(r"<script\b[^>]*>(.*?)</script\s*>", re.S | re.I)
_TAG = re.compile(r"<[a-z][^>]*>", re.I)
_SNIPPET_CHARS = 400

# Reaching these stages means the site showed the address to a (registered) user (§3.4 tiers).
_PAYMENT_STAGES = {DiscoveryStage.AUTHENTICATED, DiscoveryStage.DEPOSIT_PAGE}


def html_to_text(html: str) -> str:
    """Rough visible text with line breaks at block elements, for saved HTML without a
    rendered text capture (tests, archived pages). Capture normally saves inner_text()."""
    text = _SCRIPT.sub(" ", re.sub(r"<style\b.*?</style\s*>", " ", html, flags=re.S | re.I))
    text = re.sub(
        r"<(?:br|/?(?:p|div|h[1-6]|li|tr|section|footer|header|button)\b)[^>]*>",
        "\n",
        text,
        flags=re.I,
    )
    text = html_lib.unescape(re.sub(r"<[^>]+>", " ", text))
    return "\n".join(" ".join(line.split()) for line in text.splitlines() if line.strip())


@dataclass(frozen=True)
class NetworkBody:
    url: str
    resource_type: str  # xhr, fetch, script, document…
    text: str


@dataclass
class SnapshotContent:
    """Everything extraction needs from one page state, already loaded from disk."""

    snapshot_id: str
    stage: DiscoveryStage
    page_url: str
    html: str
    visible_text: str
    network: list[NetworkBody] = field(default_factory=list)
    qr_texts: list[str] = field(default_factory=list)
    archived: bool = False  # Wayback snapshot: every sighting gets source ARCHIVE


def _sources(content: SnapshotContent) -> Iterator[tuple[AddressSource, str]]:
    yield AddressSource.DOM_TEXT, content.visible_text
    yield AddressSource.DOM_ATTRIBUTE, "\n".join(_TAG.findall(_SCRIPT.sub(" ", content.html)))
    yield AddressSource.SCRIPT, "\n".join(_SCRIPT.findall(content.html))
    for body in content.network:
        if body.resource_type == "script":
            yield AddressSource.SCRIPT, body.text
        elif body.resource_type in ("xhr", "fetch", "websocket", "eventsource", "other"):
            yield AddressSource.NETWORK_RESPONSE, body.text
    for qr in content.qr_texts:
        yield AddressSource.QR_CODE, strip_payment_uri(qr.strip())


@dataclass
class _Accepted:
    raw: str
    fmt: AddressFormat
    normalized: str
    verifiable: bool
    context: str
    near: str


def _accept(text: str, blocklist: frozenset[str], by_lines: bool) -> Iterator[_Accepted]:
    """Validated, non-blocklisted addresses in `text`. Where formats overlap on one token,
    the first format (in PATTERNS order) that validates wins, so SOL never shadows BTC/TRON."""
    seen_starts: set[int] = set()
    for match in find_candidates(text, by_lines):
        if match.start in seen_starts:
            continue
        result = validate(match.raw, match.format_guess)
        if not result.valid or result.normalized is None:
            continue
        if match.format_guess == AddressFormat.SOL and not mentions_solana(match.near):
            continue  # no checksum: only trust it next to a Solana label
        seen_starts.add(match.start)
        if is_blocked(result.normalized, blocklist):
            continue
        yield _Accepted(
            match.raw,
            match.format_guess,
            result.normalized,
            result.verifiable,
            match.context,
            match.near,
        )


def _dedupe_key(fmt: AddressFormat, normalized: str) -> str:
    return normalized.lower() if fmt == AddressFormat.EVM else normalized


def extract(content: SnapshotContent, blocklist: frozenset[str]) -> list[CryptoAddress]:
    """All validated addresses in one snapshot, one CryptoAddress per address."""
    page_coins = coins_in(content.visible_text)
    found: dict[str, CryptoAddress] = {}
    for source, text in _sources(content):
        if content.archived:
            source = AddressSource.ARCHIVE
        for acc in _accept(text, blocklist, by_lines=source == AddressSource.DOM_TEXT):
            labels = label(acc.fmt, acc.near, page_coins)
            payment = (
                content.stage in _PAYMENT_STAGES
                or source in (AddressSource.QR_CODE, AddressSource.WALLET_MOCK)
                or (source != AddressSource.SCRIPT and has_payment_context(acc.near))
                or (
                    source == AddressSource.NETWORK_RESPONSE
                    and any(lab.confidence >= 0.9 for lab in labels)
                )
            )
            address = CryptoAddress(
                address=acc.raw,
                normalized=acc.normalized,
                tier=AddressTier.PRIMARY if payment else AddressTier.LOW_CONFIDENCE,
                format=acc.fmt,
                checksum_valid=True,
                checksum_verifiable=acc.verifiable,
                labels=labels,
                sightings=[
                    Sighting(
                        source=source,
                        stage=content.stage,
                        page_url=content.page_url,
                        context_snippet=acc.context[:_SNIPPET_CHARS],
                    )
                ],
                first_seen_stage=content.stage,
            )
            key = _dedupe_key(acc.fmt, acc.normalized)
            found[key] = merge_address(found[key], address) if key in found else address
    return list(found.values())


def merge_address(old: CryptoAddress, new: CryptoAddress) -> CryptoAddress:
    """Combine two sightings sets of the same address (same dedupe key)."""
    # Report the string as the user saw it: prefer a visible-text appearance.
    shown = old.address
    if (
        old.sightings[0].source != AddressSource.DOM_TEXT
        and new.sightings[0].source == AddressSource.DOM_TEXT
    ):
        shown = new.address
    primary = AddressTier.PRIMARY in (old.tier, new.tier)
    return old.model_copy(
        update={
            "address": shown,
            "tier": AddressTier.PRIMARY if primary else AddressTier.LOW_CONFIDENCE,
            "labels": merge_labels(old.labels, new.labels),
            "sightings": old.sightings + new.sightings,
        }
    )


def merge_all(existing: list[CryptoAddress], new: list[CryptoAddress]) -> list[CryptoAddress]:
    """Merge addresses from a later snapshot into those found so far (order preserved)."""
    merged = {a.dedupe_key: a for a in existing}
    for address in new:
        key = address.dedupe_key
        merged[key] = merge_address(merged[key], address) if key in merged else address
    return list(merged.values())
