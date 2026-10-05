"""Wayback Machine recovery for non-live sites (DESIGN §5.2a step 1).

Everything goes through the egress proxy, and archived pages are rendered in the same
sandboxed browser as live ones: an archived scam page and its scripts are still hostile.
"""

from dataclasses import dataclass
from urllib.parse import quote

import httpx

from scamhunter.models import SiteStatus
from scamhunter.triage.liveness import classify_response

CDX_URL = "https://web.archive.org/cdx/search/cdx"
MAX_CANDIDATES = 3  # snapshots tried, newest first
CDX_LIMIT = 15
USABLE = {SiteStatus.LIVE}  # parked/suspended/empty/challenge snapshots are skipped


@dataclass(frozen=True)
class ArchivedCapture:
    timestamp: str  # YYYYMMDDhhmmss
    original: str

    @property
    def raw_url(self) -> str:
        """The archived page as originally served, without the Wayback toolbar (id_ mode)."""
        return f"https://web.archive.org/web/{self.timestamp}id_/{self.original}"


def parse_cdx(rows: list[list[str]]) -> list[ArchivedCapture]:
    """CDX JSON (header row first) → captures, newest first, one per timestamp."""
    if len(rows) < 2:
        return []
    header = rows[0]
    ts, orig = header.index("timestamp"), header.index("original")
    seen, out = set(), []
    for row in reversed(rows[1:]):
        if row[ts] not in seen:
            seen.add(row[ts])
            out.append(ArchivedCapture(row[ts], row[orig]))
    return out


async def find_captures(client: httpx.AsyncClient, url: str) -> list[ArchivedCapture]:
    target = url.split("://", 1)[-1]
    query = (
        f"{CDX_URL}?url={quote(target, safe='/')}&output=json&filter=statuscode:200"
        f"&fl=timestamp,original&limit=-{CDX_LIMIT}"
    )
    for attempt in range(2):  # the CDX API is often slow; one retry with more patience
        try:
            response = await client.get(query, timeout=30 + 30 * attempt)
            response.raise_for_status()
            return parse_cdx(response.json())
        except httpx.TimeoutException:
            if attempt == 1:
                raise
    return []


async def usable_captures(
    client: httpx.AsyncClient, url: str
) -> tuple[list[ArchivedCapture], list[str]]:
    """The newest capture (trying up to MAX_CANDIDATES) whose content isn't itself a
    parked/suspended/empty page, as a 0-or-1 list. Returns (captures to render, notes)."""
    notes: list[str] = []
    try:
        captures = await find_captures(client, url)
    except (httpx.HTTPError, ValueError) as exc:
        return [], [f"wayback: lookup failed ({type(exc).__name__})"]
    if not captures:
        return [], ["wayback: no archived snapshot"]
    usable = []
    for capture in captures[:MAX_CANDIDATES]:
        try:
            resp = await client.get(capture.raw_url, timeout=30, follow_redirects=True)
        except httpx.HTTPError as exc:
            notes.append(f"wayback {capture.timestamp}: fetch failed ({type(exc).__name__})")
            continue
        status, reason = classify_response(
            resp.status_code, resp.headers, resp.text[:500_000], str(resp.url)
        )
        if status in USABLE:
            usable.append(capture)
            break
        notes.append(f"wayback {capture.timestamp}: skipped ({status.value}: {reason})")
    return usable, notes
