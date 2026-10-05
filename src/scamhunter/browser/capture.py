"""Turn a live page into a PageSnapshot (DOM, a11y tree, screenshot, network log, trace)."""

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import Page, Response

from scamhunter.extract.extractor import NetworkBody, SnapshotContent
from scamhunter.extract.qr import decode_qr
from scamhunter.models import DiscoveryStage, NetworkRecord, PageSnapshot

# Response bodies worth keeping: anything that can carry an address as text.
TEXT_TYPES = ("json", "javascript", "text", "xml", "x-www-form-urlencoded")
KEPT_RESOURCE_TYPES = {"xhr", "fetch", "script", "document", "other", "eventsource"}
MAX_BODY_BYTES = 2_000_000
MAX_SITE_BODY_BYTES = 50_000_000
EXCERPT_CHARS = 300
VISIBLE_TEXT_CHARS = 200_000


class NetworkRecorder:
    """Saves text response bodies to disk as they arrive; snapshots take what's new."""

    def __init__(self, site_dir: Path, run_dir: Path) -> None:
        self.dir = site_dir / "network"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.run_dir = run_dir
        self.records: list[NetworkRecord] = []
        self._taken = 0
        self._bytes = 0
        self._pending: set[asyncio.Task] = set()

    def attach(self, page: Page) -> None:
        page.on("response", self._on_response)

    def _on_response(self, response: Response) -> None:
        task = asyncio.ensure_future(self._save(response))
        self._pending.add(task)
        task.add_done_callback(self._pending.discard)

    async def _save(self, response: Response) -> None:
        request = response.request
        content_type = response.headers.get("content-type")
        record = NetworkRecord(
            url=response.url,
            method=request.method,
            status=response.status,
            resource_type=request.resource_type,
            content_type=content_type,
            body_path=None,
        )
        keep = (
            request.resource_type in KEPT_RESOURCE_TYPES
            and any(t in (content_type or "") for t in TEXT_TYPES)
            and self._bytes < MAX_SITE_BODY_BYTES
        )
        if keep:
            try:
                body = await response.body()
            except PlaywrightError:  # redirects, closed pages, evicted bodies
                body = b""
            if body and len(body) <= MAX_BODY_BYTES:
                path = self.dir / f"{len(self.records):04d}.body"
                path.write_bytes(body)
                self._bytes += len(body)
                text = body[:EXCERPT_CHARS].decode("utf-8", errors="replace")
                record = record.model_copy(
                    update={"body_path": str(path.relative_to(self.run_dir)), "body_excerpt": text}
                )
        self.records.append(record)

    async def take_new(self) -> list[NetworkRecord]:
        """Records since the previous snapshot (waits for in-flight body saves)."""
        if self._pending:
            await asyncio.wait(list(self._pending), timeout=10)
        new = self.records[self._taken :]
        self._taken = len(self.records)
        return new


async def _settle(page: Page, network_idle_ms: int) -> None:
    """Wait for the page to quiet down, bounded: scam SPAs often never reach network idle."""
    try:
        await page.wait_for_load_state("networkidle", timeout=network_idle_ms)
    except PlaywrightError:
        pass
    await page.wait_for_timeout(1500)  # SPA render after the last response


async def _visible_text(page: Page) -> str:
    parts = []
    for frame in page.frames:  # scam kits often put deposit widgets in iframes
        try:
            parts.append(await frame.inner_text("body", timeout=5000))
        except PlaywrightError:
            continue
    return "\n".join(parts)[:VISIBLE_TEXT_CHARS]


async def _html(page: Page) -> str:
    parts = []
    for frame in page.frames:
        try:
            parts.append(f"<!-- frame: {frame.url} -->\n" + await frame.content())
        except PlaywrightError:
            continue
    return "\n".join(parts)


async def take_snapshot(
    page: Page,
    recorder: NetworkRecorder,
    stage: DiscoveryStage,
    snapshot_id: str,
    site_dir: Path,
    run_dir: Path,
    network_idle_ms: int = 8000,
) -> PageSnapshot:
    """Settle the page, then save HTML, visible text, aria snapshot, screenshot, QR decodes."""
    await _settle(page, network_idle_ms)
    snap_dir = site_dir / "snapshots" / snapshot_id
    snap_dir.mkdir(parents=True, exist_ok=True)

    def rel(name: str) -> str:
        return str((snap_dir / name).relative_to(run_dir))

    html = await _html(page)
    (snap_dir / "page.html").write_text(html)
    text = await _visible_text(page)
    (snap_dir / "text.txt").write_text(text)
    try:
        aria = await page.locator("body").aria_snapshot(timeout=5000)
    except PlaywrightError:
        aria = ""
    (snap_dir / "aria.yaml").write_text(aria)
    try:
        png = await page.screenshot(full_page=True, timeout=15000)
    except PlaywrightError:
        png = await page.screenshot(timeout=15000)  # very tall pages: viewport only
    (snap_dir / "screenshot.png").write_bytes(png)
    (snap_dir / "qr.json").write_text(json.dumps(decode_qr(png)))

    snapshot = PageSnapshot(
        snapshot_id=snapshot_id,
        stage=stage,
        url=page.url,
        title=await page.title(),
        taken_at=datetime.now(UTC),
        html_path=rel("page.html"),
        visible_text=text[:2000],
        a11y_tree_path=rel("aria.yaml"),
        screenshot_path=rel("screenshot.png"),
        network=await recorder.take_new(),
        image_paths=[],
    )
    with (site_dir / "snapshots.jsonl").open("a") as f:
        f.write(snapshot.model_dump_json() + "\n")
    return snapshot


def load_snapshot_content(snapshot: PageSnapshot, run_dir: Path) -> SnapshotContent:
    """Read a saved snapshot back for extraction. Used by both the live pipeline and rescore,
    so a rescore sees exactly what the live run saw."""
    snap_dir = (run_dir / snapshot.html_path).parent
    bodies = []
    for record in snapshot.network:
        if record.body_path:
            raw = (run_dir / record.body_path).read_bytes()
            bodies.append(
                NetworkBody(record.url, record.resource_type, raw.decode("utf-8", errors="replace"))
            )
    return SnapshotContent(
        snapshot_id=snapshot.snapshot_id,
        stage=snapshot.stage,
        page_url=snapshot.url,
        html=(snap_dir / "page.html").read_text(),
        visible_text=(snap_dir / "text.txt").read_text(),
        network=bodies,
        qr_texts=json.loads((snap_dir / "qr.json").read_text()),
        archived="web.archive.org/" in snapshot.url,
    )


def load_snapshots(site_dir: Path) -> list[PageSnapshot]:
    path = site_dir / "snapshots.jsonl"
    if not path.exists():
        return []
    return [PageSnapshot.model_validate_json(line) for line in path.read_text().splitlines()]
