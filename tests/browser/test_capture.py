"""Capture end to end against a local fixture server. Runs only inside the browser-tests
container (`make test-browser`, network_mode: none), never on the host."""

import asyncio
import functools
import json
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import zxingcpp
from PIL import Image
from playwright.async_api import async_playwright

from scamhunter.browser.capture import (
    NetworkRecorder,
    load_snapshot_content,
    load_snapshots,
    take_snapshot,
)
from scamhunter.browser.sandbox import launch_browser, new_context
from scamhunter.config import load_settings
from scamhunter.extract.blocklist import load_blocklist
from scamhunter.extract.extractor import extract
from scamhunter.models import AddressSource, AddressTier, DiscoveryStage
from scamhunter.report.screenshots import highlight_address

pytestmark = pytest.mark.browser

PAGES = Path(__file__).parents[1] / "fixtures" / "pages"
ADDRS = json.loads((PAGES / "deposit_mixed.addresses.json").read_text())


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    root = tmp_path_factory.mktemp("site")
    (root / "index.html").write_text((PAGES / "spa_deposit.html").read_text())
    (root / "popup.html").write_text("<p>popup</p>")
    (root / "api").mkdir()
    (root / "api" / "address.json").write_text(
        json.dumps({"coin": "USDT", "network": "TRC20", "address": ADDRS["tron2"]})
    )
    view = memoryview(
        zxingcpp.create_barcode(f"bitcoin:{ADDRS['btc']}", zxingcpp.BarcodeFormat.QRCode).to_image(
            scale=6
        )
    )
    Image.frombytes("L", (view.shape[1], view.shape[0]), view.tobytes()).save(root / "qr.png")
    handler = functools.partial(SimpleHTTPRequestHandler, directory=str(root))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_port}/"
    httpd.shutdown()


def test_capture_extract_highlight(server: str, tmp_path: Path) -> None:
    asyncio.run(_run(server, tmp_path))


async def _run(url: str, run_dir: Path) -> None:
    settings = load_settings()
    site_dir = run_dir / "sites" / "001"
    async with async_playwright() as pw:
        browser = await launch_browser(pw, proxy=None)  # offline test: no network at all
        context = await new_context(browser, settings.browser)
        page = await context.new_page()
        recorder = NetworkRecorder(site_dir, run_dir)
        recorder.attach(page)
        await page.goto(url)
        snapshot = await take_snapshot(
            page, recorder, DiscoveryStage.LANDING, "s01", site_dir, run_dir, network_idle_ms=3000
        )

        # Files on disk, paths relative to the run dir.
        for rel in (snapshot.html_path, snapshot.screenshot_path, snapshot.a11y_tree_path):
            assert (run_dir / rel).stat().st_size > 0
        assert "HeadlessChrome" not in await page.evaluate("navigator.userAgent")
        api = [r for r in snapshot.network if r.url.endswith("/api/address.json")]
        assert api and api[0].body_path

        # Rescore path: reload from disk, extract.
        [saved] = load_snapshots(site_dir)
        content = load_snapshot_content(saved, run_dir)
        found = {a.address: a for a in extract(content, load_blocklist())}
        tron = found[ADDRS["tron2"]]
        sources = {s.source for s in tron.sightings}
        assert {AddressSource.DOM_TEXT, AddressSource.NETWORK_RESPONSE} <= sources
        assert tron.tier == AddressTier.PRIMARY
        assert found[ADDRS["btc"]].sightings[0].source == AddressSource.QR_CODE

        # Highlight screenshot.
        out = site_dir / "screenshots" / "tron.png"
        box = await highlight_address(page, ADDRS["tron2"], out)
        assert box is not None and box[2] > 0 and out.stat().st_size > 0
        assert await highlight_address(page, "not-on-page", site_dir / "x.png") is None

        # Popups are closed immediately.
        await page.click("#pop")
        await page.wait_for_timeout(1000)
        assert len(context.pages) == 1

        await context.close()
        await browser.close()
