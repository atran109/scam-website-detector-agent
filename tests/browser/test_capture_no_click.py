"""Capture-only mode never clicks (LOG 2026-10-06 22:00).

A local fake Cloudflare-style interstitial counts clicks on its "Ignore & Proceed" button.
The normal capture clicks it once (positive control, so a broken fake cannot pass this test);
capture with `click_interstitial=False` must leave the count at zero.
Runs only in the offline browser-tests container (`make test-browser`)."""

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from playwright.async_api import async_playwright

from scamhunter.browser.sandbox import launch_mock_browser
from scamhunter.config import load_settings
from scamhunter.models import Site, SiteStatus, TriageResult
from scamhunter.pipeline import RunContext, capture_site

pytestmark = pytest.mark.browser

PAGE = b"""<html><head><title>Suspected phishing</title></head><body>
<h1>Suspected phishing</h1><p>This site may be dangerous.</p>
<button onclick="fetch('/clicked')">Ignore &amp; Proceed</button></body></html>"""


class _Handler(BaseHTTPRequestHandler):
    clicks = 0

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        if self.path == "/clicked":
            type(self).clicks += 1
            body = b"ok"
        else:
            body = PAGE
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


def _capture(tmp_path: Path, port: int, *, click_interstitial: bool) -> None:
    site = Site(
        site_id="001",
        url=f"http://127.0.0.1:{port}/",
        host="127.0.0.1",
        registrable_domain="127.0.0.1",
    )
    triage = TriageResult(status=SiteStatus.LIVE, elapsed_ms=1)

    async def go() -> None:
        async with async_playwright() as pw:
            browser = await launch_mock_browser(pw)
            ctx = RunContext(
                settings=load_settings(),
                run_dir=tmp_path,
                llm=None,  # type: ignore[arg-type]
                browser=browser,
            )
            (ctx.site_dir(site)).mkdir(parents=True)
            await capture_site(ctx, site, triage, click_interstitial=click_interstitial)
            await browser.close()

    asyncio.run(go())


@pytest.fixture
def server():
    _Handler.clicks = 0
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd.server_address[1]
    httpd.shutdown()


def test_default_capture_clicks_the_interstitial_once(tmp_path: Path, server: int) -> None:
    _capture(tmp_path, server, click_interstitial=True)
    assert _Handler.clicks == 1


def test_capture_only_never_clicks(tmp_path: Path, server: int) -> None:
    _capture(tmp_path, server, click_interstitial=False)
    assert _Handler.clicks == 0
