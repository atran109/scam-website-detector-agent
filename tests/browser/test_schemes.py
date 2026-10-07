"""Only http(s), ws(s), data, blob and about may be loaded (`sandbox.restrict_schemes`, M5).

The control loads file:///etc/hostname in a plain context (it works: Playwright's own goto is not
a page script), the guarded context aborts it. Runs in the offline browser-tests container."""

import asyncio

import pytest
from playwright.async_api import async_playwright

from scamhunter.browser.sandbox import launch_mock_browser, new_context
from scamhunter.config import load_settings

pytestmark = pytest.mark.browser
# chrome:// is not on the list: Playwright's routing cannot intercept the browser's own internal
# pages. A page script cannot navigate there and the policy never asks (LOG 2026-10-07).
ODD = [
    "file:///etc/hostname",
    "view-source:http://127.0.0.1:9/",
    "ftp://127.0.0.1/",
]


def test_the_control_loads_a_file_url_and_the_guarded_context_does_not() -> None:
    async def go():
        async with async_playwright() as pw:
            browser = await launch_mock_browser(pw)
            plain = await browser.new_context()  # no scheme guard
            page = await plain.new_page()
            await page.goto("file:///etc/hostname")
            control = (await page.inner_text("body")).strip()
            # not loopback_only: that guard would refuse these URLs first and hide this one
            guarded = await new_context(browser, load_settings().browser)
            refused = []
            for url in ODD:
                gpage = await guarded.new_page()
                try:
                    await gpage.goto(url, timeout=5000)
                    refused.append((url, "LOADED"))
                except Exception as exc:  # noqa: BLE001
                    refused.append((url, str(exc).splitlines()[0][-60:]))
                await gpage.close()
            blocked = list(guarded.blocked_schemes)
            await browser.close()
            return control, refused, blocked

    control, refused, blocked = asyncio.run(go())
    assert control, "the control must load the file, or the test proves nothing"
    assert all("LOADED" not in r[1] for r in refused), refused
    assert any(u.startswith("file:") for u in blocked), blocked
