"""Launch the browser and create hardened, per-site contexts with routing rules."""

from playwright.async_api import Browser, BrowserContext, Playwright

from scamhunter.config import BrowserSettings


async def launch_browser(pw: Playwright, proxy: str) -> Browser:
    """Chromium with its sandbox ON, all traffic through the egress proxy.

    Playwright's default (chromium_sandbox=False) adds --no-sandbox; we never allow that.
    channel="chromium" uses full Chromium in new headless mode rather than the headless shell.
    """
    return await pw.chromium.launch(
        channel="chromium",
        headless=True,
        chromium_sandbox=True,
        proxy={"server": proxy},
    )


async def new_context(
    browser: Browser,
    settings: BrowserSettings,
    *,
    mobile: bool = False,
    ignore_https_errors: bool = False,
) -> BrowserContext:
    """A fresh, isolated context for one site: no downloads, no permissions, no service workers."""
    width, height = settings.viewport_mobile if mobile else settings.viewport_desktop
    return await browser.new_context(
        viewport={"width": width, "height": height},
        is_mobile=mobile,
        has_touch=mobile,
        accept_downloads=False,
        permissions=[],
        service_workers="block",
        ignore_https_errors=ignore_https_errors,  # only for sites triage saw with a bad cert
    )
