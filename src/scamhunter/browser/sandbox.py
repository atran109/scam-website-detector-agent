"""Launch the browser and create hardened, per-site contexts with routing rules."""

from playwright.async_api import Browser, BrowserContext, Page, Playwright

from scamhunter.config import BrowserSettings


async def launch_browser(pw: Playwright, proxy: str | None) -> Browser:
    """Chromium with its sandbox ON, all traffic through the egress proxy.

    Playwright's default (chromium_sandbox=False) adds --no-sandbox; we never allow that.
    channel="chromium" uses full Chromium in new headless mode rather than the headless shell.
    proxy=None is only for offline browser tests inside the container, whose network has no
    route out; every code path that visits real sites passes require_egress_proxy().
    """
    return await pw.chromium.launch(
        channel="chromium",
        headless=True,
        chromium_sandbox=True,
        proxy={"server": proxy} if proxy else None,
    )


def user_agent(browser: Browser, mobile: bool) -> str:
    """A normal Chrome UA matching the real engine version (no "HeadlessChrome")."""
    major = browser.version.split(".")[0]
    if mobile:
        return (
            f"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{major}.0.0.0 Mobile Safari/537.36"
        )
    return (
        f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        f"(KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"
    )


async def new_context(
    browser: Browser,
    settings: BrowserSettings,
    *,
    mobile: bool = False,
    ignore_https_errors: bool = False,
    accept_language: str = "en-US,en;q=0.9",
) -> BrowserContext:
    """A fresh, isolated context for one site: no downloads, no permissions, no service workers.
    Popups are closed as soon as they open (their URL is still in the trace)."""
    width, height = settings.viewport_mobile if mobile else settings.viewport_desktop
    context = await browser.new_context(
        viewport={"width": width, "height": height},
        is_mobile=mobile,
        has_touch=mobile,
        user_agent=user_agent(browser, mobile),
        locale="en-US",
        extra_http_headers={"Accept-Language": accept_language},
        accept_downloads=False,
        permissions=[],
        service_workers="block",
        ignore_https_errors=ignore_https_errors,  # only for sites triage saw with a bad cert
    )
    context.set_default_timeout(settings.navigation_timeout_ms)
    context.on("page", _close_if_popup)
    return context


async def _close_if_popup(page: Page) -> None:
    if await page.opener() is not None:
        await page.close()
