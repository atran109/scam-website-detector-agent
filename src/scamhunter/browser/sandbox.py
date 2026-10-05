"""Launch the browser and create hardened, per-site contexts with routing rules."""

from playwright.async_api import Browser, BrowserContext, Page, Playwright, Route

from scamhunter.config import BrowserSettings, is_loopback_url


async def launch_browser(pw: Playwright, proxy: str) -> Browser:
    """Chromium with its sandbox ON, all traffic through the egress proxy.

    Playwright's default (chromium_sandbox=False) adds --no-sandbox; we never allow that.
    channel="chromium" uses full Chromium in new headless mode rather than the headless shell.
    The proxy is required: every code path that visits real sites passes the value from
    require_egress_proxy().
    """
    return await pw.chromium.launch(
        channel="chromium",
        headless=True,
        chromium_sandbox=True,
        proxy={"server": proxy},
    )


# Mock mode's network-level guard: everything except loopback goes to a "proxy" that nothing
# listens on, so it fails inside Chromium's network stack: redirects, IP literals, subresources,
# websockets and all. (Playwright's request routing alone does NOT see server redirects:
# a loopback page could 302 the browser to llm-gateway. Found by `make selftest`.)
DEAD_PROXY = "http://127.0.0.1:1"
LOOPBACK_BYPASS = "localhost,127.0.0.1,[::1]"


async def launch_mock_browser(pw: Playwright) -> Browser:
    """Chromium for mock mode: can reach loopback only, so it can use the local mock exchange.

    Two layers: the dead-proxy trick above (network level) and, on every context, the route
    guard (new_context(..., loopback_only=True)) that records what was refused. Never used for
    real sites; `make selftest` checks that it cannot leave loopback, redirects included."""
    return await pw.chromium.launch(
        channel="chromium",
        headless=True,
        chromium_sandbox=True,
        proxy={"server": DEAD_PROXY, "bypass": LOOPBACK_BYPASS},
    )


_ALLOWED_INLINE_SCHEMES = ("data:", "blob:", "about:")


async def restrict_to_loopback(context: BrowserContext) -> list[str]:
    """Abort every request that isn't to loopback. Returns the list that records blocked URLs
    (for tests and selftest). Covers navigations, subresources, redirects and form posts."""
    blocked: list[str] = []

    async def handler(route: Route) -> None:
        url = route.request.url
        if is_loopback_url(url) or url.startswith(_ALLOWED_INLINE_SCHEMES):
            await route.continue_()
        else:
            blocked.append(url)
            await route.abort("blockedbyclient")

    await context.route("**/*", handler)
    return blocked


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
    loopback_only: bool = False,
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
    if loopback_only:
        context.blocked_urls = await restrict_to_loopback(context)  # type: ignore[attr-defined]
    context.on("page", _close_if_popup)
    return context


async def _close_if_popup(page: Page) -> None:
    if await page.opener() is not None:
        await page.close()
