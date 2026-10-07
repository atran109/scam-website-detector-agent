"""The in-page navigation guard (`browser/nav_guard.py`, LOG 2026-10-07): off-site navigations
are cancelled by the page's own Navigation API listener, before the route layer sees them.

The `self_redirect` mock variant sends the page to `localhost` (another site in mock mode) 3 s
after load. A spy route on the context counts the requests that reach that host: without the
guard it sees the navigation (the control), with it nothing arrives.
Runs in the offline browser-tests container (`make test-browser`)."""

import asyncio
from urllib.parse import urlparse

import pytest
from playwright.async_api import async_playwright

from scamhunter.browser.nav_guard import PageNavigationGuard
from scamhunter.browser.sandbox import launch_mock_browser, new_context
from scamhunter.config import load_settings
from scamhunter.mock_mode import load_exchange_module

pytestmark = pytest.mark.browser


async def with_page(variant: str, body):
    exchange = load_exchange_module().MockExchange(variant=variant)
    base = exchange.start()
    try:
        async with async_playwright() as pw:
            browser = await launch_mock_browser(pw)
            context = await new_context(browser, load_settings().browser, loopback_only=True)
            spy: list[str] = []

            async def count(route) -> None:
                if urlparse(route.request.url).hostname == "localhost":
                    spy.append(route.request.url)
                await route.fallback()

            await context.route("**/*", count)
            page = await context.new_page()
            await page.goto(base, wait_until="domcontentloaded")
            try:
                return await body(page, base, spy)
            finally:
                await browser.close()
    finally:
        exchange.stop()


def test_without_the_guard_the_timer_redirect_reaches_the_other_host() -> None:
    async def body(page, base, spy):
        await page.wait_for_timeout(4500)
        return list(spy), page.url

    seen, url = asyncio.run(with_page("self_redirect", body))
    assert seen, "the control must see the navigation, or the next test proves nothing"
    assert urlparse(url).hostname == "localhost"


def test_the_page_guard_cancels_the_timer_redirect_before_any_request() -> None:
    async def body(page, base, spy):
        guard = PageNavigationGuard(page)
        await guard.install("127.0.0.1")
        await page.wait_for_timeout(4500)
        return list(spy), page.url, await guard.drain(), await guard.drain()

    seen, url, blocked, again = asyncio.run(with_page("self_redirect", body))
    assert seen == [], "no request for the other host reached the route layer"
    assert urlparse(url).hostname == "127.0.0.1", "the page stayed where it was"
    assert len(blocked) == 1 and blocked[0].startswith("http://localhost:")
    assert again == [], "drain() empties the list"


def test_the_guard_cancels_a_button_and_window_open_but_not_same_site_moves() -> None:
    async def body(page, base, spy):
        guard = PageNavigationGuard(page)
        await guard.install("127.0.0.1")
        target = base.replace("127.0.0.1", "localhost")
        opened = await page.evaluate(f"window.open('{target}') === null")
        await page.evaluate(f"location.href = '{target}#x'")
        await page.wait_for_timeout(500)
        before = page.url
        await page.evaluate("location.hash = '#/register'")  # same site: allowed
        await page.wait_for_timeout(300)
        return opened, list(spy), before, page.url, await guard.drain()

    opened, seen, before, after, blocked = asyncio.run(with_page("self_redirect", body))
    assert opened and seen == []
    assert urlparse(before).hostname == "127.0.0.1" and after.endswith("#/register")
    assert len(blocked) == 2


def test_after_a_hop_the_guard_follows_the_new_domain() -> None:
    async def body(page, base, spy):
        guard = PageNavigationGuard(page)
        await guard.install("127.0.0.1")
        target = base.replace("127.0.0.1", "localhost")
        await guard.set_allowed("localhost")
        await page.goto(target, wait_until="domcontentloaded")  # the hop itself (browser-made)
        on_new = urlparse(page.url).hostname
        # a script on the new site may move within it, and may not go back to the old site
        await page.evaluate("location.hash = '#/login'")
        await page.evaluate(f"location.href = '{base}#back'")
        await page.wait_for_timeout(500)
        return (
            on_new,
            urlparse(page.url).hostname,
            page.url.endswith("#/login"),
            await guard.drain(),
        )

    on_new, now, moved, blocked = asyncio.run(with_page("normal", body))
    assert on_new == "localhost" and now == "localhost" and moved
    assert len(blocked) == 1 and blocked[0].startswith("http://127.0.0.1:")
