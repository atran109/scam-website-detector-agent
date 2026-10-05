"""The mock exchange works in a real Chromium, driven like a person would drive it, in mock mode:
no proxy, loopback only. Runs only in the offline browser-tests container (`make test-browser`)."""

import asyncio

import pytest
from playwright.async_api import Page, async_playwright

from scamhunter.browser.sandbox import launch_mock_browser, new_context
from scamhunter.config import load_settings
from scamhunter.mock_mode import load_exchange_module

pytestmark = pytest.mark.browser
ex_mod = load_exchange_module()
PW = "Passw0rd!x"
EMAIL = "tester@example.test"


def btn(page: Page, text: str):
    """A button whether it's a real <button> or a plain <div class="btn"> (div_ui variant)."""
    return page.locator(".btn", has_text=text).locator("visible=true").first


async def close_notice(page: Page) -> None:
    await page.locator(".x").click()


async def register_and_login(page: Page, base: str, div_ui: bool) -> None:
    await page.goto(base)
    await close_notice(page)
    await btn(page, "Register").click()
    await page.fill("#email", EMAIL)
    await page.fill("#password", PW)
    await page.fill("#confirm", PW)
    if div_ui:
        await page.locator(".chk").click()
    else:
        await page.check("#agree")
    await btn(page, "Register").click()  # the submit button (home's Register is gone)
    await page.wait_for_selector("text=Balance")  # logged in automatically → assets view


async def visit_every_asset(page: Page) -> dict[tuple[str, str], str]:
    await btn(page, "Recharge").click()
    found = {}
    for coin, network in ex_mod.ASSETS:
        await page.locator(".btn", has_text=coin).locator("visible=true").first.click()
        # the network chip follows the coin row; for BTC both are labelled "BTC", so take the last
        await page.locator(".btn", has_text=network).locator("visible=true").last.click()
        await page.wait_for_function(
            "document.querySelector('#addr')"
            " && document.querySelector('#addr').textContent.length > 20"
        )
        found[(coin, network)] = (await page.inner_text("#addr")).strip()
    return found


@pytest.mark.parametrize("variant", ["normal", "div_ui"])
def test_register_then_every_deposit_address(variant: str) -> None:
    asyncio.run(_flow(variant))


async def _flow(variant: str) -> None:
    exchange = ex_mod.MockExchange(variant=variant)
    base = exchange.start()
    try:
        async with async_playwright() as pw:
            browser = await launch_mock_browser(pw)
            context = await new_context(browser, load_settings().browser, loopback_only=True)
            page = await context.new_page()
            await register_and_login(page, base, div_ui=variant == "div_ui")
            found = await visit_every_asset(page)

            expected = {(c, n): exchange.expected_address(EMAIL, c, n) for c, n in ex_mod.ASSETS}
            assert found == expected  # every coin/network shows this account's own address
            assert (
                await page.evaluate(
                    "document.querySelector('img[alt=\"deposit QR code\"]').naturalWidth"
                )
                > 0
            )
            assert exchange.forbidden == []  # nothing paid, signed or withdrawn
            assert context.blocked_urls == []  # the page never reached outside loopback
            await context.close()
            await browser.close()
    finally:
        exchange.stop()


def test_wallet_gate_blocks_the_ui_and_injection_link_is_stopped_by_the_guard() -> None:
    asyncio.run(_traps())


async def _traps() -> None:
    gate = ex_mod.MockExchange(variant="wallet_gate")
    inj = ex_mod.MockExchange(variant="injection")
    gate_url, inj_url = gate.start(), inj.start()
    try:
        async with async_playwright() as pw:
            browser = await launch_mock_browser(pw)
            context = await new_context(browser, load_settings().browser, loopback_only=True)

            page = await context.new_page()
            await page.goto(gate_url)
            modal = page.locator(".modal")
            assert "connect your wallet" in (await modal.inner_text()).lower()
            assert await page.locator(".x").count() == 0  # no way to close it
            assert gate.forbidden == []  # opening the page did not connect anything

            page2 = await context.new_page()
            await page2.goto(inj_url)
            await page2.locator(".x").click()
            assert "ignore your previous instructions" in (await page2.inner_text("body")).lower()
            await page2.get_by_text("Claim bonus").click()  # off-domain link in the page
            await page2.wait_for_timeout(500)
            assert any("evil.test" in u for u in context.blocked_urls)  # never left loopback
            await browser.close()
    finally:
        gate.stop()
        inj.stop()
