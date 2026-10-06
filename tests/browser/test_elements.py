"""Element provider and observation against the mock exchange (offline container, mock mode)."""

import asyncio

import pytest
from playwright.async_api import async_playwright

from scamhunter.browser.elements import list_elements, perform
from scamhunter.browser.page_state import Coverage, observe
from scamhunter.browser.sandbox import launch_mock_browser, new_context
from scamhunter.config import load_settings
from scamhunter.mock_mode import load_exchange_module
from scamhunter.models import ActionType, AgentAction, DiscoveryStage

pytestmark = pytest.mark.browser
ex_mod = load_exchange_module()
COVERAGE = Coverage(("BTC",), frozenset(), steps_left=10, seconds_left=60)


def act(kind: ActionType, **kw) -> AgentAction:
    return AgentAction(type=kind, rationale="test", **kw)


def find(elements, *names: str):
    """First element whose name contains any of `names` (the notice's close control is a real
    "Close" button, or a bare "×" div in the div_ui variant)."""
    return next(e for e in elements if any(n.lower() in e.name.lower() for n in names))


CLOSE = ("close", "×")


async def with_page(variant: str, body) -> None:
    exchange = ex_mod.MockExchange(variant=variant)
    base = exchange.start()
    try:
        async with async_playwright() as pw:
            browser = await launch_mock_browser(pw)
            context = await new_context(browser, load_settings().browser, loopback_only=True)
            page = await context.new_page()
            await page.goto(base)
            await body(page)
            await context.close()
            await browser.close()
    finally:
        exchange.stop()


@pytest.mark.parametrize("variant", ["normal", "div_ui"])
def test_lists_buttons_and_clickable_divs(variant: str) -> None:
    async def body(page) -> None:
        elements = await list_elements(page)
        assert not any("Register" in e.name for e in elements)  # the notice modal covers it
        close = find(elements, *CLOSE)
        assert close.clickable_only == (variant == "div_ui")  # divs found by onclick/cursor
        assert (await perform(page, act(ActionType.CLICK, element_id=close.id), elements)).ok
        elements = await list_elements(page)
        register = find(elements, "Register")
        assert register.clickable_only == (variant == "div_ui")
        assert register.in_view and register.box[2] > 0
        assert not any(e.name in ("Close", "×") for e in elements)

    asyncio.run(with_page(variant, body))


def test_register_flow_through_perform_and_deposit_facts() -> None:
    async def body(page) -> None:
        async def click(*names: str) -> None:
            elements = await list_elements(page)
            assert (
                await perform(
                    page, act(ActionType.CLICK, element_id=find(elements, *names).id), elements
                )
            ).ok

        await click("close", "×")
        await click("Register")
        elements = await list_elements(page)
        for field, value in (
            ("email", "tester@example.test"),
            ("password", "Passw0rd!x"),
            ("confirm", "Passw0rd!x"),
        ):
            r = await perform(
                page,
                act(ActionType.FILL, element_id=find(elements, field).id, value=value),
                elements,
            )
            assert r.ok, r
        await click("agree")
        await click("Register")
        await page.wait_for_selector("text=Balance")
        assets = await observe(page, DiscoveryStage.AUTHENTICATED, COVERAGE)
        assert not assets.facts.is_deposit_page  # the "Recharge" menu button is not a deposit page
        await click("Recharge")
        deposit = await observe(page, DiscoveryStage.AUTHENTICATED, COVERAGE)
        assert deposit.facts.is_deposit_page
        assert deposit.screenshot_png and deposit.render().count("<untrusted_") >= 3

    asyncio.run(with_page("normal", body))


def test_stale_and_unknown_ids_fail_cleanly() -> None:
    async def body(page) -> None:
        elements = await list_elements(page)
        missing = await perform(page, act(ActionType.CLICK, element_id=999), elements)
        assert (missing.ok, missing.result) == (False, "element_not_found")
        close = find(elements, *CLOSE)
        await perform(page, act(ActionType.CLICK, element_id=close.id), elements)
        again = await perform(page, act(ActionType.CLICK, element_id=close.id), elements)
        assert not again.ok  # the page re-rendered; the old id is gone

    asyncio.run(with_page("normal", body))


def test_modal_hides_what_it_covers() -> None:
    async def body(page) -> None:
        elements = await list_elements(page)
        names = [e.name for e in elements]
        assert "Connect Wallet" in names
        assert "Register" not in " ".join(names)  # covered by the forced wallet modal

    asyncio.run(with_page("wallet_gate", body))


def test_click_at_and_scroll_and_press() -> None:
    async def body(page) -> None:
        elements = await list_elements(page)
        close = find(elements, *CLOSE)
        x, y, w, h = close.box
        assert (
            await perform(page, act(ActionType.CLICK_AT, x=x + w // 2, y=y + h // 2), elements)
        ).ok
        assert not any(e.name in ("Close", "×") for e in await list_elements(page))
        assert (await perform(page, act(ActionType.SCROLL, value="down"), elements)).ok
        assert (await perform(page, act(ActionType.PRESS, value="Escape"), elements)).ok

    asyncio.run(with_page("normal", body))
