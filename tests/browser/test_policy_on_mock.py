"""The policy against the real traps in the mock exchange: observe, check, resolve, act.

Drives the site only through policy-checked actions, as the loop will."""

import asyncio

import pytest
from playwright.async_api import Page, async_playwright

from scamhunter.agent.identity import new_identity, resolve_placeholders
from scamhunter.agent.policy import Policy, registrable
from scamhunter.browser.elements import perform
from scamhunter.browser.page_state import Coverage, observe
from scamhunter.browser.sandbox import launch_mock_browser, new_context
from scamhunter.config import load_settings
from scamhunter.mock_mode import load_exchange_module
from scamhunter.models import ActionType, AgentAction, BlockedReason, DiscoveryStage

pytestmark = pytest.mark.browser
ex_mod = load_exchange_module()
COVERAGE = Coverage(("BTC",), frozenset(), steps_left=10, seconds_left=60)
IDENTITY = new_identity("tester@example.test")
TRAPS = ["I have paid", "Upload receipt", "Confirm payment"]  # on the address view


def act(kind: ActionType, **kw) -> AgentAction:
    return AgentAction(type=kind, rationale="test", **kw)


class Driver:
    def __init__(self, page: Page, base: str) -> None:
        self.page = page
        self.policy = Policy(registrable("127.0.0.1"), IDENTITY)
        self.stage = DiscoveryStage.LANDING

    async def state(self):
        return await observe(self.page, self.stage, COVERAGE)

    async def try_action(self, kind: ActionType, *names: str, **kw):
        """Check the action the way the loop will; run it only if allowed. Returns the decision."""
        state = await self.state()
        element = next(e for e in state.elements if any(n.lower() in e.name.lower() for n in names))
        action = act(kind, element_id=element.id, **kw)
        decision = self.policy.check(action, state.elements, state.facts)
        if decision.allowed:
            if action.value:
                action = action.model_copy(
                    update={"value": resolve_placeholders(action.value, IDENTITY)}
                )
            result = await perform(self.page, action, state.elements)
            assert result.ok, result
        return decision

    async def click(self, *names: str):
        return await self.try_action(ActionType.CLICK, *names)

    async def fill(self, name: str, value: str):
        return await self.try_action(ActionType.FILL, name, value=value)

    async def register(self) -> None:
        for names in (("close", "×"), ("register",)):
            assert (await self.click(*names)).allowed
        for field in ("email", "password", "confirm"):
            value = "{identity.email}" if field == "email" else "{identity.password}"
            assert (await self.fill(field, value)).allowed
        assert (await self.click("agree")).allowed
        assert (await self.click("register")).allowed
        await self.page.wait_for_selector("text=Balance")
        self.stage = DiscoveryStage.AUTHENTICATED


async def with_driver(variant: str, body) -> None:
    exchange = ex_mod.MockExchange(variant=variant)
    base = exchange.start()
    try:
        async with async_playwright() as pw:
            browser = await launch_mock_browser(pw)
            context = await new_context(browser, load_settings().browser, loopback_only=True)
            page = await context.new_page()
            await page.goto(base)
            await body(Driver(page, base), exchange)
            assert exchange.forbidden == []  # nothing was paid, signed or withdrawn
            await context.close()
            await browser.close()
    finally:
        exchange.stop()


@pytest.mark.parametrize("variant", ["normal", "div_ui"])
def test_traps_are_blocked_and_the_deposit_path_is_open(variant: str) -> None:
    async def body(driver: Driver, exchange) -> None:
        await driver.register()
        assets = await driver.state()
        assert not assets.facts.is_deposit_page
        wallet = await driver.try_action(ActionType.CLICK, "Connect Wallet")
        assert not wallet.allowed and wallet.blocked_at == BlockedReason.WALLET_REQUIRED
        assert not (await driver.click("Withdraw")).allowed
        assert (await driver.click("Recharge")).allowed  # the menu button is plain navigation

        driver.stage = DiscoveryStage.DEPOSIT_PAGE
        assert (await driver.click("USDT")).allowed
        await driver.click("TRC20")
        await driver.page.wait_for_selector("#addr")
        state = await driver.state()
        assert state.facts.is_deposit_page and not state.facts.has_card_or_bank_fields
        for trap in TRAPS:
            blocked = [e for e in state.elements if trap.lower() in e.name.lower()]
            assert blocked, f"trap {trap!r} not listed"
            for e in blocked:
                action = act(ActionType.CLICK, element_id=e.id)
                assert not driver.policy.check(action, state.elements, state.facts).allowed
        click_at = act(ActionType.CLICK_AT, x=10, y=10)
        assert not driver.policy.check(click_at, state.elements, state.facts).allowed

    asyncio.run(with_driver(variant, body))


def test_amount_field_takes_only_the_stated_minimum() -> None:
    async def body(driver: Driver, exchange) -> None:
        await driver.register()
        await driver.click("Recharge")
        driver.stage = DiscoveryStage.DEPOSIT_PAGE
        await driver.click("USDT")
        await driver.click("TRC20")
        state = await driver.state()
        assert state.facts.stated_minimum == str(exchange.min_amount)
        wrong = await driver.fill("amount", "100")
        assert not wrong.allowed and str(exchange.min_amount) in wrong.reason
        assert (await driver.fill("amount", str(exchange.min_amount))).allowed
        assert (await driver.click("Next")).allowed  # no card or bank fields here
        await driver.page.wait_for_selector("#addr")

    asyncio.run(with_driver("amount_first", body))
