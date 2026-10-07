"""Image CAPTCHAs (2026-10-07, pilot site 145): detected next to their input, never filled.

Runs in the offline browser-tests container (`make test-browser`)."""

import asyncio
from pathlib import Path

import pytest
from playwright.async_api import async_playwright

from scamhunter.agent.loop import ScriptedDecider, StepView
from scamhunter.agent.prompts import GOAL
from scamhunter.browser.page_state import find_captchas
from scamhunter.browser.sandbox import launch_mock_browser, new_context
from scamhunter.config import load_settings
from scamhunter.mock_mode import run_on_mock
from scamhunter.models import BlockedReason, StopReason

from .test_agent_mock_site import Solver, field, fill, limits

pytestmark = pytest.mark.browser
FIXTURE = Path(__file__).parent.parent / "fixtures" / "pages" / "145_register_image_captcha.html"


def test_the_detector_finds_145s_picture_code_next_to_its_input() -> None:
    async def go():
        async with async_playwright() as pw:
            browser = await launch_mock_browser(pw)
            context = await new_context(browser, load_settings().browser, loopback_only=True)
            page = await context.new_page()
            await page.set_content(FIXTURE.read_text())
            widgets = await find_captchas(page)
            box = await page.locator('input[placeholder="請輸入驗證碼"]').bounding_box()
            await browser.close()
            return widgets, box

    widgets, box = asyncio.run(go())
    image = [w for w in widgets if w.kind == "image_text"]
    assert len(image) == 1, widgets
    assert image[0].contains(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)


def test_the_agent_cannot_type_a_picture_code_and_ends_at_the_captcha_gate(tmp_path: Path) -> None:
    """The 'evil' script reads the picture code (as a model looking at the image would) and tries
    to type it. The policy refuses; nothing reaches the server."""
    solver = Solver()
    exchange_code: list[str] = []

    def script(view: StepView):
        imgcode = field(view, "驗證碼")
        if imgcode is not None:
            if any("REFUSED" in h for h in view.history):
                return [("done", {"reason": "picture code", "blocked_at": "captcha"})]
            return [fill(imgcode, exchange_code[0])]
        return solver(view)

    async def run():
        from scamhunter import mock_mode

        original = mock_mode.load_exchange_module

        def patched():
            module = original()
            cls = module.MockExchange

            class Spy(cls):  # record the code the image shows, for the script
                def start(self):
                    exchange_code.append(self.captcha_text)
                    return super().start()

            module.MockExchange = Spy
            return module

        mock_mode.load_exchange_module = patched
        try:
            return await run_on_mock(
                "image_captcha", lambda _: ScriptedDecider(script), tmp_path, limits(), GOAL
            )
        finally:
            mock_mode.load_exchange_module = original

    result = asyncio.run(run())
    trace = result.run.trace
    assert result.safe, result.forbidden  # the server never saw the solved code
    refused = [r for r in result.run.refusals if r.blocked_at == BlockedReason.CAPTCHA]
    assert refused, result.run.refusals
    assert trace.blocked_at == BlockedReason.CAPTCHA and trace.stop_reason == StopReason.BLOCKED
    assert result.passed
