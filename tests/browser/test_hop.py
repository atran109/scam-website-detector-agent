"""The one cross-domain hop on the mock `app_domain` variant: the landing domain (127.0.0.1) has
only a Login link to the app on a second domain (localhost) and a Telegram link.

Runs in the offline browser-tests container (`make test-browser`)."""

import asyncio
from pathlib import Path

import pytest

from scamhunter.agent.loop import ScriptedDecider, StepView
from scamhunter.agent.prompts import GOAL
from scamhunter.mock_mode import MockRun, run_on_mock
from scamhunter.models import StopReason

from .test_agent_mock_site import TARGETS, Solver, click, limits

pytestmark = pytest.mark.browser


def hop_script(*, telegram_first: bool, give_up_after: int | None = None):
    solver = Solver()
    seen = {"telegram": False, "attempts": 0}

    def script(view: StepView):
        links = {e.name.lower(): e for e in view.state.elements if e.role == "link"}
        if "127.0.0.1" in view.state.url and "login" in links:  # the marketing domain
            if telegram_first and not seen["telegram"]:
                seen["telegram"] = True
                return [click(links["telegram support"])]
            seen["attempts"] += 1
            if give_up_after is not None and seen["attempts"] > give_up_after:
                return [("done", {"reason": "the app link was refused"})]
            return [click(links["login"])]
        return solver(view)

    return script


def run_with(script, tmp_path: Path, **loop_kwargs) -> MockRun:
    return asyncio.run(
        run_on_mock(
            "app_domain", lambda _: ScriptedDecider(script), tmp_path, limits(), GOAL, loop_kwargs
        )
    )


def test_a_confirmed_hop_reaches_the_app_and_is_recorded(tmp_path: Path) -> None:
    asked: list[str] = []

    async def agree(question: str) -> bool:
        asked.append(question)
        return True

    result = run_with(hop_script(telegram_first=True), tmp_path, confirm=agree)
    trace = result.run.trace
    hops = [q for q in asked if q.startswith("HOP")]
    assert len(hops) == 1, "one question for the hop (the Telegram link never asks)"
    assert "localhost" in hops[0] and "'Login'" in hops[0]
    assert trace.stop_reason == StopReason.GOAL_REACHED and result.safe
    assert set(result.found_turn) == set(TARGETS), "all six addresses came from the app domain"
    assert len(trace.hops) == 1
    hop = trace.hops[0]
    assert hop.source_url.startswith("http://127.0.0.1:") and hop.link_text == "Login"
    assert hop.target_domain == "localhost" and hop.target_url.startswith("http://localhost:")
    linked = trace.linked_domains
    assert any(u.startswith("http://localhost:") for u in linked), "the app domain is reported"
    assert "https://t.me/mockex_support" in linked, "platform links are recorded, never followed"
    assert any("social or app-store" in r.reason for r in result.run.refusals), "Telegram refused"


def test_a_declined_hop_is_refused_recorded_and_the_run_goes_on(tmp_path: Path) -> None:
    async def refuse(question: str) -> bool:
        return not question.startswith("HOP")

    result = run_with(hop_script(telegram_first=False, give_up_after=1), tmp_path, confirm=refuse)
    trace = result.run.trace
    assert trace.hops == [] and result.found_turn == {}
    assert any(u.startswith("http://localhost:") for u in trace.linked_domains)
    assert any("operator declined this hop" in r.reason for r in result.run.refusals)
    assert result.safe


def test_without_a_confirmation_callback_hops_are_refused(tmp_path: Path) -> None:
    result = run_with(hop_script(telegram_first=False, give_up_after=1), tmp_path, confirm=None)
    trace = result.run.trace
    assert trace.hops == [] and result.found_turn == {}
    assert any("needs the operator's confirmation" in r.reason for r in result.run.refusals)
