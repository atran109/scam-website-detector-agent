"""The route guard (2026-10-07, pilot site 071): a page that sends the browser to another site by
itself (a timer, a button with no href) is stopped before any request leaves.

`self_redirect` mock variant: the home page redirects to localhost after 3 s and its "Start"
button does the same; the server logs any request that arrives for localhost as forbidden.
Runs in the offline browser-tests container (`make test-browser`)."""

import asyncio
from pathlib import Path

import pytest

from scamhunter.agent.loop import ScriptedDecider, StepView
from scamhunter.agent.prompts import GOAL
from scamhunter.mock_mode import MockRun, run_on_mock
from scamhunter.models import StopReason

from .test_agent_mock_site import TARGETS, Solver, click, limits, named

pytestmark = pytest.mark.browser


def run(script, tmp_path: Path) -> MockRun:
    return asyncio.run(
        run_on_mock("self_redirect", lambda _: ScriptedDecider(script), tmp_path, limits(), GOAL)
    )


def test_the_timer_redirect_is_stopped_and_the_run_still_solves_the_site(tmp_path: Path) -> None:
    solver = Solver()
    waited = {"done": False}

    def script(view: StepView):
        if not waited["done"]:  # sit on the home page long enough for the 3 s timer
            waited["done"] = True
            return [("wait", {"seconds": 4})]
        return solver(view)

    result = run(script, tmp_path)
    trace = result.run.trace
    assert result.safe, result.forbidden  # no request ever reached "localhost"
    assert any(u.startswith("http://localhost:") for u in trace.linked_domains)
    assert set(result.found_turn) == set(TARGETS) and trace.stop_reason == StopReason.GOAL_REACHED
    assert result.passed


def test_a_button_without_href_that_leaves_the_site_is_stopped_before_loading(
    tmp_path: Path,
) -> None:
    solver = Solver()
    clicked = {"start": False}

    def script(view: StepView):
        if not clicked["start"] and named(view, "start"):
            clicked["start"] = True
            return [click(named(view, "start")[0])]
        return solver(view)

    result = run(script, tmp_path)
    trace = result.run.trace
    start = next(s for s in trace.steps if s.result == "blocked_navigation")
    assert "localhost" in (start.policy_note or "")
    assert start.page_url.startswith("http://127.0.0.1:")
    assert result.safe, result.forbidden
    assert set(result.found_turn) == set(TARGETS)
