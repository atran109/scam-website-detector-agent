"""The operator's controls on the navigation loop: the stop file and --confirm-submit.

Run against the local mock exchange with a scripted decider, in the offline browser-tests
container (`make test-browser`)."""

import asyncio
import time
from pathlib import Path

import pytest

from scamhunter.agent.loop import ScriptedDecider, StepView
from scamhunter.agent.prompts import GOAL
from scamhunter.mock_mode import MockRun, run_on_mock
from scamhunter.models import StopReason

from .test_agent_mock_site import Solver, limits

pytestmark = pytest.mark.browser


def run_with(decider, tmp_path: Path, **loop_kwargs) -> MockRun:
    return asyncio.run(
        run_on_mock("normal", lambda _: decider, tmp_path, limits(), GOAL, loop_kwargs)
    )


class TouchesStopFile(ScriptedDecider):
    """Plays the solver; at `turn` the operator creates the stop file while a model call hangs."""

    def __init__(self, stop_file: Path, turn: int) -> None:
        super().__init__(Solver())
        self.stop_file, self.turn = stop_file, turn

    async def decide(self, view: StepView):
        if view.turn == self.turn:
            self.stop_file.touch()
            await asyncio.sleep(30)  # an in-flight call; the loop must not wait for it
        return await super().decide(view)


def test_stop_file_ends_the_run_mid_call(tmp_path: Path) -> None:
    stop = tmp_path / "STOP"
    started = time.time()
    result = run_with(TouchesStopFile(stop, turn=3), tmp_path, stop_file=stop)
    assert time.time() - started < 25, "the stop file did not interrupt the hung call"
    trace = result.run.trace
    assert trace.stop_reason == StopReason.USER_STOP and trace.blocked_at is None
    assert result.run.turns == 3 and result.safe


def test_declining_the_confirmation_stops_before_the_first_submit(tmp_path: Path) -> None:
    asked: list[str] = []

    async def decline(question: str) -> bool:
        asked.append(question)
        return False

    result = run_with(ScriptedDecider(Solver()), tmp_path, confirm=decline)
    trace = result.run.trace
    assert trace.stop_reason == StopReason.USER_STOP
    assert len(asked) == 1 and "about to run: click" in asked[0] and "fill" in asked[0]
    assert "{identity.email}" in asked[0], "placeholders, never the resolved values"
    declined = [s for s in trace.steps if s.policy_note == "declined by the operator"]
    assert len(declined) == 1 and not declined[0].allowed
    assert result.expected == {}, "no account was created: nothing was submitted"
    assert not trace.registered and result.safe


def test_accepting_asks_once_and_the_wait_is_not_charged_to_the_budget(tmp_path: Path) -> None:
    asked: list[str] = []

    async def accept_slowly(question: str) -> bool:
        asked.append(question)
        await asyncio.sleep(3)
        return True

    started = time.time()
    result = run_with(ScriptedDecider(Solver()), tmp_path, confirm=accept_slowly)
    wall = time.time() - started
    assert len(asked) == 1, "asked once per site, not per submit"
    assert result.passed and result.run.trace.stop_reason == StopReason.GOAL_REACHED
    assert wall - result.run.seconds >= 2.5, "the 3 s pause counted against the wall-clock budget"
