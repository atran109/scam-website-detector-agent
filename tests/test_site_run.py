"""Pieces of the real-site navigation wiring that need no browser: the trigger, the spend cap,
the zero-visit guard, the wallet setting and prompt, and the empty-selection error."""

import argparse
from pathlib import Path

import pytest

from scamhunter.agent.loop import AgentLimits
from scamhunter.agent.prompts import system_prompt
from scamhunter.agent.site_run import (
    NavigationOptions,
    Spend,
    should_navigate,
    spend_blocks,
    worst_case_usd,
)
from scamhunter.cli import _selected
from scamhunter.config import load_settings
from scamhunter.llm.client import LLMClient, TokenUsage
from scamhunter.models import Classification, EvidenceSource, Site, Verdict
from scamhunter.pipeline import NoSitesVisited, check_visited, count_visited

BAND = (0.35, 0.65)


def classification(probability: float) -> Classification:
    scam = probability >= 0.45
    return Classification(
        verdict=Verdict.SCAM if scam else Verdict.NOT_SCAM,
        scam_type=None,
        scam_probability=probability,
        confidence=max(probability, 1 - probability),
        evidence_source=EvidenceSource.LIVE,
        reasoning="t",
        signals=[],
        judgment=None,
        method="heuristic+llm",
    )


@pytest.mark.parametrize(
    ("probability", "expected"),
    [(0.95, True), (0.5, True), (0.40, True), (0.36, True), (0.2, False), (0.05, False)],
)
def test_navigation_trigger(probability: float, expected: bool) -> None:
    assert should_navigate(classification(probability), BAND) is expected


def options(cap: float | None, spent: float = 0.0) -> NavigationOptions:
    limits = AgentLimits(
        max_steps=30, max_seconds=300, max_consecutive_failures=4, target_assets=()
    )
    return NavigationOptions(
        limits=limits,
        llm=LLMClient("http://gateway.invalid"),
        spend_cap_usd=cap,
        spend=Spend(spent),
    )


def test_worst_case_is_both_token_caps_at_model_prices() -> None:
    # Sonnet 5.5: $2 / $10 per million; caps 250k in, 25k out -> $0.50 + $0.25
    assert worst_case_usd(options(None).limits, "claude-sonnet-5-5") == pytest.approx(0.75)


def test_session_spend_cap_stops_new_sites_before_it_can_be_crossed() -> None:
    model = "claude-sonnet-5-5"
    assert spend_blocks(options(None, spent=99), model) is None  # no cap set
    assert spend_blocks(options(5.0, spent=4.0), model) is None  # 4.00 + 0.75 <= 5
    reason = spend_blocks(options(5.0, spent=4.30), model)  # 4.30 + 0.75 > 5
    assert reason and "session spend cap" in reason


def test_token_usage_plus_adds_every_field() -> None:
    a = TokenUsage(10, 2, 1, 0, 4, 1)
    b = TokenUsage(5, 3, 2, 1, 0, 2)
    assert a.plus(b) == TokenUsage(15, 5, 3, 1, 4, 3)


def test_a_run_that_expected_visits_but_made_none_is_an_error() -> None:
    with pytest.raises(NoSitesVisited, match="0 of 56"):
        check_visited(56, 0)
    check_visited(56, 1)  # a partial run is not this guard's business
    check_visited(0, 0)  # nothing was expected (all sites dead or already done)


def test_count_visited_needs_a_saved_snapshot(tmp_path: Path) -> None:
    sites = [
        Site(site_id=i, url=f"https://{i}.test", host=f"{i}.test", registrable_domain=f"{i}.test")
        for i in ("001", "002", "003")
    ]
    (tmp_path / "sites" / "001").mkdir(parents=True)
    (tmp_path / "sites" / "001" / "snapshots.jsonl").write_text('{"snapshot_id": "s01"}\n')
    (tmp_path / "sites" / "002").mkdir(parents=True)  # directory made, page never loaded
    (tmp_path / "sites" / "003").mkdir(parents=True)
    (tmp_path / "sites" / "003" / "snapshots.jsonl").write_text("")
    assert count_visited(tmp_path, sites) == 1


def test_an_empty_site_selection_is_an_error() -> None:
    with pytest.raises(SystemExit, match="matches no site"):
        _selected(argparse.Namespace(only="9999"))


def test_wallet_mock_is_off_and_the_prompt_says_never_connect_a_wallet() -> None:
    assert load_settings().features.wallet_mock is False
    prompt = system_prompt(False)
    never = prompt[prompt.index("\nNever\n") :]
    assert "- connect a wallet;" in never.split("\n\n")[0] + "\n"
    assert "test wallet" not in prompt  # the mock-wallet rule is absent
    assert "wallet_required" in prompt  # and a wallet-only site ends with that gate
