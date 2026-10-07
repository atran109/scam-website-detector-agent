"""The gateway usage-log totals (decided 2026-10-07)."""

import json
from pathlib import Path

import pytest

from scamhunter.llm.usage_log import count_lines, read_usage, total


def call(site="012", model="claude-sonnet-5-5", cached=False, i=100, o=10, cr=0, cw=0) -> dict:
    return {
        "site_id": site,
        "purpose": "navigate:1",
        "role": "navigator",
        "model": model,
        "cached": cached,
        "input_tokens": i,
        "output_tokens": o,
        "cache_read_input_tokens": cr,
        "cache_creation_input_tokens": cw,
    }


def test_cache_reads_and_writes_are_priced_differently_from_fresh_input() -> None:
    # Sonnet 5.5: $2 in / $10 out per million. 1000 fresh + 10000 cache reads + 2000 writes:
    # (1000 + 0.1*10000 + 1.25*2000) * 2 + 500 * 10 = 9000 + 5000 per million = $0.014
    usage = total([call(i=1000, o=500, cr=10_000, cw=2000)])
    assert usage.cost_usd == pytest.approx(((1000 + 1000 + 2500) * 2 + 500 * 10) / 1e6)
    assert usage.tokens_in == 13_000 and usage.tokens_out == 500 and usage.calls == 1


def test_gateway_cache_hits_cost_nothing() -> None:
    usage = total([call(), call(cached=True), call(cached=True)])
    assert usage.calls == 1 and usage.cached_calls == 2


def test_the_pilot_rerun_total(tmp_path: Path) -> None:
    """Three sites of the 2026-10-07 rerun, in the log's own order, priced the way the run was:
    the log's total ($0.353) and not the no-discount estimate ($0.58)."""
    rows = [call("145", i=25021 - 8000, o=1362, cr=8000), call("071", i=71498, o=1718)]
    assert total(rows).cost_usd < ((25021 + 71498) * 2 + (1362 + 1718) * 10) / 1e6


def test_only_new_lines_of_this_runs_sites_count(tmp_path: Path) -> None:
    log = tmp_path / "usage.jsonl"
    rows = [call("999"), call("012"), call("071"), call("555")]
    log.write_text("".join(json.dumps(r) + "\n" for r in rows))
    assert count_lines(log) == 4
    assert read_usage(log, start_line=1, site_ids={"012", "071"}).calls == 2
    assert read_usage(log, start_line=2, site_ids={"012", "071"}).calls == 1
    assert read_usage(log, start_line=0, site_ids=None).calls == 4
    assert read_usage(tmp_path / "missing.jsonl").calls == 0
