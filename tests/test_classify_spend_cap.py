"""classify --spend-cap: stop judging once the estimated spend reaches the cap (DESIGN §8.6)."""

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from scamhunter import pipeline
from scamhunter.config import load_settings
from scamhunter.llm.client import PRICES_PER_MTOK, TokenUsage
from scamhunter.models import Site


class _FakeLLM:
    def __init__(self, *_: object, **__: object) -> None:
        pass

    async def aclose(self) -> None:
        pass


def _sites(n: int) -> list[Site]:
    return [
        Site(
            site_id=f"{i:04d}",
            url=f"https://s{i}.example/",
            host=f"s{i}.example",
            registrable_domain=f"s{i}.example",
        )
        for i in range(1, n + 1)
    ]


@pytest.fixture
def one_dollar_per_site(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every judgment costs $1.00 at the judge model's price; returns the ids judged."""
    judged: list[str] = []
    settings = load_settings()
    price_out = PRICES_PER_MTOK[settings.llm.judge_model][1]

    async def analyze(ctx: object, site: Site, triage: object, snapshots: object) -> object:
        judged.append(site.site_id)
        classification = SimpleNamespace(
            verdict=SimpleNamespace(value="scam"),
            scam_probability=0.9,
            evidence_source=SimpleNamespace(value="live"),
        )
        usage = TokenUsage(tokens_out=int(1_000_000 / price_out), llm_calls=1)
        return SimpleNamespace(classification=classification, usage=usage)

    monkeypatch.setattr(pipeline, "LLMClient", _FakeLLM)
    monkeypatch.setattr(pipeline, "analyze", analyze)
    monkeypatch.setattr(pipeline, "load_snapshots", lambda _dir: [])
    monkeypatch.setattr(pipeline, "build_result", lambda site, *a, **k: site.site_id)
    monkeypatch.setattr(pipeline, "write_jsonl", lambda path, records: None)
    monkeypatch.setattr(pipeline, "load_triage", lambda path: {s.site_id: None for s in _sites(5)})
    return judged


def _run(cap: float | None, capsys: pytest.CaptureFixture[str]) -> tuple[list, str]:
    settings = load_settings()
    settings.run.concurrency = 1
    results = asyncio.run(
        pipeline.classify_from_evidence(settings, _sites(5), Path("unused"), spend_cap_usd=cap)
    )
    return results, capsys.readouterr().out


def test_stops_at_the_cap(one_dollar_per_site: list[str], capsys) -> None:
    results, out = _run(2.50, capsys)
    assert results == ["0001", "0002", "0003"]
    assert one_dollar_per_site == ["0001", "0002", "0003"]
    assert "2 sites not classified: spend cap of $2.50 reached" in out


def test_no_cap_judges_everything(one_dollar_per_site: list[str], capsys) -> None:
    results, out = _run(None, capsys)
    assert len(results) == 5 and "spend cap" not in out


def test_cap_not_reached_says_nothing(one_dollar_per_site: list[str], capsys) -> None:
    results, out = _run(100.0, capsys)
    assert len(results) == 5 and "spend cap" not in out
