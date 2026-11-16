"""triage --new-only: dataset batches are checked once each (DESIGN §8.2 step 3). No network."""

import asyncio
from pathlib import Path

import pytest

from scamhunter import pipeline
from scamhunter.config import load_settings
from scamhunter.models import Site, SiteStatus, TriageResult


class _FakeClient:
    async def __aenter__(self) -> "_FakeClient":
        return self

    async def __aexit__(self, *_: object) -> None:
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
def probed(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Replaces the network probe; returns the URLs it was asked to check."""
    urls: list[str] = []

    async def probe(url: str, *_: object) -> TriageResult:
        urls.append(url)
        return TriageResult(status=SiteStatus.LIVE, elapsed_ms=1)

    monkeypatch.setattr(pipeline, "probe", probe)
    monkeypatch.setattr(pipeline, "require_egress_proxy", lambda: "http://proxy.invalid")
    monkeypatch.setattr(pipeline, "make_client", lambda *a, **k: _FakeClient())
    return urls


def _triage(sites: list[Site], out: Path, new_only: bool) -> list:
    return asyncio.run(pipeline.run_triage(load_settings(), sites, out, new_only=new_only))


def test_second_batch_checks_only_new_sites_and_keeps_the_first(
    probed: list[str], tmp_path: Path
) -> None:
    _triage(_sites(2), tmp_path, new_only=True)
    assert len(probed) == 2

    new = _triage(_sites(5), tmp_path, new_only=True)
    assert [r.site.site_id for r in new] == ["0003", "0004", "0005"]
    assert len(probed) == 5  # 0001 and 0002 were not contacted again
    assert list(pipeline.load_triage(tmp_path / "triage.jsonl")) == [
        "0001",
        "0002",
        "0003",
        "0004",
        "0005",
    ]


def test_without_the_flag_every_site_is_checked_and_the_file_replaced(
    probed: list[str], tmp_path: Path
) -> None:
    _triage(_sites(2), tmp_path, new_only=False)
    _triage(_sites(1), tmp_path, new_only=False)
    assert len(probed) == 3
    assert list(pipeline.load_triage(tmp_path / "triage.jsonl")) == ["0001"]


def test_moved_lines_are_refused(probed: list[str], tmp_path: Path) -> None:
    _triage(_sites(2), tmp_path, new_only=True)
    moved = _sites(2)
    moved[0] = moved[0].model_copy(update={"url": "https://other.example/"})
    with pytest.raises(ValueError, match="ids must stay fixed"):
        _triage(moved, tmp_path, new_only=True)
    assert len(probed) == 2  # nothing was contacted
