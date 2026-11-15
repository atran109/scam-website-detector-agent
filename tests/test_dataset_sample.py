"""eval/dataset_v1/sample.py and the URL guard of scripts/fetch_sources.py (DESIGN §8.2)."""

import importlib.util
import json
from datetime import date, timedelta
from pathlib import Path

import pytest
from eval.dataset_v1.models import Candidate, ManifestRow
from eval.dataset_v1.sample import (
    MAX_CAPTURES,
    MAX_CHECKS,
    QUOTAS,
    append_batch,
    capture_ids,
    live_counts,
    load_manifest,
    next_batch,
    remove_conflicts,
)

from scamhunter.config import REPO_ROOT

spec = importlib.util.spec_from_file_location("fetch", REPO_ROOT / "scripts" / "fetch_sources.py")
fetch = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
spec.loader.exec_module(fetch)  # type: ignore[union-attr]

SCAM = {"dfpi", "scamsniffer", "metamask_block"}


def cand(domain: str, source: str, listed_on: date | None = None, note: str = "") -> Candidate:
    return Candidate(
        url=f"https://{domain}/",
        registrable_domain=domain,
        source=source,  # type: ignore[arg-type]
        expected="scam" if source in SCAM else "not_scam",
        listed_on=listed_on,
        source_note=note,
    )


def pool() -> list[Candidate]:
    """A candidate pool larger than any quota, in every source."""
    start = date(2026, 9, 1)
    out = [cand(f"dfpi{i}.example", "dfpi") for i in range(30)]
    out += [
        cand(f"ss{d}-{i}.example", "scamsniffer", start + timedelta(days=d))
        for d in range(60)
        for i in range(40)
    ]
    out += [cand(f"mm{i}.example", "metamask_block") for i in range(900)]
    out += [cand(f"tr{i}.example", "tranco", note=f"rank {i + 1}") for i in range(5000)]
    out += [cand(f"cg{i}.example", "coingecko") for i in range(300)]
    out += [cand(f"mma{i}.example", "metamask_allow") for i in range(50)]
    out += [cand(f"look{i}.example", "dfpi_lookalike") for i in range(40)]
    return out


def rows(n: int) -> list[ManifestRow]:
    return [
        ManifestRow(
            **cand(f"old{i}.example", "metamask_block").model_dump(),
            site_id=f"{i + 1:04d}",
            batch=1,
        )
        for i in range(n)
    ]


def test_conflicting_domain_dropped_from_both_sides() -> None:
    kept, dropped = remove_conflicts(
        [
            cand("x.example", "scamsniffer"),
            cand("x.example", "metamask_allow"),
            cand("y.example", "tranco"),
        ]
    )
    assert [c.registrable_domain for c in kept] == ["y.example"]
    assert dropped == ["x.example"]


def test_same_domain_in_two_scam_lists_keeps_the_dated_one() -> None:
    day = date(2026, 11, 1)
    kept, dropped = remove_conflicts(
        [cand("x.example", "metamask_block"), cand("x.example", "scamsniffer", day)]
    )
    assert [(c.source, c.listed_on) for c in kept] == [("scamsniffer", day)]
    assert dropped == []


def test_dfpi_wins_over_other_scam_lists() -> None:
    kept, _ = remove_conflicts([cand("x.example", "scamsniffer"), cand("x.example", "dfpi")])
    assert [c.source for c in kept] == ["dfpi"]


def test_append_never_renumbers(tmp_path: Path) -> None:
    urls, manifest = tmp_path / "urls.txt", tmp_path / "manifest.jsonl"
    first = append_batch(urls, manifest, [cand("a.example", "tranco")])
    second = append_batch(urls, manifest, [cand("b.example", "tranco"), cand("c.example", "dfpi")])
    assert [r.site_id for r in first + second] == ["0001", "0002", "0003"]
    assert [r.batch for r in first + second] == [1, 2, 2]
    assert urls.read_text().splitlines() == [
        "https://a.example/",
        "https://b.example/",
        "https://c.example/",
    ]
    assert [r.site_id for r in load_manifest(manifest)] == ["0001", "0002", "0003"]


def test_append_empty_batch_writes_nothing(tmp_path: Path) -> None:
    urls, manifest = tmp_path / "urls.txt", tmp_path / "manifest.jsonl"
    assert append_batch(urls, manifest, []) == []
    assert not urls.exists()


def test_first_batch_takes_all_dfpi_and_respects_batch_size() -> None:
    batch = next_batch(pool(), [], {}, batch_size=500)
    assert len(batch) == 500
    assert sum(c.source == "dfpi" for c in batch) == 30
    assert {c.source for c in batch} == set(QUOTAS)


def test_met_quota_stops_sampling() -> None:
    batch = next_batch(pool(), [], {"tranco": QUOTAS["tranco"]})
    assert batch and all(c.source != "tranco" for c in batch)


def test_all_quotas_met_gives_empty_batch() -> None:
    done = {source: quota for source, quota in QUOTAS.items()}
    assert [c for c in next_batch(pool(), [], done) if c.source != "dfpi"] == []


def test_cap_of_4000_checks() -> None:
    assert MAX_CHECKS == 4000
    assert next_batch(pool(), rows(4000), {}) == []
    assert len(next_batch(pool(), rows(3990), {})) == 10


def test_never_resamples_a_domain_already_in_the_manifest() -> None:
    first = next_batch(pool(), [], {})
    manifest = [
        ManifestRow(**c.model_dump(), site_id=f"{i + 1:04d}", batch=1) for i, c in enumerate(first)
    ]
    second = next_batch(pool(), manifest, {})
    assert not {c.registrable_domain for c in first} & {c.registrable_domain for c in second}


def test_same_seed_same_batch() -> None:
    assert next_batch(pool(), [], {}) == next_batch(pool(), [], {})


def test_scamsniffer_newest_days_first_and_even() -> None:
    batch = [c for c in next_batch(pool(), [], {}) if c.source == "scamsniffer"]
    per_day: dict[date, int] = {}
    for c in batch:
        per_day[c.listed_on] = per_day.get(c.listed_on, 0) + 1  # type: ignore[index]
    assert max(per_day.values()) - min(per_day.values()) <= 1
    newest = date(2026, 9, 1) + timedelta(days=59)
    assert newest in per_day


def test_tranco_half_from_the_top_thousand() -> None:
    batch = [c for c in next_batch(pool(), [], {}) if c.source == "tranco"]
    top = sum(int(c.source_note.split()[1]) <= 1000 for c in batch)
    assert abs(top - (len(batch) - top)) <= 1


def _triage(path: Path, statuses: dict[str, str]) -> Path:
    lines = [
        json.dumps({"site": {"site_id": sid}, "triage": {"status": status}})
        for sid, status in statuses.items()
    ]
    path.write_text("\n".join(lines) + "\n")
    return path


def test_live_counts_by_source(tmp_path: Path) -> None:
    manifest = rows(3)
    triage = _triage(tmp_path / "t.jsonl", {"0001": "live", "0002": "parked", "0003": "live"})
    assert live_counts(manifest, triage) == {"metamask_block": 2}
    assert live_counts(manifest, tmp_path / "missing.jsonl") == {}


def test_capture_ids_stop_at_each_quota_and_at_the_total(tmp_path: Path) -> None:
    manifest = rows(QUOTAS["metamask_block"] + 20)
    triage = _triage(tmp_path / "t.jsonl", {r.site_id: "live" for r in manifest})
    ids = capture_ids(manifest, triage)
    assert ids == [r.site_id for r in manifest[: QUOTAS["metamask_block"]]]
    assert MAX_CAPTURES == 500


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/list.json",
        "http://raw.githubusercontent.com/x",
        "https://raw.githubusercontent.com.evil.example/x",
        "https://user@evil.example@raw.githubusercontent.com/x",
        "file:///etc/passwd",
    ],
)
def test_fetcher_refuses_other_hosts(url: str) -> None:
    with pytest.raises(ValueError):
        fetch.check_url(url)


def test_fetcher_accepts_the_four_providers() -> None:
    for url in (
        "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/archive/2026-11-01.json",
        "https://dfpi.ca.gov/consumers/crypto/crypto-scam-tracker/",
        "https://tranco-list.eu/top-1m.csv.zip",
        "https://api.coingecko.com/api/v3/exchanges?per_page=250&page=1",
    ):
        fetch.check_url(url)
