"""eval/dataset_v1/cluster.py and split.py (DESIGN §8.5, plan Task 8). No network."""

import json
from datetime import UTC, date, datetime
from pathlib import Path

import pytest
from eval.dataset_v1 import split as split_module
from eval.dataset_v1.cluster import ClusterInput, by_cluster, clusters, dom_skeleton_hash
from eval.dataset_v1.models import ManifestRow
from eval.dataset_v1.split import SplitInput, assign_split, load_inputs

from scamhunter.models import DiscoveryStage, PageSnapshot

KIT = (
    "<html><body>"
    + "<div><a href='/x'>{brand}</a><span>{brand}</span></div>" * 12
    + "</body></html>"
)


def ci(
    site_id: str,
    domain: str,
    addresses: list[str] | None = None,
    dom_hash: str | None = None,
    judgeable: bool = True,
) -> ClusterInput:
    return ClusterInput(
        site_id=site_id,
        registrable_domain=domain,
        addresses=addresses or [],
        dom_hash=dom_hash,
        judgeable=judgeable,
    )


def si(site_id: str, source: str, listed_on: date | None = None) -> SplitInput:
    expected = "scam" if source in {"dfpi", "scamsniffer", "metamask_block"} else "not_scam"
    return SplitInput(site_id=site_id, source=source, expected=expected, listed_on=listed_on)


def singletons(rows: list[SplitInput]) -> dict[str, str]:
    return {r.site_id: f"c{r.site_id}" for r in rows}


# ---------- dom_skeleton_hash ----------


def test_same_kit_with_different_text_hashes_the_same() -> None:
    a = dom_skeleton_hash(KIT.format(brand="Binance Pro"))
    b = dom_skeleton_hash(KIT.format(brand="Coinbase Elite").replace("/x", "/y"))
    assert a is not None and a == b


def test_different_structure_hashes_differently() -> None:
    other = KIT.replace("<span>", "<p>").replace("</span>", "</p>")
    assert dom_skeleton_hash(KIT) != dom_skeleton_hash(other)


def test_small_page_has_no_hash() -> None:
    assert dom_skeleton_hash("<html><body><h1>Not Found</h1></body></html>") is None


# ---------- clusters ----------


def test_links_by_domain_address_and_structure() -> None:
    rows = [
        ci("0001", "a.example"),
        ci("0002", "a.example"),  # same domain as 0001
        ci("0003", "b.example", addresses=["0xabc"]),
        ci("0004", "c.example", addresses=["0xabc"]),  # same address as 0003
        ci("0005", "d.example", dom_hash="h"),
        ci("0006", "e.example", dom_hash="h"),  # same structure as 0005
        ci("0007", "f.example"),
    ]
    assert by_cluster(clusters(rows)) == {
        "c0001": ["0001", "0002"],
        "c0002": ["0003", "0004"],
        "c0003": ["0005", "0006"],
        "c0004": ["0007"],
    }


def test_links_are_transitive() -> None:
    rows = [
        ci("0001", "a.example", addresses=["0xabc"]),
        ci("0002", "b.example", addresses=["0xabc"], dom_hash="h"),
        ci("0003", "c.example", dom_hash="h"),
    ]
    assert len(set(clusters(rows).values())) == 1


def test_blank_pages_do_not_fuse() -> None:
    rows = [
        ci("0001", "a.example", dom_hash="h", judgeable=False),
        ci("0002", "b.example", dom_hash="h", judgeable=False),
    ]
    assert len(set(clusters(rows).values())) == 2


def test_one_unjudgeable_page_takes_no_structure_link() -> None:
    rows = [
        ci("0001", "a.example", dom_hash="h"),
        ci("0002", "b.example", dom_hash="h", judgeable=False),
    ]
    assert len(set(clusters(rows).values())) == 2


def test_cluster_ids_do_not_depend_on_input_order() -> None:
    rows = [ci("0003", "a.example"), ci("0001", "b.example"), ci("0002", "a.example")]
    assert clusters(rows) == clusters(list(reversed(rows)))
    assert clusters(rows)["0001"] == "c0001"


# ---------- assign_split ----------


def test_newest_dated_scam_clusters_fill_test_to_a_third() -> None:
    rows = [si(f"{i:04d}", "scamsniffer", date(2026, 10, i)) for i in range(1, 7)]
    split = assign_split(rows, singletons(rows))
    assert [s for s in sorted(split) if split[s] == "test"] == ["0005", "0006"]


def test_a_third_counts_sites_not_clusters() -> None:
    # The newest cluster has 3 of the 9 dated sites, so it alone fills test.
    rows = [si(f"{i:04d}", "scamsniffer", date(2026, 10, i)) for i in range(1, 10)]
    assignment = singletons(rows) | {"0007": "big", "0008": "big", "0009": "big"}
    split = assign_split(rows, assignment)
    assert sorted(s for s in split if split[s] == "test") == ["0007", "0008", "0009"]


def test_mixed_cluster_follows_its_dated_member() -> None:
    rows = [si(f"{i:04d}", "scamsniffer", date(2026, 10, i)) for i in range(1, 6)]
    rows.append(si("0006", "dfpi"))  # undated, but clustered with the newest dated site
    assignment = singletons(rows) | {"0005": "mixed", "0006": "mixed"}
    split = assign_split(rows, assignment)
    assert split["0006"] == split["0005"] == "test"


def test_metamask_only_scam_clusters_are_dev() -> None:
    rows = [si(f"{i:04d}", "metamask_block") for i in range(1, 10)]
    assert set(assign_split(rows, singletons(rows)).values()) == {"dev"}


@pytest.mark.parametrize("source", ["dfpi", "tranco", "coingecko", "metamask_allow"])
def test_random_draw_sends_a_third_to_test(source: str) -> None:
    rows = [si(f"{i:04d}", source) for i in range(1, 31)]
    split = assign_split(rows, singletons(rows))
    assert sum(v == "test" for v in split.values()) == 10


def test_each_legitimate_source_is_drawn_separately() -> None:
    rows = [si(f"{i:04d}", "tranco") for i in range(1, 4)]
    rows += [si(f"{i:04d}", "coingecko") for i in range(4, 7)]
    split = assign_split(rows, singletons(rows))
    assert sum(split[r.site_id] == "test" for r in rows[:3]) == 1
    assert sum(split[r.site_id] == "test" for r in rows[3:]) == 1


def test_cluster_with_a_scam_list_site_counts_as_scam() -> None:
    rows = [si("0001", "metamask_block"), si("0002", "metamask_allow")]
    split = assign_split(rows, {"0001": "c1", "0002": "c1"})
    assert split == {"0001": "dev", "0002": "dev"}  # the MetaMask-only scam rule, not a draw


def test_no_cluster_straddles_the_split() -> None:
    rows = [si(f"{i:04d}", "scamsniffer", date(2026, 9, 1 + i % 28)) for i in range(1, 41)]
    rows += [si(f"{i:04d}", "dfpi") for i in range(41, 61)]
    rows += [si(f"{i:04d}", "tranco") for i in range(61, 81)]
    cl = {r.site_id: f"c{int(r.site_id) % 13}" for r in rows}  # clusters that cross sources
    split = assign_split(rows, cl)
    assert all(len({split[s] for s in members}) == 1 for members in by_cluster(cl).values())
    assert set(split) == {r.site_id for r in rows}


def test_split_is_deterministic() -> None:
    rows = [si(f"{i:04d}", "dfpi") for i in range(1, 31)]
    assert assign_split(rows, singletons(rows)) == assign_split(rows, singletons(rows))


# ---------- the command, on a tiny run folder ----------


def _site(run_dir: Path, site_id: str, html: str) -> None:
    rel = f"sites/{site_id}/snapshots/s01"
    (run_dir / rel).mkdir(parents=True)
    (run_dir / rel / "page.html").write_text(html)
    (run_dir / rel / "text.txt").write_text("text")
    snap = PageSnapshot(
        snapshot_id="s01",
        stage=DiscoveryStage.LANDING,
        url=f"https://s{site_id}.example/",
        title="",
        taken_at=datetime(2026, 11, 15, tzinfo=UTC),
        html_path=f"{rel}/page.html",
        visible_text="text",
        a11y_tree_path=f"{rel}/aria.yaml",
        screenshot_path="",
        network=[],
    )
    (run_dir / "sites" / site_id / "snapshots.jsonl").write_text(snap.model_dump_json() + "\n")


@pytest.fixture
def run(tmp_path: Path) -> tuple[Path, Path]:
    """Three captured sites with the same page structure; 0003 is a parked page. 0004 was in
    the manifest but never captured."""
    run_dir = tmp_path / "runs" / "dataset-v1"
    for site_id in ("0001", "0002", "0003"):
        _site(run_dir, site_id, KIT.format(brand=site_id))
    (run_dir / "checkpoint.jsonl").write_text("")
    verdicts = {"0001": "scam", "0002": "scam", "0003": "excluded"}
    (run_dir / "labeller.jsonl").write_text(
        "".join(
            json.dumps({"site_id": s, "verdict": v, "reason": "r", "cost_usd": 0.0}) + "\n"
            for s, v in verdicts.items()
        )
    )
    manifest = tmp_path / "manifest.jsonl"
    manifest.write_text(
        "".join(
            ManifestRow(
                url=f"https://s{i}.example/",
                registrable_domain=f"s{i}.example",
                source="scamsniffer",
                expected="scam",
                listed_on=date(2026, 10, int(i)),
                site_id=i,
                batch=1,
            ).model_dump_json()
            + "\n"
            for i in ("0001", "0002", "0003", "0004")
        )
    )
    return run_dir, manifest


def test_load_inputs_reads_captured_sites_only(run: tuple[Path, Path]) -> None:
    cluster_rows, split_rows = load_inputs(*run)
    assert [r.site_id for r in cluster_rows] == ["0001", "0002", "0003"]
    assert [r.judgeable for r in cluster_rows] == [True, True, False]
    assert len({r.dom_hash for r in cluster_rows}) == 1
    assert split_rows[0].listed_on == date(2026, 10, 1)


def test_command_writes_split_once(
    run: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    run_dir, manifest = run
    monkeypatch.setattr(split_module, "REPO_ROOT", run_dir.parent.parent)
    out = run_dir.parent.parent / "split.jsonl"
    args = ["--manifest", str(manifest), "--out", str(out)]

    assert split_module.main(args) == 0
    lines = [json.loads(x) for x in out.read_text().splitlines()]
    cluster_of = {x["site_id"]: x["cluster_id"] for x in lines}
    assert cluster_of["0001"] == cluster_of["0002"] != cluster_of["0003"]  # parked page apart
    assert "3 sites in 2 clusters" in capsys.readouterr().out

    assert split_module.main(args) == 1  # made once
    assert split_module.main([*args, "--force"]) == 0


def test_command_needs_the_labeller_file(run: tuple[Path, Path]) -> None:
    run_dir, manifest = run
    (run_dir / "labeller.jsonl").unlink()
    with pytest.raises(SystemExit, match="make label"):
        load_inputs(run_dir, manifest)
