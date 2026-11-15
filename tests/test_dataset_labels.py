"""eval/dataset_v1/labels.py and funnel.py (DESIGN §8.3, §8.4; plan Task 9). No network."""

from datetime import date

import pytest
from eval.dataset_v1.funnel import (
    dfpi_address_check,
    pick_agent_sites,
    reached_registration,
    tally,
)
from eval.dataset_v1.labels import (
    COLUMNS,
    agreement,
    build_labels,
    freeze_queue,
    merge_reviewed,
    read_csv,
    review_queue,
    write_csv,
)
from eval.dataset_v1.models import ManifestRow

from scamhunter.labeller import LabellerVerdict
from scamhunter.models import (
    ActionType,
    AgentAction,
    AgentStep,
    BlockedReason,
    NavigationTrace,
    StopReason,
)


def manifest_row(site_id: str, source: str = "scamsniffer") -> ManifestRow:
    return ManifestRow(
        url=f"https://s{site_id}.example/",
        registrable_domain=f"s{site_id}.example",
        source=source,  # type: ignore[arg-type]
        expected="scam",
        listed_on=date(2026, 10, 1),
        site_id=site_id,
        batch=1,
    )


def draft(site_id: str, verdict: str) -> LabellerVerdict:
    return LabellerVerdict(site_id=site_id, verdict=verdict, reason="why", cost_usd=0.05)  # type: ignore[arg-type]


def row(
    site_id: str, split: str, labeller: str, verdict: str | None = None, by: str = "none"
) -> dict:
    return {
        "site_id": site_id,
        "split": split,
        "labeller_verdict": labeller,
        "verdict": verdict or labeller,
        "reviewed_by": by,
    }


# ---------- build_labels ----------


def test_rows_start_as_the_labeller_draft() -> None:
    split = {"0001": {"cluster_id": "c0001", "split": "test"}}
    [r] = build_labels([manifest_row("0001")], {"0001": draft("0001", "scam")}, split)
    assert list(r) == COLUMNS
    assert r["verdict"] == r["labeller_verdict"] == "scam"
    assert r["reviewed_by"] == "none"
    assert (r["cluster_id"], r["split"], r["listed_on"]) == ("c0001", "test", "2026-10-01")
    assert r["notes"] == "why"


def test_site_without_a_labeller_line_is_error() -> None:
    split = {"0001": {"cluster_id": "c0001", "split": "dev"}}
    [r] = build_labels([manifest_row("0001")], {}, split)
    assert r["verdict"] == r["labeller_verdict"] == "error"


def test_only_sites_in_the_split_get_rows() -> None:
    split = {"0002": {"cluster_id": "c0001", "split": "dev"}}
    rows = build_labels([manifest_row("0001"), manifest_row("0002")], {}, split)
    assert [r["site_id"] for r in rows] == ["0002"]


def test_rebuild_keeps_reviewed_rows_untouched(tmp_path) -> None:
    split = {s: {"cluster_id": f"c{s}", "split": "test"} for s in ("0001", "0002")}
    first = build_labels(
        [manifest_row("0001"), manifest_row("0002")],
        {"0001": draft("0001", "scam"), "0002": draft("0002", "error")},
        split,
    )
    first[0] |= {"verdict": "not_scam", "reviewed_by": "alex", "notes": "a real shop"}
    path = tmp_path / "labels.csv"
    write_csv(path, first)

    # The labeller later relabels both; only the unreviewed row may change.
    again = build_labels(
        [manifest_row("0001"), manifest_row("0002")],
        {"0001": draft("0001", "excluded"), "0002": draft("0002", "scam")},
        split,
    )
    merged = merge_reviewed(again, read_csv(path))
    assert merged[0]["verdict"] == "not_scam" and merged[0]["labeller_verdict"] == "scam"
    assert merged[0]["notes"] == "a real shop"
    assert merged[1]["verdict"] == "scam"


# ---------- review_queue ----------


def test_queue_holds_all_test_rows_first() -> None:
    rows = [
        row("0001", "dev", "scam"),
        row("0002", "test", "scam"),
        row("0003", "test", "not_scam"),
    ]
    queue = review_queue(rows, {"0001": "not_scam", "0002": "scam", "0003": "not_scam"})
    assert queue[:2] == ["0002", "0003"]


def test_queue_holds_dev_disagreements_and_errors() -> None:
    rows = [
        row("0001", "dev", "scam"),  # pipeline says not_scam
        row("0002", "dev", "error"),
        row("0003", "dev", "excluded"),  # the pipeline never says excluded
        row("0004", "dev", "scam"),  # agrees
    ]
    verdicts = {"0001": "not_scam", "0002": "scam", "0003": "not_scam", "0004": "scam"}
    queue = review_queue(rows, verdicts)
    assert {"0001", "0002", "0003"} <= set(queue)


def test_queue_samples_a_fifth_of_agreeing_dev_rows_with_the_seed() -> None:
    rows = [row(f"{i:04d}", "dev", "scam") for i in range(1, 51)]
    verdicts = {r["site_id"]: "scam" for r in rows}
    queue = review_queue(rows, verdicts)
    assert len(queue) == 10
    assert queue == review_queue(rows, verdicts)  # seeded: the same every time


# ---------- agreement ----------


def test_changed_means_reviewed_and_different() -> None:
    rows = [
        row("0001", "test", "scam", "not_scam", by="alex"),  # changed
        row("0002", "test", "scam", "scam", by="alex"),  # confirmed
        row("0003", "test", "scam", "not_scam", by="none"),  # edited but not marked reviewed
        row("0004", "dev", "scam", "not_scam", by="alex"),  # dev disagreement, changed
    ]
    verdicts = {"0001": "scam", "0002": "scam", "0003": "scam", "0004": "not_scam"}
    out = agreement(rows, freeze_queue(rows, verdicts, {}))
    assert out["test"] == {"queued": 3, "reviewed": 2, "changed": 1, "rate": 0.5}
    assert out["dev_disagreement"]["changed"] == 1
    assert out["dev_sample"]["reviewed"] == 0 and out["dev_sample"]["rate"] is None


def test_saved_queue_keeps_its_sample_when_labels_change() -> None:
    rows = [row(f"{i:04d}", "dev", "scam") for i in range(1, 51)]
    verdicts = {r["site_id"]: "scam" for r in rows}
    saved = freeze_queue(rows, verdicts, {})
    sample = {s for s, part in saved.items() if part == "dev_sample"}
    assert len(sample) == 10

    # A labeller retry turns one agreeing row into a disagreement: it is added, and the
    # random sample stays exactly the one that was reviewed.
    outside = next(r for r in rows if r["site_id"] not in sample)
    outside["labeller_verdict"] = "not_scam"
    again = freeze_queue(rows, verdicts, saved)
    assert {s for s, part in again.items() if part == "dev_sample"} == sample
    assert again[outside["site_id"]] == "dev_disagreement"
    assert freeze_queue(rows, verdicts, again) == again


def test_failed_write_leaves_the_labels_file_as_it_was(tmp_path) -> None:
    split = {"0001": {"cluster_id": "c0001", "split": "test"}}
    rows = build_labels([manifest_row("0001")], {"0001": draft("0001", "scam")}, split)
    path = tmp_path / "labels.csv"
    write_csv(path, rows)
    before = path.read_text()

    rows[0]["my_column"] = "added in a spreadsheet"
    with pytest.raises(SystemExit, match="my_column"):
        write_csv(path, rows)
    assert path.read_text() == before


# ---------- funnel ----------


def label_row(site_id: str, source: str, verdict: str = "scam", by: str = "alex") -> dict:
    return {"site_id": site_id, "source": source, "verdict": verdict, "reviewed_by": by}


def test_pick_takes_reviewed_scams_with_an_account_flow_dfpi_first() -> None:
    rows = [
        label_row("0001", "scamsniffer"),
        label_row("0002", "dfpi"),
        label_row("0003", "dfpi", verdict="not_scam"),
        label_row("0004", "dfpi", by="none"),  # not reviewed
        label_row("0005", "scamsniffer"),  # no account flow
    ]
    flows = {"0001": True, "0002": True, "0003": True, "0004": True, "0005": False}
    assert pick_agent_sites(rows, flows) == ["0002", "0001"]


def test_pick_never_takes_more_than_the_limit() -> None:
    rows = [label_row(f"{i:04d}", "dfpi") for i in range(1, 61)]
    picked = pick_agent_sites(rows, {r["site_id"]: True for r in rows})
    assert len(picked) == 40


def _step(action: ActionType, allowed: bool = True, result: str = "ok") -> AgentStep:
    return AgentStep(
        index=0,
        page_url="https://x.example/",
        action=AgentAction(type=action, rationale="r"),
        allowed=allowed,
        result=result,
        screenshot_path="",
        tokens_in=0,
        tokens_out=0,
        elapsed_ms=0,
    )


def trace(
    steps: list[ActionType] = (),  # type: ignore[assignment]
    stop: StopReason = StopReason.NO_PROGRESS,
    blocked: BlockedReason | None = None,
    registered: bool = False,
    logged_in: bool = False,
    deposit: bool = False,
) -> NavigationTrace:
    return NavigationTrace(
        goal="g",
        steps=[_step(a) for a in steps],
        stop_reason=stop,
        blocked_at=blocked,
        registered=registered,
        logged_in=logged_in,
        reached_deposit=deposit,
        assets_tried=[],
    )


@pytest.mark.parametrize(
    ("nav", "expected"),
    [
        (trace([ActionType.CLICK]), False),
        (trace([ActionType.CLICK, ActionType.FILL]), True),
        (trace(stop=StopReason.BLOCKED, blocked=BlockedReason.INVITE_CODE), True),
        (trace(stop=StopReason.BLOCKED, blocked=BlockedReason.GEO_BLOCK), False),
        (trace(registered=True), True),
    ],
)
def test_reached_registration(nav: NavigationTrace, expected: bool) -> None:
    assert reached_registration(nav) is expected


def test_a_refused_or_failed_fill_is_not_reaching_registration() -> None:
    nav = trace([ActionType.CLICK])
    nav.steps.append(_step(ActionType.FILL, allowed=False, result="refused"))
    nav.steps.append(_step(ActionType.FILL, result="element_not_found"))
    assert reached_registration(nav) is False


def test_tally_counts_each_funnel_step_and_stop_reason() -> None:
    sites = [
        (trace([ActionType.FILL], StopReason.GOAL_REACHED, None, True, True, True), ["0xabc"]),
        (trace([ActionType.FILL], StopReason.BLOCKED, BlockedReason.SMS_VERIFICATION), []),
        (trace([ActionType.CLICK]), []),
        (None, []),
    ]
    counts = tally(sites)
    assert counts["sites"] == 4
    assert counts["navigated"] == 3
    assert counts["reached_registration"] == 2
    assert (counts["registered"], counts["logged_in"], counts["deposit_page"]) == (1, 1, 1)
    assert counts["address"] == 1
    assert counts["stop:goal_reached"] == 1 and counts["stop:blocked"] == 1


def test_dfpi_address_check() -> None:
    notes = {
        "0001": "Fake exchange | addresses: 0xAbC123 TXyz",
        "0002": "Fake exchange | addresses: bc1qold",
        "0003": "Fake exchange",
        "0004": "Fake exchange | addresses: TRon9",
    }
    found = {"0001": ["0xabc123"], "0002": ["bc1qnew"], "0003": ["0xdef"], "0004": []}
    out = {r["site_id"]: r["outcome"] for r in dfpi_address_check(notes, found)}
    assert out == {"0001": "match", "0002": "different", "0004": "none_found"}


def test_build_command_twice_keeps_a_review(tmp_path, monkeypatch) -> None:
    import json

    from eval.dataset_v1 import labels as labels_module

    run_dir = tmp_path / "runs" / "dataset-v1"
    run_dir.mkdir(parents=True)
    monkeypatch.setattr(labels_module, "REPO_ROOT", tmp_path)
    manifest = tmp_path / "manifest.jsonl"
    manifest.write_text(manifest_row("0001").model_dump_json() + "\n")
    split = tmp_path / "split.jsonl"
    split.write_text(json.dumps({"site_id": "0001", "cluster_id": "c0001", "split": "test"}) + "\n")
    (run_dir / "labeller.jsonl").write_text(draft("0001", "scam").model_dump_json() + "\n")
    out = tmp_path / "labels.csv"
    args = ["--build", "--labels", str(out), "--manifest", str(manifest), "--split", str(split)]

    assert labels_module.main(args) == 0
    rows = read_csv(out)
    rows[0] |= {"verdict": "not_scam", "reviewed_by": "alex"}
    write_csv(out, rows)
    assert labels_module.main(args) == 0
    assert read_csv(out)[0]["verdict"] == "not_scam"
