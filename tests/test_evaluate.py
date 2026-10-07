"""eval/evaluate.py: verdict precision/recall at two thresholds and address precision/recall."""

import importlib.util
from pathlib import Path

import pytest

from scamhunter.config import REPO_ROOT

spec = importlib.util.spec_from_file_location("evaluate", REPO_ROOT / "eval" / "evaluate.py")
ev = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
spec.loader.exec_module(ev)  # type: ignore[union-attr]


def rec(p: float, addresses=(), source="live") -> dict:
    return {
        "scam_probability": p,
        "crypto_addresses": list(addresses),
        "evidence_source": source,
        "status": "live",
    }


LABELS = [
    {"url": "a", "verdict": "scam", "expected_addresses": "X1|X2"},
    {"url": "b", "verdict": "scam", "expected_addresses": ""},
    {"url": "c", "verdict": "not_scam", "expected_addresses": ""},
    {"url": "d", "verdict": "not_scam", "expected_addresses": ""},
]
RESULTS = {"a": rec(0.9, ["X1"]), "b": rec(0.47), "c": rec(0.46), "d": rec(0.1)}


def test_the_threshold_decides_the_borderline_sites() -> None:
    low, _ = ev.verdict_metrics(LABELS, RESULTS, 0.45)  # b, c predicted scam
    assert (low.tp, low.fp, low.fn, low.tn) == (2, 1, 0, 1)
    assert low.precision == pytest.approx(2 / 3) and low.recall == 1.0
    high, _ = ev.verdict_metrics(LABELS, RESULTS, 0.5)  # only a predicted scam
    assert (high.tp, high.fp, high.fn, high.tn) == (1, 0, 1, 2)
    assert high.precision == 1.0 and high.recall == 0.5 and high.accuracy == 0.75
    assert [e["url"] for e in low.errors] == ["c"] and [e["url"] for e in high.errors] == ["b"]


def test_missing_results_are_reported_not_counted() -> None:
    metrics, missing = ev.verdict_metrics(LABELS, {"a": RESULTS["a"]}, 0.45)
    assert metrics.n == 1 and missing == ["b", "c", "d"]


def test_address_precision_and_recall_use_exact_strings() -> None:
    m = ev.address_metrics(LABELS, {**RESULTS, "a": rec(0.9, ["X1", "Y9"])})
    assert (m.sites, m.expected, m.found, m.correct) == (1, 2, 2, 1)
    assert m.precision == 0.5 and m.recall == 0.5
    assert m.missed == [{"url": "a", "addresses": ["X2"]}]
    assert m.extra == [{"url": "a", "addresses": ["Y9"]}]


def test_only_scam_and_not_scam_labels_are_loaded(tmp_path: Path) -> None:
    csv_path = tmp_path / "labels.csv"
    csv_path.write_text(
        "url,verdict,scam_type,expected_addresses,label_basis,notes\n"
        "a,scam,,,,\nb,not_scam,,,,\nc,unknown,,,,\nd,,,,,\n"
    )
    assert [r["url"] for r in ev.load_labels(csv_path)] == ["a", "b"]


def test_report_has_both_thresholds() -> None:
    out = ev.report(LABELS, RESULTS, (0.45, 0.5))
    assert set(out["thresholds"]) == {"0.45", "0.5"} and out["labelled"] == 4
