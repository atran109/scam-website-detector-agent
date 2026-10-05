"""Tests for the read-only review page: hostile text is escaped, no scripts, safe references."""

import csv
import re
from datetime import UTC, datetime
from pathlib import Path

from scamhunter.models import (
    Classification,
    DiscoveryStage,
    EvidenceSource,
    LLMJudgment,
    PageSnapshot,
    ProcessingStatus,
    ScamType,
    Signal,
    SignalTier,
    Site,
    SiteResult,
    SiteStatus,
    TriageResult,
    Verdict,
)
from scamhunter.report.review import clip, order_results, write_review

NOW = datetime.now(UTC)
XSS = "<script>alert(1)</script>"
THRESHOLD = 0.45


def result(site_id: str, p: float, *, hostile: bool = False) -> SiteResult:
    verdict = Verdict.SCAM if p >= THRESHOLD else Verdict.NOT_SCAM
    text = f"quoted {XSS} <img src=x onerror=alert(2)>" if hostile else "quoted text"
    judgment = LLMJudgment(
        verdict=verdict,
        scam_type=ScamType.FAKE_EXCHANGE,
        probability_scam=p,
        key_evidence=[text],
        impersonated_brand=None,
        reasoning=text,
    )
    return SiteResult(
        site=Site(
            site_id=site_id,
            url=f"https://{'evil' if hostile else 'ok'}{site_id}.test/{XSS}"
            if hostile
            else f"https://ok{site_id}.test",
            host="x.test",
            registrable_domain="x.test",
        ),
        triage=TriageResult(status=SiteStatus.LIVE, elapsed_ms=1),
        processing_status=ProcessingStatus.COMPLETED,
        classification=Classification(
            verdict=verdict,
            scam_type=ScamType.FAKE_EXCHANGE if p >= THRESHOLD else None,
            scam_probability=p,
            confidence=p if p >= THRESHOLD else 1 - p,
            evidence_source=EvidenceSource.LIVE,
            reasoning=text,
            signals=[
                Signal(
                    name=f"sig {XSS}",
                    tier=SignalTier.STRONG,
                    weight=3,
                    evidence=XSS,
                    source="content",
                )
            ],
            judgment=judgment,
            method="heuristic+llm",
        ),
        addresses=[],
        navigation=None,
        notes=[f"note {XSS}"],
        started_at=NOW,
        finished_at=NOW,
        pipeline_version="test",
    )


def add_screenshot(run_dir: Path, site_id: str) -> None:
    snap_dir = run_dir / "sites" / site_id / "snapshots" / "s01"
    snap_dir.mkdir(parents=True)
    (snap_dir / "screenshot.png").write_bytes(b"\x89PNG fake")
    snap = PageSnapshot(
        snapshot_id="s01",
        stage=DiscoveryStage.LANDING,
        url="https://x.test",
        title="t",
        taken_at=NOW,
        html_path=f"sites/{site_id}/snapshots/s01/page.html",
        visible_text="",
        a11y_tree_path="",
        screenshot_path=f"sites/{site_id}/snapshots/s01/screenshot.png",
        network=[],
    )
    (run_dir / "sites" / site_id / "snapshots.jsonl").write_text(snap.model_dump_json() + "\n")


def build(tmp_path: Path, results: list[SiteResult]) -> tuple[str, Path]:
    for r in results:
        add_screenshot(tmp_path, r.site.site_id)
    index = write_review(results, "run1", tmp_path, THRESHOLD)
    return index.read_text(), index.parent


def test_no_script_and_hostile_text_escaped(tmp_path: Path) -> None:
    page, _ = build(tmp_path, [result("001", 0.9, hostile=True)])
    assert "<script" not in page.lower()
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "<img src=x" not in page and "&lt;img src=x onerror" in page


def test_csp_and_no_external_or_embedded_references(tmp_path: Path) -> None:
    page, review_dir = build(tmp_path, [result("001", 0.9, hostile=True)])
    assert "default-src 'none'; img-src 'self'" in page
    assert not re.search(r"<(iframe|object|embed|form)", page, re.I)
    urls = re.findall(r'(?:src|href)="([^"]+)"', page)
    assert urls and all(not u.startswith(("http:", "https:", "//")) for u in urls)
    assert not re.search(r"\.(html|zip|body)\b", " ".join(u for u in urls if u != "style.css"))
    assert (review_dir / "style.css").exists()
    assert 'src="../sites/001/snapshots/s01/screenshot.png"' in page


def test_order_borderline_first_then_by_id() -> None:
    rs = [
        result("001", 0.95),
        result("002", 0.40),
        result("003", 0.10),
        result("004", 0.46),
        result("005", 0.60),
    ]
    assert [r.site.site_id for r in order_results(rs, THRESHOLD)] == [
        "004",
        "002",
        "005",
        "001",
        "003",
    ]  # 0.01, 0.05, 0.15 away; then 001, 003 by id


def test_long_text_truncated_with_marker() -> None:
    out = clip("x" * 50, 10)
    assert out.startswith("x" * 10) and "[truncated 40 more characters]" in out
    assert "‮" not in clip("a‮b", 10)


def test_labels_template_columns_and_no_eval_write(tmp_path: Path) -> None:
    build(tmp_path, [result("002", 0.9), result("001", 0.2)])
    rows = list(csv.reader((tmp_path / "review" / "labels_template.csv").open()))
    assert rows[0] == [
        "site_id",
        "url",
        "my_label",
        "my_notes",
        "pipeline_verdict",
        "pipeline_probability",
    ]
    assert [r[0] for r in rows[1:]] == ["001", "002"]
    assert all(r[2] == "" and r[3] == "" for r in rows[1:])
    assert not (tmp_path / "eval").exists()
