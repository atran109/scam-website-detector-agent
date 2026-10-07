"""analyze() after navigation (2026-10-07, pilot sites 012 and 021): the landing page and the
agent's best page both reach the judge, signals come from every snapshot, the non-content check
looks at capture snapshots only, and addresses are on the record whatever the verdict."""

import asyncio
import io
import json
from datetime import UTC, datetime
from pathlib import Path

from PIL import Image

from scamhunter.config import load_settings
from scamhunter.llm.client import LLMResponse
from scamhunter.models import (
    DiscoveryStage,
    PageSnapshot,
    ProcessingStatus,
    Site,
    SiteStatus,
    TriageResult,
    Verdict,
)
from scamhunter.pipeline import RunContext, analyze, build_result, merge_signals

SITE = Site(
    site_id="012", url="https://hyip.test", host="hyip.test", registrable_domain="hyip.test"
)
TRIAGE = TriageResult(status=SiteStatus.LIVE, elapsed_ms=1)
LANDING_TEXT = (
    "Join 480,000+ traders. Guaranteed returns of 2% daily on every plan. "
    + "Our AI trading plans pay total profit + capital at maturity. " * 10
)
DEPOSIT_TEXT = (
    "Payment Details\nPayment ID: DEP-1\n100.000000 USDTERC20\nPayment Address:\n"
    "0x76b10e09316c4c36c13bdb8b834953edb01659dc\nPaid\nChange Gateway"
)
MAINTENANCE_TEXT = "We'll Be Back Soon!\nOur website is currently undergoing scheduled maintenance."


def png() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (40, 30), "white").save(buf, "PNG")
    return buf.getvalue()


def snap(run: Path, sid: str, stage: DiscoveryStage, url: str, text: str) -> PageSnapshot:
    d = run / "sites" / SITE.site_id / "snapshots" / sid
    d.mkdir(parents=True)
    (d / "page.html").write_text(f"<html><body><pre>{text}</pre></body></html>")
    (d / "text.txt").write_text(text)
    (d / "qr.json").write_text("[]")
    (d / "screenshot.png").write_bytes(png())
    rel = f"sites/{SITE.site_id}/snapshots/{sid}"
    return PageSnapshot(
        snapshot_id=sid,
        stage=stage,
        url=url,
        title=sid,
        taken_at=datetime.now(UTC),
        html_path=f"{rel}/page.html",
        visible_text=text,
        a11y_tree_path="",
        screenshot_path=f"{rel}/screenshot.png",
        network=[],
    )


class FakeJudge:
    """Stands in for the gateway: records the request, answers with a fixed judgment."""

    def __init__(self, probability: float) -> None:
        self.requests: list[dict] = []
        self.probability = probability

    async def call(self, role, site_id, purpose, request, usage, cache=True) -> LLMResponse:
        self.requests.append(request)
        verdict = "scam" if self.probability >= 0.5 else "not_scam"
        text = json.dumps(
            {
                "key_evidence": ['"Guaranteed returns of 2% daily"'],
                "impersonated_brand": "",
                "reasoning": "t",
                "scam_type": "investment_hyip" if verdict == "scam" else "none",
                "verdict": verdict,
                "probability_scam": self.probability,
            }
        )
        return LLMResponse(text=text, stop_reason="end_turn", model="m", cached=False)


def run_analyze(tmp_path: Path, snapshots, probability: float = 0.55):
    llm = FakeJudge(probability)
    ctx = RunContext(settings=load_settings(), run_dir=tmp_path, llm=llm)  # type: ignore[arg-type]
    return asyncio.run(analyze(ctx, SITE, TRIAGE, snapshots)), llm


def pilot_012(tmp_path: Path, last_maintenance: bool = False) -> list[PageSnapshot]:
    snaps = [
        snap(tmp_path, "s01", DiscoveryStage.LANDING, "https://hyip.test/", LANDING_TEXT),
        snap(tmp_path, "a001", DiscoveryStage.LANDING, "https://hyip.test/", LANDING_TEXT),
        snap(tmp_path, "a002", DiscoveryStage.AUTHENTICATED, "https://hyip.test/dash", "Dashboard"),
        snap(tmp_path, "a003", DiscoveryStage.DEPOSIT_PAGE, "https://hyip.test/dep", DEPOSIT_TEXT),
    ]
    if last_maintenance:
        snaps.append(
            snap(
                tmp_path,
                "a004",
                DiscoveryStage.NAVIGATION,
                "https://hyip.test/reg",
                MAINTENANCE_TEXT,
            )
        )
    return snaps


def test_the_judge_sees_the_landing_page_and_the_deposit_page(tmp_path: Path) -> None:
    analysis, llm = run_analyze(tmp_path, pilot_012(tmp_path))
    request = llm.requests[0]
    content = request["messages"][0]["content"]
    note = content[-1]["text"]
    assert sum(1 for b in content if b["type"] == "image") == 2
    assert "Guaranteed returns of 2% daily" in note, "landing text"
    assert "Payment Address" in note and "https://hyip.test/dep" in note, "deposit page"
    assert "1 primary address(es) on it" in note


def test_signals_come_from_every_snapshot_and_the_deposit_flow_raises_the_score(
    tmp_path: Path,
) -> None:
    analysis, _ = run_analyze(tmp_path, pilot_012(tmp_path), probability=0.55)
    names = {s.name for s in analysis.classification.signals}
    assert {"guaranteed_returns", "profit_plus_capital"} <= names, "from the landing page"
    assert "deposit_address_after_registration" in names
    # 012 in the pilot: judge 0.55 on the payment page alone, heuristics 0.18 → 0.44 not_scam.
    assert analysis.classification.verdict == Verdict.SCAM
    assert analysis.classification.scam_probability > 0.6


def test_a_maintenance_page_reached_by_the_agent_does_not_make_the_site_non_content(
    tmp_path: Path,
) -> None:
    """Pilot site 021: the agent ended on /register's maintenance page."""
    analysis, llm = run_analyze(tmp_path, pilot_012(tmp_path, last_maintenance=True))
    assert analysis.triage is None, "status not revised"
    assert analysis.classification.method == "heuristic+llm" and llm.requests


def test_a_maintenance_landing_page_is_still_non_content(tmp_path: Path) -> None:
    snaps = [snap(tmp_path, "s01", DiscoveryStage.LANDING, "https://hyip.test/", MAINTENANCE_TEXT)]
    analysis, llm = run_analyze(tmp_path, snaps)
    assert analysis.triage is not None and analysis.triage.status == SiteStatus.EMPTY
    assert not llm.requests


def test_addresses_are_on_the_record_whatever_the_verdict(tmp_path: Path) -> None:
    analysis, _ = run_analyze(tmp_path, pilot_012(tmp_path), probability=0.02)
    # force a not_scam classification to check the output contract, not the scorer
    not_scam = analysis.classification.model_copy(
        update={"verdict": Verdict.NOT_SCAM, "scam_probability": 0.1, "confidence": 0.9}
    )
    analysis.classification = not_scam
    result = build_result(
        SITE,
        TRIAGE,
        analysis,
        processing=ProcessingStatus.COMPLETED,
        notes=[],
        started=datetime.now(UTC),
        trace_path=None,
    )
    assert [a.address for a in result.addresses] == ["0x76b10e09316c4c36c13bdb8b834953edb01659dc"]
    assert result.other_addresses == []


def test_merge_signals_keeps_the_heaviest_per_name() -> None:
    from scamhunter.models import Signal, SignalTier

    weak = Signal(name="x", tier=SignalTier.WEAK, weight=0.5, evidence="a", source="content")
    strong = Signal(name="x", tier=SignalTier.STRONG, weight=3.0, evidence="b", source="content")
    other = Signal(name="y", tier=SignalTier.WEAK, weight=0.5, evidence="c", source="content")
    assert merge_signals([[weak, other], [strong]]) == [strong, other]
