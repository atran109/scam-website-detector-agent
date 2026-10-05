"""Tests for report.writer and the cross-site sibling pass (no network)."""

from datetime import UTC, datetime
from pathlib import Path

from scamhunter.classify.scorer import score_content, score_without_content
from scamhunter.config import load_settings
from scamhunter.models import (
    AddressFormat,
    AddressSource,
    AddressTier,
    Asset,
    AssetLabel,
    CryptoAddress,
    DiscoveryStage,
    EvidenceSource,
    LLMJudgment,
    Network,
    ProcessingStatus,
    ResultsFile,
    ScamType,
    Sighting,
    Site,
    SiteResult,
    SiteStatus,
    TriageResult,
    Verdict,
)
from scamhunter.pipeline import apply_sibling_signals
from scamhunter.report.writer import primary_sighting, to_record, write_results

SETTINGS = load_settings()
NOW = datetime.now(UTC)
TRON = "TQeneWJctmxhk6NpbNnnLdcNUEmGHzs1sC"


def sighting(stage: DiscoveryStage, source=AddressSource.DOM_TEXT) -> Sighting:
    return Sighting(source=source, stage=stage, page_url="https://x.test", context_snippet="c")


def address(*stages: DiscoveryStage) -> CryptoAddress:
    return CryptoAddress(
        address=TRON,
        normalized=TRON,
        tier=AddressTier.PRIMARY,
        format=AddressFormat.TRON,
        checksum_valid=True,
        checksum_verifiable=True,
        labels=[AssetLabel(asset=Asset.USDT, network=Network.TRON, confidence=0.9, evidence="e")],
        sightings=[sighting(s) for s in stages],
        first_seen_stage=stages[0],
    )


def result(
    site_id: str, domain: str, status: SiteStatus, classification, addresses=()
) -> SiteResult:
    return SiteResult(
        site=Site(site_id=site_id, url=f"https://{domain}", host=domain, registrable_domain=domain),
        triage=TriageResult(status=status, elapsed_ms=1),
        processing_status=ProcessingStatus.COMPLETED,
        classification=classification,
        addresses=list(addresses),
        navigation=None,
        started_at=NOW,
        finished_at=NOW,
        pipeline_version="test",
    )


def live_scam():
    j = LLMJudgment(
        verdict=Verdict.SCAM,
        scam_type=ScamType.FAKE_EXCHANGE,
        probability_scam=0.95,
        key_evidence=["e"],
        impersonated_brand=None,
        reasoning="r",
    )
    return score_content([], j, 0.45)[0]


def test_primary_sighting_prefers_earliest_deposit_page() -> None:
    a = address(DiscoveryStage.LANDING, DiscoveryStage.DEPOSIT_PAGE, DiscoveryStage.DEPOSIT_PAGE)
    assert primary_sighting(a) is a.sightings[1]
    assert primary_sighting(address(DiscoveryStage.LANDING)) is not None


def test_record_and_file_validate(tmp_path: Path) -> None:
    scam = result(
        "001",
        "x.test",
        SiteStatus.LIVE,
        live_scam(),
        [address(DiscoveryStage.LANDING, DiscoveryStage.LANDING)],
    )
    dead = result(
        "002", "y.test", SiteStatus.DNS_FAILURE, score_without_content([], 0.45, "dns_failure")
    )
    record = to_record(scam, tmp_path, tmp_path / "out")
    assert record.is_scam and record.crypto_addresses == [TRON]
    assert record.address_details[0].sighting_count == 2
    path = write_results([dead, scam], "r", tmp_path, tmp_path / "out", "test")
    parsed = ResultsFile.model_validate_json(path.read_text())
    assert [r.url for r in parsed.results] == ["https://x.test", "https://y.test"]


def test_sibling_of_live_scam_leans_scam() -> None:
    scam = result("001", "sebca.art", SiteStatus.LIVE, live_scam())
    dead = result(
        "002", "sebca.sbs", SiteStatus.DNS_FAILURE, score_without_content([], 0.45, "dns_failure")
    )
    unrelated = result(
        "003", "other.com", SiteStatus.DNS_FAILURE, score_without_content([], 0.45, "dns_failure")
    )
    out = apply_sibling_signals([scam, dead, unrelated], SETTINGS)
    assert out[1].classification.verdict == Verdict.SCAM
    assert out[1].classification.evidence_source == EvidenceSource.SIGNALS_ONLY
    assert any(s.name == "sibling_of_scam:sebca.art" for s in out[1].classification.signals)
    assert out[2].classification.verdict == Verdict.NOT_SCAM
