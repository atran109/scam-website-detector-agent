"""Flatten SiteResults into output/results.json (ResultsFile)."""

import hashlib
import shutil
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from scamhunter.models import (
    CryptoAddress,
    DiscoveryStage,
    NavigationSummary,
    OutputRecord,
    ResultsFile,
    ResultsMeta,
    Sighting,
    SiteResult,
    Verdict,
)

SCAM_DEFINITION = "See README §Scam definition"


def primary_sighting(address: CryptoAddress) -> Sighting:
    """DESIGN §3.4: the earliest deposit_page sighting if any, else the earliest overall."""
    deposit = [s for s in address.sightings if s.stage == DiscoveryStage.DEPOSIT_PAGE]
    return (deposit or address.sightings)[0]


def _copy_screenshot(
    sighting: Sighting, site_id: str, address: CryptoAddress, run_dir: Path, out_dir: Path
) -> str | None:
    if not sighting.screenshot_path:
        return None
    src = run_dir / sighting.screenshot_path
    if not src.exists():
        return None
    digest = hashlib.sha256(address.normalized.encode()).hexdigest()[:8]
    name = f"{site_id}_{address.format.value}_{digest}.png"
    (out_dir / "screenshots").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, out_dir / "screenshots" / name)
    return f"screenshots/{name}"


def to_record(result: SiteResult, run_dir: Path, out_dir: Path) -> OutputRecord:
    c = result.classification
    details = []
    for address in result.addresses + result.low_confidence_addresses:
        sighting = primary_sighting(address)
        details.append(
            {
                "address": address.address,
                "normalized": address.normalized,
                "tier": address.tier,
                "format": address.format,
                "labels": address.labels,
                "source": sighting.source,
                "stage": sighting.stage,
                "screenshot": _copy_screenshot(
                    sighting, result.site.site_id, address, run_dir, out_dir
                ),
                "sighting_count": len(address.sightings),
            }
        )
    nav = result.navigation
    return OutputRecord(
        url=result.site.url,
        final_url=result.triage.final_url,
        status=result.triage.status,
        processing_status=result.processing_status,
        classification=c.verdict,
        is_scam=c.verdict == Verdict.SCAM,
        scam_type=c.scam_type,
        scam_probability=c.scam_probability,
        confidence=c.confidence,
        evidence_source=c.evidence_source,
        reasoning=c.reasoning,
        signals=[s.name for s in c.signals if s.weight != 0],
        crypto_addresses=[a.address for a in result.addresses],
        low_confidence_addresses=[a.address for a in result.low_confidence_addresses],
        address_details=details,
        app_download_urls=result.app_downloads,
        navigation=NavigationSummary(
            registered=nav.registered,
            reached_deposit=nav.reached_deposit,
            steps=len(nav.steps),
            stop_reason=nav.stop_reason,
            blocked_at=nav.blocked_at,
            linked_domains=nav.linked_domains,
            hops=nav.hops,
        )
        if nav
        else None,
        notes=result.notes,
    )


def write_results(
    results: Sequence[SiteResult], run_id: str, run_dir: Path, out_dir: Path, pipeline_version: str
) -> Path:
    """Validated results.json with exactly one record per result, in input order."""
    ids = [r.site.site_id for r in results]
    assert len(ids) == len(set(ids)), "duplicate site in results"
    if (out_dir / "screenshots").exists():
        shutil.rmtree(out_dir / "screenshots")  # only this run's evidence
    file = ResultsFile(
        meta=ResultsMeta(
            run_id=run_id,
            generated_at=datetime.now(UTC),
            total_urls=len(results),
            pipeline_version=pipeline_version,
            scam_definition=SCAM_DEFINITION,
        ),
        results=[
            to_record(r, run_dir, out_dir) for r in sorted(results, key=lambda r: r.site.site_id)
        ],
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "results.json"
    path.write_text(file.model_dump_json(indent=2))
    return path
