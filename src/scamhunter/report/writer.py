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


def _copy_screenshot(sighting: Sighting, site_id: str, run_dir: Path, out_dir: Path) -> str | None:
    if not sighting.screenshot_path:
        return None
    src = run_dir / sighting.screenshot_path
    if not src.exists():
        return None
    # Hundreds of addresses can come from one captured API/page snapshot. Key the exported
    # file by its source so every detail still has evidence without duplicating that image.
    digest = hashlib.sha256(sighting.screenshot_path.encode()).hexdigest()[:12]
    name = f"{site_id}_{digest}.png"
    (out_dir / "screenshots").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, out_dir / "screenshots" / name)
    return f"screenshots/{name}"


def to_record(result: SiteResult, run_dir: Path, out_dir: Path) -> OutputRecord:
    c = result.classification
    details = []
    for address in result.addresses + result.low_confidence_addresses:
        sighting = primary_sighting(address)
        screenshot_sighting = (
            sighting
            if sighting.screenshot_path
            else next((seen for seen in address.sightings if seen.screenshot_path), sighting)
        )
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
                    screenshot_sighting, result.site.site_id, run_dir, out_dir
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


def supplement_address_evidence(
    primary_path: Path, supplements: Sequence[tuple[str, Path]], out_dir: Path
) -> list[str]:
    """Use a saved run's record when it found more primary addresses for the same URL.

    Classification stays from the primary run; only address evidence and the more complete
    navigation summary move over. This lets the published report use repeat-run discoveries
    without revisiting a target or silently hand-editing JSON.
    """
    primary = ResultsFile.model_validate_json(primary_path.read_text())
    records = {record.url: record for record in primary.results}
    changed: list[str] = []
    for run_id, supplement_dir in supplements:
        supplement = ResultsFile.model_validate_json((supplement_dir / "results.json").read_text())
        for candidate in supplement.results:
            current = records.get(candidate.url)
            if current is None or len(candidate.crypto_addresses) <= len(current.crypto_addresses):
                continue
            for detail in candidate.address_details:
                if not detail.screenshot:
                    continue
                source = supplement_dir / detail.screenshot
                if source.exists():
                    target = out_dir / detail.screenshot
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, target)
            records[candidate.url] = current.model_copy(
                update={
                    "crypto_addresses": candidate.crypto_addresses,
                    "low_confidence_addresses": candidate.low_confidence_addresses,
                    "address_details": candidate.address_details,
                    "navigation": candidate.navigation,
                    "notes": [
                        *current.notes,
                        f"address evidence supplemented from saved run {run_id}",
                    ]
                    if f"address evidence supplemented from saved run {run_id}" not in current.notes
                    else current.notes,
                }
            )
            changed.append(candidate.url)
    merged = primary.model_copy(update={"results": [records[r.url] for r in primary.results]})
    primary_path.write_text(merged.model_dump_json(indent=2))
    return changed
