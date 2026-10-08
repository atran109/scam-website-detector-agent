"""Flatten SiteResults into output/results.json (ResultsFile)."""

import hashlib
import re
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

# A query parameter that names a client IP and holds an IPv4 address. Scam redirect URLs echo the
# visitor IP they saw (site 084: `recaptcha.cloud/?…&ip=<the operator's home IP>…`, LOG
# 2026-10-08); recorded URLs are evidence, but the operator's address must not be published.
_IP_PARAM = re.compile(r"([?&][a-z_]*ip=)\d{1,3}(?:\.\d{1,3}){3}\b", re.I)


def redact_ip(url: str) -> str:
    """The URL with any IP-valued `…ip=` query parameter replaced by `<redacted>`."""
    return _IP_PARAM.sub(r"\1<redacted>", url)


def _redact_navigation(nav: NavigationSummary | None) -> NavigationSummary | None:
    if nav is None:
        return None
    return nav.model_copy(
        update={
            "linked_domains": [redact_ip(u) for u in nav.linked_domains],
            "hops": [
                h.model_copy(
                    update={
                        "source_url": redact_ip(h.source_url),
                        "target_url": redact_ip(h.target_url),
                    }
                )
                for h in nav.hops
            ],
        }
    )


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
        navigation=_redact_navigation(
            NavigationSummary(
                registered=nav.registered,
                reached_deposit=nav.reached_deposit,
                steps=len(nav.steps),
                stop_reason=nav.stop_reason,
                blocked_at=nav.blocked_at,
                linked_domains=nav.linked_domains,
                hops=nav.hops,
            )
            if nav
            else None
        ),
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


def _address_keys(record: OutputRecord) -> set[str]:
    """Primary addresses of a record by format-aware key (EVM case-insensitive)."""
    return {
        d.normalized.lower() if d.format.value == "evm" else d.normalized
        for d in record.address_details
        if d.tier.value == "primary"
    }


def supplement_address_evidence(
    primary_path: Path, supplements: Sequence[tuple[str, Path]], out_dir: Path
) -> tuple[list[str], list[str]]:
    """Use a saved run's record when it found strictly more primary addresses for the same URL,
    *including every address already published* (a superset).

    Classification stays from the primary run; only address evidence and the more complete
    navigation summary move over, with a provenance note. A saved run whose addresses are not a
    superset (for example a new account given other per-account addresses) is not merged: the
    record gets a note and the URL is returned as a conflict for a person to resolve. Returns
    (merged urls, conflict urls). Visitor IPs in recorded URLs are redacted on every record.
    No target is revisited and no JSON is hand-edited."""
    primary = ResultsFile.model_validate_json(primary_path.read_text())
    records = {record.url: record for record in primary.results}
    changed: list[str] = []
    conflicts: list[str] = []
    for run_id, supplement_dir in supplements:
        supplement = ResultsFile.model_validate_json((supplement_dir / "results.json").read_text())
        for candidate in supplement.results:
            current = records.get(candidate.url)
            if current is None:
                continue
            have, offered = _address_keys(current), _address_keys(candidate)
            if not offered - have:
                continue  # nothing new
            if not have <= offered:
                note = (
                    f"saved run {run_id} found a different address set "
                    f"({len(offered - have)} new, {len(have - offered)} not seen again); not merged"
                )
                if note not in current.notes:
                    records[candidate.url] = current.model_copy(
                        update={"notes": [*current.notes, note]}
                    )
                conflicts.append(candidate.url)
                continue
            for detail in candidate.address_details:
                if not detail.screenshot:
                    continue
                source = supplement_dir / detail.screenshot
                if source.exists():
                    target = out_dir / detail.screenshot
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, target)
            note = f"address evidence supplemented from saved run {run_id}"
            records[candidate.url] = current.model_copy(
                update={
                    "crypto_addresses": candidate.crypto_addresses,
                    "low_confidence_addresses": candidate.low_confidence_addresses,
                    "address_details": candidate.address_details,
                    "navigation": _redact_navigation(candidate.navigation),
                    "notes": current.notes if note in current.notes else [*current.notes, note],
                }
            )
            changed.append(candidate.url)
    # Every published record is redacted here too: `report` copies a run's results.json that may
    # predate the redaction in `to_record` (site 084, LOG 2026-10-08).
    published = [
        records[r.url].model_copy(
            update={"navigation": _redact_navigation(records[r.url].navigation)}
        )
        for r in primary.results
    ]
    merged = primary.model_copy(update={"results": published})
    primary_path.write_text(merged.model_dump_json(indent=2))
    return changed, conflicts
