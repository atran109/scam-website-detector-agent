"""Compute run statistics (RunSummary)."""

import hashlib
from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime

from scamhunter.config import DEFAULT_SETTINGS_PATH
from scamhunter.models import RunSummary, SiteResult


def summarize(
    results: Sequence[SiteResult], run_id: str, gateway_usage: dict | None = None
) -> RunSummary:
    addresses = [a for r in results for a in r.addresses + r.low_confidence_addresses]
    return RunSummary(
        run_id=run_id,
        started_at=min((r.started_at for r in results), default=datetime.now(UTC)),
        finished_at=max((r.finished_at for r in results), default=datetime.now(UTC)),
        config_hash=hashlib.sha256(DEFAULT_SETTINGS_PATH.read_bytes()).hexdigest()[:12],
        counts_by_status=dict(Counter(r.triage.status.value for r in results)),
        counts_by_verdict=dict(Counter(r.classification.verdict.value for r in results)),
        counts_by_scam_type=dict(
            Counter(r.classification.scam_type.value for r in results if r.classification.scam_type)
        ),
        sites_with_addresses=sum(1 for r in results if r.addresses),
        addresses_by_format=dict(Counter(a.format.value for a in addresses)),
        navigation_stop_reasons=dict(
            Counter(r.navigation.stop_reason.value for r in results if r.navigation)
        ),
        total_tokens_in=sum(r.cost.get("tokens_in", 0) for r in results),
        total_tokens_out=sum(r.cost.get("tokens_out", 0) for r in results),
        gateway_usage=gateway_usage,
    )
