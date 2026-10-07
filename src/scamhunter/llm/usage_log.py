"""Totals from the gateway's usage log (`runs/llm_cache/usage.jsonl`), the ground truth for what
a run cost (decided 2026-10-07: the run's own estimate and a hand estimate from checkpoint
tokens disagreed, $0.35 against $0.6 for the same run, because the latter ignored the prompt
cache's discounts).

The gateway appends one line per model call: site, purpose, role, model, whether the response
came from its own cache (no tokens spent), and the API's token counts, where `input_tokens`
excludes cache reads and writes. Prices are `llm.client.PRICES_PER_MTOK`; cache reads cost 0.1x
the input price and 5-minute cache writes 1.25x."""

import json
from collections.abc import Iterable
from pathlib import Path

from pydantic import BaseModel

from scamhunter.llm.client import PRICES_PER_MTOK
from scamhunter.store import RUNS_DIR

USAGE_LOG = RUNS_DIR / "llm_cache" / "usage.jsonl"


class GatewayUsage(BaseModel):
    calls: int = 0  # calls that reached the API
    cached_calls: int = 0  # answered from the gateway's response cache: free
    tokens_in: int = 0  # input, cache reads and cache writes together
    tokens_out: int = 0
    cost_usd: float = 0.0
    by_model: dict[str, float] = {}  # model -> cost_usd

    def line(self) -> str:
        return (
            f"${self.cost_usd:.3f} ({self.calls} calls, {self.cached_calls} gateway-cache hits; "
            f"{self.tokens_in:,} tokens in, {self.tokens_out:,} out)"
        )


def count_lines(path: Path = USAGE_LOG) -> int:
    if not path.exists():
        return 0
    with path.open("rb") as f:
        return sum(1 for _ in f)


def total(records: Iterable[dict]) -> GatewayUsage:
    usage = GatewayUsage()
    for r in records:
        if r.get("cached"):
            usage.cached_calls += 1
            continue
        price_in, price_out = PRICES_PER_MTOK[r["model"]]
        fresh = r.get("input_tokens", 0)
        reads = r.get("cache_read_input_tokens", 0)
        writes = r.get("cache_creation_input_tokens", 0)
        out = r.get("output_tokens", 0)
        cost = ((fresh + 0.1 * reads + 1.25 * writes) * price_in + out * price_out) / 1_000_000
        usage.calls += 1
        usage.tokens_in += fresh + reads + writes
        usage.tokens_out += out
        usage.cost_usd += cost
        usage.by_model[r["model"]] = usage.by_model.get(r["model"], 0.0) + cost
    usage.cost_usd = round(usage.cost_usd, 6)
    usage.by_model = {m: round(c, 6) for m, c in usage.by_model.items()}
    return usage


def read_usage(
    path: Path = USAGE_LOG, start_line: int = 0, site_ids: set[str] | None = None
) -> GatewayUsage:
    """Usage from line `start_line` (0-based, as counted by `count_lines` before the run) on,
    optionally only for these site ids (another run sharing the gateway is then not counted)."""
    if not path.exists():
        return GatewayUsage()
    records = []
    with path.open() as f:
        for i, line in enumerate(f):
            if i < start_line or not line.strip():
                continue
            record = json.loads(line)
            if site_ids is None or str(record.get("site_id")) in site_ids:
                records.append(record)
    return total(records)
