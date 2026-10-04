"""Per-site state machine and run orchestration: stage order, transitions, concurrency, timeouts."""

import asyncio
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

import tldextract

from scamhunter.config import Settings, require_egress_proxy
from scamhunter.models import Site, TriageRecord
from scamhunter.store import write_jsonl
from scamhunter.triage.liveness import make_client, probe

# Bundled public-suffix snapshot only: no network fetch, no cache writes.
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def load_sites(path: Path) -> list[Site]:
    """One Site per non-blank line, in file order. No dedupe: paths like /wap are significant."""
    sites: list[Site] = []
    for line_no, line in enumerate(path.read_text().splitlines(), start=1):
        url = line.strip()
        if not url:
            continue
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError(f"{path}:{line_no}: not an http(s) URL: {url!r}")
        sites.append(
            Site(
                site_id=f"{len(sites) + 1:03d}",
                url=url,
                host=parts.hostname,
                registrable_domain=_extract(parts.hostname).top_domain_under_public_suffix,
            )
        )
    return sites


async def run_triage(settings: Settings, sites: list[Site], out_dir: Path) -> list[TriageRecord]:
    """Probe every site through the egress proxy; write triage.jsonl in input order."""
    proxy = require_egress_proxy()
    semaphore = asyncio.Semaphore(settings.triage.concurrency)
    verified = make_client(proxy, settings.http, settings.triage, verify=True)
    unverified = make_client(proxy, settings.http, settings.triage, verify=False)

    async def one(site: Site) -> TriageRecord:
        async with semaphore:
            result = await probe(site.url, verified, unverified, settings.triage)
        print(f"  {site.site_id} {result.status.value:<17} {site.url}", flush=True)
        return TriageRecord(site=site, triage=result)

    async with verified, unverified:
        records = await asyncio.gather(*(one(site) for site in sites))

    assert len(records) == len(sites), "triage must produce exactly one record per URL"
    write_jsonl(out_dir / "triage.jsonl", records)
    return records


def status_counts(records: list[TriageRecord]) -> Counter[str]:
    return Counter(r.triage.status.value for r in records)
