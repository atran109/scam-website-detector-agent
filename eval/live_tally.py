"""Live-site tally from saved evidence only (no visits): where does each live site's deposit
address sit relative to the landing page?

Buckets, first match wins:
  address_on_landing   a validated, non-contract address is already in the landing snapshot
  wallet_gated         the visible text asks to connect a wallet and has no login/register wording
  registration_gated   login/register wording, or an account menu (Recharge, Withdraw, Assets…)
  unclear              none of the above (shops, content sites, trackers)
  non_content          checked FIRST: the rendered page is parked, expired, a directory listing,
                       a maintenance page or stuck loading (pipeline.rendered_non_content, the
                       detector the pipeline uses). Not counted in the effective live total.

Only visible text is matched (raw HTML is full of SPA-bundle words). Every bucket carries the
matched snippets, so each call can be checked by eye. Usage:
    python eval/live_tally.py runs/pilot-5 [--triage runs/triage-1/triage.jsonl]
"""

import argparse
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from scamhunter.agent.policy import WALLET_CONNECT
from scamhunter.browser.capture import load_snapshot_content, load_snapshots
from scamhunter.extract.blocklist import load_blocklist
from scamhunter.extract.extractor import extract
from scamhunter.models import CryptoAddress
from scamhunter.pipeline import rendered_non_content

AUTH_WORDS = re.compile(
    r"\b(?:log ?in|sign ?in|sign ?up|register|create (?:an )?account)\b|登录|登錄|注册|註冊", re.I
)
# Menu words of the cheap exchange / H5 app kits: an account concept without a login word.
ACCOUNT_MENU = re.compile(r"\b(?:recharge|withdraw|assets|my account|deposit)\b|充值|提现", re.I)
SNIPPET_CHARS = 36


@dataclass
class SiteTally:
    site_id: str
    bucket: str
    evidence: list[str] = field(default_factory=list)


def _snippets(pattern: re.Pattern[str], text: str, limit: int = 3) -> list[str]:
    out: list[str] = []
    for match in pattern.finditer(text):
        start, end = max(0, match.start() - SNIPPET_CHARS), match.end() + SNIPPET_CHARS
        snippet = " ".join(text[start:end].split())
        if snippet not in out:
            out.append(snippet)
        if len(out) >= limit:
            break
    return out


def bucket_site(site_id: str, text: str, addresses: list[CryptoAddress]) -> SiteTally:
    """Pure function of a landing snapshot's visible text and its extracted addresses."""
    if addresses:
        evidence = [f"{a.tier.value} {a.format.value} {a.address[:12]}…" for a in addresses[:3]]
        return SiteTally(site_id, "address_on_landing", evidence)
    wallet, auth = _snippets(WALLET_CONNECT, text), _snippets(AUTH_WORDS, text)
    if wallet and not auth:
        return SiteTally(site_id, "wallet_gated", [f"wallet: {s}" for s in wallet])
    if auth:
        evidence = [f"auth: {s}" for s in auth]
        if wallet:
            evidence += [f"also wallet: {s}" for s in wallet[:1]]
        return SiteTally(site_id, "registration_gated", evidence)
    if menu := _snippets(ACCOUNT_MENU, text):
        return SiteTally(site_id, "registration_gated", [f"account menu: {s}" for s in menu])
    return SiteTally(site_id, "unclear", [f"{len(text.split())} words of visible text"])


def live_site_ids(triage_path: Path) -> set[str]:
    rows = (json.loads(line) for line in triage_path.read_text().splitlines())
    return {r["site"]["site_id"] for r in rows if r["triage"]["status"] == "live"}


def tally_run(run_dir: Path) -> list[SiteTally]:
    blocklist = load_blocklist()
    out: list[SiteTally] = []
    for site_dir in sorted((run_dir / "sites").glob("*")):
        snapshots = load_snapshots(site_dir)
        if not snapshots:
            continue
        if found := rendered_non_content(run_dir, snapshots):
            out.append(SiteTally(site_dir.name, "non_content", [f"{found[0].value}: {found[1]}"]))
            continue
        content = load_snapshot_content(snapshots[0], run_dir)  # the landing snapshot
        out.append(bucket_site(site_dir.name, content.visible_text, extract(content, blocklist)))
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--triage", type=Path, help="triage.jsonl, to restrict to live sites")
    args = parser.parse_args()
    rows = tally_run(args.run_dir)
    if args.triage:
        live = live_site_ids(args.triage)
        print(
            f"live sites in triage: {len(live)}; with a saved landing snapshot: "
            f"{len([r for r in rows if r.site_id in live])}"
        )
        rows = [r for r in rows if r.site_id in live]
    counts: dict[str, int] = {}
    for row in rows:
        counts[row.bucket] = counts.get(row.bucket, 0) + 1
        print(f"{row.site_id}  {row.bucket:<19} " + " | ".join(row.evidence))
    print(counts)
    effective = len(rows) - counts.get("non_content", 0)
    print(f"effective live sites (excluding non_content): {effective} of {len(rows)}")


if __name__ == "__main__":
    main()
