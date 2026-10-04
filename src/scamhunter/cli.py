"""Entrypoints: run, triage, rescore, eval, report."""

import argparse
import asyncio
import sys

from scamhunter.config import REPO_ROOT, load_settings
from scamhunter.pipeline import load_sites, run_triage, status_counts
from scamhunter.store import new_run_id, run_dir

URLS_PATH = REPO_ROOT / "data" / "urls.txt"


def _select(sites: list, only: str | None) -> list:
    if not only:
        return sites
    wanted = {f"{int(i):03d}" for i in only.split(",")}
    return [s for s in sites if s.site_id in wanted]


def cmd_triage(args: argparse.Namespace) -> int:
    settings = load_settings()
    sites = _select(load_sites(URLS_PATH), args.only)
    out = run_dir(args.run_id or new_run_id())
    print(f"Triage of {len(sites)} URLs → {out}/triage.jsonl")
    records = asyncio.run(run_triage(settings, sites, out))
    print("\nStatus counts:")
    for status, count in status_counts(records).most_common():
        print(f"  {status:<17} {count}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scamhunter")
    sub = parser.add_subparsers(dest="command", required=True)

    triage = sub.add_parser("triage", help="stage 0 only → runs/<id>/triage.jsonl")
    triage.add_argument("--run-id", help="run directory name (default: timestamp)")
    triage.add_argument("--only", help="comma-separated site numbers, e.g. 17,42")

    for name in ("run", "rescore", "eval", "report"):
        sub.add_parser(name, help="not implemented yet")

    args = parser.parse_args(argv)
    if args.command == "triage":
        return cmd_triage(args)
    print(f"{args.command}: not implemented")
    return 1


if __name__ == "__main__":
    sys.exit(main())
