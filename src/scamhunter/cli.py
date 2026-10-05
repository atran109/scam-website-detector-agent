"""Entrypoints: run, triage, rescore, eval, report."""

import argparse
import asyncio
import shutil
import sys
from collections.abc import Sequence

from scamhunter.config import REPO_ROOT, Settings, load_settings
from scamhunter.models import Site, SiteResult
from scamhunter.pipeline import (
    PIPELINE_VERSION,
    apply_sibling_signals,
    load_checkpoint,
    load_sites,
    rescore,
    run_pipeline,
    run_triage,
    status_counts,
)
from scamhunter.report.summary import summarize
from scamhunter.report.writer import write_results
from scamhunter.store import RUNS_DIR, new_run_id, run_dir

URLS_PATH = REPO_ROOT / "data" / "urls.txt"
OUTPUT_DIR = REPO_ROOT / "output"


def _select(sites: list[Site], only: str | None) -> list[Site]:
    if not only:
        return sites
    wanted = {f"{int(i):03d}" for i in only.split(",")}
    return [s for s in sites if s.site_id in wanted]


def _finalize(results: Sequence[SiteResult], settings: Settings, run_id: str) -> None:
    """Cross-site pass, then results.json + screenshots + summary inside the run directory."""
    out = run_dir(run_id)
    final = apply_sibling_signals(list(results), settings)
    path = write_results(final, run_id, out, out / "output", PIPELINE_VERSION)
    summary = summarize(final, run_id)
    (out / "summary.json").write_text(summary.model_dump_json(indent=2))
    print(f"\n{path} ({len(final)} records)")
    print(
        f"verdicts: {summary.counts_by_verdict}  tokens: {summary.total_tokens_in} in / "
        f"{summary.total_tokens_out} out  sites with addresses: {summary.sites_with_addresses}"
    )


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


def cmd_run(args: argparse.Namespace) -> int:
    settings = load_settings()
    sites = _select(load_sites(URLS_PATH), args.only)
    run_id = args.run_id or new_run_id()
    out = run_dir(run_id)
    if args.triage_from and not (out / "triage.jsonl").exists():
        shutil.copyfile(RUNS_DIR / args.triage_from / "triage.jsonl", out / "triage.jsonl")
    results = asyncio.run(run_pipeline(settings, sites, out, resume=args.resume))
    _finalize(results, settings, run_id)
    return 0


def cmd_rescore(args: argparse.Namespace) -> int:
    settings = load_settings()
    sites = load_sites(URLS_PATH)
    results = asyncio.run(rescore(settings, sites, run_dir(args.run_id)))
    _finalize(results, settings, args.run_id)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Publish a run's results into output/ (the deliverable)."""
    src = run_dir(args.run_id)
    if not (src / "output" / "results.json").exists():
        settings = load_settings()
        _finalize(list(load_checkpoint(src / "checkpoint.jsonl").values()), settings, args.run_id)
    if OUTPUT_DIR.exists():
        shutil.rmtree(OUTPUT_DIR / "screenshots", ignore_errors=True)
    shutil.copytree(src / "output", OUTPUT_DIR, dirs_exist_ok=True)
    print(f"published {src / 'output'} → {OUTPUT_DIR}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scamhunter")
    sub = parser.add_subparsers(dest="command", required=True)

    triage = sub.add_parser("triage", help="stage 0 only → runs/<id>/triage.jsonl")
    triage.add_argument("--run-id", help="run directory name (default: timestamp)")
    triage.add_argument("--only", help="comma-separated site numbers, e.g. 17,42")

    run = sub.add_parser("run", help="full pipeline → runs/<id>/output/results.json")
    run.add_argument("--run-id", help="run directory name (default: timestamp)")
    run.add_argument("--only", help="comma-separated site numbers, e.g. 17,42")
    run.add_argument("--resume", action="store_true", help="skip sites already checkpointed")
    run.add_argument("--triage-from", help="reuse triage.jsonl from another run id")
    run.add_argument("--no-agent", action="store_true", help="skip navigation (M3)")

    for name, help_text in (
        ("rescore", "re-classify a run from saved evidence (no visits)"),
        ("report", "publish a run's results into output/"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--run-id", required=True)
    sub.add_parser("eval", help="not implemented yet (M4)")

    args = parser.parse_args(argv)
    handlers = {"triage": cmd_triage, "run": cmd_run, "rescore": cmd_rescore, "report": cmd_report}
    if args.command in handlers:
        return handlers[args.command](args)
    print(f"{args.command}: not implemented")
    return 1


if __name__ == "__main__":
    sys.exit(main())
