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
    NoSitesVisited,
    apply_sibling_signals,
    load_checkpoint,
    load_sites,
    rescore,
    run_capture_only,
    run_pipeline,
    run_triage,
    status_counts,
)
from scamhunter.report.review import write_review
from scamhunter.report.summary import summarize
from scamhunter.report.writer import write_results
from scamhunter.store import RUNS_DIR, new_run_id, run_dir

URLS_PATH = REPO_ROOT / "data" / "urls.txt"
OUTPUT_DIR = REPO_ROOT / "output"


def _select(sites: list[Site], only: str | None) -> list[Site]:
    if not only:
        return sites
    by_id = {s.site_id: s for s in sites}
    wanted = [f"{int(i):03d}" for i in only.split(",")]
    return [by_id[i] for i in wanted if i in by_id]  # the order given (the pilot's order)


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


def _selected(args: argparse.Namespace) -> list[Site]:
    """The sites a command works on; an empty selection is an error, not a clean no-op."""
    sites = _select(load_sites(URLS_PATH), args.only)
    if not sites:
        raise SystemExit(f"error: --only {args.only!r} matches no site in data/urls.txt")
    return sites


async def ask_operator(question: str) -> bool:
    """--confirm-submit: show what is about to happen and wait for the operator. Enter = go
    ahead; n = stop this site. No terminal (end of input) counts as no."""
    print("\n=== CONFIRM BEFORE FIRST SUBMIT ===\n" + question, flush=True)
    try:
        answer = await asyncio.to_thread(input, "Enter = go ahead, n = stop this site > ")
    except EOFError:
        print("(no terminal to answer on: stopping this site)", flush=True)
        return False
    return answer.strip().lower() not in {"n", "no", "stop"}


def cmd_triage(args: argparse.Namespace) -> int:
    settings = load_settings()
    sites = _selected(args)
    out = run_dir(args.run_id or new_run_id())
    print(f"Triage of {len(sites)} URLs → {out}/triage.jsonl")
    records = asyncio.run(run_triage(settings, sites, out))
    print("\nStatus counts:")
    for status, count in status_counts(records).most_common():
        print(f"  {status:<17} {count}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    from scamhunter.agent.loop import AgentLimits
    from scamhunter.llm.client import LLMClient

    settings = load_settings()
    sites = _selected(args)
    run_id = args.run_id or new_run_id()
    out = run_dir(run_id)
    if (out / "checkpoint.jsonl").exists() and not args.resume:
        # A reused id would append to the old checkpoint and delete the old evidence of any
        # site it visits again (2026-10-07: `RUN_ID=pilot-1` hit the 2026-10-04 run).
        print(
            f"error: runs/{run_id} already holds a run; pick a new --run-id, or pass --resume "
            "to continue it",
            file=sys.stderr,
        )
        return 1
    if args.triage_from and not (out / "triage.jsonl").exists():
        shutil.copyfile(RUNS_DIR / args.triage_from / "triage.jsonl", out / "triage.jsonl")
    concurrency = 1 if args.confirm_submit else args.concurrency
    llm = None
    nav = None
    if settings.agent.enabled and not args.no_agent:
        from scamhunter.agent.site_run import NavigationOptions

        # The navigator's client waits 200 s with one retry (the gateway gives up after 3 x 60 s).
        llm = LLMClient(settings.llm.gateway_url, timeout_s=200, retries=1)
        stop_file = out / "STOP"
        nav = NavigationOptions(
            limits=AgentLimits.from_settings(
                settings.agent,
                max_steps=args.max_steps or settings.agent.max_steps,
                max_seconds=args.max_seconds or settings.agent.max_seconds,
            ),
            llm=llm,
            stop_file=stop_file,
            confirm=ask_operator if args.confirm_submit else None,
            force=args.force_navigation,
            spend_cap_usd=args.spend_cap,
            progress=lambda line: print(f"    {line}", flush=True),
        )
        print(
            f"navigator on (max {nav.limits.max_steps} steps, {nav.limits.max_seconds} s per site"
            f"{f', session cap ${args.spend_cap:.2f}' if args.spend_cap else ''}"
            f"{', confirm before first submit' if args.confirm_submit else ''}"
            f"{', navigation forced on every site' if args.force_navigation else ''}); "
            f"stop everything with: touch runs/{run_id}/STOP",
            flush=True,
        )
    try:
        results = asyncio.run(
            run_pipeline(settings, sites, out, resume=args.resume, nav=nav, concurrency=concurrency)
        )
    except NoSitesVisited as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if nav is not None:
        print(f"estimated LLM spend this run: ${nav.spend.usd:.2f}")
    _finalize(results, settings, run_id)
    return 0


def cmd_capture(args: argparse.Namespace) -> int:
    settings = load_settings()
    sites = _selected(args)
    out = run_dir(args.run_id or new_run_id())
    if not (out / "triage.jsonl").exists():
        shutil.copyfile(RUNS_DIR / args.triage_from / "triage.jsonl", out / "triage.jsonl")
    try:
        rows = asyncio.run(
            run_capture_only(
                settings, sites, out, settle_ms=args.settle_ms, force_mobile=args.mobile
            )
        )
    except NoSitesVisited as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    errors = [r for r in rows if "error" in r]
    print(f"\n{len(rows)} captured, {len(errors)} errors → {out}/capture.jsonl")
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


def cmd_review(args: argparse.Namespace) -> int:
    """Read-only HTML review page + labels template from a run's saved evidence."""
    run = RUNS_DIR / args.run_id
    checkpoint = run / "checkpoint.jsonl"
    if not checkpoint.exists():
        print(f"no checkpoint at {checkpoint}")
        return 1
    results = list(load_checkpoint(checkpoint).values())
    path = write_review(results, args.run_id, run, load_settings().classify.scam_threshold)
    print(f"{path} ({len(results)} sites); labels template next to it")
    return 0


def cmd_agent_mock(args: argparse.Namespace) -> int:
    """M3 step E: the real navigator (Claude via the gateway) against the local mock exchange.
    Mock mode only: the browser can reach loopback and nothing else (DESIGN §5.6.0)."""
    import logging

    from scamhunter.agent.loop import AgentLimits, ClaudeDecider
    from scamhunter.agent.prompts import GOAL, system_prompt
    from scamhunter.llm.client import LLMClient
    from scamhunter.mock_mode import GATED_VARIANTS, SOLVABLE_VARIANTS, evaluate_navigator

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    settings = load_settings()
    all_variants = [*SOLVABLE_VARIANTS, *GATED_VARIANTS]
    variants = all_variants if args.variants == "all" else args.variants.split(",")
    if unknown := set(variants) - set(all_variants):
        print(f"unknown variants: {sorted(unknown)}")
        return 1
    limits = AgentLimits.from_settings(
        settings.agent, max_steps=args.max_steps, max_seconds=args.max_seconds
    )
    out = run_dir(args.run_id or new_run_id())

    async def go() -> list[dict]:
        # Navigator: the gateway gives up after 3 × 60 s; the run's wall-clock watchdog bounds
        # everything else. One crawler-side retry for a dropped connection.
        llm = LLMClient(settings.llm.gateway_url, timeout_s=200, retries=1)
        try:
            return await evaluate_navigator(
                lambda name, policy: ClaudeDecider(
                    llm,
                    f"mock-{name}",
                    system_prompt(policy.mock_wallet_active),  # prompt and policy agree
                    response_cache=False,
                ),
                variants,
                args.repeat,
                out,
                limits,
                GOAL,
                settings.llm.navigator_model,
                args.spend_cap,
                resume=args.resume,
            )
        finally:
            await llm.aclose()

    rows = asyncio.run(go())
    print(f"\n{out / 'agent_mock' / 'summary.json'}")
    for row in rows:
        print(
            f"  {row['run']:<20} {'PASS' if row['passed'] else 'FAIL'}  steps {row['steps']:>2}"
            f"  first {row['first_correct_step']}  {row['found']}  full {row['full_coverage_step']}"
            f"  blocked_at {row['blocked_at']}  ${row['cost_usd']:.3f}"
            f"  refusals {len(row['refusals'])}"
        )
    return 0


def cmd_pipeline_mock(args: argparse.Namespace) -> int:
    """The mock variants through `process_site`, not the step-E harness. Mock mode only."""
    import logging

    from scamhunter.agent.loop import AgentLimits
    from scamhunter.llm.client import LLMClient
    from scamhunter.mock_mode import GATED_VARIANTS, SOLVABLE_VARIANTS, evaluate_pipeline_on_mock

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    settings = load_settings()
    all_variants = [*SOLVABLE_VARIANTS, *GATED_VARIANTS]
    variants = all_variants if args.variants == "all" else args.variants.split(",")
    if unknown := set(variants) - set(all_variants):
        print(f"unknown variants: {sorted(unknown)}")
        return 1
    limits = AgentLimits.from_settings(
        settings.agent, max_steps=args.max_steps, max_seconds=args.max_seconds
    )
    out = run_dir(args.run_id or new_run_id())

    async def go() -> list[dict]:
        llm = LLMClient(settings.llm.gateway_url, timeout_s=200, retries=1)
        try:
            return await evaluate_pipeline_on_mock(
                variants,
                out,
                settings,
                limits,
                llm,
                args.spend_cap,
                confirm=ask_operator if args.confirm_submit else None,
            )
        finally:
            await llm.aclose()

    rows = asyncio.run(go())
    print(f"\n{out / 'pipeline_mock' / 'summary.json'}")
    for r in rows:
        print(
            f"  {r['variant']:<16} {'PASS' if r.get('passed') else 'FAIL'}  steps {r.get('steps')}"
            f"  {r.get('found')}  verdict {r.get('verdict')}  out {r.get('output_correct')}/"
            f"{r.get('output_addresses')}  blocked_at {r.get('result_blocked_at')}"
            f"  ${r['site_cost_usd']:.3f}"
        )
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
    run.add_argument("--no-agent", action="store_true", help="capture and judge only, no navigator")
    run.add_argument(
        "--confirm-submit",
        action="store_true",
        help="ask before the first form submission on each site (forces one site at a time)",
    )
    run.add_argument(
        "--force-navigation",
        action="store_true",
        help="navigate every site that loaded with content, whatever the first judgment says",
    )
    run.add_argument("--max-steps", type=int, help="navigator steps per site (settings default)")
    run.add_argument("--max-seconds", type=int, help="navigator wall-clock per site")
    run.add_argument(
        "--spend-cap", type=float, help="session cap in USD for navigation (estimated)"
    )
    run.add_argument("--concurrency", type=int, help="sites at once (settings default)")

    capture = sub.add_parser(
        "capture", help="landing capture of live sites only (no agent/clicks/LLM)"
    )
    capture.add_argument("--run-id", help="run directory name (default: timestamp)")
    capture.add_argument("--only", help="comma-separated site numbers, e.g. 17,42")
    capture.add_argument("--settle-ms", type=int, default=8000, help="network-idle wait per page")
    capture.add_argument("--mobile", action="store_true", help="mobile viewport and UA first")
    capture.add_argument(
        "--triage-from", default="triage-1", help="run id whose triage.jsonl to use"
    )

    for name, help_text in (
        ("rescore", "re-classify a run from saved evidence (no visits)"),
        ("report", "publish a run's results into output/"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--run-id", required=True)
    mock = sub.add_parser("agent-mock", help="navigator vs the local mock exchange (M3 step E)")
    mock.add_argument("--run-id", help="run directory name (default: timestamp)")
    mock.add_argument("--variants", default="all", help="comma-separated, or 'all'")
    mock.add_argument("--repeat", type=int, default=3)
    mock.add_argument("--spend-cap", type=float, default=10.0, help="USD for the whole session")
    mock.add_argument("--max-steps", type=int, default=35)
    mock.add_argument("--max-seconds", type=int, default=600)
    mock.add_argument("--resume", action="store_true", help="keep runs already in summary.json")
    pmock = sub.add_parser(
        "pipeline-mock", help="mock variants through process_site, the real-site path (M3)"
    )
    pmock.add_argument("--run-id", help="run directory name (default: timestamp)")
    pmock.add_argument("--variants", default="all", help="comma-separated, or 'all'")
    pmock.add_argument("--spend-cap", type=float, default=5.0, help="USD for the whole session")
    pmock.add_argument(
        "--confirm-submit", action="store_true", help="ask before the first submit (dry run)"
    )
    pmock.add_argument("--max-steps", type=int, default=30)
    pmock.add_argument("--max-seconds", type=int, default=300)
    review = sub.add_parser("review", help="read-only HTML review page from saved evidence")
    review.add_argument("--run-id", required=True)
    sub.add_parser("eval", help="not implemented yet (M4)")

    args = parser.parse_args(argv)
    handlers = {
        "triage": cmd_triage,
        "run": cmd_run,
        "capture": cmd_capture,
        "rescore": cmd_rescore,
        "report": cmd_report,
        "review": cmd_review,
        "agent-mock": cmd_agent_mock,
        "pipeline-mock": cmd_pipeline_mock,
    }
    if args.command in handlers:
        return handlers[args.command](args)
    print(f"{args.command}: not implemented")
    return 1


if __name__ == "__main__":
    sys.exit(main())
