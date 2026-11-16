"""The agent funnel subset (DESIGN §8.3): pick the sites, then tally how far the agent got.

    python -m eval.dataset_v1.funnel --pick                          # ids for `make run --only`
    python -m eval.dataset_v1.funnel --tally --run-id dataset-v1-agent

Picked: human-reviewed scam rows whose landing page shows an account, deposit or wallet flow
(the agent's own trigger), DFPI platforms first, at most 40. The tally counts each funnel step,
the stop reasons, and checks extracted addresses against the ones DFPI published."""

import argparse
import sys
from collections import Counter
from pathlib import Path

from eval.dataset_v1.labels import LABELS_PATH, is_reviewed, read_csv
from eval.dataset_v1.sample import MANIFEST_PATH, PRIORITY, REPO_ROOT, load_manifest

from scamhunter.agent.site_run import account_trigger
from scamhunter.labeller import landing_snapshot
from scamhunter.models import ActionType, BlockedReason, NavigationTrace, SiteResult

MAX_AGENT_SITES = 40  # DESIGN §8.6
FILL_DONE = {"ok", "navigated"}  # AgentStep.result values of an action that was carried out

# Gates that mean the agent got as far as a sign-up form before it stopped.
SIGN_UP_GATES = {
    BlockedReason.INVITE_CODE,
    BlockedReason.SMS_VERIFICATION,
    BlockedReason.EMAIL_VERIFICATION,
    BlockedReason.CAPTCHA,
    BlockedReason.KYC,
}


def pick_agent_sites(
    rows: list[dict], account_flow: dict[str, bool], limit: int = MAX_AGENT_SITES
) -> list[str]:
    """Site ids for the agent run: reviewed scam rows with an account flow, DFPI first, then
    the other sources in the sampler's priority order, then by site id."""
    eligible = [
        r
        for r in rows
        if r["verdict"] == "scam" and is_reviewed(r) and account_flow.get(r["site_id"], False)
    ]
    eligible.sort(key=lambda r: (PRIORITY.index(r["source"]), r["site_id"]))
    return [r["site_id"] for r in eligible[:limit]]


def reached_registration(nav: NavigationTrace) -> bool:
    """Registered, typed into a form, or stopped at a sign-up gate (LOG 2026-11-15). A fill
    counts only if it happened: the policy allowed it and the browser carried it out."""
    filled = any(
        step.action.type == ActionType.FILL and step.allowed and step.result in FILL_DONE
        for step in nav.steps
    )
    return nav.registered or filled or nav.blocked_at in SIGN_UP_GATES


def tally(sites: list[tuple[NavigationTrace | None, list[str]]]) -> dict[str, int]:
    """Counts over (navigation trace, primary addresses) per site. A step's count includes the
    sites that went further, so the numbers only shrink down the funnel."""
    counts: Counter[str] = Counter(sites=len(sites))
    for nav, addresses in sites:
        counts["address"] += bool(addresses)
        if nav is None:
            continue
        counts["navigated"] += 1
        counts["reached_registration"] += reached_registration(nav)
        counts["registered"] += nav.registered
        counts["logged_in"] += nav.logged_in
        counts["deposit_page"] += nav.reached_deposit
        counts[f"stop:{nav.stop_reason.value}"] += 1
    return dict(counts)


def _same(a: str, b: str) -> bool:
    # EVM addresses differ only by checksum case; every other format is case-sensitive.
    return a.lower() == b.lower() if a.lower().startswith("0x") else a == b


def dfpi_address_check(notes: dict[str, str], found: dict[str, list[str]]) -> list[dict]:
    """For each site whose DFPI note lists addresses: `match` if the agent found one of them,
    `different` if it found only others (operators rotate addresses, so not an error), or
    `none_found`."""
    out = []
    for site_id, note in sorted(notes.items()):
        if " | addresses: " not in note:
            continue
        listed = note.split(" | addresses: ", 1)[1].split()
        got = found.get(site_id, [])
        if any(_same(a, b) for a in listed for b in got):
            outcome = "match"
        else:
            outcome = "different" if got else "none_found"
        out.append({"site_id": site_id, "dfpi": listed, "found": got, "outcome": outcome})
    return out


# ---------- Reading runs ----------


def _results(run_dir: Path) -> dict[str, SiteResult]:
    path = run_dir / "checkpoint.jsonl"
    if not path.exists():
        raise SystemExit(f"error: {path} missing")
    results = (SiteResult.model_validate_json(x) for x in path.read_text().splitlines())
    return {r.site.site_id: r for r in results}


def account_flows(run_dir: Path, results: dict[str, SiteResult]) -> dict[str, bool]:
    """The agent's account trigger per captured site, from the landing text and addresses."""
    flows = {}
    for site_id, result in results.items():
        snapshot = landing_snapshot(run_dir / "sites" / site_id)
        text_file = (run_dir / snapshot.html_path).parent / "text.txt" if snapshot else None
        text = text_file.read_text() if text_file and text_file.exists() else ""
        # Every tier, as the pipeline passes all extracted addresses to should_navigate.
        has_address = bool(
            result.addresses or result.low_confidence_addresses or result.other_addresses
        )
        flows[site_id] = account_trigger(text, has_address)
    return flows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--pick", action="store_true")
    action.add_argument("--tally", action="store_true")
    parser.add_argument("--run-id", help="default: dataset-v1 (pick), dataset-v1-agent (tally)")
    parser.add_argument("--labels", type=Path, default=LABELS_PATH)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    args = parser.parse_args(argv)

    if args.pick:
        run_dir = REPO_ROOT / "runs" / (args.run_id or "dataset-v1")
        picked = pick_agent_sites(read_csv(args.labels), account_flows(run_dir, _results(run_dir)))
        print(f"{len(picked)} sites picked for the agent run:")
        print(",".join(picked))
        return 0

    run_dir = REPO_ROOT / "runs" / (args.run_id or "dataset-v1-agent")
    results = _results(run_dir)
    counts = tally([(r.navigation, [a.address for a in r.addresses]) for r in results.values()])
    for key, value in counts.items():
        print(f"{key:<24} {value}")
    notes = {m.site_id: m.source_note for m in load_manifest(args.manifest) if m.source == "dfpi"}
    found = {s: [a.address for a in r.addresses] for s, r in results.items()}
    checks = dfpi_address_check({s: n for s, n in notes.items() if s in results}, found)
    for c in checks:
        print(f"DFPI {c['site_id']}: {c['outcome']} (DFPI {c['dfpi']}, found {c['found']})")
    print(f"DFPI address check: {dict(Counter(c['outcome'] for c in checks))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
