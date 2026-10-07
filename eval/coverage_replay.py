"""Replay a saved navigation trace under three coverage rules and say when each asset counts
(no visits; LOG 2026-10-07). The rules:
  labels     a primary address counts for an asset only if a label of confidence >= 0.6 says so
             (the rule before 2026-10-07)
  selection  an address shown while a coin was selected counts for that coin
  sharing    selection, plus: an address seen for two selections covers its whole family
Usage: python eval/coverage_replay.py runs/pilot-20261007b 012"""

import argparse
import json
from pathlib import Path

from scamhunter.agent.coverage import (
    CoverageTracker,
    coin_and_network,
    family_of,
    key_for_selection,
)
from scamhunter.agent.loop import asset_keys
from scamhunter.browser.capture import load_snapshot_content, load_snapshots
from scamhunter.extract.blocklist import load_blocklist
from scamhunter.extract.extractor import extract
from scamhunter.models import AddressTier, DiscoveryStage

TARGETS = ("BTC", "ETH", "USDT-ERC20", "USDT-TRC20", "USDC-ERC20", "USDC-TRC20")


def replay(run_dir: Path, site_id: str) -> dict:
    site_dir = run_dir / "sites" / site_id
    trace = json.loads((site_dir / "agent_trace.json").read_text())
    snaps = {s.snapshot_id: s for s in load_snapshots(site_dir)}
    blocklist = load_blocklist()
    labels: set[str] = set()
    selection: set[str] = set()
    tracker = CoverageTracker(TARGETS)
    sharing: set[str] = set()
    first = {"labels": {}, "selection": {}, "sharing": {}}
    coin = network = None
    turns = sorted({s["index"] for s in trace["steps"]})
    for turn in turns:
        steps = [s for s in trace["steps"] if s["index"] == turn]
        for s in steps:
            a = s["action"]
            if s["allowed"] and a["type"] == "select" and a.get("value"):
                c, n = coin_and_network(a["value"])
                if c:
                    coin, network = c, n
        shot = next(
            (s["screenshot_path"] for s in steps if s["allowed"] and s["screenshot_path"]), ""
        )
        if not shot:
            continue
        snap = snaps[shot.split("/")[-2]]
        content = load_snapshot_content(snap, run_dir)
        found = [a for a in extract(content, blocklist) if a.tier == AddressTier.PRIMARY]
        deposit = snap.stage == DiscoveryStage.DEPOSIT_PAGE
        text = content.visible_text.lower()
        for a in found:
            labels |= asset_keys(a) & set(TARGETS)
        shown = [
            (family_of(a.format), a.address)
            for a in found
            if family_of(a.format) and a.address.lower() in text
        ]
        if deposit:
            for family, _address in shown:
                key = key_for_selection(family, coin, network)
                if key in TARGETS:
                    selection.add(key)
            sharing |= tracker.observe(coin, network, shown)
        for name, got in (("labels", labels), ("selection", selection), ("sharing", sharing)):
            for asset in got:
                first[name].setdefault(asset, turn)
    return {"first": first, "done_turn": max(turns), "turns": turns}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("site_id")
    args = parser.parse_args()
    out = replay(args.run_dir, args.site_id)
    print(f"site {args.site_id}: the agent called done at turn {out['done_turn']}")
    print(f"{'asset':<12}" + "".join(f"{r:>12}" for r in out["first"]))
    for asset in TARGETS:
        print(
            f"{asset:<12}"
            + "".join(f"{out['first'][r].get(asset, '-')!s:>12}" for r in out["first"])
        )
    reachable = {a for a in TARGETS if any(a in out["first"][r] for r in out["first"])}
    for rule, got in out["first"].items():
        done = max(got.values()) if got and set(got) >= reachable else None
        print(f"{rule}: covers {len(got)} of {len(TARGETS)}; all it can reach by turn {done}")


if __name__ == "__main__":
    main()
