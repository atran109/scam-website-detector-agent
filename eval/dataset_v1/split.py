"""Assign each cluster to dev or test (DESIGN §8.5) and write data/dataset/v1/split.jsonl.

    python -m eval.dataset_v1.split            # after `make label RUN=dataset-v1`
    python -m eval.dataset_v1.split --force    # overwrite an existing split (avoid: §8.5)

Rules, applied per cluster (a cluster is never split):
- A cluster with any scam-list member is a scam cluster, even if it also holds a site from a
  legitimate list (a phishing copy that shares the real site's page structure).
- Scam clusters with a listing date (ScamSniffer): newest first into test until test holds a
  third of the dated sites. This is the time split. A mixed cluster follows its dated members.
- Undated scam clusters with a DFPI member: seeded random draw, a third of their sites to test.
- Other undated scam clusters (MetaMask blocklist only): dev.
- Legitimate clusters: seeded random draw per source, a third of each source's sites to test.

The run must be labelled first: sites the labeller called excluded or error take no
page-structure link (parked and error pages look alike across unrelated domains)."""

import argparse
import json
import random
import sys
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path
from typing import Literal

from eval.dataset_v1.cluster import ClusterInput, by_cluster, clusters, dom_skeleton_hash
from eval.dataset_v1.models import SCAM_SOURCES
from eval.dataset_v1.sample import MANIFEST_PATH, PRIORITY, REPO_ROOT, SEED, load_manifest
from pydantic import BaseModel

from scamhunter.labeller import landing_snapshot, latest_verdicts
from scamhunter.models import AddressTier, SiteResult

Split = Literal["dev", "test"]
SPLIT_PATH = REPO_ROOT / "data" / "dataset" / "v1" / "split.jsonl"
TEST_SHARE = 1 / 3
MAX_CLUSTER_SHARE = 0.15  # a bigger cluster is printed as a warning to inspect (runbook)


class SplitInput(BaseModel):
    site_id: str
    source: str
    expected: Literal["scam", "not_scam"]
    listed_on: date | None = None


def _fill_test(groups: list[list[str]], split: dict[str, Split]) -> None:
    """Groups in the given order go to test while test holds under a third of all their sites;
    the rest go to dev. A group is placed whole, so test can end a little over a third."""
    total = sum(len(g) for g in groups)
    in_test = 0
    for group in groups:
        side: Split = "test" if in_test < total * TEST_SHARE else "dev"
        in_test += len(group) if side == "test" else 0
        for site_id in group:
            split[site_id] = side


def assign_split(rows: list[SplitInput], assignment: dict[str, str]) -> dict[str, Split]:
    """site_id -> "dev" or "test". Deterministic: one `random.Random(SEED)`, groups in a fixed
    order, clusters sorted by id before shuffling."""
    info = {r.site_id: r for r in rows}
    dated: list[tuple[date, str]] = []
    draws: dict[str, list[str]] = defaultdict(list)  # "dfpi" or a legitimate source -> clusters
    split: dict[str, Split] = {}
    members = by_cluster({s: c for s, c in assignment.items() if s in info})

    for cluster_id, site_ids in sorted(members.items()):
        sites = [info[s] for s in site_ids]
        if any(s.expected == "scam" for s in sites):
            dates = [s.listed_on for s in sites if s.listed_on is not None]
            if dates:
                dated.append((min(dates), cluster_id))
            elif any(s.source == "dfpi" for s in sites):
                draws["dfpi"].append(cluster_id)
            else:
                for s in site_ids:
                    split[s] = "dev"
        else:
            sources = {s.source for s in sites}
            draws[next(p for p in PRIORITY if p in sources)].append(cluster_id)

    newest_first = sorted(dated, key=lambda d: (-d[0].toordinal(), d[1]))
    _fill_test([members[c] for _, c in newest_first], split)

    rng = random.Random(SEED)
    for group in ["dfpi"] + [p for p in PRIORITY if p not in SCAM_SOURCES]:
        cluster_ids = sorted(draws.get(group, []))
        rng.shuffle(cluster_ids)
        _fill_test([members[c] for c in cluster_ids], split)
    return split


# ---------- Reading a run ----------


def _primary_addresses(result: SiteResult) -> list[str]:
    every = result.addresses + result.low_confidence_addresses + result.other_addresses
    return sorted({a.dedupe_key for a in every if a.tier == AddressTier.PRIMARY})


def load_inputs(run_dir: Path, manifest_path: Path) -> tuple[list[ClusterInput], list[SplitInput]]:
    """Cluster and split inputs for every captured site (its folder exists under sites/).
    Needs the classify checkpoint (addresses) and the labeller file (judgeable)."""
    checkpoint, labels = run_dir / "checkpoint.jsonl", run_dir / "labeller.jsonl"
    for path, command in ((checkpoint, "make classify"), (labels, "make label")):
        if not path.exists():
            raise SystemExit(f"error: {path} missing; run `{command} RUN={run_dir.name}` first")
    results = {
        r.site.site_id: r
        for r in (SiteResult.model_validate_json(x) for x in checkpoint.read_text().splitlines())
    }
    verdicts = latest_verdicts(labels)
    cluster_rows, split_rows = [], []
    for row in load_manifest(manifest_path):
        site_dir = run_dir / "sites" / row.site_id
        if not site_dir.is_dir():
            continue
        snapshot = landing_snapshot(site_dir)
        html_file = run_dir / snapshot.html_path if snapshot else None
        dom_hash = (
            dom_skeleton_hash(html_file.read_text())
            if html_file is not None and html_file.exists()
            else None
        )
        verdict = verdicts.get(row.site_id)
        result = results.get(row.site_id)
        cluster_rows.append(
            ClusterInput(
                site_id=row.site_id,
                registrable_domain=row.registrable_domain,
                addresses=_primary_addresses(result) if result else [],
                dom_hash=dom_hash,
                judgeable=verdict is not None and verdict.verdict in ("scam", "not_scam"),
            )
        )
        split_rows.append(
            SplitInput(
                site_id=row.site_id,
                source=row.source,
                expected=row.expected,
                listed_on=row.listed_on,
            )
        )
    return cluster_rows, split_rows


def report(
    split_rows: list[SplitInput], assignment: dict[str, str], split: dict[str, Split]
) -> list[str]:
    """The figures the runbook records: cluster count, largest cluster, scam/legitimate counts
    per split, mixed clusters, and a warning for any cluster over 15% of the sites."""
    info = {r.site_id: r for r in split_rows}
    members = by_cluster(assignment)
    largest_id, largest = max(members.items(), key=lambda kv: (len(kv[1]), kv[0]))
    share = len(largest) / len(assignment)
    lines = [
        f"{len(assignment)} sites in {len(members)} clusters; largest {largest_id} with "
        f"{len(largest)} sites ({share:.0%})"
    ]
    counts = Counter((split[s], info[s].expected) for s in assignment)
    for side in ("dev", "test"):
        lines.append(
            f"  {side}: {counts[(side, 'scam')]} scam-list, {counts[(side, 'not_scam')]} "
            "legitimate-list sites"
        )
    for cluster_id, site_ids in members.items():
        if len({info[s].expected for s in site_ids}) > 1:
            lines.append(f"  mixed cluster {cluster_id} (counted as scam): {', '.join(site_ids)}")
    if share > MAX_CLUSTER_SHARE:
        lines.append(f"WARNING: {largest_id} holds over 15% of the sites; inspect it first")
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run-id", default="dataset-v1")
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--out", type=Path, default=SPLIT_PATH)
    parser.add_argument("--force", action="store_true", help="overwrite an existing split")
    args = parser.parse_args(argv)
    if args.out.exists() and not args.force:
        print(f"error: {args.out} exists; the split is made once (DESIGN §8.5)", file=sys.stderr)
        return 1
    cluster_rows, split_rows = load_inputs(REPO_ROOT / "runs" / args.run_id, args.manifest)
    if not cluster_rows:
        print("error: no captured sites in this run", file=sys.stderr)
        return 1
    assignment = clusters(cluster_rows)
    split = assign_split(split_rows, assignment)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        "".join(
            json.dumps({"site_id": s, "cluster_id": assignment[s], "split": split[s]}) + "\n"
            for s in sorted(assignment)
        )
    )
    print("\n".join(report(split_rows, assignment, split)))
    print(f"→ {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
