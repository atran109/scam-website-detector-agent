"""The dataset's labels file, the human review queue and the agreement report (DESIGN §8.4).

    python -m eval.dataset_v1.labels --build       # write or refresh eval/dataset_v1/labels.csv
    python -m eval.dataset_v1.labels --queue       # site ids to review, test split first
    python -m eval.dataset_v1.labels --agreement   # how often review changed the labeller's verdict

Every row starts as the labeller's draft: `verdict` equals `labeller_verdict` and
`reviewed_by` is `none`. Reviewing a row means editing `verdict` (and `expected_addresses`,
`notes` as needed) and setting `reviewed_by` to the reviewer's name. `--build` never touches a
reviewed row, so it is safe to rerun after the labeller retries its errors."""

import argparse
import csv
import json
import random
import sys
from pathlib import Path

from eval.dataset_v1.models import ManifestRow
from eval.dataset_v1.sample import MANIFEST_PATH, REPO_ROOT, SEED, load_manifest
from eval.dataset_v1.split import SPLIT_PATH

from scamhunter.labeller import LabellerVerdict, latest_verdicts
from scamhunter.models import SiteResult

LABELS_PATH = REPO_ROOT / "eval" / "dataset_v1" / "labels.csv"
COLUMNS = [
    "url",
    "verdict",
    "scam_type",
    "expected_addresses",
    "label_basis",
    "notes",
    "labeled_by",
    "site_id",
    "source",
    "listed_on",
    "cluster_id",
    "split",
    "labeller_verdict",
    "reviewed_by",
]
DEV_SAMPLE_SHARE = 0.2  # agreeing dev rows that are still reviewed (DESIGN §8.4)


def is_reviewed(row: dict) -> bool:
    return row.get("reviewed_by", "none") not in ("", "none")


def build_labels(
    manifest: list[ManifestRow],
    labeller: dict[str, LabellerVerdict],
    split: dict[str, dict],
) -> list[dict]:
    """One row per site in the split (the captured sites), in site-id order. A site the
    labeller has no line for is `error`, so it lands in the review queue."""
    by_id = {m.site_id: m for m in manifest}
    rows = []
    for site_id in sorted(split):
        m = by_id[site_id]
        draft = labeller.get(site_id)
        verdict = draft.verdict if draft else "error"
        rows.append(
            {
                "url": m.url,
                "verdict": verdict,
                "scam_type": "",
                "expected_addresses": "",
                "label_basis": "labeller draft, not yet reviewed",
                "notes": draft.reason if draft else "no labeller line for this site",
                "labeled_by": "labeller",
                "site_id": site_id,
                "source": m.source,
                "listed_on": m.listed_on.isoformat() if m.listed_on else "",
                "cluster_id": split[site_id]["cluster_id"],
                "split": split[site_id]["split"],
                "labeller_verdict": verdict,
                "reviewed_by": "none",
            }
        )
    return rows


def merge_reviewed(new: list[dict], existing: list[dict]) -> list[dict]:
    """New rows, except that every reviewed row of the existing file is kept exactly as it is."""
    kept = {r["site_id"]: r for r in existing if is_reviewed(r)}
    return [kept.get(r["site_id"], r) for r in new]


def _queue_parts(rows: list[dict], pipeline_verdicts: dict[str, str]) -> dict[str, list[str]]:
    """Why each queued site is there: the whole test split; dev rows where the labeller and
    the pipeline disagree (an `excluded` or `error` draft always does); a seeded 20% of the
    other dev rows."""
    test = sorted(r["site_id"] for r in rows if r["split"] == "test")
    dev = [r for r in rows if r["split"] == "dev"]
    disagree = sorted(
        r["site_id"]
        for r in dev
        if r["labeller_verdict"] == "error"
        or r["labeller_verdict"] != pipeline_verdicts.get(r["site_id"])
    )
    rest = sorted(r["site_id"] for r in dev if r["site_id"] not in set(disagree))
    sample = sorted(random.Random(SEED).sample(rest, round(len(rest) * DEV_SAMPLE_SHARE)))
    return {"test": test, "dev_disagreement": disagree, "dev_sample": sample}


def review_queue(rows: list[dict], pipeline_verdicts: dict[str, str]) -> list[str]:
    """Site ids to review by hand, test split first."""
    parts = _queue_parts(rows, pipeline_verdicts)
    return parts["test"] + parts["dev_disagreement"] + parts["dev_sample"]


def agreement(rows: list[dict], pipeline_verdicts: dict[str, str]) -> dict[str, dict]:
    """Per queue part: rows reviewed so far, how many the reviewer changed, and the rate. The
    dev disagreement rows are reported apart from the random dev sample, because they were
    picked for disagreeing and would make the labeller look worse than it is."""
    by_id = {r["site_id"]: r for r in rows}
    out = {}
    for part, site_ids in _queue_parts(rows, pipeline_verdicts).items():
        reviewed = [by_id[s] for s in site_ids if is_reviewed(by_id[s])]
        changed = sum(r["verdict"] != r["labeller_verdict"] for r in reviewed)
        out[part] = {
            "queued": len(site_ids),
            "reviewed": len(reviewed),
            "changed": changed,
            "rate": changed / len(reviewed) if reviewed else None,
        }
    return out


# ---------- Files ----------


def read_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def load_split(path: Path) -> dict[str, dict]:
    if not path.exists():
        raise SystemExit(f"error: {path} missing; run `python -m eval.dataset_v1.split` first")
    return {x["site_id"]: x for x in (json.loads(line) for line in path.read_text().splitlines())}


def pipeline_verdicts(run_dir: Path) -> dict[str, str]:
    path = run_dir / "checkpoint.jsonl"
    if not path.exists():
        raise SystemExit(f"error: {path} missing; run `make classify RUN={run_dir.name}` first")
    results = (SiteResult.model_validate_json(x) for x in path.read_text().splitlines())
    return {r.site.site_id: r.classification.verdict.value for r in results}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--build", action="store_true")
    action.add_argument("--queue", action="store_true")
    action.add_argument("--agreement", action="store_true")
    parser.add_argument("--run-id", default="dataset-v1")
    parser.add_argument("--labels", type=Path, default=LABELS_PATH)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--split", type=Path, default=SPLIT_PATH)
    args = parser.parse_args(argv)
    run_dir = REPO_ROOT / "runs" / args.run_id

    if args.build:
        new = build_labels(
            load_manifest(args.manifest),
            latest_verdicts(run_dir / "labeller.jsonl"),
            load_split(args.split),
        )
        existing = read_csv(args.labels)
        rows = merge_reviewed(new, existing)
        write_csv(args.labels, rows)
        kept = sum(is_reviewed(r) for r in rows)
        print(f"{len(rows)} rows ({kept} reviewed rows kept as they were) → {args.labels}")
        return 0

    rows = read_csv(args.labels)
    if not rows:
        print(f"error: {args.labels} missing or empty; run with --build first", file=sys.stderr)
        return 1
    verdicts = pipeline_verdicts(run_dir)
    if args.queue:
        queue = review_queue(rows, verdicts)
        reviewed = {r["site_id"] for r in rows if is_reviewed(r)}
        todo = [s for s in queue if s not in reviewed]
        (run_dir / "review_queue.txt").write_text("\n".join(queue) + "\n")
        print(f"{len(queue)} sites in the queue, {len(todo)} not yet reviewed:")
        print(",".join(todo))
        return 0
    for part, figures in agreement(rows, verdicts).items():
        rate = "n/a" if figures["rate"] is None else f"{figures['rate']:.0%}"
        print(
            f"{part:<17} queued {figures['queued']:>4}  reviewed {figures['reviewed']:>4}  "
            f"changed {figures['changed']:>4}  rate {rate}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
