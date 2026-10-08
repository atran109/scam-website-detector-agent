"""Precision/recall on verdicts and addresses against a labels file (M4; no visits).

    python eval/evaluate.py runs/<id>/output/results.json [--labels eval/labels.csv]
                            [--thresholds 0.45 0.5] [--labeled-by alex] [--json out.json]

Labels CSV columns: url, verdict (scam | not_scam; any other value is skipped), scam_type,
expected_addresses ("|"-separated, exactly as shown on the site), label_basis, notes, labeled_by
(alex | assistant; `--labeled-by` scores one author's labels only). A site is
predicted a scam at threshold t if its `scam_probability` is at least t, so one results file
gives the whole 0.45 versus 0.5 comparison (DESIGN §5.4: the shipped threshold is 0.45, a lean
toward recall). Address metrics use the exact strings of `crypto_addresses` (primary tier)."""

import argparse
import csv
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

DEFAULT_THRESHOLDS = (0.45, 0.5)
LABELS = Path(__file__).with_name("labels.csv")


@dataclass
class VerdictMetrics:
    threshold: float
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    errors: list[dict] = field(default_factory=list)

    @property
    def n(self) -> int:
        return self.tp + self.fp + self.fn + self.tn

    @property
    def precision(self) -> float | None:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else None

    @property
    def recall(self) -> float | None:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else None

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p and r else None

    @property
    def accuracy(self) -> float | None:
        return (self.tp + self.tn) / self.n if self.n else None


@dataclass
class AddressMetrics:
    sites: int = 0  # labelled sites with expected addresses
    expected: int = 0
    found: int = 0
    correct: int = 0
    missed: list[dict] = field(default_factory=list)
    extra: list[dict] = field(default_factory=list)

    @property
    def precision(self) -> float | None:
        return self.correct / self.found if self.found else None

    @property
    def recall(self) -> float | None:
        return self.correct / self.expected if self.expected else None


def load_labels(path: Path, labeled_by: str | None = None) -> list[dict]:
    with path.open(newline="") as f:
        rows = [r for r in csv.DictReader(f) if r.get("verdict") in ("scam", "not_scam")]
    return [r for r in rows if labeled_by is None or r.get("labeled_by") == labeled_by]


def load_results(path: Path) -> dict[str, dict]:
    data = json.loads(path.read_text())
    records = data["results"] if isinstance(data, dict) else data
    return {r["url"]: r for r in records}


def verdict_metrics(
    labels: list[dict], results: dict[str, dict], threshold: float
) -> tuple[VerdictMetrics, list[str]]:
    m = VerdictMetrics(threshold)
    missing: list[str] = []
    for row in labels:
        record = results.get(row["url"])
        if record is None:
            missing.append(row["url"])
            continue
        predicted = record["scam_probability"] >= threshold
        actual = row["verdict"] == "scam"
        if predicted and actual:
            m.tp += 1
        elif predicted:
            m.fp += 1
        elif actual:
            m.fn += 1
        else:
            m.tn += 1
        if predicted != actual:
            m.errors.append(
                {
                    "url": row["url"],
                    "label": row["verdict"],
                    "probability": record["scam_probability"],
                    "evidence_source": record.get("evidence_source"),
                    "status": record.get("status"),
                }
            )
    return m, missing


def address_metrics(labels: list[dict], results: dict[str, dict]) -> AddressMetrics:
    m = AddressMetrics()
    for row in labels:
        expected = {a for a in (row.get("expected_addresses") or "").split("|") if a}
        record = results.get(row["url"])
        if not expected or record is None:
            continue
        found = set(record["crypto_addresses"])
        m.sites += 1
        m.expected += len(expected)
        m.found += len(found)
        m.correct += len(found & expected)
        if expected - found:
            m.missed.append({"url": row["url"], "addresses": sorted(expected - found)})
        if found - expected:
            m.extra.append({"url": row["url"], "addresses": sorted(found - expected)})
    return m


def pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.0%}"


def report(labels: list[dict], results: dict[str, dict], thresholds: tuple[float, ...]) -> dict:
    out: dict = {"labelled": len(labels), "thresholds": {}}
    for t in thresholds:
        m, missing = verdict_metrics(labels, results, t)
        out["thresholds"][str(t)] = {
            **asdict(m),
            "precision": m.precision,
            "recall": m.recall,
            "f1": m.f1,
            "accuracy": m.accuracy,
            "missing_results": missing,
        }
    a = address_metrics(labels, results)
    out["addresses"] = {**asdict(a), "precision": a.precision, "recall": a.recall}
    return out


def print_report(out: dict) -> None:
    print(f"{out['labelled']} labelled sites with a verdict label")
    print(
        f"{'threshold':>10} {'n':>3} {'TP':>3} {'FP':>3} {'FN':>3} {'TN':>3} "
        f"{'precision':>10} {'recall':>7} {'F1':>5} {'accuracy':>9}"
    )
    for t, m in out["thresholds"].items():
        n = m["tp"] + m["fp"] + m["fn"] + m["tn"]
        print(
            f"{t:>10} {n:>3} {m['tp']:>3} {m['fp']:>3} {m['fn']:>3} {m['tn']:>3} "
            f"{pct(m['precision']):>10} {pct(m['recall']):>7} {pct(m['f1']):>5} "
            f"{pct(m['accuracy']):>9}"
        )
    for t, m in out["thresholds"].items():
        if m["missing_results"]:
            print(f"  no result for {len(m['missing_results'])} labelled urls (threshold {t})")
        for e in m["errors"]:
            print(
                f"  [{t}] {e['label']:<8} predicted the other way: p={e['probability']:.2f} "
                f"{e['url']} ({e['evidence_source']}, {e['status']})"
            )
    a = out["addresses"]
    print(
        f"addresses: {a['sites']} labelled sites with expected addresses; "
        f"precision {pct(a['precision'])} ({a['correct']}/{a['found']}), "
        f"recall {pct(a['recall'])} ({a['correct']}/{a['expected']})"
    )
    for e in a["missed"]:
        print("  missed", e["url"], e["addresses"])
    for e in a["extra"]:
        print("  extra ", e["url"], e["addresses"])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("results", type=Path)
    parser.add_argument("--labels", type=Path, default=LABELS)
    parser.add_argument("--thresholds", type=float, nargs="+", default=list(DEFAULT_THRESHOLDS))
    parser.add_argument("--labeled-by", help="only this author's labels (alex | assistant)")
    parser.add_argument("--json", type=Path, help="also write the report here")
    args = parser.parse_args()
    labels = load_labels(args.labels, args.labeled_by)
    out = report(labels, load_results(args.results), tuple(args.thresholds))
    print_report(out)
    if args.json:
        args.json.write_text(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
