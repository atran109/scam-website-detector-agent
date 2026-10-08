"""Data for the dead-site (signals-only) rule, from a finished run's saved records. No visits.

For every signal that can fire without page content (domain and probe signals), count how
often it appears on live content sites judged scam vs not_scam, cross-check the hand labels,
and show how the run's no-content records would be decided under three rules:

  current   the scorer's rule: >=1 moderate/strong signal or >=3 weak signals lean scam
  A         only the kept signals count; any kept signal leans scam; none -> not_scam, p=0.4
  B         as A, but no kept signal -> the live base rate, shrunk toward 0.5 (Wayback factor)

Circularity: the judge was shown these signals and the fused score includes them (0.3 * p_h),
so live verdicts are not independent of the signals being measured.

Usage: python eval/dead_site_rule_report.py runs/<id> [--keep a,b,c]
"""

import argparse
import csv
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from scamhunter.classify.domain import domain_signals, load_brands  # noqa: E402
from scamhunter.classify.scorer import (  # noqa: E402
    HARD_RULES,
    NOTHING_P,
    SIGNALS_ONLY_BAND,
    WAYBACK_SHRINK,
    score_without_content,
)
from scamhunter.classify.signals import triage_signals  # noqa: E402
from scamhunter.models import EvidenceSource, SiteResult, Verdict  # noqa: E402

THRESHOLD = 0.45
MIN_SITES = 5  # fewer live occurrences than this: too rare to judge
NO_CONTENT = (EvidenceSource.SIGNALS_ONLY, EvidenceSource.NONE)


def family(name: str) -> str:
    """`cheap_tld:.top` -> `cheap_tld`; brand signals keep one row per signal kind."""
    return name.split(":")[0]


def load_results(run_dir: Path) -> list[SiteResult]:
    """The run's latest analysis: rescore.jsonl if present, else the checkpoint (last line wins)."""
    path = run_dir / "rescore.jsonl"
    if not path.exists():
        path = run_dir / "checkpoint.jsonl"
    by_id: dict[str, SiteResult] = {}
    for line in path.read_text().splitlines():
        r = SiteResult.model_validate_json(line)
        by_id[r.site.site_id] = r
    return sorted(by_id.values(), key=lambda r: r.site.site_id)


def no_content_signals(r: SiteResult, brands) -> list:
    """The signals a site would carry with no page content (domain + probe), recomputed."""
    return domain_signals(r.site.host, r.site.registrable_domain, brands) + triage_signals(r.triage)


def load_human_labels(path: Path) -> dict[str, str]:
    with path.open() as f:
        return {row["site_id"]: row["label"] for row in csv.DictReader(f)}


def load_verdict_labels(path: Path, url_to_id: dict[str, str]) -> dict[str, str]:
    with path.open() as f:
        return {
            url_to_id[row["url"]]: row["verdict"]
            for row in csv.DictReader(f)
            if row["url"] in url_to_id
        }


def lean(signals, kept: set[str]) -> float | None:
    """Policy A/B scoring for one site: band probability if any kept signal fired, else None."""
    used = [s for s in signals if family(s.name) in kept and s.weight > 0]
    if not used:
        return None
    return min(SIGNALS_ONLY_BAND[0] + 0.05 * sum(s.weight for s in used), SIGNALS_ONLY_BAND[1])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--keep", help="comma-separated signal families for policies A and B")
    args = parser.parse_args()

    results = load_results(args.run_dir)
    brands = load_brands()
    url_to_id = {r.site.url: r.site.site_id for r in results}
    human = load_human_labels(ROOT / "eval" / "human_labels.csv")
    verdict_labels = load_verdict_labels(ROOT / "eval" / "labels.csv", url_to_id)

    live = [r for r in results if r.classification.evidence_source == EvidenceSource.LIVE]
    dead = [r for r in results if r.classification.evidence_source in NO_CONTENT]

    # ---- base rates
    final_scam = sum(r.classification.verdict == Verdict.SCAM for r in live)
    judged = [r for r in live if r.classification.judgment is not None]
    judge_scam = sum(r.classification.judgment.verdict == Verdict.SCAM for r in judged)
    judge_p = sum(r.classification.judgment.probability_scam >= THRESHOLD for r in judged)
    print(
        f"Run {args.run_dir.name}: {len(results)} records, {len(live)} live-content, "
        f"{len(dead)} no-content (signals_only + none)\n"
    )
    print("Base rate among live-content sites")
    for what, k, n in (
        ("final verdict scam", final_scam, len(live)),
        ("judge's own verdict scam", judge_scam, len(judged)),
        (f"judge probability >= {THRESHOLD}", judge_p, len(judged)),
    ):
        print(f"  {what + ':':<30}{k}/{n} = {k / n:.1%}")
    print()

    # ---- per-signal table on live sites (by final verdict)
    rows: dict[str, Counter] = {}
    sites_by_family: dict[str, list[str]] = {}
    for r in live:
        verdict = r.classification.verdict
        for fam in sorted({family(s.name) for s in no_content_signals(r, brands)}):
            rows.setdefault(fam, Counter())[verdict] += 1
            sites_by_family.setdefault(fam, []).append(r.site.site_id)
    dead_counts = Counter(
        fam for r in dead for fam in {family(s.name) for s in no_content_signals(r, brands)}
    )
    n_scam, n_legit = final_scam, len(live) - final_scam
    print(
        f"Signals that can fire without content, on live sites ({n_scam} scam / {n_legit} not_scam)"
    )
    print(
        f"{'signal':<34}{'scam':>5}{'not':>5}{'n':>4}{'ratio':>7}{'P(s|scam)':>11}{'P(s|not)':>10}"
        f"{'LR*':>6}{'dead n':>8}  note"
    )
    all_fams = sorted(
        set(rows) | set(dead_counts), key=lambda f: -sum(rows.get(f, Counter()).values())
    )
    for fam in all_fams:
        c = rows.get(fam, Counter())
        s, ns = c[Verdict.SCAM], c[Verdict.NOT_SCAM]
        n = s + ns
        ratio = f"{s}:{ns}"
        lr = ((s + 0.5) / (n_scam + 1)) / ((ns + 0.5) / (n_legit + 1))
        note = "too rare to judge" if n < MIN_SITES else ""
        if fam in HARD_RULES:
            note = (note + "; " if note else "") + "hard rule"
        print(
            f"{fam:<34}{s:>5}{ns:>5}{n:>4}{ratio:>7}{s / n_scam:>11.0%}{ns / n_legit:>10.0%}"
            f"{lr:>6.1f}{dead_counts[fam]:>8}  {note}"
        )
    print("  *LR = P(signal | scam) / P(signal | not_scam), each with +0.5 smoothing\n")

    # ---- cross-check against hand labels
    print("Cross-check on live sites with hand labels")
    print("  eval/human_labels.csv (user's contact-sheet groups) and eval/labels.csv (25 verdicts)")
    for fam in all_fams:
        ids = sites_by_family.get(fam, [])
        h = Counter(human[i] for i in ids if i in human)
        v = Counter(verdict_labels[i] for i in ids if i in verdict_labels)
        if h or v:
            hs = ", ".join(f"{k} {n}" for k, n in sorted(h.items())) or "-"
            vs = ", ".join(f"{k} {n}" for k, n in sorted(v.items())) or "-"
            print(f"  {fam:<32} human: {hs:<40} labels.csv: {vs}")
    disagree = [
        (r.site.site_id, verdict_labels[r.site.site_id], r.classification.verdict.value)
        for r in live
        if r.site.site_id in verdict_labels
        and verdict_labels[r.site.site_id] != r.classification.verdict.value
    ]
    print(f"  live verdicts vs labels.csv disagreements: {disagree or 'none'}\n")

    # ---- three rules on the no-content records
    if not args.keep:
        print("Pass --keep to compare the policies.")
        return 0
    kept = set(args.keep.split(","))
    base = final_scam / len(live)
    p_b = 0.5 + WAYBACK_SHRINK * (base - 0.5)
    print(f"Kept for policies A and B: {', '.join(sorted(kept))}")
    print(
        f"Policy B no-signal probability: 0.5 + {WAYBACK_SHRINK} x ({base:.3f} - 0.5) = {p_b:.3f}\n"
    )
    rule_counts = {"current": Counter(), "A": Counter(), "B": Counter()}
    flips: dict[str, list[str]] = {"A": [], "B": []}
    for r in dead:
        signals = no_content_signals(r, brands)
        current = score_without_content(signals, THRESHOLD, "")
        assert current.verdict == r.classification.verdict, r.site.site_id  # code == record
        hard = any(s.name in HARD_RULES for s in signals)
        p_lean = lean(signals, kept)
        p_a = HARD_RULES["cloudflare_phishing_interstitial"][0] if hard else (p_lean or NOTHING_P)
        p_bb = p_a if hard or p_lean is not None else p_b
        verdicts = {
            "current": current.verdict.value,
            "A": "scam" if p_a >= THRESHOLD else "not_scam",
            "B": "scam" if p_bb >= THRESHOLD else "not_scam",
        }
        for rule, v in verdicts.items():
            rule_counts[rule][v] += 1
        names = ",".join(sorted({family(s.name) for s in signals if s.weight > 0})) or "-"
        for rule in ("A", "B"):
            if verdicts[rule] != verdicts["current"]:
                flips[rule].append(
                    f"{r.site.site_id} {verdicts['current']}->{verdicts[rule]} "
                    f"[{r.triage.status.value}] {r.site.registrable_domain} ({names})"
                )
    print(f"No-content verdicts ({len(dead)} records)")
    print(f"{'rule':<10}{'scam':>6}{'not_scam':>10}")
    for rule, c in rule_counts.items():
        print(f"{rule:<10}{c['scam']:>6}{c['not_scam']:>10}")
    for rule in ("A", "B"):
        print(f"\nFlips vs current under {rule} ({len(flips[rule])}):")
        for line in flips[rule]:
            print(f"  {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
