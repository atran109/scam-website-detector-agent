"""Seeded sampling of candidates into the dataset's URL file (DESIGN §8.2 step 2).

    python -m eval.dataset_v1.sample                 # append the next batch
    python -m eval.dataset_v1.sample --capture-ids   # print the --only list for `capture`

Sites are checked for liveness in batches, because most listed scam sites are already dead and
nobody knows in advance how many must be checked to find enough live ones. Each run of this
tool reads the liveness results so far, works out which sources still need live sites, and
appends the next batch to `data/dataset/v1/urls.txt`. Lines are only ever appended, so a site's
id (its line number) never changes."""

import argparse
import json
import random
from collections import Counter, defaultdict
from pathlib import Path

from eval.dataset_v1.models import Candidate, ManifestRow, Source

REPO_ROOT = Path(__file__).resolve().parents[2]
CANDIDATES_PATH = REPO_ROOT / "data" / "dataset" / "candidates.jsonl"
URLS_PATH = REPO_ROOT / "data" / "dataset" / "v1" / "urls.txt"
MANIFEST_PATH = REPO_ROOT / "data" / "dataset" / "v1" / "manifest.jsonl"
TRIAGE_PATH = REPO_ROOT / "runs" / "dataset-v1" / "triage.jsonl"

SEED = 20261114
MAX_CHECKS = 4_000  # liveness checks in total (DESIGN §8.6)
MAX_CAPTURES = 500  # captured sites in total (DESIGN §8.6)
TAKE_ALL = 10_000  # a quota no source reaches: every live site is kept

# Live sites wanted per source (DESIGN §8.1).
QUOTAS: dict[Source, int] = {
    "dfpi": TAKE_ALL,
    "scamsniffer": 200,
    "metamask_block": 50,
    "tranco": 50,
    "coingecko": 60,
    "metamask_allow": 30,
    "dfpi_lookalike": 10,
}
# How many candidates to check per live site still wanted. Listed scam sites are mostly dead;
# legitimate ones mostly answer. A guess that only sets batch sizes: quotas decide the result.
CHECKS_PER_LIVE_SITE: dict[Source, int] = {
    "dfpi": 1,
    "scamsniffer": 4,
    "metamask_block": 4,
    "tranco": 2,
    "coingecko": 2,
    "metamask_allow": 2,
    "dfpi_lookalike": 2,
}
# When two lists of the same kind name one domain, the earlier source here keeps it.
PRIORITY: list[Source] = [
    "dfpi",
    "scamsniffer",
    "metamask_block",
    "coingecko",
    "metamask_allow",
    "dfpi_lookalike",
    "tranco",
]
TRANCO_TOP = 1_000  # half of the Tranco sample comes from ranks 1..TRANCO_TOP


def remove_conflicts(cands: list[Candidate]) -> tuple[list[Candidate], list[str]]:
    """One candidate per registrable domain. A domain on both a scam list and a legitimate
    list is dropped from both and returned in the second value, so it is never sampled."""
    by_domain: dict[str, list[Candidate]] = defaultdict(list)
    for cand in cands:
        by_domain[cand.registrable_domain].append(cand)
    kept: list[Candidate] = []
    dropped: list[str] = []
    for domain, group in by_domain.items():
        if len({c.expected for c in group}) > 1:
            dropped.append(domain)
            continue
        kept.append(min(group, key=lambda c: PRIORITY.index(c.source)))
    return kept, dropped


def _interleave(groups: list[list[Candidate]]) -> list[Candidate]:
    """Round-robin: the first of each group, then the second of each, and so on."""
    out: list[Candidate] = []
    for i in range(max((len(g) for g in groups), default=0)):
        out.extend(g[i] for g in groups if i < len(g))
    return out


def _ordered(source: Source, cands: list[Candidate]) -> list[Candidate]:
    """The fixed order in which a source's candidates are drawn. Same input, same order."""
    rng = random.Random(f"{SEED}:{source}")
    pool = sorted(cands, key=lambda c: c.url)
    if source == "scamsniffer":  # equal numbers per day, newest day first
        by_day: dict[str, list[Candidate]] = defaultdict(list)
        for cand in pool:
            by_day[str(cand.listed_on)].append(cand)
        days = sorted(by_day, reverse=True)
        for day in days:
            rng.shuffle(by_day[day])
        return _interleave([by_day[day] for day in days])
    if source == "tranco":  # half well-known sites, half from further down the list
        top = [c for c in pool if _rank(c) <= TRANCO_TOP]
        rest = [c for c in pool if _rank(c) > TRANCO_TOP]
        rng.shuffle(top)
        rng.shuffle(rest)
        return _interleave([top, rest])
    rng.shuffle(pool)
    return pool


def _rank(cand: Candidate) -> int:
    parts = cand.source_note.split()
    return int(parts[1]) if len(parts) == 2 and parts[1].isdigit() else 10**9


def next_batch(
    cands: list[Candidate],
    manifest: list[ManifestRow],
    live_by_source: dict[Source, int],
    batch_size: int = 500,
) -> list[Candidate]:
    """The candidates to check next: none from a source whose quota of live sites is met, none
    already in the manifest, and never more than MAX_CHECKS manifest rows in total."""
    capacity = min(batch_size, MAX_CHECKS - len(manifest))
    if capacity <= 0:
        return []
    kept, _ = remove_conflicts(cands)
    taken = {row.registrable_domain for row in manifest}
    available: dict[Source, list[Candidate]] = {}
    for source in PRIORITY:
        mine = [c for c in kept if c.source == source and c.registrable_domain not in taken]
        available[source] = _ordered(source, mine)

    wants: dict[Source, int] = {}
    for source in PRIORITY:
        need = QUOTAS[source] - live_by_source.get(source, 0)
        wanted = max(need, 0) * CHECKS_PER_LIVE_SITE[source]
        wants[source] = min(wanted, len(available[source]))

    # DFPI first (it is the core source), then the rest share what is left in proportion.
    take: dict[Source, int] = {"dfpi": min(wants["dfpi"], capacity)}
    left = capacity - take["dfpi"]
    others = [s for s in PRIORITY if s != "dfpi"]
    total = sum(wants[s] for s in others)
    for source in others:
        take[source] = wants[source] if total <= left else wants[source] * left // total
    spare = left - sum(take[s] for s in others)
    for source in sorted(others, key=lambda s: -wants[s]):  # hand out rounding leftovers
        extra = min(spare, wants[source] - take[source])
        take[source] += extra
        spare -= extra

    return [cand for source in PRIORITY for cand in available[source][: take[source]]]


def load_manifest(path: Path) -> list[ManifestRow]:
    if not path.exists():
        return []
    return [ManifestRow.model_validate_json(line) for line in path.read_text().splitlines() if line]


def append_batch(urls_path: Path, manifest_path: Path, batch: list[Candidate]) -> list[ManifestRow]:
    """Append a batch to the URL file and the manifest. Existing lines are never touched."""
    if not batch:
        return []
    existing = load_manifest(manifest_path)
    number = max((row.batch for row in existing), default=0) + 1
    rows = [
        ManifestRow(**cand.model_dump(), site_id=f"{len(existing) + i:04d}", batch=number)
        for i, cand in enumerate(batch, start=1)
    ]
    urls_path.parent.mkdir(parents=True, exist_ok=True)
    with urls_path.open("a") as urls, manifest_path.open("a") as manifest:
        for row in rows:
            urls.write(row.url + "\n")
            manifest.write(row.model_dump_json() + "\n")
    return rows


def _live_ids(triage_path: Path) -> set[str]:
    if not triage_path.exists():
        return set()
    live: set[str] = set()
    for line in triage_path.read_text().splitlines():
        if line.strip():
            record = json.loads(line)
            if record["triage"]["status"] == "live":
                live.add(record["site"]["site_id"])
    return live


def live_counts(manifest: list[ManifestRow], triage_path: Path) -> dict[Source, int]:
    """Live sites so far per source, from a run's triage.jsonl."""
    live = _live_ids(triage_path)
    return dict(Counter(row.source for row in manifest if row.site_id in live))


def capture_ids(manifest: list[ManifestRow], triage_path: Path) -> list[str]:
    """The site ids to capture: live sites in manifest order, up to each source's quota and
    MAX_CAPTURES in total."""
    live = _live_ids(triage_path)
    counts: Counter[str] = Counter()
    ids: list[str] = []
    for row in manifest:
        if row.site_id not in live or counts[row.source] >= QUOTAS[row.source]:
            continue
        if len(ids) >= MAX_CAPTURES:
            break
        counts[row.source] += 1
        ids.append(row.site_id)
    return ids


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--batch-size", type=int, default=500)
    parser.add_argument("--capture-ids", action="store_true", help="print the --only list")
    args = parser.parse_args(argv)

    manifest = load_manifest(MANIFEST_PATH)
    if args.capture_ids:
        print(",".join(str(int(site_id)) for site_id in capture_ids(manifest, TRIAGE_PATH)))
        return 0
    lines = CANDIDATES_PATH.read_text().splitlines()
    cands = [Candidate.model_validate_json(line) for line in lines if line]
    _, dropped = remove_conflicts(cands)
    live = live_counts(manifest, TRIAGE_PATH)
    rows = append_batch(
        URLS_PATH, MANIFEST_PATH, next_batch(cands, manifest, live, args.batch_size)
    )

    added = Counter(row.source for row in rows)
    checked = Counter(row.source for row in manifest)
    print(f"{'source':<16}{'checked':>8}{'live':>6}{'quota':>7}{'added':>7}")
    for source in PRIORITY:
        quota = "all" if QUOTAS[source] == TAKE_ALL else str(QUOTAS[source])
        print(
            f"{source:<16}{checked[source]:>8}{live.get(source, 0):>6}{quota:>7}{added[source]:>7}"
        )
    print(f"\n{len(dropped)} domains on both a scam list and a legitimate list were left out.")
    print(f"{len(manifest) + len(rows)} of {MAX_CHECKS} liveness checks used.")
    if not rows:
        print("Nothing added: every quota is met, or the check cap is reached.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
