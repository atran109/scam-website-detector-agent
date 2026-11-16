# Stage A1 Evaluation Dataset: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a labelled, split set of about 450 captured sites (DESIGN §8) and the tools that
produce it, so Stage A2 can report held-out classifier numbers.

**Architecture:** Dataset tooling lives in `eval/dataset_v1/` and `scripts/`, outside the
pipeline. It feeds the existing `triage`, `capture` and `classify` commands through a new
`--urls` option. One new CLI command (`label`) calls a new gateway role. Tasks 1 to 9 are code
with unit tests and touch no network; Task 10 is the operator runbook that downloads lists,
visits sites and spends money, and each of its steps needs the user's go-ahead.

**Tech Stack:** Python 3.12, Pydantic v2, httpx, pytest, the existing Docker Compose stack.

**Spec:** `docs/DESIGN.md` §8 (approved 2026-11-14), `docs/ROADMAP.md` Stage A1, `CLAUDE.md`.

## Global Constraints

- Never visit a real target site outside the Docker container, and never before `make selftest`
  passes. Tasks 1 to 9 make no network calls at all; their tests use fixtures.
- Never add `--no-sandbox`, `--disable-web-security`, or enable downloads.
- Page content and feed content are untrusted data. Model prompts wrap them with
  `scamhunter.llm.sanitize.untrusted`.
- Keys only in `.env`; never logged, never in fixtures.
- Dataset capture is landing page only: no agent, no form submissions (§8.2).
- Caps (§8.6): 4,000 liveness checks, 500 captured sites, 40 agent runs, $80 LLM spend in
  total, split as classify $25, labeller $40, agent $15.
- Providers' raw lists are never committed (`data/dataset/sources/` is gitignored and
  dockerignored).
- Every random choice uses `random.Random(20261114)`; rerunning a tool gives the same output.
- Type hints everywhere; line length 100; `make check` before every commit; one LOG.md entry
  per task that makes a decision. Work on a branch `stage-a1-dataset`, PR at the end.

## Changes to DESIGN §8 that this plan needs (approve with the plan)

§8.2 says `--urls` is the only pipeline change. Reading the code showed three more are needed:

1. **A `labeller` gateway role.** The gateway picks the model by role and accepts only
   `judge`, `helper` and `navigator`. The labeller needs a stronger model than the judge, so
   the gateway gains a fourth role and settings gain `labeller_model`. This widens the LLM
   gateway's whitelist (DESIGN §5.6) by one role with the same request rules.
2. **Four-digit site ids for `--urls` files.** Ids are three digits today; a 4,000-line file
   would overflow them. Files passed with `--urls` get four-digit ids; `data/urls.txt` keeps
   three.
3. **`--spend-cap` on `classify`.** Only `run` and the mock commands have one today.

Task 1 writes these into §8.2 and LOG.md before any code.

## Review Focus

1. **Feed entries that are not plain domains** (wildcards `*.x.com`, full URLs with paths, IP
   addresses, punycode, upper case, blank lines): parsers normalise or skip them and count what
   they skipped; they never raise on one bad line. Test in Task 3.
2. **The same domain in a scam list and a legitimate list** (MetaMask allowlist against
   ScamSniffer): dropped from both and reported, never sampled. Test in Task 4.
3. **Rerunning the sampler after more batches**: existing lines of `urls.txt` and their ids
   never change; new batches only append. Test in Task 4.
4. **A labeller reply that is malformed or steered by page text** (unknown verdict, extra
   keys, empty): recorded as `error`, never as a label, and the site is queued for human
   review. Test in Task 7.
5. **Blank or error pages sharing one DOM hash**: excluded and non-live sites get no
   structure-hash link, so they cannot fuse unrelated sites into one giant cluster. Test in
   Task 8.

---

## File structure

| File | Responsibility |
|---|---|
| `src/scamhunter/pipeline.py`, `cli.py` | `--urls`, id width, `classify --spend-cap`, `label` command |
| `src/scamhunter/llm/gateway.py`, `config.py`, `config/settings.yaml` | `labeller` role and model |
| `src/scamhunter/labeller.py` | Build the labeller request, parse the reply |
| `eval/dataset_v1/models.py` | `Candidate`, `ManifestRow`, `LabelRow` |
| `eval/dataset_v1/sources.py` | One pure parser per provider format |
| `scripts/fetch_sources.py` | Host-side download of the providers' lists |
| `eval/dataset_v1/sample.py` | Seeded sampling, `urls.txt` and `manifest.jsonl`, quota tracking |
| `eval/dataset_v1/cluster.py`, `split.py` | Clusters and the dev/test split |
| `eval/dataset_v1/labels.py` | Assemble `labels.csv`, review queue, agreement report |
| `eval/dataset_v1/funnel.py` | Pick agent sites, tally the funnel |
| `eval/evaluate.py` | `--split` and `--reviewed-only` filters |
| `tests/test_dataset_*.py`, `tests/fixtures/dataset/` | Unit tests and small hand-made fixtures |

Data paths: `data/dataset/sources/` (raw, ignored), `data/dataset/candidates.jsonl` (ignored),
`data/dataset/v1/urls.txt`, `manifest.jsonl` and `split.jsonl` (committed), `runs/dataset-v1/` (ignored),
`eval/dataset_v1/labels.csv` (committed).

---

### Task 1: Record the design changes

**Files:** Modify `docs/DESIGN.md` §8.2 and §5.6 (gateway roles list), `docs/LOG.md`,
`.gitignore`, `.dockerignore`.

- [ ] **Step 1:** Replace §8.2's last paragraph with the three changes above; add `labeller`
  to the role list in §5.6.
- [ ] **Step 2:** Add `data/dataset/sources/` and `data/dataset/candidates.jsonl` to
  `.gitignore`; add `data/dataset/sources` to `.dockerignore`.
- [ ] **Step 3:** Append a LOG entry (`DECISION [arch]`), naming the 23:47 entry it amends.
- [ ] **Step 4:** `make check`; commit `Design: gateway labeller role, 4-digit ids, classify cap`.

### Task 2: `--urls` and site id width

**Files:** Modify `src/scamhunter/pipeline.py:86`, `src/scamhunter/cli.py`, `Makefile`
(`classify` and `rescore` gain `$(ARGS)`); Test `tests/test_pipeline.py`, new `tests/test_cli_urls.py`.

**Interfaces — Produces:**
- `load_sites(path: Path, id_width: int = 3) -> list[Site]`
- CLI option `--urls PATH` on `triage`, `capture`, `classify`, `rescore`, `run`. Given: sites
  load from `PATH` with `id_width=4`. Absent: `data/urls.txt`, width 3 (unchanged).
- `--only 12,27` pads to the width of the loaded ids.

- [ ] **Step 1: Failing tests**

```python
def test_load_sites_width_four(tmp_path):
    f = tmp_path / "u.txt"; f.write_text("https://a.example\nhttps://b.example\n")
    assert [s.site_id for s in load_sites(f, id_width=4)] == ["0001", "0002"]

def test_load_sites_default_width_unchanged(tmp_path):
    f = tmp_path / "u.txt"; f.write_text("https://a.example\n")
    assert load_sites(f)[0].site_id == "001"

def test_only_pads_to_loaded_width():
    sites = [Site(site_id="0012", url="https://a.example", host="a.example",
                  registrable_domain="a.example")]
    assert _select(sites, "12") == sites

def test_urls_option_missing_file_is_an_error(tmp_path):
    with pytest.raises(SystemExit):
        main(["triage", "--urls", str(tmp_path / "nope.txt")])
```

- [ ] **Step 2:** Run `pytest tests/test_cli_urls.py tests/test_pipeline.py -q`; expect failures.
- [ ] **Step 3:** Implement. `_selected(args)` chooses the path and width; the "matches no
  site" message names the file actually used.
- [ ] **Step 4:** `make check` passes (all 656 existing tests still pass: the default path is unchanged).
- [ ] **Step 5:** Commit `CLI: --urls with four-digit site ids`.

### Task 3: Candidate model and source parsers

**Files:** Create `eval/dataset_v1/__init__.py`, `models.py`, `sources.py`,
`tests/test_dataset_sources.py`, `tests/fixtures/dataset/` (hand-written miniature files using
`.example` and `.test` names only; no real scam domains in fixtures).

**Interfaces — Produces:**

```python
Source = Literal["dfpi", "scamsniffer", "metamask_block", "tranco",
                 "coingecko", "metamask_allow", "dfpi_lookalike"]
class Candidate(BaseModel):
    url: str                    # "https://<host>/" unless the source gave a full URL
    registrable_domain: str
    source: Source
    expected: Literal["scam", "not_scam"]
    listed_on: date | None = None
    source_note: str = ""       # DFPI: scam type; addresses found in the narrative
class ParseResult(BaseModel):
    candidates: list[Candidate]
    skipped: dict[str, int]     # reason -> count

def normalise_host(raw: str) -> str | None   # lower-case, strip scheme/path/port/"*.", IDNA; None if IP or invalid
def parse_scamsniffer_day(text: str, listed_on: date) -> ParseResult
def parse_metamask_config(text: str) -> tuple[ParseResult, ParseResult]   # (blocklist, allowlist)
def parse_dfpi(html: str) -> tuple[ParseResult, ParseResult]              # (scam sites, look-alikes)
def parse_tranco(csv_text: str, top: int = 100_000) -> ParseResult
def parse_coingecko_exchanges(json_text: str) -> ParseResult
```

- [ ] **Step 0: Confirm real formats before writing fixtures.** With the user's go-ahead,
  fetch one ScamSniffer daily file, MetaMask's `src/config.json`, the DFPI page, the first 20
  lines of Tranco and one CoinGecko `/exchanges` page (provider sites only). Note each format
  in LOG.md and shape the fixtures to match. If CoinGecko's exchange list needs an API key or
  lacks site URLs, record it and stop for a decision; the fallback is the exchange detail
  endpoint within the free plan's 10,000 calls a month.
- [ ] **Step 1: Failing tests**, one per parser plus:

```python
@pytest.mark.parametrize("raw,want", [
    ("Example.TEST", "example.test"), ("*.example.test", "example.test"),
    ("https://example.test/path?q=1", "example.test"), ("example.test:8443", "example.test"),
    ("192.0.2.7", None), ("", None), ("not a host", None),
])
def test_normalise_host(raw, want):
    assert normalise_host(raw) == want

def test_bad_lines_are_counted_not_raised():
    r = parse_scamsniffer_day('["good.example", "192.0.2.7", "", 5]', date(2026, 11, 1))
    assert [c.registrable_domain for c in r.candidates] == ["good.example"]
    assert sum(r.skipped.values()) == 3

def test_dfpi_extracts_sites_addresses_and_lookalikes():
    scams, legit = parse_dfpi(FIXTURE_DFPI)   # 2 rows; row 1 has 2 sites, an 0x address, a look-alike
    assert len(scams.candidates) == 3
    assert "0x" in scams.candidates[0].source_note
    assert [c.source for c in legit.candidates] == ["dfpi_lookalike"]
```

- [ ] **Step 2:** Run; expect failures. **Step 3:** Implement with the stdlib (`json`, `csv`,
  `html.parser`) and `tldextract`; no new dependency. **Step 4:** `make check`. **Step 5:** Commit.

### Task 4: Fetcher and sampler

**Files:** Create `scripts/fetch_sources.py`, `eval/dataset_v1/sample.py`,
`tests/test_dataset_sample.py`.

**Interfaces — Consumes:** Task 3 parsers. **Produces:**

```python
# scripts/fetch_sources.py  (host; run only by the operator)
ALLOWED_HOSTS = {"raw.githubusercontent.com", "dfpi.ca.gov", "tranco-list.eu", "api.coingecko.com"}
MAX_BYTES = 60_000_000
def main(argv) -> int   # --days 60; writes data/dataset/sources/* and data/dataset/candidates.jsonl

# eval/dataset_v1/sample.py
QUOTAS: dict[Source, int] = {"dfpi": 10_000, "scamsniffer": 200, "metamask_block": 50,
                             "tranco": 50, "coingecko": 60, "metamask_allow": 30, "dfpi_lookalike": 10}
MAX_CHECKS = 4_000
class ManifestRow(Candidate):
    site_id: str   # four digits, equals the line number in urls.txt
    batch: int
def remove_conflicts(cands: list[Candidate]) -> tuple[list[Candidate], list[str]]
def next_batch(cands, manifest: list[ManifestRow], live_by_source: dict[Source, int],
               batch_size: int = 500) -> list[Candidate]
def append_batch(urls_path: Path, manifest_path: Path, batch: list[Candidate]) -> list[ManifestRow]
def live_counts(manifest: list[ManifestRow], triage_path: Path) -> dict[Source, int]
```

Rules the tests pin: `dfpi` takes every candidate (the 10,000 quota is "all"); ScamSniffer
draws an equal number per day, newest days first; a source whose live count has met its quota
contributes nothing to the next batch; `next_batch` returns `[]` once `MAX_CHECKS` manifest
rows exist; a registrable domain appears at most once in the manifest; the fetcher refuses any
URL whose host is not in `ALLOWED_HOSTS`, refuses redirects to other hosts and stops at
`MAX_BYTES`.

- [ ] **Step 1: Failing tests**

```python
def test_conflicting_domain_dropped_from_both_sides():
    kept, dropped = remove_conflicts([cand("x.example", "scamsniffer"), cand("x.example", "metamask_allow"),
                                      cand("y.example", "tranco")])
    assert [c.registrable_domain for c in kept] == ["y.example"] and dropped == ["x.example"]

def test_append_never_renumbers(tmp_path):
    first = append_batch(u, m, [cand("a.example", "tranco")])
    second = append_batch(u, m, [cand("b.example", "tranco")])
    assert (first[0].site_id, second[0].site_id) == ("0001", "0002")
    assert u.read_text().splitlines()[0] == "https://a.example/"

def test_met_quota_stops_sampling():
    batch = next_batch(cands, manifest=[], live_by_source={"tranco": 50})
    assert all(c.source != "tranco" for c in batch)

def test_cap_of_4000_checks():
    assert next_batch(cands, manifest=rows(4000), live_by_source={}) == []

def test_same_seed_same_batch():
    assert next_batch(cands, [], {}) == next_batch(cands, [], {})

def test_fetcher_refuses_other_hosts():
    with pytest.raises(ValueError):
        check_url("https://evil.example/list.json")
```

- [ ] **Steps 2–5:** fail, implement, `make check`, commit. The fetcher's network path is not
  unit-tested; its URL check, size cap and parsers are.

### Task 5: `classify --spend-cap`

**Files:** Modify `src/scamhunter/cli.py`, `src/scamhunter/pipeline.py:1127`
(`classify_from_evidence`); Test `tests/test_pipeline.py`.

**Interfaces — Produces:** `classify_from_evidence(settings, sites, run_dir, spend_cap_usd: float | None = None)`.
Before each site, if the summed `TokenUsage.cost_usd` of finished sites is at or over the cap,
stop, checkpoint what is done and print how many sites remain. Rerunning continues from the
checkpoint (cache hits are free).

- [ ] **Step 1: Failing test:** a fake judge costing $1 a site, cap $2.50, five sites → three
  results, a "2 sites not classified: spend cap" message, exit code 0.
- [ ] **Steps 2–5:** fail, implement, `make check`, commit.

### Task 6: Gateway `labeller` role

**Files:** Modify `src/scamhunter/llm/gateway.py:54`, `src/scamhunter/llm/client.py` (`Role`,
`PRICES_PER_MTOK`), `src/scamhunter/config.py`, `config/settings.yaml`; Test `tests/test_llm.py`.

**Interfaces — Produces:** role `"labeller"` accepted by `validate_request`; setting
`llm.labeller_model`; a price entry for that model.

- [ ] **Step 0:** Load the `claude-api` skill and confirm the current strongest model id and
  its per-token prices. Do not write either from memory. Record them in LOG.md.
- [ ] **Step 1: Failing tests:** `validate_request` accepts `role="labeller"`; still rejects
  `role="admin"`, server tools and unknown `output_config` keys for it; the gateway maps the
  role to `labeller_model`.
- [ ] **Steps 2–5:** fail, implement, `make check`, commit.

### Task 7: The labeller

**Files:** Create `src/scamhunter/labeller.py`; Modify `src/scamhunter/cli.py` (`label`
command), `Makefile` (`label` target, same shape as `classify`); Test `tests/test_labeller.py`.

**Interfaces — Consumes:** Task 6 role; `ManifestRow` (read as plain JSON; `src/` does not
import `eval/`). **Produces:**

```python
class LabellerVerdict(BaseModel):
    site_id: str
    verdict: Literal["scam", "not_scam", "excluded", "error"]
    reason: str
    cost_usd: float
def build_request(site_dir: Path, source: str, expected: str, source_note: str) -> dict
def parse_reply(site_id: str, text: str, cost_usd: float) -> LabellerVerdict
async def label_run(client, run_dir: Path, manifest: list[dict], out: Path, spend_cap_usd: float) -> list[LabellerVerdict]
# CLI: scamhunter label --run-id dataset-v1 --manifest data/dataset/v1/manifest.jsonl --spend-cap 40
# writes runs/<id>/labeller.jsonl, appending; sites already in the file are skipped
```

The request holds the landing screenshot (image block), the first 6,000 characters of
`text.txt` and the source's note, each wrapped with `untrusted(...)`, and asks for JSON output
with exactly `verdict` and `reason`. The system prompt states the scam definition from LOG
2026-10-03 and that `excluded` means "nothing here to judge".

- [ ] **Step 1: Failing tests**

```python
def test_page_text_is_wrapped_as_untrusted(site_dir):
    req = build_request(site_dir, "tranco", "not_scam", "")
    assert "ignore previous instructions" not in req["system"]          # only inside the untrusted block

@pytest.mark.parametrize("text", ['{"verdict":"definitely"}', "", "not json",
                                  '{"verdict":"scam","reason":"x","run":"rm"}'])
def test_bad_reply_is_error_not_label(text):
    assert parse_reply("0001", text, 0.0).verdict == "error"

def test_stops_at_spend_cap_and_resumes(fake_client, tmp_path): ...   # $1 a call, cap $2 → 2 lines; rerun adds none twice
def test_no_snapshot_means_excluded_without_a_call(fake_client, tmp_path): ...
```

- [ ] **Steps 2–5:** fail, implement, `make check`, commit.

### Task 8: Clusters and split

**Files:** Create `eval/dataset_v1/cluster.py`, `split.py`, `tests/test_dataset_split.py`.

**Interfaces — Produces:**

```python
def dom_skeleton_hash(html: str) -> str | None   # sha256 of the opening-tag sequence; None under 30 tags
def clusters(rows: list[ClusterInput]) -> dict[str, str]          # site_id -> cluster_id ("c0001"…)
class ClusterInput(BaseModel):
    site_id: str; registrable_domain: str; addresses: list[str]; dom_hash: str | None; judgeable: bool
def assign_split(rows: list[SplitInput], clusters: dict[str, str]) -> dict[str, Literal["dev", "test"]]
```

Rules from §8.5, as tests: links are same registrable domain, a shared address, or an equal
`dom_hash`; rows with `judgeable=False` or `dom_hash=None` take no hash link; dated scam
clusters sort by earliest `listed_on` and the newest fill test until it holds one third of
them; DFPI-only clusters and each legitimate source draw one third to test with the seeded
generator; MetaMask-only scam clusters are dev; a mixed cluster follows its dated members; no
cluster is ever split.

- [ ] **Step 1: Failing tests** for each rule above, plus:

```python
def test_blank_pages_do_not_fuse():
    rows = [ci("0001", "a.example", dom_hash="h", judgeable=False),
            ci("0002", "b.example", dom_hash="h", judgeable=False)]
    assert len(set(clusters(rows).values())) == 2

def test_no_cluster_straddles_the_split():
    split = assign_split(rows, cl)
    assert all(len({split[s] for s in members}) == 1 for members in by_cluster(cl).values())
```

- [ ] **Steps 2–5:** fail, implement (union-find), `make check`, commit.

### Task 9: Labels file, review queue, agreement, funnel, evaluate filters

**Files:** Create `eval/dataset_v1/labels.py`, `funnel.py`; Modify `eval/evaluate.py`; Test
`tests/test_dataset_labels.py`, `tests/test_evaluate.py`.

**Interfaces — Produces:**

```python
# labels.py
COLUMNS = ["url", "verdict", "scam_type", "expected_addresses", "label_basis", "notes", "labeled_by",
           "site_id", "source", "listed_on", "cluster_id", "split", "labeller_verdict", "reviewed_by"]
def build_labels(manifest, labeller, pipeline_results, clusters, split) -> list[dict]
def review_queue(rows: list[dict], pipeline_verdicts: dict[str, str]) -> list[str]   # site ids, test first
def agreement(rows: list[dict]) -> dict   # per split: reviewed, changed, rate
# funnel.py
def pick_agent_sites(rows, results, limit: int = 40) -> list[str]
def tally(results) -> dict[str, int]   # reached_registration, registered, logged_in, deposit_page, address, by stop reason
# evaluate.py: --split {dev,test}  --reviewed-only
```

Rules as tests: the queue holds every `split=test` row, every dev row where
`labeller_verdict` differs from the pipeline verdict or is `error`, and a seeded 20% of the
remaining dev rows; `verdict` starts equal to `labeller_verdict` and `reviewed_by` starts
`none`; `agreement` counts a row as changed when `reviewed_by != "none"` and `verdict !=
labeller_verdict`; `pick_agent_sites` takes only rows with `verdict=scam`, `reviewed_by=alex`
and an account or deposit trigger (`agent.site_run.should_navigate`'s account leg), `dfpi`
first, never more than 40; `evaluate.py --reviewed-only` drops `reviewed_by=none` rows and
`excluded` rows are skipped as today.

- [ ] **Steps 1–5:** failing tests for each rule, implement, `make check`, commit.
- [ ] **Step 6:** Open the PR for Tasks 1 to 9; CI green before Task 10.

### Task 10: Operator runbook (each step needs the user's go-ahead)

No code. Run from the merged branch; record every count and dollar figure in LOG.md.

- [ ] **1. Fetch:** `.venv/bin/python scripts/fetch_sources.py --days 60`. Record candidates
  per source and skip counts. Downloads files from the four provider hosts only.
- [ ] **2. First batch:** `python -m eval.dataset_v1.sample --batch 1`; commit `urls.txt` and
  `manifest.jsonl`.
- [ ] **3. Liveness:** `make triage RUN_ID=dataset-v1 ARGS="--urls data/dataset/v1/urls.txt
  --new-only"` (selftest runs first; `--new-only` keeps earlier batches' results and checks
  only the new sites). Record status counts per source. Repeat steps 2 and 3 with further
  batches until quotas are met or 4,000 checks are used. If DFPI yields fewer than 20 live
  sites, stop and ask the user (§8.1 expected 40 to 80).
- [ ] **4. Capture:** `make capture RUN_ID=dataset-v1 ARGS="--urls … --only <ids within quota>"`,
  at most 500 sites.
- [ ] **5. Classify:** `make classify RUN=dataset-v1 ARGS="--urls … --spend-cap 25"`. Check
  the cost after the first 10 sites before letting it finish.
- [ ] **6. Label:** `make label RUN=dataset-v1 ARGS="--spend-cap 40"`. (Before the split since
  2026-11-15: the split needs the labeller's `excluded` calls.)
- [ ] **7. Cluster and split:** `python -m eval.dataset_v1.split`; commit
  `data/dataset/v1/split.jsonl`; record cluster count, largest cluster, and scam/legitimate
  counts per split. If any cluster holds more than 15% of the sites, stop and inspect it before
  going on. The command refuses to run while sites lack a label or a classify result: rerun
  step 5 or 6 first.
- [ ] **8. Review (the user):** `python -m eval.dataset_v1.labels --build`, then `--queue`
  (commit `labels.csv` and `data/dataset/v1/review_queue.jsonl`); `make review
  RUN=dataset-v1`, then work through the review queue, editing `verdict` and setting `reviewed_by=alex` in `eval/dataset_v1/labels.csv`.
- [ ] **9. Agreement:** `python -m eval.dataset_v1.labels --agreement`; record the rates.
- [ ] **10. Agent funnel:** `make run RUN_ID=dataset-v1-agent ARGS="--urls … --only <≤40 ids>
  --triage-from dataset-v1 --force-navigation --spend-cap 15"`, then
  `python -m eval.dataset_v1.funnel`. Compare addresses with DFPI's where it listed one.
- [ ] **11. Close out:** commit `labels.csv`; update DESIGN §8 (actual counts, anything that
  differed), ROADMAP A1 checkboxes, README source and licence list; LOG entry; PR.

**Done means:** `eval/dataset_v1/labels.csv` is committed with every test-split row reviewed;
`python eval/evaluate.py runs/dataset-v1/output/results.json --labels eval/dataset_v1/labels.csv
--split test --reviewed-only` prints precision and recall; LOG.md holds the counts, the
agreement rates, the funnel and the total spend.

## Not in this plan

Stage A2 (model comparison, confidence intervals, CI gate), A3 (mock variants, red team) and
A4 (replay viewer, README pitch) each get their own plan.
