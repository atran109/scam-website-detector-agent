# Roadmap: Ferret

> Status: **shape approved 2026-11-14 (LOG); details open in §9.** Ferret is a standalone personal
> project. It stays in this repository with its history, data and docs. Each stage's decisions get
> LOG.md entries, and DESIGN.md gains a section for the service when Stage B starts.

## 1. Goal

Turn the existing batch pipeline into a measured, continuously running scam-intelligence service
that is worth showing for **software, AI engineer, forward-deployed and backend** roles.

**The one-sentence pitch:**
> Ferret sends a sandboxed LLM agent to register on crypto scam sites and extract their deposit
> addresses, follows shared wallets and templates to the operator's other domains, and measures
> how well every part works.

**What a recruiter should see in 30 seconds:** a live link, a GIF of the agent reaching a deposit
page, and three numbers (operators and domains tracked, classifier precision/recall on held-out
data, cost per site).

**What an interviewer can dig into:**

| Topic | Where it comes from |
|---|---|
| LLM evaluation: held-out data, leakage, confidence intervals, label quality | Stage A |
| Agent reliability and prompt-injection defence | Stage A agent and red-team suites |
| Queues, concurrency, data modelling, failure recovery | Stage B |
| Sandboxing hostile workloads in production | Stage B (plus the existing isolation) |
| Entity resolution: grouping domains into operators | Stage B |
| Cost/quality trade-offs, model distillation | Stage C triage model |

## 2. What does not change

The existing hard rules in `CLAUDE.md` carry over unchanged, on the laptop and on any server:

- Real sites are visited only inside the hardened container, behind the egress proxy, after
  `make selftest` passes. On a cloud VM the selftest also proves the metadata endpoint
  (169.254.169.254) is unreachable.
- The action whitelist and policy stay in code. Never pay, sign, withdraw, solve CAPTCHAs or guess
  invite codes.
- **No public "scan this URL" endpoint.** The public API and dashboard serve stored results only;
  the only things that queue a visit are discovery and the operator CLI.
- Budget caps on LLM spend and on visits per day, enforced in code.

## 3. Target architecture

```text
   known scam sites                seed lists              (Stage C, optional)
   (addresses, template    +    (public feeds,      +     certificate stream
    hashes, favicons)            labeled dataset)          with a name filter
          |                           |                           |
          +--------- sibling discovery / operator CLI ------------+
                                      |
                                      v
                 +--------------------------------------------------+
                 | Postgres                                          |
                 |  sites · jobs (queue) · captures · verdicts ·     |
                 |  addresses · sightings · operators · agent_steps ·|
                 |  eval_runs                                        |
                 +---------+------------------------------+----------+
                           | SKIP LOCKED                  |
                           v                              v
          +-----------------------------+      +--------------------+
          | worker (N, each sandboxed)  |      | FastAPI (read-only)|
          |  capture -> extract ->      |      +---------+----------+
          |  judge -> agent -> cluster  |                |
          +------+------------+---------+                v
                 |            |                 static dashboard:
         egress proxy    LLM gateway            operators, sites,
         (unchanged)     (unchanged)            agent replays, benchmark

   CI: GitHub Actions -> lint, unit tests, browser suite, benchmark on cached responses
```

The existing `scamhunter` package stays the core. The new pieces wrap it: a database layer
replaces JSONL checkpoints, a worker replaces the CLI loop, and sibling discovery adds to
`data/urls.txt`.

## 4. Stages

Three stages. Each ends with something worth showing on its own, so stopping after any stage
leaves a finished project. Estimates assume about 10 hours a week and are deliberately less
optimistic than the first draft.

### Stage A. Public, measured, demo-able (≈30–35 h, weeks 1–3)

The stage to finish before anything else: it is enough to put on a resume.

**A0. Public-ready (≈4 h)**
- [x] Name fixed to Ferret; MIT LICENSE added (2026-11-14, LOG).
- [x] GitHub Actions: `make check` on every push to main and every PR, with the browser suite
  as a second job. Both jobs passed on GitHub (2026-11-14, reported by the user).
- [x] Tracked files scanned for personal data, the home IP and secrets: nothing found. Commit
  author emails are part of the history and become visible when the repo is public.
- [x] Scam URLs stay as they are in the data files; defanged only where people read them
  (README examples, the dashboard).
- [ ] Flip the repository to public (the user's step, on GitHub).
- Work on branches with PRs from here on.

**A1. Labeled dataset (≈12 h)**
- Positives (sources chosen 2026-11-14, LOG): the California DFPI Crypto Scam Tracker (fake
  trading platforms and pig butchering, the type the agent targets; some entries list deposit
  addresses to check extraction against), ScamSniffer's `scam-database` (GPL-3.0; daily archive
  files give listing dates for the time split) and MetaMask's `eth-phishing-detect` blocklist.
  The two blocklists are mostly wallet-drainer phishing, so they test the classifier more than
  the agent. Most feed URLs are dead on arrival, so expect to capture well over 1,000 to keep
  about 300 live positives.
- Negatives: non-crypto sites from the Tranco top list, exchanges from CoinGecko's API, and
  MetaMask's allowlist plus the legitimate look-alikes DFPI names (hard negatives). At least
  30% negatives.
- The feeds are inputs only: the repository publishes our own verdicts and evidence, with the
  source of each URL recorded, not copies of the lists.
- Capture once through the existing sandbox, store the evidence, never revisit for evaluation.
- **AI-assisted labels, kept honest:**
  - The labeller is a separate pass with the strongest model and the full evidence (agent
    findings and screenshots included), so it sees more than the classifier it is scoring.
  - The user reviews every site where the labeller and the pipeline disagree, plus a random 20%
    of the agreements.
  - The user labels the whole held-out test set (about 150 sites) by hand.
  - The human-versus-labeller agreement rate is reported next to the results.
- Two splits: by **operator cluster** (sibling domains share templates, so a random split leaks)
  and by **time** (older sites for dev, newer for test). The test set is touched only for
  reported numbers.

**A2. Classifier benchmark (`make bench`, ≈6 h)**
- Compare rules only, model only and the 70/30 blend; Haiku vs Sonnet vs Opus; effort levels.
- Report precision, recall, F1, Brier score and a reliability chart, each with bootstrap
  confidence intervals, plus cost per site and p50/p95 latency. Markdown and JSON output,
  committed per benchmark run.
- Cached LLM responses make reruns free and deterministic. CI runs the benchmark on the cache
  and fails a PR that drops held-out recall or precision past a set margin.

**A3. Agent benchmark and red team (≈8 h)**
- The 13 mock-exchange variants become a scored suite: deposit page reached, addresses correct,
  correct `blocked_at` on gated variants, steps, seconds and dollars, several runs per variant
  to measure variance.
- New variants for the README's known gaps: an iframe-hosted deposit page, a canvas-rendered
  address, a non-English (e.g. Vietnamese) flow.
- **Real-site funnel** from the dataset captures: reached registration, registered, logged in,
  reached a deposit page, extracted an address, and the stop reason where it ended.
- **Failure-driven variants:** each distinct real-site failure becomes a new mock variant, so
  the suite grows from evidence.
- About 15 prompt-injection variants (hidden text, alt text and ARIA labels; fake "system"
  messages; lures to other domains; "type the API key"; "click Withdraw" or "I have paid").
  Attack success rate is measured with the code policy and with it disabled (mock mode only),
  to show what code enforcement buys over prompting alone.

**A4. Agent replay and README (≈4 h)**
- Replay viewer built on the existing review page: each step's screenshot with the action taken
  and the reason. A GIF of one mock run goes at the top of the README.
- README top rewritten as a pitch with the headline benchmark table.

**Done means:** the repo is public with green CI; one command reproduces the benchmark report;
the README opens with the GIF and held-out numbers.

### Stage B. Live service with operator tracking (≈35–40 h, weeks 4–7)

**B1. Data layer (≈8 h)**
- Postgres 17 via Docker Compose; SQLAlchemy 2.0 (async) and Alembic migrations, keeping the
  Pydantic models as the API/output contract.
- Tables: `sites`, `jobs`, `captures`, `addresses`, `address_sightings`, `operators`, `verdicts`
  (one per scorer version, so rescoring adds rows), `agent_runs`, `agent_steps`, `eval_runs`.
  HTML, screenshots and traces stay on disk with paths in the database.
- Importer for saved runs and `output/results.json`, which becomes an export.

**B2. Queue and workers (≈10 h)**
- A `jobs` table claimed with `SELECT … FOR UPDATE SKIP LOCKED`, with leases, heartbeats, retry
  with backoff and dead-lettering after N attempts. No Redis or Celery.
- Each worker claims one job and runs `process_site` in a fresh sandboxed browser. Global daily
  caps on visits and LLM spend.
- Scheduler re-checks known scam sites (daily, then weekly) for takedowns and address changes.

**B3. Operator clustering and sibling discovery (≈10 h)**
- Group sites into operators by shared deposit addresses, template hashes (DOM structure,
  favicon), linked domains and support handles. Every link records its evidence; weak links
  alone never merge two clusters.
- Discovery pivots from confirmed scams: search for other domains with the same favicon hash,
  template or address (candidate sources: urlscan.io search, certificate transparency lookups
  for related names; check terms and rate limits), and queue them with the reason recorded.
- Metric: discovery hit rate (queued domains that turn out to be scams), tracked per source.

**B4. API, dashboard and deployment (≈10 h)**
- FastAPI, read-only: `/operators`, `/sites`, `/addresses`, `/stats`, `/eval`. Rate limited.
- Static dashboard regenerated from the API: operator pages (domains, wallets, timeline), site
  cards with screenshots, agent replays, benchmark results, one metrics page (jobs per day,
  queue depth, dollars per site, agent stop reasons). Scam URLs defanged, never clickable.
- Only verdicts above a high-confidence threshold are published.
- Deployment decided at this point (§9). Default: one small Linux VM with Docker Compose,
  deployed by a GitHub Actions workflow on tag, selftest extended for the cloud.

**Done means:** left alone for 48 hours, the service finds, processes and clusters new sites
without intervention and survives a killed worker mid-job; the README opens with the live link.

### Stage C. Depth, pick by target role (≈25 h, optional)

Independent items; do the ones that fit the roles being interviewed for.

| Item | Hours | Best for |
|---|---:|---|
| **Triage model:** embeddings plus rule signals into logistic regression or gradient boosting; route confident cases past the LLM; report dollars per 1,000 sites against recall | 8 | AI/ML |
| **Address rotation check:** two registrations on one site, compare deposit addresses, to tell per-victim addresses from shared ones | 4 | AI engineer, FDE |
| **On-chain totals** for found addresses (received, payment count, active dates) from free explorer APIs, cached | 4 | FDE, story |
| **Certificate-stream discovery** with a name filter and hourly cap; measured against sibling discovery's hit rate | 6 | Backend |
| **OpenTelemetry traces, Prometheus, Grafana, alerts** | 6 | Backend, infra |
| **Blog post and 2-minute demo video** | 4 | All |

## 5. Schedule and cut lines

| Stage | Hours | Running total | Weeks (at 10 h/wk) |
|---|---:|---:|---|
| A. Public, measured, demo-able | 30–35 | 35 | 1–3 |
| B. Live service with operators | 35–40 | 75 | 4–7 |
| C. Depth (optional) | up to 25 | 100 | 8–10 |
| Buffer (things break) | ~15 | ~115 | |

- **After Stage A:** apply with it. Strong for AI engineer and FDE roles on its own.
- **After Stage B:** the full story for all four role types.
- **Stage C:** only items that serve an upcoming interview.

## 6. Running cost

| Item | Cost |
|---|---|
| Dataset capture and labelling (one-off) | about $40–80 in LLM spend |
| Full model comparison (one-off, per run) | about $10–30 |
| VM (from Stage B) | $6–12 a month |
| Service LLM spend (capped in code) | $20–40 a month |
| Domain for the dashboard (optional) | ~$1 a month |

## 7. Risks

| Risk | Mitigation |
|---|---|
| Labels are circular (the same model labels and is scored) | Labeller sees more evidence; human review of all disagreements and of the whole test set; agreement rate reported |
| Feeds are mostly dead URLs | Over-capture by 3–4x; Wayback evidence counted separately from live |
| Wrong "scam" label published on a legitimate business | Publish only high-confidence verdicts; show the evidence; a contact for disputes |
| Host's acceptable-use policy forbids a VM that registers on scam sites | Read the policy before choosing; low rate; fall back to running locally and publishing snapshots |
| Sibling discovery sources restrict automated use | Check terms and rate limits first; cache results; record the source of every lead |
| Feed terms forbid redistribution | Publish only our own verdicts and evidence, not feed copies |
| Scope creep stalls the project | Each stage ships on its own; Stage C is a menu, not a list |
| LLM spend runs away | Daily cap in code, alert at 80%, cached responses for benchmarks |
| Public dashboard spreads live scam links | Defang URLs; no clickable links to scam sites |

## 8. Changes from the first draft

- Seven phases became three stages, with a resume-ready stopping point after three weeks.
- Hours raised from about 80 to about 100–115; dataset building was the main underestimate.
- Operator clustering moved from the showcase into the core service.
- Discovery starts from known scams (shared addresses and templates). The certificate stream
  became an optional Stage C item because of its low expected hit rate.
- Labelling is AI-assisted with human review, instead of fully by hand.
- Added: real-site agent funnel, failure-driven mock variants, confidence intervals, a time
  split, the benchmark as a CI gate, an agent replay viewer.
- Full tracing and Grafana moved to Stage C; Stage B keeps one metrics page.

## 9. Still open

1. **Hosting:** a cloud VM or local with published snapshots (decided at Stage B4).
2. **Which Stage C items**, decided after Stage B by target role.
