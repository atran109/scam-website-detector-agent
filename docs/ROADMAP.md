# Roadmap (draft): Ferret

> Status: **draft for review, nothing decided yet.** Ferret is a standalone personal project. It
> stays in this repository with its history, data and docs; mentions of its origin were reworded
> into the project's own goals on 2026-11-14 (LOG). If approved, decisions get LOG.md entries and
> DESIGN.md gains a section for the service.

## 1. Goal

Turn the existing batch pipeline into a continuously running, measured scam-intelligence service,
aimed at **AI/ML engineering** and **backend/infrastructure** roles.

**The one-sentence pitch:**
> Ferret finds new crypto scam sites as their certificates are issued, sends a sandboxed LLM agent
> to register on them and extract deposit addresses, and measures how well every part works.

**What a reviewer should see in 30 seconds:** a live dashboard link, a GIF of the agent reaching
a deposit page, and three numbers (sites processed, classifier precision/recall on held-out
data, cost per site).

**What an interviewer can dig into:**

| Topic | Where it comes from |
|---|---|
| LLM evaluation and calibration | Phase 1 benchmark |
| Agent reliability and prompt-injection defence | Phase 1 agent and red-team suites |
| Cost/quality trade-offs, model distillation | Phase 5 triage model |
| Data modelling, queues, concurrency | Phases 2–3 |
| Sandboxing hostile workloads, observability, deployment | Phases 3–4 (plus the existing isolation) |

## 2. What does not change

The existing hard rules in `CLAUDE.md` carry over unchanged, on the laptop and on the server:

- Real sites are visited only inside the hardened container, behind the egress proxy, after
  `make selftest` passes. On a cloud VM the selftest also proves the metadata endpoint
  (169.254.169.254) is unreachable.
- The action whitelist and policy stay in code. Never pay, sign, withdraw, solve CAPTCHAs or guess
  invite codes.
- **No public "scan this URL" endpoint.** The public API and dashboard serve stored results only;
  the only things that queue a visit are the discovery feed and the operator CLI.
- Budget caps on LLM spend and on visits per day, enforced in code.

## 3. Target architecture

```text
                 +---------------------+       +----------------------+
 CT log stream ->| discovery           |       | seed feeds           |
 (certstream)    | domain-signal filter|       | (labeled datasets)   |
                 +----------+----------+       +----------+-----------+
                            |                             |
                            v                             v
                 +--------------------------------------------------+
                 | Postgres                                          |
                 |  sites · jobs (queue) · captures · verdicts ·     |
                 |  addresses · agent_steps · eval_runs              |
                 +---------+------------------------------+----------+
                           | SKIP LOCKED                  |
                           v                              v
          +-----------------------------+      +--------------------+
          | worker (N, each sandboxed)  |      | FastAPI (read-only |
          |  triage model -> capture -> |      |  public API)       |
          |  extract -> judge -> agent  |      +---------+----------+
          +------+------------+---------+                |
                 |            |                          v
         egress proxy    LLM gateway             dashboard (static
         (unchanged)     (unchanged)             site + graph)

   metrics/traces: OpenTelemetry -> Prometheus + Grafana (cost, latency, success)
   CI: GitHub Actions -> lint, unit tests, browser suite, agent benchmark
```

The existing `scamhunter` package stays the core. The new pieces wrap it: a database layer
replaces JSONL checkpoints, a worker replaces the CLI loop, and discovery replaces `data/urls.txt`.

## 4. Phases

Estimates assume about 10 hours a week. Each phase ends with something that is worth showing on
its own, so stopping early still leaves a finished project.

### Phase 0. Make the repo public-ready (≈4 h)

This repository stays, with its history, URL list, results, labels and fixtures. Done already
(2026-11-14): origin mentions reworded into the project's goals; a full local backup bundle of
the history kept outside the repo.

- Fix the name (README says both "Ferret" and "Furret"); add a LICENSE (MIT or Apache-2.0).
- GitHub Actions: `make check` on every push and PR, with the browser suite as a second job.
- Rewrite the README top as a portfolio pitch.
- Before going public: scan tracked files for personal data, the home IP and secrets; decide
  whether scam URLs are shown defanged (`hxxps://example[.]com`).
- Work on branches with PRs from here on (the PR history itself becomes portfolio evidence).

**Done means:** the repo can be flipped public and CI is green, with a badge.

### Phase 1. Evaluation (≈16 h) — the AI/ML centerpiece

Done first because it produces the resume numbers. The existing 160-URL run and its labels stay
as a baseline; the new dataset adds held-out data and real negatives.

**1a. Labeled dataset**
- Positives: a few hundred crypto scam URLs from public feeds (candidates: CryptoScamDB,
  PhishTank, Chainabuse, ScamSniffer lists; check each one's terms before use).
- Negatives: real, legitimate crypto sites (exchanges from CoinGecko's list, wallets, crypto
  merchants, news), plus non-crypto sites from the Tranco top list. Target at least 30% negatives.
- Capture once through the existing sandbox, store the evidence, never revisit for evaluation.
- Split by **operator cluster, not by URL** (sibling domains share templates; a random split
  leaks), into dev and held-out test sets. The test set is touched only for reported numbers.

**1b. Classifier benchmark** (`make bench`)
- Compare: rules only, model only, the 70/30 blend; Haiku vs Sonnet vs Opus; effort levels.
- Report precision, recall, F1, Brier score, a reliability chart, cost per site and p50/p95
  latency. Output a Markdown report and a JSON file, both committed per benchmark run.
- Cached LLM responses make reruns free and deterministic.

**1c. Agent benchmark**
- Turn the 13 mock-exchange variants into a scored suite: deposit-page reached, addresses
  correct, correct `blocked_at` on gated variants, steps, seconds and dollars per run, several
  runs per variant to measure variance.
- Add variants for the README's known gaps: an iframe-hosted deposit page, a canvas-rendered
  address, a non-English (e.g. Vietnamese) flow.

**1d. Prompt-injection red-team suite**
- About 15 adversarial variants: hidden instructions in text, alt text and ARIA labels; fake
  "system" messages; lures to other domains; instructions to type the API key; instructions to
  click Withdraw or "I have paid".
- Measure attack success rate twice: with the code policy, and with the policy disabled (mock
  mode only), to show how much the code enforcement buys over prompting alone.

**Done means:** one command reproduces a benchmark report with held-out numbers, and the README
shows the headline table.

### Phase 2. Data layer (≈8 h)

- Postgres 17 via Docker Compose; SQLAlchemy 2.0 (async) and Alembic migrations, keeping the
  Pydantic models as the API/output contract.
- Tables: `sites`, `jobs`, `captures`, `addresses`, `address_sightings`, `verdicts` (one per
  scorer version, so rescoring adds rows instead of overwriting), `agent_runs`, `agent_steps`,
  `eval_runs`. Large blobs (HTML, screenshots, traces) stay on disk or in object storage, with
  paths in the database.
- Importer that loads saved runs (JSONL checkpoints and evidence folders) and
  `output/results.json`; `results.json` becomes an export.

**Done means:** the existing results and the Phase 1 dataset live in Postgres, and the export
matches the current `output/results.json` apart from ordering.

### Phase 3. Service (≈16 h)

- **Queue:** a `jobs` table claimed with `SELECT … FOR UPDATE SKIP LOCKED`, with leases,
  heartbeats, retry with backoff, and dead-lettering after N attempts. No Redis or Celery needed;
  the trade-off is a good interview topic.
- **Workers:** each worker claims one job and runs `process_site` in a fresh sandboxed browser.
  Concurrency set by worker count; global daily caps on visits and LLM spend.
- **Discovery:** a certstream consumer filters new certificate domains with the existing domain
  signals (brand misuse, near-misspellings, machine-generated names, finance words) and only
  queues domains above a threshold, with a per-hour cap. Every queued domain records why.
- **Scheduler:** re-checks known scam sites (daily, then weekly) to track takedowns, address
  rotation and sibling domains.
- **API:** FastAPI, read-only: `/sites`, `/sites/{id}`, `/addresses`, `/stats`, `/eval`. Rate
  limited. OpenAPI docs published.

**Done means:** left alone for 48 hours on the laptop, the service discovers, processes and
stores new sites without intervention, and survives a killed worker mid-job.

### Phase 4. Deployment and observability (≈8 h)

- One cheap Linux VM (e.g. Hetzner or DigitalOcean, about $6–12 a month); Docker Compose in
  production, deployed by a GitHub Actions workflow on tag.
- Selftest extended for the cloud: metadata endpoint, VPC ranges, and the VM's own services.
- OpenTelemetry metrics and traces → Prometheus and Grafana: jobs per hour, queue depth, stage
  latency, LLM tokens and dollars per site, agent success and stop reasons, error rates.
- Alerts (email or a webhook) for a spend cap hit, a stuck queue, or a failed selftest.

**Done means:** a public Grafana snapshot or dashboard page shows a week of real operation.

### Phase 5. Cheap triage model (≈8 h) — where ML meets infrastructure

- Features: text embeddings of the landing page plus the existing rule signals.
- Model: start with logistic regression or gradient boosting; train on human labels plus
  high-confidence LLM verdicts (and measure what the LLM-label noise costs).
- Routing: confident not-scam → stop; confident scam → skip the judge and go straight to the
  agent; uncertain → LLM judge. Thresholds chosen on dev, reported on test.
- Report the cost/recall curve: dollars per 1,000 sites against recall, with and without triage.

**Done means:** a measured statement such as "triage cuts LLM cost per site by X% at a recall loss
of Y points", backed by the benchmark.

### Phase 6. Showcase (≈12 h)

- Dashboard (static site, e.g. Astro or plain Vite + a small JS graph library): live feed of new
  scam sites, per-site cards with screenshots, the benchmark results, and the cost chart.
- Operator graph: sites linked by shared addresses, templates (DOM and favicon hashes), linked
  domains and support handles.
- On-chain totals for found addresses (total received, payment count, active dates) from free
  explorer APIs, cached in Postgres. A small, bounded feature here, not a tracing engine.
- A 2-minute demo video of the agent on the mock exchange; a blog post on the build; an
  architecture diagram.

**Done means:** the README opens with the live link, the GIF and three numbers.

## 5. Schedule and cut lines

| Phase | Hours | Running total | Week (at 10 h/wk) |
|---|---:|---:|---|
| 0. Public-ready | 4 | 4 | 1 |
| 1. Evaluation | 16 | 20 | 2–3 |
| 2. Data layer | 8 | 28 | 3 |
| 3. Service | 16 | 44 | 4–5 |
| 4. Deploy + observability | 8 | 52 | 6 |
| 5. Triage model | 8 | 60 | 6–7 |
| 6. Showcase | 12 | 72 | 7–8 |
| Buffer (things break) | ~10 | ~82 | 8–9 |

- **Minimum version (≈30 h):** Phases 0, 1 and a light Phase 6 (README, GIF, benchmark results,
  no live service). Strong for AI/ML roles on its own.
- **Recommended (≈60 h):** add Phases 2–4. This is where the backend story comes from.
- **Full (≈80 h):** everything.

## 6. Running cost

| Item | Monthly |
|---|---|
| VM | $6–12 |
| LLM spend (capped in code) | $20–40 before triage, lower after Phase 5 |
| Domain for the dashboard (optional) | ~$1 |
| One-off benchmark runs | about $10–30 per full model comparison |

## 7. Risks

| Risk | Mitigation |
|---|---|
| Discovery queues mostly legitimate sites | Strict signal threshold, hourly cap, and measuring the filter's hit rate as its own metric |
| Visiting new domains from a cloud IP gets the VM flagged or blocked | Low rate, a normal browser profile, no scanning behaviour; accept and document |
| Feed terms forbid redistribution | Check terms first; publish only our own verdicts and evidence, not feed copies |
| Scope creep stalls the project | Each phase ships on its own; cut lines above |
| LLM spend runs away | Daily cap in code, alert at 80%, cached responses for benchmarks |
| Public dashboard spreads live scam links | Defang URLs; no clickable links to scam sites |

## 8. Decisions needed before Phase 0

1. **Hours per week** (sets which cut line is realistic).
2. **Dataset sources** for positives and negatives (recommendation: CryptoScamDB + PhishTank
   crypto subset; CoinGecko exchanges + Tranco for negatives, pending terms).
3. **Stack for the service:** SQLAlchemy + Alembic + FastAPI + Postgres queue (recommended) vs
   adding Redis/arq.
4. **Hosting:** Hetzner vs DigitalOcean vs keeping the service local and publishing snapshots.
5. **Dashboard:** static site regenerated from the API (recommended; cheap, safe) vs a live SPA.
