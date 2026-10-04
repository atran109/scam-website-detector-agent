# Decision & Progress Log

Append-only. Newest at the bottom. Never edit old entries; if I was wrong, add a new entry.
Tags: `DECISION` · `FINDING` · `PROBLEM` · `RESULT` · `TODO-LATER`
Format: `## YYYY-MM-DD HH:MM · H+<hours since start> · TAG: short title`


---

## 2026-10-03 · H+? · DECISION: scam definition
Backfilled from planning conversation.
- A site is a scam if its main purpose is to get victims to send money, credentials, or wallet access under false pretenses.
- Categories: fake exchange/trading platform, investment/HYIP, pig butchering, phishing/impersonation, wallet drainer, giveaway/doubling, fake recovery service. Fake e-commerce added after seeing the URL list.
- Strong signals: promised returns, brand impersonation, typosquat, new domain, seed-phrase field, mandatory invite code.
- Not sufficient alone: showing a crypto address, accepting crypto, being offshore/unlicensed.

## 2026-10-03 · H+? · DECISION: custom Playwright + Claude loop as navigator
- Considered: browser-use, Stagehand (Browserbase), LangGraph, own loop.
- Chose own loop: need network-response capture, init-script control (mock wallet), enforced action whitelist, per-site isolated contexts; easiest to explain.
- Rejected: browser-use as primary (black-box loop, hard to enforce safety rules); Stagehand (TS-first, cloud-leaning, may not expose Playwright hooks, unverified); LangGraph (graph is small, adds a dependency without helping the hard part).
- Revisit if: navigation success is poor after the first full day, then use browser-use as a fallback navigator for failing sites only.

## 2026-10-03 · H+? · FINDING: Claude sandbox cannot reach the target sites
- Ran a plain-HTTP triage from the cloud container; all 160 hosts failed with proxy errors. Proxy status showed 403 on CONNECT (egress policy denial), sampled from the 20 most recent entries.
- Did not retry or route around the block.
- Consequence: live triage and the crawler must run on my own infrastructure. No live/dead data yet.

## 2026-10-03 · H+? · FINDING: URL list profile (static, no network)
- 160 unique. 71 `.com`; cheap TLDs dominate the rest.
- Name groups (rough, overlapping): about 37 exchange lookalikes, about 26 shop/store, about 15 forex/trading, plus meme tokens, mining, gold, USDC-themed.
- About 10 URLs with `h5.`/`m.`/`web.`/`web3.` or `/wap`, `/h5`: hypothesis is mobile SPA fake exchanges (unverified).
- 5 on free hosting platforms; likely dead.
- Sibling domains likely share operators.

## 2026-10-03 · H+? · DECISION: logging and planning setup
- Plan lives in `docs/PLAN.md`; decisions in this file; progress via small git commits and `runs/<timestamp>/summary.json`.
- Not using Notion or Obsidian: keep everything in the repo so it ships with the deliverable.

---

<!-- Add new entries below this line -->

## 2026-10-03 · H+? · DECISION: design doc written (`docs/DESIGN.md`)
- Spec → action items, code layout, ontology (format ≠ network ≠ asset), 29 assumptions, architecture.
- Navigate on scam-or-uncertain even if addresses are already found: the goal is coverage of target assets, not one address.
- Still open: dead-site default verdict (A6). Decide after triage.

## 2026-10-04 · H+? · DECISION: one address can carry several asset/network labels
- Format (EVM, TRON, BTC…) is certain from checksum; network and asset are inferred from page context.
- Scam deposit pages often reuse one `0x…` address for ETH, USDT-ERC20 and BNB, so `CryptoAddress.labels` is now a list of `AssetLabel`s, each with its own evidence and confidence.
- Noted: legacy `1…`/`3…` strings are also valid Bitcoin Cash legacy addresses; default network Bitcoin, context can override.

## 2026-10-04 · H+? · FINDING: Stagehand v4 research
- v4 (Python 4.1.0, Sep 2026, MIT) removed `agent()`; it's now primitives (`observe`, `act`, `extract`) and you write the loop. Python is a local SDK in v4 (was a hosted-API client in v3). Runs locally; can attach to a Playwright-launched browser via its DevTools endpoint. Claude supported (`anthropic/…` model strings).
- Useful: `observe()` → `act(action)` replays without an LLM call; `%variables%` keep secrets from the model.
- Gaps for this task: documented Page API has `addInitScript`, `screenshot`, `evaluate`, locators, but no network request/response events and no request routing (only console events).
- Caution: server-side caching sends variable values to the cache service (Browserbase); launch-options example uses `--disable-web-security` and `accept_downloads=True`, which we must not copy.
- Observability page I was pointed to is v3 TypeScript: dashboards/recordings are Browserbase-cloud only; local metrics are only Stagehand's own token counts.

## 2026-10-04 · H+? · DECISION: Stagehand deferred; element finding behind an interface
- Expected saving is ~2-5h on element finding only; Playwright is still needed for network capture, routing and tracing; two drivers on one browser is an untested risk; each step would cost two LLM calls.
- Most navigation failures are expected to be gates (invite code, SMS, CAPTCHA, geo-block), which Stagehand doesn't fix.
- Chose: `browser/elements.py` `ElementProvider` (Playwright default). Pilot tags every navigation failure by cause; if element-finding dominates, time-box a 1-2h Stagehand trial.
- Revisit if: failure tally after the pilot.

## 2026-10-04 · H+? · DECISION: non-semantic widgets handled explicitly
- Cheap H5 app kits often render buttons as plain `<div>`s, which may be missing from the accessibility tree (general knowledge, not yet observed on these sites).
- Element list includes `cursor: pointer` / click-handler elements; screenshot goes to Claude; `click_at(x, y)` added as a logged fallback tool.

## 2026-10-04 · H+? · DECISION: Playwright tracing instead of Browserbase recordings
- Browserbase cloud rejected: cost, another key, scam traffic through a third party (acceptable-use terms unchecked), less to show on our own sandbox.
- Keep Playwright `trace.zip` for scam sites and failures: timeline, DOM snapshots, screenshots, network with bodies, viewable locally.

## 2026-10-04 · H+? · DECISION: plan merged with my own draft plan
- Kept from my draft: definition-of-done items (one record per URL, clean-checkout run, no secrets in artifacts, private repo shared with `@rraina`), quality checks, risk register, decision-log table, internal uncertain state.
- Added: dedicated navigation milestone, risk-first order (baseline sandbox → thin end-to-end → navigation → full hardening before the batch), network + QR address sources, screenshots at discovery, hand-labeled accuracy numbers, `processing_status` separate from site `status`, prompt-injection and private-network risks, cut list.

## 2026-10-04 · H+? · DECISION: crawler runs in hardened Docker on my personal Mac
- Weighed: hardened laptop Docker vs throwaway cloud server.
- Cloud is safer mainly in **blast radius** (nothing personal on the box, disposable IP), not in likelihood: a real compromise needs a Chromium exploit either way, and scam kits rarely carry one.
- Deciding factors: I've never done remote-server work (estimated 2-4h to learn, plus slower debugging on live sites, where the hardest navigation bugs show up), against 15-25 working hours. Docker Desktop on a Mac runs containers in a Linux VM, which narrows the isolation gap.
- Noted: a mixed setup (debug live sites on the laptop, final batch in the cloud) gives little real safety, since the laptop has already visited the sites.
- Corrected an earlier claim: geofencing is about country, not cloud vs home, so it isn't a cloud-specific risk. Datacenter-IP cloaking is real in principle but unmeasured for this list.
- Revisit if: 3+ spare hours at the end, as a cloud comparison run; or if I'd ever have to use a work laptop (then cloud, no question).

## 2026-10-04 · H+? · DECISION: egress proxy container instead of host firewall rules
- Host firewall rules are awkward on Docker Desktop. Instead: crawler on an internal-only Docker network; its only route out is a Squid proxy that denies private/loopback/link-local ranges (incl. 169.254.169.254) by resolved IP and logs every request.
- Works unchanged on a cloud server later. `make selftest` must pass before the first real visit.
- Moved this into M1 (baseline), since the home network is now what's at risk.

## 2026-10-04 · H+? · DECISION: capture and classification are separate stages
- Every visit saves evidence; `make rescore` rebuilds classifications and `results.json` without revisiting sites.
- Why: fast and safe classifier tuning, stable evaluation even if sites change or go offline mid-project, and hand labels made from the same evidence the classifier saw.

## 2026-10-04 · H+? · DECISION: run-location trade-off written up (DESIGN §6.1)
- Security vs accuracy, summarized: cloud wins on worst-case outcome (large, high confidence); probability of compromise is tiny either way; effect of IP type on captured evidence is unknown (low confidence, slight lean Mac); cloud costs ~3-5.5h of a 15-25h budget.
- Stayed with Docker on the Mac. Flip conditions: unrecoverable data on the Mac, ~25h budget, or a smooth cloud trial.
- Added `host.docker.internal` (the Mac itself) to the `make selftest` checks: from inside Docker Desktop it's how a container can reach services on the host.
- README must state that evidence was captured from a residential US IP.

## 2026-10-04 · H+? · DECISION: output contract and address policy
- Each record carries `is_scam` (bool) next to `classification`, `crypto_addresses` (primary, plain strings), `low_confidence_addresses`, and `address_details` (labels, evidence, `normalized`, `tier`).
- Addresses are reported exactly as seen on the site, plus a `normalized` form used for dedupe. Why: exact-string comparison against ground truth is likely; low-confidence addresses stay in their own list to protect precision.

## 2026-10-04 · H+? · DECISION: verdict bias, models, per-site limits
- `scam_threshold: 0.45`: lean toward recall, since a missed scam costs more than a false flag here. README reports precision/recall at 0.45 and 0.5.
- Strong model for navigation and judging, Haiku-class `helper_model` for cheap calls; final split decided after measuring the first 10 sites.
- Give up on a site after 4 consecutive failed steps. One disposable email provider; if verification never arrives, record `blocked_at: email_verification`.
- Policy defaults gathered in DESIGN §7.

## 2026-10-04 · H+? · DECISION: repo contents and schedule freezes
- Repo ships docs, src, tests, urls, results, sample evidence, eval labels, `.env.example`; never `.env` or real cookies.
- Feature freeze at deadline −6h, code freeze at −3h, clean-checkout test at −1h. README is written from this log.

## 2026-10-04 · H+? · FINDING: deadline flexible; API key self-funded, reimbursed
- Still setting a self-imposed target date so the freeze points in PLAN have something to key off.
- Spend limit set in the console; invoices kept for reimbursement.

## 2026-10-04 18:11 · H+? · DECISION: repo skeleton (M0) and DESIGN/PLAN fixes from review
Skeleton built per DESIGN §2.1; Dockerfile, docker-compose.yml and squid.conf deferred to M1. Only pydantic (plus pytest and ruff for dev) pinned; other deps get pinned in the milestone that first uses them. Decisions from reviewing DESIGN/PLAN:
- Docs moved into `docs/`; `claude.md` renamed `CLAUDE.md` (otherwise not picked up on case-sensitive filesystems).
- Output models added to §3.3 and `models.py`: `ResultsFile`, `ResultsMeta`, `OutputRecord`, `AddressDetail`, `NavigationSummary`, all `extra="forbid"`. `is_scam` must match `classification` (validator). The §3.4 `_comment` field became a sentence above the example. `tests/test_models.py` validates the §3.4 example read straight from DESIGN.md, so doc and schema can't drift apart.
- Flattening: `address_details` source/stage/screenshot come from the earliest `deposit_page` sighting, else the earliest overall; `sighting_count` added.
- Confidence: new `scam_probability` (0–1); verdict = scam iff ≥ `scam_threshold` (0.45). `confidence` = P(stated verdict correct) = p for scam, 1−p for not_scam (validated, ±0.01 for rounding). Consequences: p in [0.45, 0.5) gives "scam" with confidence < 0.5 (intended); a not_scam always has confidence > 0.55, so A6's old "dead site confidence ≤0.3" was impossible. Reworded to "scam_probability just under 0.45" (example: 0.4 → 0.6). §5.4 scorer now produces `scam_probability`.
- Lowercase EVM follows A17: primary with deposit context, low_confidence otherwise (enum comment fixed). CLAUDE.md address rule reworded: validate format and checksum where the format has one; lowercase EVM is format-valid but unverifiable.
- `Identity.identity_id` added; `BlockedReason` enum added (invite_code, sms_verification, email_verification, captcha, kyc, geo_block, payment_required, other) and used for `blocked_at`; `SiteStatus.GEO_BLOCKED` added.
- `dedupe_key`: EVM → lowercased `normalized`, others → `normalized` unchanged.
- `cli.py` gains `rescore`; `selftest` stays Makefile-only. `report` added to the §2.1 Makefile comment. Unused `HttpUrl` import dropped.
- PLAN: target date placeholder added (still <FILL IN>); M1 key item → "set a spend limit in the Anthropic console"; key-budget open question dropped.
- `data/urls.txt`: 160 URLs, no duplicates, no trailing newline. The loader must not dedupe and must keep paths.

## 2026-10-04 18:11 · H+? · TODO-LATER: AgentAction arguments (M3)
`AgentAction` has only `value`/`url`/`x`/`y`/`element_id`, but §5.5 tools take `option` (select), `key` (press), `direction` (scroll), `seconds` (wait), `reason` + `blocked_at` (done). Left as specified for now. In M3, decide between overloading `value` and adding typed fields (preferred: typed fields with `blocked_at: BlockedReason`), then update DESIGN §3.3.
