# Plan: Crypto Scam Detection Agent (TRM Labs challenge)

> Written at the start, expected to change. When it changes, add a dated entry to `LOG.md` saying what changed and why. Design details live in `DESIGN.md`.

**Submission:** private GitHub repo shared with `@rraina`

## Next actions

1. [x] Deadline: none, ASAP (freeze points apply relative to whenever submission is decided)
2. [x] API key: my own, reimbursed. Set a monthly spend limit in the Anthropic console; keep invoices for reimbursement
3. [ ] Create the private repo; commit `docs/`, `data/urls.txt`, `CLAUDE.md`, `.gitignore`, `.env.example`
4. [x] Install Docker Desktop; limit file sharing to the project folder; check Python 3.12
5. [x] Claude Code session 1 (plan mode first): M1 sandbox, egress proxy, `make selftest`; then the first watched run of triage inside the container
6. [x] Log the triage counts; decide the dead-site default verdict (Wayback → signals → not_scam; DESIGN §5.2a)

## Goal

For each of 160 URLs: classify scam / not scam, and for scams extract every crypto address the site exposes (BTC, ETH, USDT/USDC on ERC-20 and TRC-20 first; others welcome), including addresses only shown after registering, logging in, or opening a deposit page. Write JSON with confidence and reasoning. Bonus: a screenshot of each address in context. Deliver code with setup instructions and a README (architecture, assumptions, alternatives, creative choices, next steps).

## Definition of done

- [ ] All 160 URLs processed, including inactive or unreachable sites: **exactly one output record per input URL** (no URL lost to normalization; paths like `/wap` and `/h5` kept)
- [ ] Every URL has a `scam` / `not_scam` classification, a boolean `is_scam` (easy to script against), a site `status`, and a `processing_status`
- [ ] Scam records include validated BTC, ETH, USDT/USDC and other detected addresses, exactly as shown on the site plus a `normalized` form, each with asset/network labels, where it was found, and a screenshot taken at discovery; low-confidence addresses kept in a separate list
- [ ] The navigation agent reaches deposit pages on sites that require registration/login, or records exactly where it was blocked
- [ ] Browser automation handles client-rendered pages and approved interactions without exposing the host
- [ ] Results written to schema-valid JSON with reproducible evidence (traces, screenshots) and confidence/reasoning
- [ ] Accuracy measured against a hand-labeled sample, with numbers in the README
- [ ] README explains architecture, scam definition, assumptions, alternatives, creative choices, limitations, next steps
- [ ] Documented run command works from a clean checkout
- [ ] No real secrets (API keys, cookies from real accounts) in the repo or artifacts; synthetic credentials kept per site for reproducibility
- [ ] Repository is private and shared with `@rraina`

## Approach (one paragraph)

Deterministic pipeline for probing, capturing, extracting, validating and writing output. LLM only for classification and for navigation decisions. Navigation is our own loop: Playwright drives the browser, Claude picks one whitelisted action per step, and element finding sits behind a small `ElementProvider` interface so Stagehand could be swapped in if the pilot shows that's the bottleneck. It runs in hardened Docker on my personal Mac, behind an egress proxy container that blocks the home network. Capture and classification are separate stages, so the classifier can be re-run from saved evidence without revisiting sites. Stack: Python 3.12 / asyncio, Playwright (Chromium; mobile viewport for H5 sites), Docker, Claude (vision + tool use), Pydantic, JSONL checkpoints, Playwright tracing.

## Order of work: riskiest first

Navigation is the hardest part and decides extraction completeness (weighted High), so it's proven early, against the local mock exchange and then real sites, before polishing anything. **Baseline safety is never skipped:** even the first real-site visit runs in a container with no host mounts, downloads blocked, a fresh browser context, and the egress proxy blocking the home network (proven by `make selftest`). Full hardening comes before the 160-site batch.

## Time budget

Adjust the hours to the real schedule.

| # | Milestone | Hours | Gate ("done means") |
|---|---|---|---|
| M0 | Scope and design | 0.5 | Mostly done: `DESIGN.md` reviewed, dead-site default decided after triage |
| M1 | Baseline sandbox + triage | 3 | Container + egress proxy run on the Mac; `make selftest` passes; all 160 bucketed by status |
| M2 | Thin end-to-end | 5 | 10-20 URLs go capture → extract → classify → JSON with inspectable evidence |
| M3 | Navigation agent | 6 | Mock exchange solved end to end; real sites reach deposit pages or record `blocked_at`; failure causes tallied |
| M4 | Classification + confidence | 3 | Rubric tuned on hand labels; explanations defensible |
| M5 | Full hardening | 1.5 | Remaining layers in `DESIGN.md` §5.6 in place and checked |
| M6 | Batch run + quality checks | 3 | All 160 done; quality report written |
| M7 | Docs + submission | 3 | Clean-checkout run works; repo shared |
| | Buffer | 2-3 | Something will break |

## Milestones

### M0. Scope and design (mostly done)

- [x] Input/output schemas (`DESIGN.md` §3)
- [x] Scam taxonomy and signal tiers: strong / moderate / weak (`DESIGN.md` §3.2, §5.4)
- [x] Evidence sources: page text, attributes, scripts, **network responses**, **QR codes**, domain signals, brand impersonation, wallet requests (mock wallet), behavior after interaction
- [x] Stack and agent approach; alternatives recorded (`DESIGN.md` §6)
- [x] Threat model (`DESIGN.md` §5.6)
- [x] Decide dead-site default verdict once triage counts are in (DESIGN §5.2a)

### M1. Baseline sandbox + triage

- [x] Where the crawler runs: hardened Docker on my personal Mac (decided; cloud server deferred to future work)
- [x] Docker Desktop: limit file sharing to the project folder
- [x] `docker-compose.yml`: crawler on an internal-only network; Squid egress proxy denying 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16 and logging requests
- [x] `make selftest`: home router, `host.docker.internal` (the Mac itself) and 169.254.169.254 all fail; a normal site succeeds. **Must pass before the first real visit**
- [x] Dockerfile: non-root user, Playwright + Chromium, no host mounts except `runs/` and `output/`
- [x] Browser baseline: fresh context per URL, downloads blocked, permissions denied, Chromium sandbox on (seccomp profile)
- [x] Pulled forward from M5: `cap_drop: ALL`, `no-new-privileges`, CPU/memory/PID limits
- [x] Run `triage.py` on all 160 → status buckets
- [x] Log the counts in `LOG.md`; revisit time budget

### M2. Thin end-to-end

- [x] Load URLs without lossy dedupe (paths are significant)
- [x] `capture.py`: final URL, status, title, visible text, HTML, accessibility tree, screenshot, **network responses**
- [x] Mobile viewport + user agent for `h5.`/`m.`/`/wap`/`/h5` and empty SPA shells
- [x] Address candidates from all sources; chain-specific checksum validators; contract/example blocklist
- [x] Asset/network **labels list** with confidence from nearby context
- [x] Normalize + dedupe addresses (format-aware keys)
- [x] Screenshot with the address highlighted **at the moment of discovery**
- [x] Classifier v1: signals + LLM judge with quoted evidence
- [x] Structured record per site even on timeout/error (`processing_status`)
- [x] Output contract (DESIGN §3): `is_scam`, `crypto_addresses` (primary), `low_confidence_addresses`, `address_details`; address tiers PRIMARY / LOW_CONFIDENCE
- [x] Model split: strong model for navigation and judging, `helper_model` (Haiku-class) for cheap helper calls; measure on the first 10 sites before fixing it
- [x] `make rescore`: rebuild classifications and `results.json` from saved evidence, no site visits
- [x] Unit tests for validators and extractor on fixture pages
- [x] Retry `tls_error` and `timeout` sites (incl. #112 ReadTimeout) once in Chromium before treating them as dead
- [x] Cloudflare phishing interstitials (#009, #035): verdict scam; try one click through the warning to capture the real page
- [x] Wayback recovery for non-live sites (DESIGN §5.2a), **time-boxed to 2h**; else signals-only rule

### M3. Navigation agent

- [ ] Local mock exchange fixture (register → login → deposit → coin/network selector) with failure variants and traps. **Mock mode (decided 2026-10-05):** runs inside the crawler container (no route out); the browser runs without the proxy only under an explicit `--mock` flag that refuses every non-loopback URL; `make selftest` checks that refusal
- [ ] `elements.py`: accessibility roles **plus** non-semantic clickables (`cursor: pointer`, click handlers)
- [ ] Tool whitelist incl. `click_at` fallback; policy checks (same-domain, placeholders only, no payments/signing)
- [ ] Synthetic identity + disposable mailbox (`check_email`)
- [ ] Iterate every coin and network on the deposit page; extract after every step
- [ ] Stop conditions and `blocked_at` (invite code, SMS, CAPTCHA, KYC, geo-block, `email_verification`)
- [ ] Give-up rule: stop a site after 4 consecutive failed steps (`max_consecutive_failures`)
- [ ] Disposable email: **mail.tm** (decided 2026-10-05); API token held in memory only, never logged or written to disk; mail traffic goes through the egress proxy; if the verification email never arrives, record `blocked_at: email_verification` and move on
- [ ] Policy rules from the 2026-10-05 decisions (deposit amounts, deposit-page clicks, "I have paid"/receipt blocked, wallet clicks, text reply = failed step): DESIGN §5.5
- [ ] Mock wallet (`window.ethereum`) via init script, logging requested recipients: **deferred until after the pilot, not cut.** Tally wallet-gated sites (`blocked_at: wallet_required`) in the pilot; build it if there are several. Connect-wallet clicks become allowed once it exists (sign/approve stay blocked)
- [ ] Smaller step budget for `fake_shop` (e.g. 12 instead of 25), set in `agent` settings
- [ ] Pilot on 10-20 real sites; **tally failure causes**. If element-finding dominates, time-box a 1-2h Stagehand `ElementProvider` trial
- [ ] (If time) register twice on 3-5 sites to test per-account addresses

### M4. Classification and confidence

- [ ] Transparent scoring rubric with signal tiers and weights
- [ ] Hard rules first (seed-phrase field, parked/empty)
- [ ] Classifier returns label, scam type, confidence, reasons, evidence references
- [ ] Internal `uncertain` band, mapped to the binary label for output
- [ ] Verdict bias: `scam_threshold: 0.45` (lean toward recall); report precision/recall at 0.45 and 0.5 in the README
- [ ] Re-classify after navigation with the new evidence
- [ ] Dead-site policy in the scorer: Wayback shrink factor, signals-only band (0.5–0.65), `evidence_source` on every record; calibrate on hand labels incl. dead sites
- [ ] **Decide the signals-only rule** (numbers in LOG 2026-10-05). `finance_terms_in_domain` no longer counts for dead sites (done); now 47 of 60 dead-site scam verdicts rest on weak signals only. Do NOT pick (a) "≥1 moderate" or (b) "≥3 weak" yet: after the full live run, compute the scam base rate on live sites and each signal's scam/legit ratio on live sites, and propose the rule from those. Re-run the count after the Chromium rechecks, Wayback and the sibling pass
- [ ] **New signal: mobile exchange template.** Menu cluster (Recharge, Withdraw, Finance, Loan, Service, Contract, Assets, Team, Chat Room, "AI Quant", "Follow") plus a forced Connect Wallet modal. Pilot evidence: #100 matches 9 of 12 words, #057 six, #055 only the modal; #027 (a token project) shares generic words (Contract, Follow, Team, Assets), so require a cluster of the distinctive words (Recharge/Withdraw/Finance/Loan/Service/AI Quant/Chat Room/Connect Wallet), not any one. Also covers the sites whose heuristic score stays low today (#055, #057, #100, #128)
- [ ] **New signal: domain/content mismatch** (e.g. #003: `addmklwhisky.com` serves a Chinese immigration-service site). Not built yet and not logged as deferred before 2026-10-05 (DESIGN §5.4 lists "mismatched branding" but no code implements it). Options: deterministic (no alphabetic token ≥4 letters of the domain appears in the page title or text), and/or a `domain_content_mismatch` boolean in the judge's output schema
- [ ] Random-looking-domain check is English-only (letter-pair table): check non-English names (pinyin initials, Dutch, Vietnamese) against the 30 flagged
- [ ] Hand-label 20-30 sites in `eval/labels.csv` **from saved screenshots and text** (not by revisiting live sites); measure accuracy/precision/recall; tune via `make rescore`

### M5. Full hardening

- [ ] Container: read-only root filesystem (`cap_drop`, `no-new-privileges` and limits already done in M1)
- [ ] Re-run `make selftest`; review `egress.log` for anything unexpected
- [ ] Verify the Chromium sandbox is on inside the container (no silent `--no-sandbox`)
- [ ] Browser: block non-http(s) schemes and service workers; close popups; no extensions
- [ ] LLM: page content wrapped as untrusted data; structured outputs validated
- [ ] Per-site timeouts at every level; bounded concurrency; retries with backoff
- [ ] Secrets only in `.env`; never logged

### M6. Batch run and quality checks

- [ ] Re-run triage on a different day than M1 (sites flap) before the batch
- [ ] Run all 160 with bounded parallelism and checkpointing (`--resume` works)
- [ ] Track processed / partial / failed / timed-out counts
- [ ] Verify exactly one record per input URL
- [ ] Validate JSON against the schema
- [ ] Verify every address passes its checksum and isn't blocklisted
- [ ] Manually review a sample of scam and not-scam results
- [ ] Scan artifacts: no real secrets or cookies
- [ ] Keep Playwright traces for scam sites and failures
- [ ] Short quality report (`runs/<ts>/summary.json` + notes)

### M7. Documentation and submission

- [ ] Setup and run instructions tested from a clean checkout
- [ ] Architecture diagram (from `DESIGN.md` §5.1)
- [ ] Scam definition, signal tiers, assumptions
- [ ] Short crypto primer: format vs network vs asset, why labels carry confidence
- [ ] Alternatives and tradeoffs (from `DESIGN.md` §6 + pilot data)
- [ ] Security controls and limitations (incl. per-account addresses, geo-blocking, dead sites)
- [ ] Results with numbers (accuracy, addresses found, before/after network capture)
- [ ] What more time would improve
- [ ] Sample output and troubleshooting notes
- [ ] Repo contents: `README.md`, `docs/` (DESIGN, PLAN, LOG), `src/`, `tests/`, `data/urls.txt`, `output/results.json`, sample evidence/traces, `eval/labels.csv`, `.env.example`; no `.env`, no raw cookies
- [ ] Repo private; access shared with `@rraina`

## Risk register

| Risk | Mitigation |
|---|---|
| **Hostile content** (exploits, drive-by downloads) | Isolated container, fresh context per site, downloads blocked, no persistence or privileged APIs |
| **Prompt injection** from page text | Content wrapped as untrusted data; action whitelist enforced in code, not by the prompt |
| **Private-network probing** from the browser (home router, other devices) | Internal-only network + egress proxy denying private ranges; `make selftest` before any real visit; optional guest Wi-Fi |
| **Personal machine as blast radius** | Container + Docker Desktop VM + no mounts beyond `runs/`/`output/`; never open saved HTML in a normal browser; residual risk documented |
| **Home IP visible to scam operators** | Accepted and documented; cloud server listed as future work |
| **Interaction-gated content** | Navigation agent with bounded action policy; every action recorded |
| **Non-semantic widgets** (`<div>` buttons) | Clickable detection + screenshot + `click_at` fallback |
| **Gates** (invite code, SMS, CAPTCHA, geo-block) | Recorded as `blocked_at`; no CAPTCHA-solving services |
| **Per-account deposit addresses** | Documented as a limitation; record discovery stage; test on a few sites if time allows |
| **Dead sites** skew the verdicts | Separate `status` field; default verdict decided after triage and documented |
| **False positives** | Require multiple signals unless a strong one fires; keep evidence for review |
| **False negatives** | Navigate scam/uncertain sites even when an address is already visible; network + QR sources |
| **Invalid or irrelevant addresses** | Checksums, contract/example blocklist, cross-site constant filter |
| **Output not parsed correctly by the grader** | `is_scam` boolean plus `crypto_addresses` as plain strings; JSON-schema validation; sample output in README |
| **README squeezed at the end** | Feature freeze and code freeze (see Schedule guardrails); README drafted from `LOG.md` during the last 3h |
| **Runtime/cost overruns** | 10-20 URL pilot first; step/time budgets; token tracking; LLM response cache |
| **Unreproducible results** | Pinned dependencies, logged config hash, temperature 0, cached LLM responses, traces |

## Decision log (summary; full entries in `LOG.md`)

| Decision | Choice | Why | Revisit when |
|---|---|---|---|
| Run location | Hardened Docker on personal Mac + egress proxy | No remote-server experience; 15-25h budget; fast live-site debugging; Docker Desktop VM adds a boundary | Finish with 3+ spare hours (cloud comparison run) |
| Browser execution | Isolated, disposable context per site in a container | Limits impact from hostile pages | Sandbox proves too slow |
| Capture vs classification | Separate stages; `make rescore` from saved evidence | Fast, safe classifier tuning; stable eval if sites change | — |
| Navigator | Own Playwright + Claude tool-use loop | Network capture, routing, init scripts, explainability | Pilot nav success is poor |
| Element finding | `ElementProvider` interface, Playwright default | Keeps Stagehand as a cheap swap-in | Pilot shows element-finding is the main failure cause |
| Stagehand v4 | Deferred | Saves ~2-5h on one sub-problem; no documented network capture; two-driver risk | Same as above |
| Browserbase cloud | Rejected | Cost, third-party traffic, less to show on sandboxing; Playwright tracing covers recordings | — |
| LangGraph | Rejected | Small graph; plain-Python state machine is clearer | Routing grows complex |
| Extraction | Deterministic regex + checksum validation first | Testable and explainable | Obfuscated or interaction-only addresses are missed |
| Address labels | List of asset/network labels per address, each with confidence | One EVM address can serve ETH and USDT-ERC20 | — |
| Classification | Tiered signals + LLM judge with quoted evidence, fused into confidence | Balances repeatability and coverage | Manual review shows systematic errors |
| Failure handling | Structured record, then continue | Preserves one result per URL | Failure rate is unusually high |
| Concurrency | Low, bounded (about 6) | Reduces risk and rate limits | Runtime exceeds budget |
| Output contract | `is_scam` + `crypto_addresses` (primary) + `low_confidence_addresses` + `address_details` | Easy for scripts and humans to read | Grader format is clarified |
| Address policy | Report exactly as seen plus `normalized`; low-confidence kept apart | Exact-string comparison against ground truth; protects precision | — |
| Verdict bias | `scam_threshold` 0.45 | Missing a scam costs more than a false flag for this task | Hand-label results show too many false positives |
| Models | Strong model for navigation/judging; Haiku-class helper | Cost and quality | First-10-site measurement |
| Email verification | One disposable provider; else record `blocked_at` | Bounded effort | Many sites blocked by it |
| Give-up rule | 4 consecutive failed steps | Bounds time and cost per site | Pilot shows premature give-ups |
| Freeze points | See Schedule guardrails | Protect docs and submission | — |
| Dead-site verdict | Wayback snapshot → normal classifier (shrunk); else domain/sibling/warning signals → lean scam; else `not_scam`, low confidence | 104/160 not live; labels likely from a scam feed | Hand labels on dead sites |

## Schedule guardrails

- Feature freeze: deadline minus 6h. After that, only fixes, the batch run and evaluation
- Code freeze: deadline minus 3h. README is finished from `LOG.md` in the last 3h
- Clean-checkout test: deadline minus 1h; then share the repo with `@rraina`

## Known facts about the list (static analysis, no network)

- 160 unique URLs; 71 `.com`; long tail of cheap TLDs (`.store` 13, `.xyz` 8, `.top` 7, `.cc` 6)
- Rough name groups (overlapping): about 37 exchange lookalikes, about 26 shop/store, about 15 forex/trading, plus meme tokens, cloud mining, gold, USDC-themed
- About 10 URLs use `h5.`/`m.`/`web.`/`web3.` prefixes or `/wap`, `/h5` paths: likely mobile SPA fake exchanges (unverified)
- 5 on free hosting platforms (Shopify, Netlify, Workers, Azure Front Door): likely taken down
- Sibling domains likely share operators/templates (sebca.art/.sbs, vnexchange.me/.top, `.store` shop clusters)
- Fake e-commerce is in scope as a scam type and may have no crypto address
- The Claude cloud sandbox's egress policy blocks these hosts, so all live work runs on my Mac

## Cut list (drop in this order if time runs short)

1. Cloud-server comparison run (bonus: does a datacenter IP see different content?)
2. Stagehand trial (unless the pilot demands it)
3. Mock wallet drainer capture
4. Highlighted-box screenshots (keep plain screenshots taken at discovery)
5. Per-account address test (keep the README note)
6. OCR on non-QR images
7. Cross-site clustering

**Never cut:** address validation, baseline sandboxing (incl. egress proxy + selftest), the navigation agent, the accuracy check, the README.

## Open questions

- Which sites in the list are legitimate negatives?
- Which disposable email provider?
- Per-task model split: decide after measuring the first 10 sites