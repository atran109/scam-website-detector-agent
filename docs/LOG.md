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
- `data/urls.txt`: 160 URLs, no duplicates, no trailing newline. The loader must not dedupe and must keep paths.

## 2026-10-04 18:11 · H+? · TODO-LATER: AgentAction arguments (M3)
`AgentAction` has only `value`/`url`/`x`/`y`/`element_id`, but §5.5 tools take `option` (select), `key` (press), `direction` (scroll), `seconds` (wait), `reason` + `blocked_at` (done). Left as specified for now. In M3, decide between overloading `value` and adding typed fields (preferred: typed fields with `blocked_at: BlockedReason`), then update DESIGN §3.3.

## 2026-10-04 18:58 · H+? · DECISION: M1 sandbox, egress proxy and triage design
- Target date: none, ASAP (PLAN updated).
- **Squid error codes through httpx.** Tested: for https URLs a proxy failure surfaces only as `ProxyError("503 Service Unavailable")`; X-Squid-Error is not in the exception. But httpx's documented `trace` request extension sees the CONNECT response headers, giving `ERR_DNS_FAIL` / `ERR_CONNECT_FAIL <errno>` / `ERR_ACCESS_DENIED`. Used that instead of the planned DNS-over-HTTPS fallback: same information, no third party. errno 110 → TIMEOUT.
- **Invalid TLS:** retry unverified; classify from content; record `tls_valid=false` as a weak scam signal (DESIGN §5.4, §5.1a). Capture will use `ignore_https_errors` for those sites.
- **Models:** `TriageResult.reason`, `TriageResult.tls_valid`, `TriageRecord`. Settings gain `triage:` and `http:` sections; `config.py` loads them as strict typed models.
- **Browser-like headers:** Chrome 154 on Windows UA + matching Accept, Accept-Language, Accept-Encoding (br/zstd decoders added), sec-ch-ua and Sec-Fetch headers. Limitation: TLS/HTTP2 fingerprint is still httpx's.
- **Squid image:** own Dockerfile on digest-pinned Alpine 3.22 with squid=6.12-r0, run as the squid user. Deny list extends PLAN's with 100.64/10 (CGNAT/Tailscale), 0/8, 198.18/15, multicast/reserved, IPv6 loopback/ULA/link-local; ports 80/443 only; no X-Forwarded-For or Via.
- **Hardening pulled forward from M5:** `cap_drop: ALL`, `no-new-privileges`, memory/PID/CPU limits on both containers.
- **Chromium sandbox under cap_drop ALL:** Playwright's default adds `--no-sandbox`, so we launch with `chromium_sandbox=True` and Playwright's seccomp profile (v1.63.0: Docker default + clone/unshare/setns). The first launch aborted with `sys_chroot(...) failed`, because Docker's profile allows `chroot` only if the container has CAP_SYS_CHROOT. Fix: made `chroot` unconditional in our copy instead of `cap_add: SYS_CHROOT`. The kernel still checks the capability per namespace, so the container user (CapEff=0) can't chroot; only Chromium's sandboxed child in its own user namespace can. This is the only change from the vendored file, and a test asserts it.
- Full Chromium in new headless mode (`channel="chromium"`) rather than the headless shell: harder for scam kits to detect.
- **Code-level gates:** `require_egress_proxy()` refuses to contact sites unless EGRESS_PROXY is set and `/.dockerenv` exists; `make triage`/`make run` depend on `make selftest`.
- `REPO_ROOT` comes from `SCAMHUNTER_HOME` in the container (the package is installed into site-packages there).

## 2026-10-04 18:58 · H+? · RESULT: make selftest passes (30/30)
Run `selftest-5`, container on Docker Desktop 29.8.1 (arm64):
- Non-root (uid 10001), CapEff=0.
- No direct route out (1.1.1.1:443 unreachable); no external DNS inside the container.
- Through httpx and through Chromium, all denied with `ERR_ACCESS_DENIED`:
  - home router 192.168.0.1, 169.254.169.254, host/gateway.docker.internal, 127.0.0.1;
  - the proxy's own manager;
  - DNS tricks localtest.me and 169.254.169.254.nip.io;
  - port 8080.
- https://example.com loads.
- No `--no-sandbox`. Renderer has Seccomp=2 in its own user namespace.
- Downloads are refused, and egress.log records every request.

Triage probe exercised on safe hosts only (example.com, `.invalid`, expired.badssl.com, neverssl.com): live / dns_failure / invalid-TLS-fetched-unverified / SPA-shell paths all behave as designed. The Docker mount of a path outside the project folder was refused, which suggests file sharing is already restricted (user to confirm). No target site contacted yet.

## 2026-10-04 19:22 · H+? · RESULT: first triage of all 160 URLs (run triage-1)
Selftest re-ran first (30/30). 160 records, one per URL, about 2 minutes, from a residential US IP through the egress proxy. No target domain hit the egress deny list (all 38 denials in egress.log are selftest probes).

| status | n | what it actually is |
|---|---|---|
| live | 56 | 29 content pages, 27 SPA shells (little static text + scripts); 6 with invalid TLS certs (003, 004, 029, 036, 044, 139) |
| dns_failure | 53 | domain gone |
| http_error | 23 | 14× Cloudflare 522 + 1× 521/525/526 (origin down), 4× 404 (incl. Azure Front Door), 3× 402 (Shopify-style "payment required": store suspended), 1× 502 |
| tls_error | 14 | all handshake failures, none cert errors: TLSV1_UNRECOGNIZED_NAME / ALERT_INTERNAL_ERROR / HANDSHAKE_FAILURE (typical of a hostname dropped from Cloudflare or the host), 5 with an empty error |
| timeout | 10 | 9 connect timeouts (ERR_CONNECT_FAIL 110), 1 ReadTimeout (112) |
| suspended | 3 | 2× Cloudflare "Suspected phishing" interstitial (009 workers.dev, 035), 1× "account has been suspended" (159) |
| empty | 1 | default nginx page (153) |

Findings:
- 104/160 (65%) are not live, so A7 holds and the dead-site default verdict now dominates accuracy. The decision is still open (PLAN M0).
- The two Cloudflare phishing interstitials are third-party scam evidence for dead sites.
- tls_error may include TLS-fingerprint cloaking: Python's handshake isn't Chrome's. Recheck those 14 (and the ReadTimeout) with Chromium in M2 before treating them as dead.
- 402 is better read as `suspended` than `http_error` (proposed classifier tweak, not yet made).
- Sibling pairs differ: vnexchange.me tls_error vs vnexchange.top timeout; sebca.art 525 vs sebca.sbs DNS failure.
- Mobile-style hosts: 4 of the ~10 h5./m./web3. hosts are live (055, 057, 067; plus timeouts/522s for the rest).

## 2026-10-04 19:40 · H+? · DECISION: dead-site verdict policy and triage follow-ups
- **Dead sites (A6, DESIGN §5.2a):** three steps, first match wins:
  1. Wayback snapshot through the sandbox (archived pages are still hostile) → normal classifier, `scam_probability` shrunk toward 0.5 (`0.5 + 0.8·(p−0.5)`, to calibrate), `evidence_source: wayback`, no navigation.
  2. Domain / sibling / warning-page signals → lean scam, low confidence (0.5–0.65), `signals_only`.
  3. Otherwise `not_scam`, p=0.4, `none`.

  Why: 104/160 are not live and labels likely come from a scam feed; `status` + `evidence_source` keep each verdict's basis visible.
- **Wayback:** moved off the cut list into M2/M4, time-boxed to 2h of build time; if it overruns, the signals-only rule covers it. Archived sightings use `source: archive` with normal tier rules (to revisit if they pollute the primary list).
- **New `EvidenceSource` enum** (live / wayback / signals_only / none) on `Classification` and `OutputRecord`; §3.4 example and contract table updated.
- **Cloudflare "Suspected phishing" interstitial** (#009, #035) is a hard rule → scam. In M2, try one click through the warning to capture the real page.
- **Triage:** HTTP 402 → `suspended` (unpaid hosting/store). Done, with a test.
- **M2:** retry `tls_error` + `timeout` sites (incl. #112 ReadTimeout) once in Chromium before calling them dead (Python's TLS fingerprint may be cloaked against).
- **M6:** re-run triage on a different day before the final batch.
- **README limitations note:** some dead/timeout sites may be geo-blocking a residential US IP rather than down (A13).

## 2026-10-04 20:30 · H+? · DECISION: M2 step 1, extraction design details
- **API key placement (M2 plan):** a separate `llm-gateway` container holds the key; the crawler never does. Models: judge `claude-sonnet-5-5`, helper `claude-haiku-4-5`; measure on the first 10 sites. Solana-format strings (no checksum) only count next to a "SOL/Solana" label.
- **Validators:** own base58check and bech32/bech32m code (BIP-173/350 reference); EIP-55 via pycryptodome keccak (hashlib's sha3_256 is not keccak). Checked against published vectors (BIP-173/350, EIP-55, wiki examples, USDT/USDC contracts, XRPL genesis); one-character mutations are rejected.
- **Context windows:** a ±200-char window bled across page sections (a footer address inherited "deposit" from the section above). Labels and payment context now use a tight "near" context. For visible text: the address's own line plus up to 3 lines above, stopping at any line that holds another address-like token (each address owns the lines above it up to the previous address). For JSON/attributes/scripts: ±100 chars. The ±200 window remains for evidence snippets. Capture-time DOM-block context would be better still if pilots show mislabels.
- **Tier rules as implemented:** primary if the stage is authenticated/deposit, the source is QR or wallet mock, a payment keyword is in near context (not for scripts), or a network response names coin + network. QR codes count as payment context.
- **"Mentioned elsewhere on page" (0.4)** adds every compatible coin, not just one.
- **QR codes:** decoded from the full-page screenshot (covers img, canvas, CSS backgrounds) with zxing-cpp + Pillow.
- **Problem found:** YAML parses unquoted `0x…` as hex integers, so EVM blocklist entries loaded as numbers. All entries quoted (config + DESIGN §3.5); the loader now rejects non-strings.

## 2026-10-04 21:30 · H+? · DECISION: M2 step 3, classification v1 and the LLM gateway
- **llm-gateway container** holds the key (`env_file: .env` on that service only). It sits on the internal network with no direct internet and reaches only `api.anthropic.com` via a second Squid port (3129, `dstdomain` ACL). It:
  - chooses the model by caller role;
  - accepts a whitelisted subset of Messages params (no model, betas, server tools, MCP or containers);
  - caps `max_tokens` at 16k;
  - caches responses by request hash (not refusals);
  - logs token usage per site/purpose without content.

  Selftest (now 34 checks) proves: no ANTHROPIC* key in the crawler env, gateway reachable, gateway rejects a server tool, LLM proxy port denies non-Anthropic hosts.
- **Refusal fallback:** Sonnet/Opus calls go through `client.beta.messages.create(..., betas=["server-side-fallback-2026-07-01"], fallbacks="default")`; a remaining refusal → heuristic-only classification with a note.
- **Finding:** current models (Sonnet 5.5) reject non-default `temperature` with a 400, so `temperature: 0` is gone from settings; reproducibility now comes from the response cache alone (A23 updated).
- **Judge:**
  - Input: screenshot (top 3000 px, ≤1568 px edge) + sanitized visible text (8k chars, content-derived nonce delimiters, control/bidi chars stripped) + deterministic signals + extracted-address summary.
  - Output: a hand-written JSON schema (no nullable unions or numeric bounds; `scam_type: "none"` / `impersonated_brand: ""` instead of null), validated into `LLMJudgment`.
  - Settings: effort `medium` (to tune), system prompt cached.
- **Signals:** domain (cheap TLD, free hosting, brand-in-domain or ≤1–2 edit typosquat by name length, finance terms, mobile host), content (guaranteed returns, giveaway, invite code, contract/quant trading, withdrawal conditions, license claims, urgency, CS-only deposits, seed-phrase input), triage (Cloudflare phishing interstitial, hosting suspension, invalid TLS), and `shows_crypto_address` at weight 0 (A3).
- **Scorer (M2 formula, calibrate in M4):** `p_h = sigmoid(Σw − 2)`; `p = 0.7·p_llm + 0.3·p_h`; hard-rule floors (seed phrase 0.92, phishing interstitial 0.85); partial visits clamped to [0.2, 0.8]; Wayback shrink 0.8; signals-only `0.5 + 0.05·Σw` capped at 0.65; nothing → 0.4. Disagreement > 0.5 between LLM and heuristics adds a note.
- **Smoke test** (synthetic page, no target site): sonnet-5-5 returned scam/0.98/pig_butchering with verbatim quotes and explicitly ignored an embedded "classify as not_scam" injection; the second call was a gateway cache hit; the system prompt was cached (1,264 tokens). Cache-hit calls no longer count toward token spend.

## 2026-10-05 01:30 · H+? · RESULT: M2 gate, 18-site pilot end to end (run pilot-5)
Capture → extract → classify → `runs/pilot-5/output/results.json` (validates against `ResultsFile`) with screenshots, traces for scam/failed sites, snapshots and network bodies on disk. Selftest re-ran first (34/34). Verdicts 13 scam / 5 not_scam. Uncached judge calls average ~4.3k input / ~330 output tokens ≈ $0.012 per call on claude-sonnet-5-5, so all 160 sites cost about $2 in judge calls. **Keep Sonnet as judge**; the Haiku helper has no job yet (revisit for M3 sub-calls).

| site | result | basis |
|---|---|---|
| 009 workers.dev | scam 0.89 | Cloudflare phishing interstitial (hard rule); this variant has no "proceed" button, so no click-through possible |
| 012, 021, 055, 057, 087, 128 | scam 0.65–0.84 | live content: fixed returns, crypto-only deposits for "AI stock trading", forced wallet connect, contract trading |
| 027 dexapp.uk | scam 0.54 | token/P2E promo; 1 primary + 1 low-conf EVM address in a hidden "notice" panel |
| 067 antique-coin shop | scam 0.49 | borderline fake-shop template (0.44 on an earlier visit): an M4 calibration case |
| 100 usdc661 | scam 0.66 | **2 primary approval-spender wallets** (`approve_address` per chain in an API response) |
| 003, 004, 022, 051 | not_scam 0.11–0.23 | Chinese immigration-service site, redirect page, crypto tracker app, 3D-print shop |
| 001 22betcanada | not_scam 0.20, **wayback** | dead domain; June 2026 snapshot is a disclosed 22Bet affiliate site |
| 107, 108, 112 | scam 0.53–0.65, signals_only | dead, no usable archive (107: CDX timeout); brand-in-domain upbit/bitget, finance terms |

Problems found and fixed during the pilot:
1. **Screenshot hangs lost whole snapshots (6/18 sites).** Playwright waits for web fonts that never load. Artifacts are now saved independently, with a CDP screenshot fallback and text-only judging when no image exists.
2. **Token contracts reported as primary (23 on site 100).** The ±100-char payment window caught neighbouring JSON key names. Now JSON-key-aware: values under contract/token keys are dropped, payment/spender keys (incl. the enclosing object key) make an address primary, and scripts stay low-confidence (DESIGN §3.4 updated). The same change surfaced the approval-drainer spender wallets.
3. **Wayback silently off.** `archive_fallback` was flipped only in DESIGN, not in config. Fixed; new test asserts config/settings.yaml == the DESIGN §3.5 block.
4. **Highlight screenshot of an invisible address** (027: hidden notice panel) was an empty page. Now highlights only visible, in-viewport occurrences; otherwise the plain snapshot screenshot is used.
5. CDX lookups time out sometimes: one retry with a longer timeout.

Open for later milestones:
- The LLM and heuristics disagree on most scams (heuristics under-weighted) → M4 calibration.
- Live re-visits give slightly different probabilities (dynamic pages → new LLM requests; e.g. 067 0.44 → 0.49). Rescore from saved evidence is reproducible (gateway cache).
- Addresses hidden behind UI (027 "Show Notice") → M3 agent.
- Possible M3/M4 signal: a token-approval spender in site config (approval drainer).

## 2026-10-05 02:10 · H+? · DECISION: read-only review page (`make review`)
`make review RUN=<id>` writes `runs/<id>/review/index.html`, `style.css` and `labels_template.csv` from `checkpoint.jsonl` and the saved screenshots: no containers, no network, no site visits. Cards are ordered borderline first (|probability − threshold| ≤ 0.15, closest first), then the rest by site id; I chose the 0.15 band since the request left "borderline" undefined.
- **Safety:** static HTML; all page/LLM text escaped and stripped of control/bidi characters; truncated with an explicit marker; no `<script>`, iframes or external URLs; saved page HTML, traces and network bodies are never embedded or linked; only PNGs under the run's `sites/` folder are referenced, by relative path.
- **CSP deviation:** the requested `default-src 'none'; img-src 'self'` blocks inline `<style>`, so the CSS is a sibling `style.css` and the policy adds `style-src 'self'`. Checked in Chromium from `file://`: all 15 screenshots of pilot-5 load, styles apply, no CSP violations.
- `labels_template.csv` is for hand labeling (`my_label`, `my_notes` blank); it never touches `eval/labels.csv`, which stays a manual copy step.

## 2026-10-05 03:20 · H+? · DECISION: content-signal detectors from pilot-5 review (fix 1 of 4)
Review of pilot-5 showed content signals barely fired: #012 ("6.5 % Weekly", "Total profit + Capital"), #087 ("Silver - 10% … Duration: 1 Week", "registered with and duly regulated by the US's … (SEC)") and #021 (stock-trading platform that takes only Bitcoin, Ethereum, Binance Coin, Tether, Tron) carried only domain signals. Added, reusing the existing tiers and weights (scoring untouched until M4):
- `guaranteed_returns` (strong) now also matches a percent per week/month and plan tiers (percent followed within 120 chars by "Duration/Term/Period: N hours/days/weeks/months"). A bare percentage is deliberately not enough: stock-quote text like "+1.02%" must stay quiet.
- `profit_plus_capital` (moderate, new): "profit + capital", "principal + interest".
- `license_claims` (moderate): "registered with / regulated by / licensed by … Securities and Exchange Commission / SEC / FCA / ASIC / CFTC…" and "SEC registered".
- `withdrawal_conditions` (moderate): also "activation wallet/address/payment" (fired on #027's "Activation Wallet").
- `crypto_only_payments` (moderate, new): ≥3 coins offered within 250 chars after a deposit/payment word on a page selling a non-crypto product (stocks, insurance, real estate, checkout) with no card/bank/PayPal option near that text. First version checked the whole page for "Visa" and missed #021 because its stock-ticker widget lists Visa; the check is now local to the payment text.

Tests use the saved pilot texts (copied to `tests/fixtures/pilot_texts/`, since `runs/` is gitignored) and negatives (#022, #051, stock quotes, ordinary percentages).

**Rescore of pilot-5 (saved evidence, no visits), heuristic p_h → final p:** #012 0.18→0.95 / 0.73→0.96; #087 0.50→0.99 / 0.84→0.98; #021 0.12→0.38 / 0.65→0.71; #027 0.12→0.38 / 0.54→0.62 (activation wallet). Every other site's heuristic score is unchanged and no verdict flipped. 1 of the 4 target gaps remains a heuristic/LLM disagreement: #055, #057, #100, #128 still sit at p_h 0.18–0.38 (their text isn't covered by these rules); the LLM carries them.

## 2026-10-05 03:50 · H+? · DECISION: parked pages detected on the rendered page too (fix 2 of 4)
#004 (adnins.cloud) was `live`: HTTP triage got a "Redirecting..." stub and the real page, "This page has been created by ParkLogic.", only appears after the JS redirect. So the detector lives in two places now:
- **Triage detector** (`classify_response`) gained ParkLogic plus other providers: fingerprints `parklogic`, `undeveloped.com`, `hugedomains.com`, `afternic.com/` (any page length), hosts `undeveloped.com`, `bodis.com`, and short-page phrases ("domain is parked", "this web page is parked", "domain is available for purchase", "inquire about this domain", "make an offer on this domain", "domain name is for sale"). Existing: Sedo, ParkingCrew, Bodis, Above, Dan, Afternic, "parked free, courtesy of".
- **`pipeline.rendered_parked()`** runs the same detector on the last rendered snapshot, inside `analyze()` so live runs and `make rescore` agree. A parked page flips the triage status to `parked`, takes the dead-site rule (Wayback first in live runs, then signals-only / nothing), and the LLM is not called. Tests: ParkLogic fixture (the real #004 page), other providers, a long real page that merely says "parked" stays live, and an `analyze()` test with no LLM.

**Result for #004 (rescore, no visits): status live → parked; verdict not_scam 0.17 → scam 0.55 (signals_only).** That flip is driven purely by weak signals: cheap `.cloud` TLD + invalid TLS certificate (0.5 each) → 0.5 + 0.05·1.0 under the signals-only rule. It follows the policy as decided, but it means a bare parked domain with nothing but a cheap TLD can be called scam. **M4 calibration case:** consider requiring a moderate-or-stronger signal (brand/sibling/warning page) before the signals-only rule leans scam. Not changed now (scoring untouched until M4).

## 2026-10-05 04:20 · H+? · DECISION: drop addresses the page labels as a contract (fix 3 of 4)
#027's low-confidence `0xe90D…` is introduced on the page as "Contract Address: 0xe90D…" (the project's own token contract; the wallet `0xD499…` sits under "Wallet Address"). Extraction now drops an address when the text right before it (own line, or the nearest line above when the address starts its line) is a contract label: "Contract Address:", "Token address:", "Smart/NFT/presale contract (BEP-20):", "合约地址". Layouts tested: same line, label on the line above, parenthetical, Chinese.
- **Decided once per address across sources.** First version only dropped the visible-text occurrence; the rescore still listed `0xe90D…` as low-confidence because the same string appears in a "Copy Address" button attribute with no label next to it. Extraction is now two-pass: pass 1 collects every candidate and marks contracts (label or contract-key); pass 2 skips marked addresses in all sources. Reported once in the "ignored N token-contract address(es)" note.
- **Exception I added:** a label line that tells visitors to send funds there ("Send ETH to the presale contract: 0x…", "invest … to") is kept. A presale/payment contract can be the scammer's collection address, which is exactly what TRM wants. Easy to remove if you'd rather drop every "contract" label.
- Not covered: a contract that the page never labels as such (e.g. only named in a prose sentence), and a snapshot-to-snapshot case (labelled in one snapshot, bare in another); with one snapshot per site today this doesn't occur.
- **Result (rescore, no visits):** #027 reports only `0xD499…` (primary); low-confidence list is empty. #100 unchanged (2 primary approval wallets).

## 2026-10-05 05:10 · H+? · DECISION: weak "random-looking domain" signal (fix 4 of 4)
`random_looking_domain` (weak, weight 0.5, like the other weak domain signals; skipped for free-hosting hosts). Flags a registrable-domain label when it has:
- digits mixed into letters: letter-digit-letter (`fxo2o`, `r7t2mj`), a run of 3+ digits next to letters (`usdc661`, `3455n`, `datahydru602`, `openai9315`), or a short name with a two-digit tail (`gete84`, `lon28`); not `22betcanada`, `coinhako01`, `luminex3`;
- almost no vowels (≤15% of 6+ letters: `gxecgcx`, `blsyqsz`, `ceffknks`);
- letter pairs no English word uses: mean ln P(bigram) < −3.9 over 5+ letters (`bqpxaf`, `zfxfa`, `twxauxjpfivt`). The table (`classify/bigrams.py`, 6 KB) is derived from the letter pairs of macOS's /usr/share/dict/words (public-domain Webster's Second); only the table is stored.

Run over all 160 domains it flags 30; each looks machine-generated or digit-stuffed and no ordinary name is flagged. **Known limitation, tested as such:** pronounceable made-up names are not caught. `kisngaf` (−3.26) scores the same as `claudetf` (−3.25), `sebca` (−3.25) and `bitget` (−3.10); `koserwry`, `proymsi`, `busigirh` likewise. A threshold that caught them would flag real names too. I kept it conservative on purpose, because a weak signal can flip a dead site under the signals-only rule (see fix 2).

## 2026-10-05 05:10 · H+? · RESULT: pilot-5 rescore after the four fixes (saved evidence, no visits)
Heuristic p_h (before → after) and final p; "before" is the original `checkpoint.jsonl`:

| site | p_h | final p | verdict | what changed |
|---|---|---|---|---|
| 012 | 0.18→0.95 | 0.73→0.96 | scam | weekly returns, profit + capital |
| 087 | 0.50→0.99 | 0.84→0.98 | scam | plan returns ("Duration: 1 Week"), SEC claim |
| 021 | 0.12→0.38 | 0.65→0.71 | scam | crypto-only payments for stock trading |
| 027 | 0.12→0.38 | 0.54→0.55 | scam | "Activation Wallet"; contract `0xe90D…` no longer reported |
| 067 | 0.18→0.27 | 0.49→0.50 | scam | random-looking domain (3455n.top) |
| 100 | 0.18→0.27 | 0.66→0.68 | scam | random-looking domain (usdc661.com) |
| 004 | 0.27→0.27 | 0.17→0.55 | **not_scam→scam** | now `parked`; dead-site rule leans scam on .cloud TLD + invalid cert alone |

All other 11 sites unchanged. Verdicts 13/5 → 14/4; the one flip (#004) is a calibration case for M4, not a detector win: a parked domain with only weak signals gets 0.55. Still low heuristic scores on #055, #057, #100, #128 (their text isn't covered); the LLM carries them.

## 2026-10-05 06:00 · H+? · FINDING: how much of the dead-site verdict rests on weak signals (rule unchanged)
Computed from `runs/triage-1/triage.jsonl` with current code, no visits: 104 of 160 sites not live (53 dns_failure, 23 http_error, 14 tls_error, 10 timeout, 3 suspended, 1 empty). Under the current signals-only rule:
- 74 get `scam` (2 by the Cloudflare phishing-warning hard rule, 11 on a moderate signal such as brand-in-domain/typosquat/free hosting/hosting suspended, **61 on weak signals only**), and 30 have no positive signal and get `not_scam` 0.4.
- Weak-only sites by number of weak signals: 36 have one, 19 two, 5 three, 1 four. The signals are mostly `finance_terms_in_domain` (32), `random_looking_domain` (21) and cheap TLDs (~40 across many TLDs); `invalid_tls_cert` only once.
- **(a) require ≥1 moderate signal:** all 61 weak-only sites flip scam → not_scam; 13 of 104 stay scam (91 end not_scam).
- **(b) weak-only needs ≥3 weak signals** (anything with a moderate or stronger signal still leans scam): 55 flip (36 + 19); 19 of 104 stay scam, of which 6 are weak-only.
Caveats: this is an upper bound for the signals-only population. 24 tls_error/timeout sites get a Chromium retry first, Wayback may supply content for some (e.g. #001 resolved to a real page), and the sibling pass adds scam verdicts back for siblings of live scams. The rule is NOT changed; the decision and a re-count after those steps are on the M4 list. One thing the numbers say regardless of choice: 82% of dead-site scam verdicts today rest on weak evidence alone.

## 2026-10-05 06:00 · H+? · FINDING: the 30 domains flagged `random_looking_domain`
Digits (10): datahydru602, small1006, fxo2o, gete84, lon28, 3455n, openai9315, r7t2mj, usdc022, usdc661. Almost no vowels (8): gxecgcx, twfxcc, blsyqsz, btcctw, ceffknks, usdcsyh, yqeydfhr, xtbcopy. Letter pairs (12): bqpxaf, byexdd, bitxex, nexcofxs, twatfx, coinexvto, coinruq, feyru, goodcmvip, rexiqok, twxauxjpfivt, zfxfa. The letter-pair table is English-only, so a non-English word or a pinyin-initials abbreviation (plausible for usdcsyh, blsyqsz, zfxfa, goodcmvip) could be flagged; unverified without a native reader. The user is checking the list by eye; M4 item added.

## 2026-10-05 06:00 · TODO-LATER: M4 additions
- **Mobile exchange template signal.** Menu cluster (Recharge/Withdraw/Finance/Loan/Service/Contract/Assets/Team/Chat Room/"AI Quant"/"Follow") plus a forced Connect Wallet modal. Saved pilot texts: #100 matches 9 of 12 words, #057 six, #055 only Connect Wallet (plus Contract/Follow), #128 none (it is a shop); #027 (token project) shares generic words (Contract, Follow, Team, Assets), so the rule must need a cluster of the distinctive words.
- **Domain/content mismatch signal (e.g. #003).** Confirmed NOT done and, until now, not logged as deferred: DESIGN §5.4 lists "mismatched branding" among the planned signals but no code implements it. #003 (`addmklwhisky.com`, a Chinese immigration-service site) scored not_scam 0.23, so this is a real gap. Options in PLAN M4.
- Signals-only rule decision (see FINDING above) and a re-count after rechecks, Wayback and the sibling pass.

## 2026-10-05 06:40 · H+? · DECISION: finance words in a domain no longer count for dead sites; dead-site rule (a)/(b) still open
- Decision: `finance_terms_in_domain` is dropped from the dead-site (no-content) rule (`scorer.DEAD_SITE_IGNORED`). It fired on 3 of the 4 sites confirmed legitimate in pilot-5, so by itself it says nothing about a site we can't see. It still appears on live sites as one weak signal. Not hidden from the listing either: dead-site records simply no longer carry it.
- Effect on `triage-1` (104 not-live sites, current code, no visits): scam verdicts 74 → 60 (14 flips scam → not_scam); weak-only scam verdicts 61 → 47 (1 weak signal: 35, 2: 10, 3: 2); not_scam 30 → 44.
- **The (a)/(b) choice stays open.** After the full live run, compute the scam base rate among live sites and each signal's scam/legit ratio on live sites, then propose the dead-site rule from those numbers (PLAN M6 item added).
