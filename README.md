# scam-website-detector-agent
Project BloodHound

Skeleton: one-line bullets drawn from `docs/LOG.md` and `docs/DESIGN.md`. Prose and final numbers come at M7; `TODO(M6)` marks every number that the batch run fills in.

## Summary & results
- Task: for each of 160 URLs, classify scam / not_scam and extract every crypto address, including ones shown only after registering or logging in → `output/results.json`.
- One record per input URL, with `is_scam`, `classification`, `scam_probability`, `confidence`, site `status`, `processing_status`, `evidence_source`, primary and low-confidence addresses (DESIGN §3.4).
- Verdicts: TODO(M6) scam / TODO(M6) not_scam; live TODO(M6), dead TODO(M6) (triage-1: 56 live, 104 not live).
- Addresses: TODO(M6) primary addresses on TODO(M6) sites; TODO(M6) found only behind registration.
- Accuracy on hand labels: **interim, 8 labels only** (the plan wants 25+; `eval/labels.csv`, `make eval RUN=<id>`): on the capture-only run `capture-2`, judged from saved evidence, precision 100% and recall 80% (4 of 5 likely scams found, 3 of 3 probably-legitimate shops cleared) at both 0.45 and 0.5; the miss is 003, a consultancy page on a whisky domain at p=0.22. TODO(M6): the same on 25+ labels.
- Navigation on real sites: reached a deposit page on TODO(M6) of TODO(M6) attempted; `blocked_at` tally TODO(M6).
- Live-site structure (13 of 56 live sites with saved HTML; pilot-5): TODO(M6) full tally; so far 2 address on landing, 6 registration-gated, 1 wallet-gated, 4 unclear.
- Mock exchange (M3 step E, Sonnet 5.5): 18/18 solvable runs found all six addresses (first by step 9, all by step 21); gated variants 12/12 after the CAPTCHA and history fixes (10/12 before); zero policy refusals; about $2.4 per 30-run batch.
- Cost: TODO(M6) total, TODO(M6) per site. Measured so far from the gateway usage log (`runs/<id>/usage.json`): judging 42 saved pages $0.47 (about $0.011 each); a live navigation of 3 real sites $0.35 (012 $0.22, 071 $0.08, 145 $0.05); a mock run $0.03–0.12.
- Confidence: `scam_probability` ≥ 0.45 ⇒ scam (leans toward recall); `confidence` = P(stated verdict correct), so 0.45–0.5 is "scam" with confidence < 0.5, which marks the shaky verdicts.
- Run it: `make selftest` → `make run` → `make report`; `make review RUN=<id>` for a read-only HTML review page.

## Architecture
- Pipeline: triage (plain HTTP via egress proxy) → capture (Chromium) → navigate (agent, scam-or-uncertain sites) → extract → classify → JSON (DESIGN §5.1).
- Capture and classification are separate stages: `make rescore` re-classifies from saved evidence without revisiting sites.
- Extraction: own validators (base58check, bech32/bech32m, EIP-55, TRON, SOL by label), JSON-key-aware, contract labels dropped, QR decoded from screenshots.
- Classification: Claude judge (screenshot + sanitized text + signals) fused with weighted heuristic signals; hard-rule floors; dead sites → Wayback → signals → not_scam (DESIGN §5.2a). The rubric (every signal with tier, weight and trigger, and the fusion formula `p = 0.7·p_llm + 0.3·sigmoid(Σweights − 2)`) is the table in DESIGN §5.4; a test keeps it in step with the code. After navigation the judge sees the landing page and the agent's best page, and signals come from every snapshot.
- Navigation agent: own observe → decide → policy → act → extract loop; Claude picks whitelisted tools; every action checked in code by `policy.py` (DESIGN §5.5).
- Element finding: accessibility roles plus non-semantic clickables (`cursor: pointer`, click handlers) behind an `ElementProvider` interface.
- LLM gateway container holds the API key; the crawler never sees it; whitelisted request shape, response cache, per-site usage log.
- Evidence per site: snapshots (HTML, text, aria, screenshot, network bodies), highlight screenshots of each address, agent trace, Playwright trace.

## Alternatives
- browser-use / Stagehand / LangGraph as the navigator: rejected for an own loop (enforced whitelist, network capture, per-site contexts); Stagehand kept as a swappable `ElementProvider`.
- Throwaway cloud server: rejected for hardened Docker on the Mac (blast radius vs time budget; DESIGN §6.1).
- Host firewall rules: rejected for an egress proxy container that works the same on a cloud box.
- Browserbase recordings: rejected for local Playwright traces.
- One action per model reply: rejected for batched fills + one click (registration 7 → 2 steps).
- Growing multi-turn agent conversation: rejected for one self-contained request per step with a compact history.
- Typed `AgentAction` fields: rejected; scalars map onto `value` so the output contract stays unchanged.
- Stopping on the first gate refusal: rejected; gate hints go back to the model, with a fallback `blocked_at`.

## Creative
- Local mock scam exchange with 10 variants, traps, decoy contracts and per-account addresses; a scripted "evil model" tries every trap and the forbidden-endpoint log must stay empty.
- Mock mode reaches loopback only, enforced at the network level (dead proxy) because Playwright routing misses server redirects (found by selftest).
- Approval-drainer spender wallets surfaced from site config (`approve_address` keys).
- Random-looking-domain signal from an English letter-pair table.
- Read-only HTML review page with a strict CSP for hand labelling from saved evidence.
- Multiple asset/network labels per address (one 0x address for ETH + USDT-ERC20).
- Capture-only mode (`make capture`): landing evidence for every live site with no clicks, agent or model calls, used to tally gate types before spending on the pilot.
- Prompt-injection defence in code: nonce-delimited untrusted blocks, and a policy that ignores what the model "wants".

## With more time
- Mock wallet (`window.ethereum` that refuses to sign): cut from v1 because only 1 of 56 live sites (2%) is wallet-gated on a landing-page tally; wallet-gated sites end `blocked_at: wallet_required`. Worth building if a larger or later sample shows more, since a modal-gated site may hide more than the landing page shows.
- Group sites by shared template: 9 of the 56 live sites (125, 128-130, 141-142, 150-152) share one Chinese-language shop template, so they probably come from few operators. Clustering on template/HTML structure would cut duplicate work and give TRM operator-level leads.
- Stagehand `ElementProvider` trial if element finding dominates the pilot's failure tally.
- Residential/regional proxies to separate geo-blocking from dead sites.
- Domain/content mismatch signal; mobile-exchange template signal; dead-site rule (a)/(b) decided from live-site base rates.
- Register twice per site to test per-account addresses.
- Cloud comparison run on a disposable server.

## Assumptions & limitations
- Evidence was collected from a residential US IP; some "dead"/timeout sites may be geo-blocking rather than down (A13).
- Dead sites are judged on Wayback evidence first, then domain/sibling/warning signals; `evidence_source` says which. TODO(M6) share of dead-site verdicts rest on weak signals only.
- Parts of the brand list were built while reviewing this URL list; brand hits overstate how well the signal generalizes.
- Pronounceable made-up domains are not caught by the random-domain signal.
- Element list covers the main frame only (no iframes or shadow DOM); `click_at` is the fallback.
- mail.tm verified live through the proxy (create, poll, read one plain-text message, 2026-10-06); not tested: rate limits, token expiry, mail with codes or links from a real site.
- Classification lean toward recall: precision/recall trade-off TODO(M6).
- Navigation heuristics (`logged_in`, coverage by label confidence) can misjudge unusual sites.
- Off-site script navigations (timers, buttons without a link, `window.open`) are cancelled inside the page before the browser starts them, so no connection is opened (proxy log checked by `make selftest`). Server-side redirects are not covered: they are undone after the fact. The route guard below that layer answers 204, but Chromium opens a preconnect (a TLS handshake, 3.8–6.7 KB in the proxy log, no page) to a navigation's target before a route handler runs; none of the Chromium switches tried removes it (experiment of 2026-10-07, `docker/preconnect_probe.py`). Browser-internal pages (`chrome://`) cannot be intercepted by Playwright's routing; page scripts cannot reach them and the policy never asks.

## Safety
- Crawler in hardened Docker (non-root, no capabilities, seccomp, Chromium sandbox on, downloads off), internal network only; egress via Squid that denies private/link-local/loopback by resolved IP and logs every request.
- `make selftest` must pass before any real visit (50 checks); real-site runs and mock runs fail to start if any check fails; there is no waiver. The DNS-rebinding probe uses names the proxy resolves from its own `/etc/hosts` to link-local, private and loopback addresses, so it does not depend on the network's DNS, and "could not resolve" counts as a failure. Further checks: the root filesystem is read-only, extensions are off, and the in-page navigation guard opens no connection to an off-site target while the same navigation without it does.
- API key only in the gateway container; the crawler talks to the gateway, which talks only to api.anthropic.com.
- Agent policy in code: never pay, sign, withdraw, claim a payment, upload receipts or IDs, connect a wallet (until a mock wallet exists), or leave the site; placeholders only for personal data (synthetic identity, 555 phone numbers).
- CAPTCHAs: at most one click on a checkbox widget (reCAPTCHA checkbox, Turnstile); any challenge or a remaining gate ends the site with `blocked_at: captcha`; enforced in code; never solved via services.
- Page content is untrusted data: delimited, control/bidi characters stripped, never followed as instructions.
- Hard per-site token caps, a wall-clock time limit that cancels in-flight calls, and a session spend cap.
- Off-site targets are never followed, except one Login/Register/App/Trade link the operator confirms (never a social, messenger or app-store link, never a real brand's site; the agent is then locked to the new domain). Every refused or followed one is recorded in `linked_domains`, and the hop in `hops`.
- Operator controls on real sites: a stop file (`touch runs/<id>/STOP`) ends the run mid-call, `--confirm-submit` asks before each site's first form submission (placeholders only are shown), and a session spend cap stops new navigations.
