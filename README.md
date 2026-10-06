# scam-website-detector-agent
Project BloodHound

Skeleton: one-line bullets drawn from `docs/LOG.md` and `docs/DESIGN.md`. Prose and final numbers come at M7; `TODO(M6)` marks every number that the batch run fills in.

## Summary & results
- Task: for each of 160 URLs, classify scam / not_scam and extract every crypto address, including ones shown only after registering or logging in → `output/results.json`.
- One record per input URL, with `is_scam`, `classification`, `scam_probability`, `confidence`, site `status`, `processing_status`, `evidence_source`, primary and low-confidence addresses (DESIGN §3.4).
- Verdicts: TODO(M6) scam / TODO(M6) not_scam; live TODO(M6), dead TODO(M6) (triage-1: 56 live, 104 not live).
- Addresses: TODO(M6) primary addresses on TODO(M6) sites; TODO(M6) found only behind registration.
- Accuracy on hand labels: precision TODO(M6) / recall TODO(M6) at threshold 0.45, and at 0.5 TODO(M6).
- Navigation on real sites: reached a deposit page on TODO(M6) of TODO(M6) attempted; `blocked_at` tally TODO(M6).
- Mock exchange (M3 step E, Sonnet 5.5): 18/18 solvable runs found all six addresses (first by step 9, all by step 21); gated variants 10/12 before the CAPTCHA fix, TODO(M6) after; zero policy refusals; $2.96 for 30 runs.
- Cost: TODO(M6) total, TODO(M6) per site (judge ≈ $0.012/call; navigator ≈ $0.07–0.15 per mock run).
- Confidence: `scam_probability` ≥ 0.45 ⇒ scam (leans toward recall); `confidence` = P(stated verdict correct), so 0.45–0.5 is "scam" with confidence < 0.5, which marks the shaky verdicts.
- Run it: `make selftest` → `make run` → `make report`; `make review RUN=<id>` for a read-only HTML review page.

## Architecture
- Pipeline: triage (plain HTTP via egress proxy) → capture (Chromium) → navigate (agent, scam-or-uncertain sites) → extract → classify → JSON (DESIGN §5.1).
- Capture and classification are separate stages: `make rescore` re-classifies from saved evidence without revisiting sites.
- Extraction: own validators (base58check, bech32/bech32m, EIP-55, TRON, SOL by label), JSON-key-aware, contract labels dropped, QR decoded from screenshots.
- Classification: Claude judge (screenshot + sanitized text + signals) fused with weighted heuristic signals; hard-rule floors; dead sites → Wayback → signals → not_scam (DESIGN §5.2a).
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
- Prompt-injection defence in code: nonce-delimited untrusted blocks, and a policy that ignores what the model "wants".

## With more time
- Mock wallet (`window.ethereum` that refuses to sign) once wallet-gated sites are counted in the pilot.
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
- mail.tm not yet exercised against the live API at M3 (TODO(M6) result).
- Classification lean toward recall: precision/recall trade-off TODO(M6).
- Navigation heuristics (`logged_in`, coverage by label confidence) can misjudge unusual sites.

## Safety
- Crawler in hardened Docker (non-root, no capabilities, seccomp, Chromium sandbox on, downloads off), internal network only; egress via Squid that denies private/link-local/loopback by resolved IP and logs every request.
- `make selftest` must pass before any real visit (41 checks). A mock-only waiver exists for one DNS-filtered network; real-site runs keep the full gate. TODO: DNS-independent rebinding probe before step F.
- API key only in the gateway container; the crawler talks to the gateway, which talks only to api.anthropic.com.
- Agent policy in code: never pay, sign, withdraw, claim a payment, upload receipts or IDs, connect a wallet (until a mock wallet exists), or leave the site; placeholders only for personal data (synthetic identity, 555 phone numbers).
- CAPTCHAs: never solved via services; a CAPTCHA gate ends the site with `blocked_at: captcha` (one-click checkbox rule: in progress).
- Page content is untrusted data: delimited, control/bidi characters stripped, never followed as instructions.
- Hard per-site token caps and a session spend cap.
