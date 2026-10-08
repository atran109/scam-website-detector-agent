# Project BloodHound

A hardened browser agent that classifies 160 supplied websites as scam/not-scam and extracts
validated cryptocurrency addresses, including addresses revealed only after registration,
login, email verification, or deposit-page navigation. The submission is
[`output/results.json`](output/results.json); evidence screenshots are in
[`output/screenshots/`](output/screenshots/).

## Results

The final run (`m6-final-20261007`) completed all 160 records with no partial or failed record.

| Result | Count |
|---|---:|
| Scam / not scam | 77 / 83 (live content 34 / 11) |
| Live / non-live at final triage | 43 / 117 |
| Primary address findings | 19 (17 unique) on 8 sites |
| Low-confidence findings | 320 (319 unique) on 2 sites |
| Navigation attempted / deposit page reached | 39 / 7 |
| Hand-label accuracy | 96% (24/25) |
| Hand-label precision / recall / F1 | 100% / 95% / 98% |
| Address-label precision / recall | 100% / 100% (3/3) |

The status breakdown is 53 DNS failures, 43 live, 19 HTTP errors, 15 TLS errors, 10 timeouts,
8 empty, 6 parked, and 6 suspended.

Verdicts by `evidence_source` (filter on it; the dead-site rows are leans, not findings):

| `evidence_source` | Scam | Not scam |
|---|---:|---:|
| `live` (page content, judged) | 34 | 11 |
| `wayback` (archived page, judged, shrunk toward 0.5) | 3 | 2 |
| `signals_only` (no content, domain or probe signals) | 40 | 28 |
| `none` (no content, no signal) | 0 | 42 |

**Dead-site rule.** Chosen from the final run's data with `eval/dead_site_rule_report.py`, with no
site visits.

- **The rule.** A site without content leans scam (p 0.5–0.65) only on a machine-generated-looking
  name (`random_looking_domain`), a brand in a domain the brand does not own, a brand typosquat, a
  hosting-takedown page, or a sibling domain judged a scam. A provider phishing warning stays a
  hard rule. Anything else (cheap TLD, invalid certificate, free hosting, mobile host, finance
  words) is listed but gives not-scam at p 0.4.
- **The data.** On the 45 live-content sites (34 scam, 11 not), `random_looking_domain` fired on 7
  scams and 0 others. Cheap TLDs separated weakly (18 vs 3). Finance words did not separate at all
  (12 vs 4, the same rate on both). The brand, typosquat and takedown signals were too rare on live
  sites to measure (at most 4 each), so they are kept on their merits. Caveat: the judge saw these
  signals and the URL, so live verdicts are not independent of them.
- **The rules not chosen,** on the same 110 no-content records:
  - the previous rule (any moderate signal or three weak ones): 22 scam / 88 not;
  - treating every unknown site at the live base rate (75.6%, shrunk to p 0.70): 110 / 0;
  - only the one measured signal: 23 / 87, which drops every brand-impersonation lean.

  The chosen rule gives 40 / 70. It flipped 18 sites to scam, all on a random-looking name.

The 25-site hand-label set has TP=21, FP=0, FN=1, TN=3 at both 0.45 and 0.50 thresholds. This is
a small, deliberately reviewable sample—not a population accuracy claim. The labels are skewed
toward suspected scams (22/25), and the three-address recall check covers one known deposit site.
By author (`labeled_by` in `eval/labels.csv`): my 8 labels give TP=4, FP=0, FN=1, TN=3 (100%
precision, 80% recall) and contain all three negatives and the one miss; the 17 written by the AI
assistant from saved screenshots are all scams and all match the pipeline (17/17). Those 17 are
not independent of the system they evaluate, so the 8-label figures are the honest ones.

**Provenance.** One published record merges two saved runs. Site 012 (`bradfordtradeins.com`)
keeps the final run's classification, but its addresses and `navigation` summary come from pilot
run `pilot-20261007b`. The final run hit its 180 s navigation limit after BTC and EVM; the pilot,
at 300 s, also reached the TRON address. The record's `notes` say so. No other record is merged.

The accepted full run and crash recovery cost approximately $4.12. Each cached rescore, including
the one that applied the dead-site rule, cost $0.00; preserved per-site accounting totals 2,724,575 input and 87,888 output tokens. The local
mock regression separately passed all 13 variants (10 solvable and 3 gated).

## What “scam” means

A scam intentionally deceives a visitor into surrendering money, crypto, credentials, a seed
phrase, or wallet authority. The taxonomy includes fake exchanges, HYIPs/investment schemes,
pig-butchering fronts, phishing, wallet drainers, giveaways, fake recovery, fake shops, and fake
tokens. Merely being offline, amateur, crypto-related, or risky is not enough.

Evidence is tiered:

- **Strong:** nearly decisive alone, such as a seed-phrase request or a provider phishing warning.
- **Moderate:** meaningful but contextual, such as guaranteed returns or a deposit address exposed
  after registration.
- **Weak:** supporting evidence only, such as a cheap TLD, invalid certificate, or random-looking
  domain.

For live content, a Claude judgment is fused with deterministic signals. For a site without usable
content, the pipeline tries a saved Wayback page, then calls it scam only if the domain looks
machine-generated, names a brand it does not belong to, or the host shows a takedown page (the
dead-site rule, below). Otherwise it emits not-scam at low confidence. `evidence_source` makes that distinction explicit.

## Architecture

```text
data/urls.txt
     |
     v
HTTP triage ---> Wayback fallback --------------------------+
     |                                                       |
     v                                                       v
Chromium capture --> deterministic extraction --> signals + Claude judge
     |                    |                                  |
     |                    +--> checksum/blocklist/labels     |
     v                                                       |
navigation trigger --> observe/decide/policy/act loop -------+
     |                                                       |
     +--> register/login/email/deposit --> capture each step  |
                                                             v
                         checkpoint.jsonl --> rescore --> results.json
```

The browser runs as a non-root user in a disposable, read-only Docker container. Its internal-only
network can leave only through a Squid proxy that rejects private, loopback, link-local, reserved,
and non-web destinations. A separate gateway is the only container with the Anthropic key. Every
real-site command depends on a 50-check isolation self-test.

The navigator is a small Playwright state machine, not an unconstrained computer-use agent. Claude
selects whitelisted actions; code enforces same-domain navigation, synthetic placeholders, bounded
amounts, CAPTCHA/gate stopping, and prohibitions on paying, signing, withdrawing, uploading IDs or
receipts, and claiming payment. Page text is nonce-delimited untrusted data. Full details and the
threat model are in [`docs/DESIGN.md`](docs/DESIGN.md).

Capture and classification are separate. HTML, visible text, accessibility state, screenshots,
text network responses, QR decodes, and action traces are saved once; `make rescore` can tune the
classifier without revisiting hostile or changing sites.

## Crypto-address model

An address **format** says how a string is encoded (for example BTC bech32, EVM `0x…`, or TRON
base58). A **network** says where it is usable (Ethereum, BSC, Polygon, Tron). An **asset** says what
may be transferred (ETH, USDT, USDC). One EVM address can legitimately carry several
asset/network labels, so labels are a list and each has a confidence and evidence string.

`crypto_addresses` contains checksum-valid addresses seen in a deposit/payment context.
`low_confidence_addresses` contains valid-looking addresses without that context, such as values
found only in a script or marketplace API. Token contracts, burn/example values, and configured
blocklist entries are excluded. Each address is returned exactly as displayed plus a normalized
form, source, discovery stage, labels, and screenshot.

## Setup and commands

Requirements: GNU Make and Python 3.12; Docker Desktop (running) for anything that uses a
browser or container. Restrict Docker's file sharing to this project directory if possible.

### No API key, no internet: check the submission

```bash
git clone <private-repository-url>
cd scam-website-detector-agent
make check                                   # pinned venv, lint, 650 unit tests
.venv/bin/python eval/evaluate.py output/results.json   # accuracy table from the published file
cp .env.example .env && make test-browser    # optional: 47 Chromium tests, offline container
```

Then read `output/results.json` (one record per URL) and the evidence screenshots in
`output/screenshots/` (each `address_details[].screenshot` points to one). `make test-browser`
needs Docker and an `.env` file, which may be the empty copy; the container has no network.

### What each command needs

| Command | Docker | API key in `.env` | Internet (visits targets) | Saved `runs/<id>/` |
|---|---|---|---|---|
| `make check`, `make test`, `eval/evaluate.py output/results.json` | – | – | – | – |
| `make test-browser` | yes | – | – | – |
| `make selftest` | yes | yes | only `example.com` | – |
| `make triage`, `make capture`, `make run`, `make pilot` | yes | yes | **yes** | – |
| `make rescore`, `make classify` | yes | yes | – | yes |
| `make review`, `make eval RUN=…`, `make report RUN=…` | – | – | – | yes |

`runs/` is gitignored (traces, raw HTML, LLM cache), so the last two rows work only where the
runs were made, not from a fresh clone. The gateway refuses to start without a key.

### Running a collection

Put `ANTHROPIC_API_KEY` in `.env` (never commit it). Run a new collection only if live-site
interaction is intended:

```bash
make triage RUN_ID=my-run
make run RUN_ID=my-run ARGS="--resume --spend-cap 5 --concurrency 2"
make eval RUN=my-run
make report RUN=my-run
```

`make run` invokes `make selftest` first and checkpoints each completed site. Reuse the exact run
ID with `--resume` after interruption. Do not reuse a run ID without `--resume`. To require human
approval before form submissions, add `--confirm-submit` (which forces concurrency 1).

Saved-evidence operations do not visit targets, but they need the original `runs/` directory
(not in git), so they only work on the machine that made the runs:

```bash
make review RUN=m6-final-20261007
make rescore RUN=m6-final-20261007
make report RUN=m6-final-20261007 ARGS="--supplement-run pilot-20261007b"
```

The last command documents one final-run limitation: the final pass captured two of
`bradfordtradeins.com`'s three deposit options, while the saved pilot captured BTC, EVM, and TRON.
Publishing selects the richer saved address evidence but preserves the final run's classification;
it does not hand-edit JSON or revisit the site. The one later edit to the published file is a
privacy redaction: site 084's recorded off-site URLs carried the visitor IP the site saw, now
`ip=<redacted>`. Rerunning `make report` would restore it from `runs/`, so reapply the redaction
after any republish.

## Output example

Every input URL appears once and in input order. Fields omitted here are present in the real file.

```json
{
  "url": "https://example.test",
  "status": "live",
  "processing_status": "completed",
  "classification": "scam",
  "is_scam": true,
  "scam_probability": 0.97,
  "confidence": 0.97,
  "evidence_source": "live",
  "crypto_addresses": ["bc1q…"],
  "low_confidence_addresses": [],
  "address_details": [{
    "address": "bc1q…",
    "normalized": "bc1q…",
    "tier": "primary",
    "format": "btc_bech32",
    "source": "dom_text",
    "stage": "deposit_page",
    "screenshot": "screenshots/001_abcd1234.png"
  }]
}
```

## Safety, assumptions, and limitations

- The home public IP remains visible to target operators. A disposable cloud host or regional
  proxy would reduce attribution and expose geo-specific behavior.
- Server-side redirects may start an external connection before Playwright can undo them. The
  in-page navigation guard prevents script/button/window navigations before a request; Squid still
  blocks private destinations. Chromium may preconnect to a public off-site host before routing can
  answer 204, without loading its page.
- Dead, timed-out, and TLS-failing sites may actually be geo-blocked. Their status and evidence
  source stay separate from the verdict.
- Disposable email uses mail.tm. SMS, KYC, CAPTCHA challenges, payments, real wallets, and external
  app installation are never bypassed; `blocked_at` records the gate.
- Addresses can be per-account or rotate. One synthetic account and one point-in-time run cannot
  prove completeness. The mock verifies per-account behavior; real sites were not registered twice.
- The browser element inventory covers the main frame; non-semantic clickables and coordinate
  clicks are fallbacks, but unusual iframes/shadow DOM can still be missed.
- Brand/domain lists were refined on this URL set, so their apparent performance may not
  generalize. The labelled evaluation is small and class-imbalanced.
- Low-confidence findings are intentionally noisy. One marketplace API accounts for most of the
  320 values; keeping them separate protects primary-address precision.

No raw cookies, browser storage state, or secrets are published. The final artifact scan found no
API/private-key patterns. All 339 published address details passed their format validator and
blocklist check and have an existing screenshot. The final egress review found no allowed request
to a private/risky destination or non-web port. Quality details are recorded in `docs/LOG.md`.

## Alternatives and tradeoffs

- An own Playwright loop was chosen over browser-use/Stagehand so network capture, policy checks,
  per-site contexts, and traces remain explicit. `ElementProvider` keeps Stagehand swappable.
- Hardened local Docker was chosen over Browserbase or a throwaway cloud server for schedule and
  observability; it has the public-IP limitation above.
- A plain Python state machine was clearer than LangGraph for this small graph.
- Deterministic extraction precedes the LLM because checksums, blocklists, provenance, and exact
  string reporting are testable. The LLM handles page meaning and navigation choices.
- Batched form fills plus one final action reduced registration steps; each call is still checked
  independently and execution stops at the first refusal.
- The navigator trigger is the union of scam/uncertain judgment and structural cues (account flow,
  wallet gate, or landing address). On the measured live set, this found all five useful
  navigation-only addresses; the narrower alternatives each missed sites.

The watched pilot exposed two policy failures: an image CAPTCHA text was typed and two off-site
navigations began before being undone. Fixes added literal-source enforcement, structural CAPTCHA
detection, a pre-request navigation guard, whole-story re-judging, proper minimum parsing,
confirmation prompts that include pending fills, and browser-loss recovery. The full mock suite and
final batch passed after those changes; the complete chronology is in
[`docs/LOG.md`](docs/LOG.md).

## Troubleshooting

- **Self-test fails:** do not run live targets. Confirm Docker Desktop is running, the router IP is
  detectable (`make selftest ROUTER_IP=x.x.x.x` if needed), and ports/services are not stale; use
  `make down`, then retry. There is intentionally no waiver.
- **A run stops or Chromium crashes:** rerun the same command with the same `RUN_ID` and
  `ARGS="--resume …"`. Error and browser-loss records are retried in isolated fresh browsers.
- **No model response:** verify `.env` contains the key and inspect the local gateway health/logs;
  the crawler intentionally never receives the key directly.
- **No site selected:** `--only` takes input numbers such as `--only 12,27`, not URLs.
- **Changed scorer appears ineffective:** use `make rescore`, not a stale container image; the
  target rebuilds first and reports gateway-cache hits separately from token use.
- **Inspect a judgment:** `make review RUN=<id>` creates a CSP-locked local review page from saved
  evidence. Do not open raw hostile HTML in a normal browser.

## With more time

Run from several regions; register twice on selected sites to measure address rotation; add a
strictly non-signing mock wallet for wallet-gated flows; cluster the nine observed shared-shop
templates into operator groups; improve iframe/shadow-DOM support; expand and rebalance the labelled
set; and test a Stagehand-backed `ElementProvider` if element location becomes the dominant failure.
