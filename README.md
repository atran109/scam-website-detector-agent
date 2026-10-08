# Crypto Scam Detection Agent

## Summary

I built a sandboxed browser agent that takes 160 suspected scam URLs, decides for each one
whether it is a scam, and pulls out the crypto deposit addresses it shows, including addresses
that appear only after registering, logging in, verifying an email and opening a deposit page.
Plain, tested code does the checking, saving, address extraction and output; a Claude model does
only two jobs that need judgment: reading a page to call it a scam, and choosing the next click.
The deliverable is [`output/results.json`](output/results.json), one record per URL in input
order; evidence screenshots are in [`output/screenshots/`](output/screenshots/). The final run
(`m6-final-20261007`) completed all 160 records.

| Result | Value |
|---|---|
| **My 8 hand labels** (n=8) | TP 4, FP 0, FN 1, TN 3: precision 100%, recall 80% |
| All 25 hand labels | TP 21, FP 0, FN 1, TN 3: precision 100%, recall 95%. 17 of the 25 were written by the AI assistant, are all scams, and all match the pipeline, so they are not independent |
| Scam / not scam | 77 / 83 (on live page content: 34 / 11) |
| Live sites at the final check | 43 of 160 (45 records were judged on live page content; see below) |
| Deposit addresses found | 22 (20 unique) on 8 sites, all checksum-valid |
| Low-confidence addresses | 320 on 2 sites (valid, but with no deposit context) |
| Navigation run / deposit page reached | 39 / 7 sites |
| Cost | about $4.12 for the final run and its crash recovery, $0.90 for a targeted rerun |

43 sites were live at the final check, but 45 records were judged on live page content: for 009
and 035 the page that loaded was a Cloudflare "suspected phishing" warning in front of the site,
so the warning itself was judged (both are scams by a fixed rule for such warnings).

## System design and architecture

```text
data/urls.txt
     |
     v
HTTP check ---> archived copy (Wayback) if dead --------------+
     |                                                        |
     v                                                        v
browser capture --> address extraction --> rule signals + Claude judge
     |                    |                                   |
     |                    +--> checksum / blocklist / labels  |
     v                                                        |
navigation decision --> look / choose / check / act loop -----+
     |                                                        |
     +--> register / log in / email / deposit, save each step |
                                                              v
                          checkpoint.jsonl --> rescore --> results.json
```

I built a pipeline in which ordinary code does every step that can be tested. An HTTP check sorts
each URL into a status (live, DNS failure, parked and so on). Live pages are opened in a real
browser and everything is saved: HTML, visible text, a screenshot, network responses and QR codes. Addresses are found with
patterns and kept only if they pass their coin's checksum. Claude reads the page and gives a
probability that it is a scam, which I blend 70/30 with a score from simple rules. A dead site
gets an archived copy from the Wayback Machine if one exists, otherwise the dead-site rule below.
<!-- evidence: docs/DESIGN.md §5.1; src/scamhunter/pipeline.py process_site(), analyze();
src/scamhunter/extract/validators.py validate(); src/scamhunter/classify/scorer.py LLM_WEIGHT -->

In the final run, the navigation agent ran on 39 of the 45 sites
judged on live content: 35 because the first verdict was scam or uncertain (probability 0.35 to
0.65), and 4 only because the landing page showed a login, a wallet button or an address. The
other 6 (003, 051, 053, 081, 091, 102) were skipped: confident not-scam, nothing to log into. Claude picks from 11 fixed actions; code checks each before it runs. The run used the default limit of 180 seconds and 25 steps per site, which cut three
deposit pages short (012, 032, 109); I reran those at 300 seconds. I chose this trigger on the
same sites, so it was never tested on fresh data.
<!-- evidence: src/scamhunter/agent/site_run.py should_navigate(); LOG 2026-10-07 19:10;
config/settings.yaml agent; LOG 2026-10-08 00:13 (batch command), 00:30 (gap report);
runs/m6-final-20261007/checkpoint.jsonl notes "first judgment" / "navigation skipped" -->

The browser runs in a locked-down Docker container that can only go out through a proxy that
refuses private addresses such as my home router. The API key lives in a separate container. A 50-check
self-test must pass before any command that visits a real site.
<!-- evidence: docker-compose.yml; docker/egress-proxy/squid.conf; Makefile (run: selftest);
runs/m6-final-20261007/selftest.json (50/50) -->

Full details and the threat model are in [`docs/DESIGN.md`](docs/DESIGN.md).

## Anything unique or creative

**A fake scam exchange to test against.** Before visiting real sites I built a local fake scam
exchange with 13 variants: 8 that can be solved and 5 that end at a gate (invite code, SMS,
CAPTCHA, wallet, image CAPTCHA). Every variant has traps ("I have paid", Withdraw, Connect Wallet,
fake token addresses), and one hides instructions aimed at the AI. After my fixes the real model
passed 30 of 30 runs, and the final check through the full pipeline passed 13 of 13.
<!-- evidence: tests/fixtures/mock_exchange/; src/scamhunter/mock_mode.py SOLVABLE_VARIANTS,
GATED_VARIANTS; LOG 2026-10-06 20:55 (30/30); LOG 2026-10-07 19:00 (pmock-3 13/13) -->

**Safety rules in code, and a pilot that broke them.** The rules (stay on the site, type only
synthetic data, never pay, sign or withdraw) are checked in code, not just asked for in the prompt.
My watched 8-site pilot still found 2 violations: the model read an image CAPTCHA and typed its
text (site 145), and a page sent the browser to 2 other sites before the agent could undo it
(071). I fixed both in code and added each as a new fake-exchange variant. In the rerun neither
happened again.
<!-- evidence: src/scamhunter/agent/policy.py; LOG 2026-10-07 07:00, 07:30 (violations), 08:10
(typing rule), 09:40 and 15:10 (navigation guards), 13:40 (rerun) -->

**Re-judging from saved evidence.** Because every page is saved, I picked the dead-site rule
from the final run's own data and applied it to all 160 records for $0, with no site visits.
<!-- evidence: eval/dead_site_rule_report.py; LOG 2026-10-08 00:04, 00:27 -->

**Evidence beyond addresses.** The output records where sites send visitors: LINE support chats
on 4 sites, a redirect domain (071), an app on a second domain (027). It also records app-install
files (`.apk`, `.mobileconfig`) on 117 and 088. A second registration on 057 and 087, 13 hours
later, got the same addresses, so on those sites they are not per-account.
<!-- evidence: output/results.json navigation.linked_domains, app_download_urls; LOG 2026-10-07
16:30 (app downloads); LOG 2026-10-08 (rerun result, per-account finding) -->

## Alternative approaches considered

| Choice | Chosen | Rejected | Why | What would change my mind |
|---|---|---|---|---|
| Agent | My own small loop | Stagehand, browser-use, LangGraph, Playwright MCP | I needed network capture, request blocking and a code check before every action. Stagehand documents neither; browser-use runs its own loop; LangGraph is overkill for about 5 states. I did not evaluate Playwright MCP: it gives a model broad browser tools in a client that can also run shell commands | Element-finding as the main failure (pilot failures were gates and absent flows) |
| Where it runs | Docker on my Mac | Cloud server, Browserbase | Cloud would cost 3 to 5.5 of my 15 to 25 hours; Browserbase routes scam traffic through a third party. Cost: sites see my home IP | A work laptop, or cloud IPs seeing different pages |
| API key | Separate gateway | Key in the browser container | A compromised browser cannot read the key or use the API to reach the internet | Nothing |
| Addresses | Patterns plus checksums | Patterns only, or the model | Checksums drop random lookalikes and are testable. Model extraction not tested | Addresses shown only in images |
| Verdict | Rules blended with the model | Model alone | The model's probability is not calibrated alone; rules flagged 16 disagreements. Never compared directly | A labelled test where the model alone does better |
| Withdraw, "I have paid" | Always blocked in code | Allowed | No money is at stake, but they send a false payment claim or an order to the scammer and give page text more chances to steer the agent | Never |
| Fake wallet | Cut | Built | 1 of 56 live sites needed a wallet on its landing page | Many wallet gates (3 in the final run) |
| When to navigate | Rule-based trigger | Navigate every live site | The pilot forced it to test the agent; the batch saved cost with the trigger | Skipped sites turning out to hide deposit flows |

<!-- evidence: LOG 2026-10-03/10-04 (own loop, Stagehand research, LangGraph, Browserbase, run
location, DESIGN §6.1 hours); LOG 2026-10-04 20:30, 21:30 (gateway); DESIGN §6 (regex-only);
DESIGN A22 and output notes "disagree" (16); LOG 2026-10-06 20:00 backfill (withdraw/"I have
paid"); LOG 2026-10-06 22:50 (wallet cut); output stop reasons (3 wallet_required); LOG
2026-10-07 03:10 (forced pilot), 19:10 (trigger), 14:30 (pilot failures not element-finding).
Playwright MCP and the "steer the agent" reason are the author's own reasoning, recorded in LOG
2026-10-08 -->

## Results in detail

**Verdicts by evidence.** `evidence_source` says what each verdict rests on. Rows other than
`live` are leans, not findings.

| `evidence_source` | Scam | Not scam |
|---|---:|---:|
| `live` (page content, judged) | 34 | 11 |
| `wayback` (archived page, judged, pulled toward 50/50 because archived evidence is weaker) | 3 | 2 |
| `signals_only` (no content; domain or hosting signals only) | 40 | 28 |
| `none` (no content and no signal) | 0 | 42 |

The status breakdown is 53 DNS failures, 43 live, 19 HTTP errors, 15 TLS errors, 10 timeouts, 8
empty, 6 parked and 6 suspended.

**Dead-site rule.** I chose it from the final run's data with `eval/dead_site_rule_report.py`,
without visiting any site.

- **The rule.** A site with no content leans scam (probability 0.5 to 0.65) only if its name looks
  machine-generated, it uses a brand name it does not own, it is a near-misspelling of a brand, its
  host shows a takedown page, or a sibling domain was judged a scam. A provider's phishing warning
  is a fixed rule. Anything else (cheap domain ending, invalid certificate, free hosting, mobile
  subdomain, finance words) is listed but gives not-scam at probability 0.4.
- **The data.** On the 45 sites judged on live content (34 scam, 11 not), a machine-generated name
  appeared on 7 scams and 0 others. Cheap domain endings separated weakly (18 vs 3). Finance words
  did not separate at all (12 vs 4, the same rate in both groups). The brand, misspelling and
  takedown signals were too rare on live sites to measure (at most 4 each), so I kept them on their
  merits. Caveat: the model saw these signals and the URL, so live verdicts are not independent of
  them.
- **The rules not chosen,** on the same 110 records with no content:
  - the previous rule (any moderate signal, or three weak ones): 22 scam, 88 not;
  - every unknown site at the live scam rate (75.6%, pulled to 0.70): 110 scam, 0 not;
  - only the one measured signal: 23 scam, 87 not, which drops every brand impersonation.

  The chosen rule gives 40 scam, 70 not. It moved 18 sites to scam, all with machine-generated
  names.

**Merged records.** Three published records combine two saved runs. Each keeps the final run's
verdict, but its addresses and navigation summary come from a later run at 300 seconds, because
the final run hit its 180-second limit on the deposit page. Each record's `notes` name the source.

| Site | Source run | Final run found | Merged record |
|---|---|---|---|
| 012 `bradfordtradeins.com` | `pilot-20261007b` | BTC, EVM | + TRON |
| 032 `elite-crown.com` | `nav-rerun-20261008` | BTC, TRON | + EVM |
| 109 `windrushs.co` | `nav-rerun-20261008` | BTC, EVM | + TRON, + a second EVM |

A later run is used only if it found every address the first run did, plus more, because a new
account could be given different addresses. The same rerun covered 057, 061, 067 and 087 and found
nothing new, so those records are unchanged.

**Hand labels.** I labelled 8 sites from saved screenshots: 5 scams, 3 not. On them the system
scores TP 4, FP 0, FN 1, TN 3. The miss is 003, a whisky domain showing an immigration-services
page. The AI assistant wrote 17 more labels from saved screenshots. All 17 are scams and all match
the pipeline, so they do not test it independently, and all three negatives are mine. The
threshold makes no difference: no record has a scam probability above 0.40 and below 0.50. Address
labels exist for one site (012): 3 of 3 found.

## What counts as a scam; crypto-address model

A scam intentionally deceives a visitor into handing over money, crypto, logins, a wallet's secret
recovery phrase, or control of a wallet. The types include fake exchanges, high-yield investment
schemes (fixed "daily returns"), pig butchering (a groomed victim steered to a fake trading app),
phishing, wallet drainers, giveaways, fake recovery services, fake shops and fake tokens. Being
offline, amateur, crypto-related or risky is not enough.

Evidence comes in three strengths. **Strong** is nearly decisive alone: a recovery-phrase request,
a provider's phishing warning, guaranteed returns. **Moderate** counts in combination: an invite
code requirement, a deposit address shown after registration. **Weak** is supporting only: a cheap
domain ending, an invalid certificate, a random-looking name.

An address has three separate properties. Its **format** is how the string is written, and it is
certain once the checksum passes: Bitcoin (`bc1…`, `1…`, `3…`), EVM (`0x…`, used by Ethereum and
compatible chains) or TRON (`T…`). Its **network** is the chain the site says to send on. Its
**asset** is the coin or token, such as USDT. Network and asset come from the page and carry a
confidence, because one EVM address can receive ETH, USDT and USDC at once.

`crypto_addresses` lists checksum-valid addresses shown in a deposit or payment context, exactly as
written on the site. `low_confidence_addresses` lists valid addresses without that context, such as
ones found only in a script. Token contracts, burn addresses and examples are excluded.

## Limitations

- **Navigation in the final run was limited.** It ran at 180 seconds and 25 steps per site, without
  forcing navigation; three deposit pages were cut short and later rerun, and 6 live sites were
  skipped by the trigger. The trigger was chosen on the same sites it ran on.
- **The labels are few and mostly mine to trust.** My 8 labels include only 3 negatives; the
  assistant's 17 are all scams that match the pipeline.
- **Two pilot safety violations** happened before the fixes (an image CAPTCHA typed, two off-site
  page loads). They were fixed in code and tested on the fake exchange.
- **Sites see my home IP address.** A disposable cloud server or a regional proxy would hide it.
- **Blocked off-site pages can still get a connection.** When the browser blocks an off-site page,
  Chromium may already have opened a connection to it ("preconnect"), so that host sees a handshake
  but no request. Redirects sent by a server can also start a connection before the agent undoes
  them.
- **Dead sites may be blocking my country,** not actually down.
- **Gates are never bypassed:** SMS, ID checks, CAPTCHA challenges, payments, real wallets and app
  installs end the visit. Email verification uses disposable mail.tm inboxes.
- **Addresses can rotate or differ per account.** Only 057 and 087 were registered twice.
- **Screenshots do not always show the address.** 12 of the 22 addresses are visible in their
  screenshot (11 boxed in red on 012, 027, 032 and 109, plus 087's XRP in an open dialog). The other
  10 (057, 099, 100, and 087's EVM, BTC and TRON) were read from page data that is not drawn on
  screen.
- **Hidden frames are missed.** The agent lists controls in the main page only; unusual frames can
  be missed.
- **The brand list was built while reviewing these URLs,** so the brand signal may not generalize.
- **Low-confidence addresses are noisy:** 280 of the 320 come from one marketplace's data feed.

No raw cookies, browser storage or secrets are published. All 342 published address details pass
their checksum and blocklist checks, and each has a screenshot file. The final review of outbound
traffic found no allowed request to a private address or a non-web port. Details are in
[`docs/LOG.md`](docs/LOG.md).

## What I would do with more time

**Find out what the addresses did, first.** I found 20 unique deposit addresses. Looking them up on
their blockchains (incoming payments, balances, where money went next) would show which ones
received victims' funds and link sites that pay into the same wallets. This is the most useful next
step for an investigator, and none of it needs another visit to a scam site.
<!-- evidence: output/results.json (20 unique primary addresses); DESIGN §1.4 (on-chain tracing
out of scope, future work) -->

**Group sites by operator.** Nine shop sites share one Chinese-language template (125, 128 to 130,
141, 142, 150 to 152). 099 and 100 show the same two addresses, and four sites send visitors to
LINE support chats. Grouping by shared address, page template and linked domain would turn 160
separate verdicts into a handful of operations.
<!-- evidence: LOG 2026-10-06 22:35, 22:50 (template); output/results.json 099/100
crypto_addresses, navigation.linked_domains (128, 129, 130, 142) -->

**Measure address rotation at scale.** Registering twice worked on 2 sites (057 and 087: same
addresses both times). Doing it on every site with a deposit page would tell whether a found
address belongs to the site or only to my account.
<!-- evidence: LOG 2026-10-08 (rerun result, per-account finding) -->

**Reach the wallets I currently stop at.** Three sites stopped at a wallet requirement, and the
agent never opens withdraw pages, where these kits ask for withdrawal fees. Both need a careful
design (a fake wallet that refuses to sign, withdraw steps that never submit) before the safety
rules could allow them.
<!-- evidence: output/results.json navigation.blocked_at (3 wallet_required: 031, 055, 082);
src/scamhunter/agent/policy.py ALWAYS_BLOCKED_CLICK (withdraw); classify/signals.py
withdrawal_conditions (withdrawal fees, "activation wallet") -->

**Also:** a larger labelled set with real legitimate sites (mine has 3), visits from several
countries, closing the preconnect gap, and navigation that handles more languages than Chinese and
English.
<!-- evidence: eval/labels.csv labeled_by; LOG 2026-10-07 13:40, 14:30 (preconnect);
src/scamhunter/agent/prompts.py (Chinese deposit labels) -->

## Setup and commands

Requirements: GNU Make and Python 3.12; Docker Desktop (running) for anything that uses a browser
or container. Restrict Docker's file sharing to this project directory if possible.

### No API key, no internet: check the submission

```bash
git clone <private-repository-url>
cd scam-website-detector-agent
make check                                   # pinned venv, lint, 656 unit tests
.venv/bin/python eval/evaluate.py output/results.json   # accuracy table from the published file
.venv/bin/python eval/evaluate.py output/results.json --labeled-by alex   # my 8 labels only
cp .env.example .env && make test-browser    # optional: 47 Chromium tests, offline container
```

Then read `output/results.json` and the screenshots in `output/screenshots/` (each
`address_details[].screenshot` points to one). `make test-browser` needs Docker and an `.env` file,
which may be the empty copy; its container has no network.

### What each command needs

| Command | Docker | API key in `.env` | Internet (visits targets) | Saved `runs/<id>/` |
|---|---|---|---|---|
| `make check`, `make test`, `eval/evaluate.py output/results.json` | – | – | – | – |
| `make test-browser` | yes | – | – | – |
| `make selftest` | yes | yes | only `example.com` | – |
| `make triage`, `make capture`, `make run`, `make pilot` | yes | yes | **yes** | – |
| `make rescore`, `make classify` | yes | yes | – | yes |
| `make review`, `make eval RUN=…`, `make report RUN=…` | – | – | – | yes |

`runs/` is not in git (it holds traces, raw HTML and the model-response cache), so the last two
rows work only on the machine that made the runs. The gateway refuses to start without a key.

### Running a collection

Put `ANTHROPIC_API_KEY` in `.env` (never commit it). Run a new collection only if visiting live
scam sites is intended:

```bash
make triage RUN_ID=my-run
make run RUN_ID=my-run ARGS="--resume --spend-cap 5 --concurrency 2"
make eval RUN=my-run
make report RUN=my-run
```

`make run` runs `make selftest` first and saves each finished site. After an interruption, rerun
with the same run ID and `--resume`; never reuse a run ID without it. To approve each form
submission yourself, add `--confirm-submit` (one site at a time). `--max-seconds 300 --max-steps
30` matches the pilot's budget; the defaults are 180 and 25.

To republish the submitted file from saved evidence (only where `runs/` exists):

```bash
make rescore RUN=m6-final-20261007
make report RUN=m6-final-20261007 ARGS="--supplement-run pilot-20261007b --supplement-run nav-rerun-20261008"
.venv/bin/python scripts/validate_run.py
```

Publishing removes any visitor IP address a site wrote into a recorded link (site 084 did), and
`scripts/validate_run.py` fails if one is published.

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

`confidence` is the chance the stated verdict is right: `scam_probability` for a scam,
1 − `scam_probability` for not-scam.

## Troubleshooting

- **Self-test fails:** do not visit live sites. Check Docker Desktop is running and the router IP is
  found (`make selftest ROUTER_IP=x.x.x.x` if needed); run `make down` and retry. There is
  deliberately no override.
- **A run stops or Chromium crashes:** rerun the same command with the same `RUN_ID` and
  `ARGS="--resume …"`. Failed records are retried, each in a fresh browser.
- **No model response:** check that `.env` has the key and that the gateway container is healthy;
  the browser container never gets the key.
- **No site selected:** `--only` takes input numbers such as `--only 12,27`, not URLs.
- **A scorer change seems to have no effect:** use `make rescore`, which rebuilds the image first.
- **Inspect a judgment:** `make review RUN=<id>` builds a local, script-free review page from
  saved evidence. Do not open saved scam HTML in a normal browser.
