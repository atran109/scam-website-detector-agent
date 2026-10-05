"""Per-site state machine and run orchestration: stage order, transitions, concurrency, timeouts.

Live run (§5.2):  TRIAGED → (live or recheck) CAPTURED → analyze → FINALIZING → checkpoint
                  TRIAGED → (not live) dead-site policy → FINALIZING → checkpoint
Rescore:          saved snapshots → analyze → results (no site visits)
Navigation (M3) and Wayback recovery (M2 step 6) slot in later.
"""

import asyncio
import json
import re
import shutil
import traceback
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import tldextract
from playwright.async_api import Browser, async_playwright
from playwright.async_api import Error as PlaywrightError

from scamhunter.browser.capture import (
    NetworkRecorder,
    load_snapshot_content,
    load_snapshots,
    take_snapshot,
)
from scamhunter.browser.sandbox import launch_browser, new_context
from scamhunter.browser.wayback import usable_captures
from scamhunter.classify.domain import domain_signals, load_brands
from scamhunter.classify.llm_judge import judge
from scamhunter.classify.scorer import score_content, score_without_content
from scamhunter.classify.signals import address_signal, content_signals, triage_signals
from scamhunter.config import Settings, require_egress_proxy
from scamhunter.extract.blocklist import load_blocklist
from scamhunter.extract.extractor import extract, merge_all
from scamhunter.llm.client import LLMClient, LLMError, TokenUsage
from scamhunter.models import (
    AddressTier,
    Classification,
    CryptoAddress,
    DiscoveryStage,
    EvidenceSource,
    PageSnapshot,
    ProcessingStatus,
    Signal,
    SignalTier,
    Site,
    SiteResult,
    SiteStatus,
    TriageRecord,
    TriageResult,
    Verdict,
)
from scamhunter.report.screenshots import highlight_address
from scamhunter.store import write_jsonl
from scamhunter.triage.liveness import classify_response, make_client, probe

PIPELINE_VERSION = "0.2.0"

# Bundled public-suffix snapshot only: no network fetch, no cache writes.
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

# Statuses re-tried once in Chromium before being treated as dead (DESIGN §5.2a).
RECHECK_STATUSES = {SiteStatus.TLS_ERROR, SiteStatus.TIMEOUT}
EMPTY_SHELL_CHARS = 50
INTERSTITIAL_BUTTON = re.compile(r"ignore\s*&\s*proceed|proceed anyway|continue to site", re.I)


# ============================================================
# Input
# ============================================================


def load_sites(path: Path) -> list[Site]:
    """One Site per non-blank line, in file order. No dedupe: paths like /wap are significant."""
    sites: list[Site] = []
    for line_no, line in enumerate(path.read_text().splitlines(), start=1):
        url = line.strip()
        if not url:
            continue
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError(f"{path}:{line_no}: not an http(s) URL: {url!r}")
        sites.append(
            Site(
                site_id=f"{len(sites) + 1:03d}",
                url=url,
                host=parts.hostname,
                registrable_domain=_extract(parts.hostname).top_domain_under_public_suffix,
            )
        )
    return sites


# ============================================================
# Triage stage
# ============================================================


async def run_triage(settings: Settings, sites: list[Site], out_dir: Path) -> list[TriageRecord]:
    """Probe every site through the egress proxy; write triage.jsonl in input order."""
    proxy = require_egress_proxy()
    semaphore = asyncio.Semaphore(settings.triage.concurrency)
    verified = make_client(proxy, settings.http, settings.triage, verify=True)
    unverified = make_client(proxy, settings.http, settings.triage, verify=False)

    async def one(site: Site) -> TriageRecord:
        async with semaphore:
            result = await probe(site.url, verified, unverified, settings.triage)
        print(f"  {site.site_id} {result.status.value:<17} {site.url}", flush=True)
        return TriageRecord(site=site, triage=result)

    async with verified, unverified:
        records = await asyncio.gather(*(one(site) for site in sites))

    assert len(records) == len(sites), "triage must produce exactly one record per URL"
    write_jsonl(out_dir / "triage.jsonl", records)
    return records


def load_triage(path: Path) -> dict[str, TriageResult]:
    records = [TriageRecord.model_validate_json(line) for line in path.read_text().splitlines()]
    return {r.site.site_id: r.triage for r in records}


def status_counts(records: list[TriageRecord]) -> Counter[str]:
    return Counter(r.triage.status.value for r in records)


# ============================================================
# Shared context
# ============================================================


@dataclass
class RunContext:
    settings: Settings
    run_dir: Path
    llm: LLMClient
    blocklist: frozenset[str] = field(default_factory=load_blocklist)
    brands: list[str] = field(default_factory=load_brands)
    proxy: str | None = None
    browser: Browser | None = None

    def site_dir(self, site: Site) -> Path:
        return self.run_dir / "sites" / site.site_id


def _is_mobile(settings: Settings, url: str) -> bool:
    host_and_path = url.split("://", 1)[-1]
    return any(re.search(p, host_and_path) for p in settings.browser.mobile_hint_patterns)


def _status_note(triage: TriageResult) -> str:
    return f"{triage.status.value} ({triage.reason or 'no detail'})"


# ============================================================
# Capture (live run only)
# ============================================================


@dataclass
class Capture:
    snapshots: list[PageSnapshot]
    notes: list[str]
    loaded: bool  # Chromium got a real page (not an error page)
    partial: bool = False


async def _open_and_snapshot(
    ctx: RunContext, site: Site, triage: TriageResult, *, mobile: bool, first_index: int
) -> tuple[Capture, bool]:
    """One browser context: load the URL, snapshot, try the Cloudflare warning click-through.
    Returns the capture and whether the page looked like an empty SPA shell."""
    settings = ctx.settings
    site_dir = ctx.site_dir(site)
    notes: list[str] = []
    snapshots: list[PageSnapshot] = []
    ignore_tls = triage.tls_valid is False or triage.status == SiteStatus.TLS_ERROR
    context = await new_context(
        ctx.browser,
        settings.browser,
        mobile=mobile,
        ignore_https_errors=ignore_tls,
        accept_language=settings.http.accept_language,
    )
    await context.tracing.start(screenshots=True, snapshots=True)
    page = await context.new_page()
    recorder = NetworkRecorder(site_dir, ctx.run_dir)
    recorder.attach(page)
    empty_shell = False
    loaded = False
    try:
        response = await page.goto(site.url, wait_until="domcontentloaded")
        loaded = response is not None
        index = first_index
        snap = await take_snapshot(
            page, recorder, DiscoveryStage.LANDING, f"s{index:02d}", site_dir, ctx.run_dir
        )
        snapshots.append(snap)
        text = (ctx.run_dir / snap.html_path).parent.joinpath("text.txt").read_text()
        empty_shell = len(text.strip()) < EMPTY_SHELL_CHARS

        # Cloudflare "Suspected phishing" interstitial: one click through (DESIGN §5.2a).
        button = page.get_by_role("button", name=INTERSTITIAL_BUTTON).or_(
            page.get_by_role("link", name=INTERSTITIAL_BUTTON)
        )
        if await button.count():
            notes.append("clicked through a browser/CDN warning page")
            await button.first.click(timeout=10000)
            index += 1
            snapshots.append(
                await take_snapshot(
                    page,
                    recorder,
                    DiscoveryStage.NAVIGATION,
                    f"s{index:02d}",
                    site_dir,
                    ctx.run_dir,
                )
            )
        elif "suspected phishing" in text.lower():
            notes.append("phishing warning page offers no way through (no proceed button)")
        await _highlight_new_addresses(ctx, site, page, snapshots[-1])
    except PlaywrightError as exc:
        notes.append(f"browser: {str(exc).splitlines()[0][:200]}")
    finally:
        await context.tracing.stop(path=str(site_dir / f"trace_{first_index:02d}.zip"))
        await context.close()
    return Capture(snapshots, notes, loaded), empty_shell


async def _highlight_new_addresses(
    ctx: RunContext, site: Site, page, snapshot: PageSnapshot
) -> None:
    """Boxed screenshot for each address visible on the current page; saved to
    highlights.json so rescore keeps them."""
    site_dir = ctx.site_dir(site)
    content = load_snapshot_content(snapshot, ctx.run_dir)
    path = site_dir / "highlights.json"
    highlights = json.loads(path.read_text()) if path.exists() else {}
    for address in extract(content, ctx.blocklist):
        if address.dedupe_key in highlights:
            continue
        out = (
            site_dir
            / "screenshots"
            / f"{site.site_id}_{address.format.value}_{address.address[:10]}.png"
        )
        box = await highlight_address(page, address.address, out)
        if box:
            highlights[address.dedupe_key] = {
                "screenshot_path": str(out.relative_to(ctx.run_dir)),
                "bbox": list(box),
            }
    path.write_text(json.dumps(highlights, indent=2))


async def capture_site(ctx: RunContext, site: Site, triage: TriageResult) -> Capture:
    mobile = _is_mobile(ctx.settings, site.url)
    capture, empty_shell = await _open_and_snapshot(ctx, site, triage, mobile=mobile, first_index=1)
    if capture.loaded and empty_shell and not mobile:
        # Empty desktop render: many scam SPAs only render for phones (A8).
        retry, _ = await _open_and_snapshot(
            ctx, site, triage, mobile=True, first_index=len(capture.snapshots) + 1
        )
        capture.snapshots += retry.snapshots
        capture.notes += ["empty desktop render; retried with mobile viewport", *retry.notes]
        capture.loaded = capture.loaded or retry.loaded
    return capture


# ============================================================
# Analysis (shared by live run and rescore)
# ============================================================


def _apply_highlights(
    addresses: list[CryptoAddress], site_dir: Path, snapshots: list[PageSnapshot]
) -> list[CryptoAddress]:
    path = site_dir / "highlights.json"
    highlights = json.loads(path.read_text()) if path.exists() else {}
    fallback = next((s.screenshot_path for s in reversed(snapshots) if s.screenshot_path), None)
    out = []
    for a in addresses:
        hl = highlights.get(a.dedupe_key)
        sightings = [
            s.model_copy(
                update={
                    "screenshot_path": hl["screenshot_path"] if hl else fallback,
                    "bbox": tuple(hl["bbox"]) if hl else None,
                }
            )
            if i == 0
            else s
            for i, s in enumerate(a.sightings)
        ]
        out.append(a.model_copy(update={"sightings": sightings}))
    return out


def _archived_note(snapshot: PageSnapshot, triage: TriageResult) -> str:
    m = re.search(r"/web/(\d{4})(\d{2})(\d{2})\d*id_/", snapshot.url)
    when = f" from {m.group(1)}-{m.group(2)}-{m.group(3)}" if m else ""
    return (
        f"This is an archived Wayback Machine snapshot{when}; the live site is now "
        f"{triage.status.value}. Judge the site as it was when archived."
    )


@dataclass
class Analysis:
    classification: Classification
    addresses: list[CryptoAddress]
    notes: list[str]
    usage: TokenUsage
    final_url: str | None = None
    triage: TriageResult | None = None  # set when analysis revised the triage status (parked)


def rendered_parked(ctx: RunContext, snapshots: list[PageSnapshot]) -> str | None:
    """Reason if the last rendered snapshot is a parking page. HTTP triage can't see these:
    many sit behind a JS redirect (the probe gets a "Redirecting..." stub), so the rendered
    page is checked with triage's own detector."""
    if not snapshots:
        return None
    last = snapshots[-1]
    html = (ctx.run_dir / last.html_path).read_text()
    status, reason = classify_response(200, {}, html, last.url)
    return reason if status == SiteStatus.PARKED else None


def mark_parked(triage: TriageResult, reason: str) -> TriageResult:
    return triage.model_copy(
        update={
            "status": SiteStatus.PARKED,
            "reason": f"rendered page is a parking page: {reason}",
        }
    )


def _has_content(ctx: RunContext, snapshots: list[PageSnapshot]) -> bool:
    for snap in snapshots:
        text = (ctx.run_dir / snap.html_path).parent.joinpath("text.txt").read_text()
        if text.strip() or "<script" in (ctx.run_dir / snap.html_path).read_text().lower():
            return True
    return False


async def analyze(
    ctx: RunContext,
    site: Site,
    triage: TriageResult,
    snapshots: list[PageSnapshot],
    *,
    partial: bool = False,
) -> Analysis:
    """Extraction + classification from saved snapshots (or the dead-site policy if none)."""
    settings = ctx.settings
    threshold = settings.classify.scam_threshold
    usage = TokenUsage()
    notes: list[str] = []
    revised: TriageResult | None = None
    if parked := rendered_parked(ctx, snapshots):
        revised = triage = mark_parked(triage, parked)
        notes.append(f"rendered page is a parking page ({parked}): dead-site rule applies")
        snapshots = []
    base_signals = domain_signals(site.host, site.registrable_domain, ctx.brands) + triage_signals(
        triage
    )

    if not snapshots or not _has_content(ctx, snapshots):
        return Analysis(
            score_without_content(base_signals, threshold, _status_note(triage)),
            [],
            notes,
            usage,
            triage=revised,
        )

    addresses: list[CryptoAddress] = []
    ignored: list[str] = []
    for snap in snapshots:
        addresses = merge_all(
            addresses, extract(load_snapshot_content(snap, ctx.run_dir), ctx.blocklist, ignored)
        )
    addresses = _apply_highlights(addresses, ctx.site_dir(site), snapshots)
    if ignored:
        notes.append(
            f"ignored {len(set(ignored))} token-contract address(es) "
            f"(labelled contract on the page or under contract keys in API/script data)"
        )

    # Judge the last snapshot: after a mobile retry or warning click-through, it's the real page.
    last = snapshots[-1]
    content = load_snapshot_content(last, ctx.run_dir)
    signals = base_signals + content_signals(content.visible_text, content.html, site.host)
    if sig := address_signal(len(addresses)):
        signals.append(sig)
    judgment = None
    try:
        judgment = await judge(
            ctx.llm,
            site.site_id,
            usage,
            url=site.url,
            final_url=last.url,
            title=last.title,
            status_note=_status_note(triage),
            page_text=content.visible_text,
            screenshot_png=(ctx.run_dir / last.screenshot_path).read_bytes()
            if last.screenshot_path
            else None,
            signals=signals,
            addresses=addresses,
            effort=settings.llm.judge_effort,
            archived_note=_archived_note(last, triage) if content.archived else "",
        )
    except LLMError as exc:
        notes.append(f"LLM judgment unavailable, heuristics only: {exc}")
    classification, score_notes = score_content(
        signals, judgment, threshold, partial=partial, archived=content.archived
    )
    return Analysis(classification, addresses, notes + score_notes, usage, last.url, revised)


# ============================================================
# Finalizing
# ============================================================


def build_result(
    site: Site,
    triage: TriageResult,
    analysis: Analysis,
    *,
    processing: ProcessingStatus,
    notes: list[str],
    started: datetime,
    trace_path: str | None,
) -> SiteResult:
    scam = analysis.classification.verdict == Verdict.SCAM
    primary = [a for a in analysis.addresses if a.tier == AddressTier.PRIMARY]
    low = [a for a in analysis.addresses if a.tier == AddressTier.LOW_CONFIDENCE]
    return SiteResult(
        site=site,
        triage=analysis.triage or triage,  # analysis may have revised the status (parked)
        processing_status=processing,
        classification=analysis.classification,
        addresses=primary if scam else [],
        low_confidence_addresses=low if scam else [],
        other_addresses=[] if scam else analysis.addresses,
        navigation=None,
        notes=notes + analysis.notes,
        trace_path=trace_path,
        cost=analysis.usage.as_dict(),
        started_at=started,
        finished_at=datetime.now(UTC),
        pipeline_version=PIPELINE_VERSION,
    )


def _error_result(
    site: Site,
    triage: TriageResult,
    error: str,
    started: datetime,
    settings: Settings,
    brands: list[str],
) -> SiteResult:
    signals = domain_signals(site.host, site.registrable_domain, brands) + triage_signals(triage)
    classification = score_without_content(
        signals, settings.classify.scam_threshold, f"pipeline error ({error})"
    )
    return build_result(
        site,
        triage,
        Analysis(classification, [], [], TokenUsage()),
        processing=ProcessingStatus.ERROR,
        notes=[f"pipeline error: {error}"],
        started=started,
        trace_path=None,
    )


def _keep_trace(site_dir: Path, result: SiteResult, run_dir: Path) -> str | None:
    """Keep Playwright traces for scam sites and failures (settings.browser.tracing)."""
    traces = sorted(site_dir.glob("trace_*.zip"))
    keep = (
        result.classification.verdict == Verdict.SCAM
        or result.processing_status != ProcessingStatus.COMPLETED
    )
    if not keep:
        for t in traces:
            t.unlink()
        return None
    return str(traces[-1].relative_to(run_dir)) if traces else None


# ============================================================
# Wayback recovery (dead-site policy step 1)
# ============================================================


async def recover_from_wayback(ctx: RunContext, site: Site) -> tuple[list[PageSnapshot], list[str]]:
    """Render the newest usable archived snapshot in the sandboxed browser."""
    settings = ctx.settings
    client = make_client(ctx.proxy, settings.http, settings.triage, verify=True)
    async with client:
        captures, notes = await usable_captures(client, site.url)
    snapshots: list[PageSnapshot] = []
    site_dir = ctx.site_dir(site)
    for capture in captures:
        context = await new_context(
            ctx.browser,
            settings.browser,
            mobile=_is_mobile(settings, site.url),
            accept_language=settings.http.accept_language,
        )
        page = await context.new_page()
        recorder = NetworkRecorder(site_dir, ctx.run_dir)
        recorder.attach(page)
        try:
            await page.goto(capture.raw_url, wait_until="domcontentloaded")
            snapshots.append(
                await take_snapshot(
                    page, recorder, DiscoveryStage.LANDING, "w01", site_dir, ctx.run_dir
                )
            )
            notes.append(f"classified from Wayback snapshot {capture.timestamp}")
        except PlaywrightError as exc:
            notes.append(f"wayback render failed: {str(exc).splitlines()[0][:150]}")
        finally:
            await context.close()
    return snapshots, notes


# ============================================================
# One site, live
# ============================================================


async def process_site(ctx: RunContext, site: Site, triage: TriageResult) -> SiteResult:
    started = datetime.now(UTC)
    site_dir = ctx.site_dir(site)
    if site_dir.exists():
        shutil.rmtree(site_dir)  # a resumed site starts clean
    site_dir.mkdir(parents=True)
    notes: list[str] = []
    snapshots: list[PageSnapshot] = []
    partial = False

    is_warning_page = any(
        s.name == "cloudflare_phishing_interstitial" for s in triage_signals(triage)
    )
    if triage.status == SiteStatus.LIVE or triage.status in RECHECK_STATUSES or is_warning_page:
        capture = await capture_site(ctx, site, triage)
        notes += capture.notes
        snapshots = capture.snapshots
        partial = capture.partial
        if triage.status in RECHECK_STATUSES:
            if capture.loaded and _has_content(ctx, snapshots):
                notes.append(f"triage said {triage.status.value}; Chromium loaded the page")
                triage = triage.model_copy(
                    update={
                        "status": SiteStatus.LIVE,
                        "reason": f"Chromium recheck loaded it (triage: {_status_note(triage)})",
                    }
                )
            else:
                notes.append(f"Chromium recheck also failed ({triage.status.value})")
                snapshots = []

    if parked := rendered_parked(ctx, snapshots):
        # Dead-site policy: a parking page is no evidence about the site, so try Wayback next.
        triage = mark_parked(triage, parked)
        notes.append(f"rendered page is a parking page ({parked})")
        snapshots = []

    if not snapshots and ctx.settings.features.archive_fallback:
        snapshots, wayback_notes = await recover_from_wayback(ctx, site)
        notes += wayback_notes

    # Capture-time facts that rescore must keep (it re-derives everything else).
    (site_dir / "capture.json").write_text(json.dumps({"notes": notes, "partial": partial}))
    analysis = await analyze(ctx, site, triage, snapshots, partial=partial)
    processing = ProcessingStatus.PARTIAL if partial else ProcessingStatus.COMPLETED
    result = build_result(
        site, triage, analysis, processing=processing, notes=notes, started=started, trace_path=None
    )
    trace = _keep_trace(site_dir, result, ctx.run_dir)
    return result.model_copy(update={"trace_path": trace})


# ============================================================
# Whole run
# ============================================================


def load_checkpoint(path: Path) -> dict[str, SiteResult]:
    if not path.exists():
        return {}
    results = [SiteResult.model_validate_json(line) for line in path.read_text().splitlines()]
    return {r.site.site_id: r for r in results}


async def run_pipeline(
    settings: Settings, sites: list[Site], run_dir: Path, *, resume: bool
) -> list[SiteResult]:
    """Live run: triage (reused if present), then every site with bounded concurrency.
    Each finished site is appended to checkpoint.jsonl immediately."""
    proxy = require_egress_proxy()
    triage_path = run_dir / "triage.jsonl"
    if triage_path.exists():
        triage = load_triage(triage_path)
    else:
        triage = {r.site.site_id: r.triage for r in await run_triage(settings, sites, run_dir)}
    missing = [s for s in sites if s.site_id not in triage]
    if missing:
        records = await run_triage(settings, missing, run_dir / "triage_extra")
        triage.update({r.site.site_id: r.triage for r in records})

    checkpoint = run_dir / "checkpoint.jsonl"
    done = load_checkpoint(checkpoint) if resume else {}
    todo = [s for s in sites if s.site_id not in done]
    print(f"{len(sites)} sites, {len(done)} already done, {len(todo)} to process")

    llm = LLMClient(settings.llm.gateway_url)
    lock = asyncio.Lock()
    semaphore = asyncio.Semaphore(settings.run.concurrency)
    async with async_playwright() as pw:
        browser = await launch_browser(pw, proxy)
        ctx = RunContext(settings, run_dir, llm, proxy=proxy, browser=browser)

        async def one(site: Site) -> SiteResult:
            started = datetime.now(UTC)
            async with semaphore:
                try:
                    result = await asyncio.wait_for(
                        process_site(ctx, site, triage[site.site_id]),
                        timeout=settings.run.site_timeout_s,
                    )
                except TimeoutError:
                    result = _error_result(
                        site, triage[site.site_id], "site timeout", started, settings, ctx.brands
                    )
                except Exception as exc:  # noqa: BLE001 - one site never crashes the run
                    traceback.print_exc()
                    result = _error_result(
                        site,
                        triage[site.site_id],
                        f"{type(exc).__name__}: {exc}",
                        started,
                        settings,
                        ctx.brands,
                    )
            async with lock:
                with checkpoint.open("a") as f:
                    f.write(result.model_dump_json() + "\n")
            c = result.classification
            print(
                f"  {site.site_id} {c.verdict.value:<8} p={c.scam_probability:.2f} "
                f"{c.evidence_source.value:<12} addrs={len(result.addresses)}"
                f"+{len(result.low_confidence_addresses)} {site.url}",
                flush=True,
            )
            return result

        await asyncio.gather(*(one(s) for s in todo))
        await browser.close()
    await llm.aclose()
    results = load_checkpoint(checkpoint)
    return [results[s.site_id] for s in sites if s.site_id in results]


async def rescore(settings: Settings, sites: list[Site], run_dir: Path) -> list[SiteResult]:
    """Re-run extraction + classification from saved evidence. No site is visited."""
    checkpoint = load_checkpoint(run_dir / "checkpoint.jsonl")
    llm = LLMClient(settings.llm.gateway_url)
    ctx = RunContext(settings, run_dir, llm)
    results = []
    for site in sites:
        old = checkpoint.get(site.site_id)
        if old is None:
            continue
        snapshots = load_snapshots(ctx.site_dir(site))
        analysis = await analyze(
            ctx,
            site,
            old.triage,
            snapshots,
            partial=old.processing_status == ProcessingStatus.PARTIAL,
        )
        capture_file = ctx.site_dir(site) / "capture.json"
        capture_notes = (
            json.loads(capture_file.read_text())["notes"] if capture_file.exists() else []
        )
        result = build_result(
            site,
            old.triage,
            analysis,
            processing=old.processing_status,
            notes=capture_notes,
            started=old.started_at,
            trace_path=old.trace_path,
        )
        results.append(result)
    await llm.aclose()
    write_jsonl(run_dir / "rescore.jsonl", results)
    return results


# ============================================================
# Cross-site pass
# ============================================================


def _family(domain: str) -> str:
    label = domain.split(".")[0]
    return label.split("-")[0] if len(label.split("-")[0]) >= 5 else label


def apply_sibling_signals(results: list[SiteResult], settings: Settings) -> list[SiteResult]:
    """A dead site whose sibling domain (same name, other TLD or suffix: sebca.art/.sbs) is a
    scam on live evidence gets a sibling signal and is re-scored (A14, DESIGN §5.2a step 2)."""
    scam_families = {
        _family(r.site.registrable_domain): r.site.registrable_domain
        for r in results
        if r.classification.verdict == Verdict.SCAM
        and r.classification.evidence_source in (EvidenceSource.LIVE, EvidenceSource.WAYBACK)
    }
    out = []
    for r in results:
        family = _family(r.site.registrable_domain)
        sibling = scam_families.get(family)
        no_content = r.classification.evidence_source in (
            EvidenceSource.SIGNALS_ONLY,
            EvidenceSource.NONE,
        )
        if sibling and sibling != r.site.registrable_domain and no_content:
            signals = [s for s in r.classification.signals if not s.name.startswith("sibling")]
            signals.append(
                Signal(
                    name=f"sibling_of_scam:{sibling}",
                    tier=SignalTier.MODERATE,
                    weight=1.5,
                    evidence=f"{sibling} classified scam on content",
                    source="cross_site",
                )
            )
            classification = score_without_content(
                signals, settings.classify.scam_threshold, _status_note(r.triage)
            )
            r = r.model_copy(update={"classification": classification})
        out.append(r)
    return out
