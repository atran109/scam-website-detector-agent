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
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import tldextract
from playwright.async_api import Browser, async_playwright
from playwright.async_api import Error as PlaywrightError

from scamhunter.agent.site_run import (
    NavigationOptions,
    mailtm_factory,
    navigate_site,
    should_navigate,
    spend_blocks,
)
from scamhunter.browser.capture import (
    NetworkRecorder,
    load_snapshot_content,
    load_snapshots,
    take_snapshot,
)
from scamhunter.browser.sandbox import launch_browser, new_context
from scamhunter.browser.wayback import usable_captures
from scamhunter.classify.domain import BrandToken, domain_signals, load_brands
from scamhunter.classify.llm_judge import judge
from scamhunter.classify.scorer import score_content, score_without_content
from scamhunter.classify.signals import address_signal, content_signals, triage_signals
from scamhunter.config import Settings, require_egress_proxy
from scamhunter.extract.app_downloads import find_app_downloads, merge_targets
from scamhunter.extract.blocklist import load_blocklist
from scamhunter.extract.extractor import extract, merge_all
from scamhunter.llm.client import LLMClient, LLMError, TokenUsage
from scamhunter.models import (
    AddressTier,
    Classification,
    CryptoAddress,
    DiscoveryStage,
    EvidenceSource,
    NavigationTrace,
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
from scamhunter.triage.liveness import SPA_SHELL_REASON, classify_response, make_client, probe

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


@dataclass(kw_only=True)
class RunContext:
    settings: Settings
    run_dir: Path
    llm: LLMClient
    blocklist: frozenset[str] = field(default_factory=load_blocklist)
    brands: list[BrandToken] = field(default_factory=load_brands)
    proxy: str | None = None
    browser: Browser | None = None
    settle_ms: int = 8000  # how long to wait for network idle before a snapshot
    force_mobile: bool = False  # load every site with the mobile viewport and user agent first
    loopback_only: bool = False  # mock mode: contexts get the loopback guard
    nav: NavigationOptions | None = None  # None: capture and judge only, no navigation agent

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
    ctx: RunContext,
    site: Site,
    triage: TriageResult,
    *,
    mobile: bool,
    first_index: int,
    click_interstitial: bool = True,
) -> tuple[Capture, bool]:
    """One browser context: load the URL, snapshot, try the Cloudflare warning click-through
    (unless `click_interstitial` is off: capture-only runs never click). Returns the capture and
    whether the page looked like an empty SPA shell."""
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
        loopback_only=ctx.loopback_only,
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
            page,
            recorder,
            DiscoveryStage.LANDING,
            f"s{index:02d}",
            site_dir,
            ctx.run_dir,
            network_idle_ms=ctx.settle_ms,
        )
        snapshots.append(snap)
        text = (ctx.run_dir / snap.html_path).parent.joinpath("text.txt").read_text()
        empty_shell = len(text.strip()) < EMPTY_SHELL_CHARS

        # Cloudflare "Suspected phishing" interstitial: one click through (DESIGN §5.2a).
        button = page.get_by_role("button", name=INTERSTITIAL_BUTTON).or_(
            page.get_by_role("link", name=INTERSTITIAL_BUTTON)
        )
        if click_interstitial and await button.count():
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
        try:
            await context.tracing.stop(path=str(site_dir / f"trace_{first_index:02d}.zip"))
        except PlaywrightError as exc:
            notes.append(f"browser trace unavailable: {str(exc).splitlines()[0][:160]}")
        try:
            await context.close()
        except PlaywrightError as exc:
            notes.append(f"browser context close failed: {str(exc).splitlines()[0][:160]}")
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


async def capture_site(
    ctx: RunContext, site: Site, triage: TriageResult, *, click_interstitial: bool = True
) -> Capture:
    mobile = ctx.force_mobile or _is_mobile(ctx.settings, site.url)
    capture, empty_shell = await _open_and_snapshot(
        ctx, site, triage, mobile=mobile, first_index=1, click_interstitial=click_interstitial
    )
    if capture.loaded and empty_shell and not mobile:
        # Empty desktop render: many scam SPAs only render for phones (A8).
        retry, _ = await _open_and_snapshot(
            ctx,
            site,
            triage,
            mobile=True,
            first_index=len(capture.snapshots) + 1,
            click_interstitial=click_interstitial,
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
    app_downloads: list[str] = field(default_factory=list)  # app files and store links (M4)


def rendered_non_content(
    run_dir: Path, snapshots: list[PageSnapshot]
) -> tuple[SiteStatus, str] | None:
    """(status, reason) if the last rendered snapshot is not the site's content, else None.
    HTTP triage can't see these: parking pages often sit behind a JS redirect (the probe gets a
    "Redirecting..." stub), and an SPA that never renders looks live. The rendered page is
    checked with triage's own detector. Parked, expired, directory-listing and maintenance pages
    come from it; a page still blank after capture's mobile retry is "stuck loading" (EMPTY)."""
    if not snapshots:
        return None
    last = snapshots[-1]
    html = (run_dir / last.html_path).read_text()
    status, reason = classify_response(200, {}, html, last.url)
    if status in (SiteStatus.PARKED, SiteStatus.EMPTY):
        return status, reason
    if status == SiteStatus.LIVE and reason == SPA_SHELL_REASON:
        return SiteStatus.EMPTY, "page never rendered content (stuck loading)"
    return None


def non_content_note(status: SiteStatus, reason: str) -> str:
    what = "a parking page" if status == SiteStatus.PARKED else "a page with no content"
    return f"rendered page is {what} ({reason})"


def mark_non_content(triage: TriageResult, status: SiteStatus, reason: str) -> TriageResult:
    return triage.model_copy(update={"status": status, "reason": non_content_note(status, reason)})


def _has_content(ctx: RunContext, snapshots: list[PageSnapshot]) -> bool:
    for snap in snapshots:
        text = (ctx.run_dir / snap.html_path).parent.joinpath("text.txt").read_text()
        if text.strip() or "<script" in (ctx.run_dir / snap.html_path).read_text().lower():
            return True
    return False


def _is_agent_snapshot(snap: PageSnapshot) -> bool:
    """Snapshots the navigation agent took (`a001`…); capture is `s01`…, Wayback `w01`."""
    return snap.snapshot_id.startswith("a")


def _best_navigation_page(snapshots: list[PageSnapshot], addresses: list[CryptoAddress]):
    """The agent's most telling page for the judge: the last deposit page that shows a primary
    address, else the last deposit page, else the last logged-in page, else the last page the
    agent saw if it is not the landing page. None if the agent took no snapshot."""
    agent = [s for s in snapshots if _is_agent_snapshot(s)]
    if not agent:
        return None
    on_deposit = {
        sg.page_url
        for a in addresses
        if a.tier == AddressTier.PRIMARY
        for sg in a.sightings
        if sg.stage == DiscoveryStage.DEPOSIT_PAGE
    }
    for wanted in (
        lambda s: s.stage == DiscoveryStage.DEPOSIT_PAGE and s.url in on_deposit,
        lambda s: s.stage == DiscoveryStage.DEPOSIT_PAGE,
        lambda s: s.stage == DiscoveryStage.AUTHENTICATED,
        lambda s: s.stage != DiscoveryStage.LANDING,
    ):
        found = [s for s in agent if wanted(s)]
        if found:
            return found[-1]
    return None


def merge_signals(groups: list[list[Signal]]) -> list[Signal]:
    """One signal per name across several pages, keeping the heaviest (first on a tie)."""
    best: dict[str, Signal] = {}
    for group in groups:
        for sig in group:
            if sig.name not in best or sig.weight > best[sig.name].weight:
                best[sig.name] = sig
    return list(best.values())


def deposit_flow_signal(addresses: list[CryptoAddress]) -> Signal | None:
    """A primary address the site showed a registered user on its deposit or account pages (the
    navigation agent's evidence, 2026-10-07). Raises the probability: a site that hands a new
    synthetic account a deposit address is collecting deposits."""
    shown = [
        a
        for a in addresses
        if a.tier == AddressTier.PRIMARY
        and any(
            sg.stage in (DiscoveryStage.DEPOSIT_PAGE, DiscoveryStage.AUTHENTICATED)
            for sg in a.sightings
        )
    ]
    if not shown:
        return None
    return Signal(
        name="deposit_address_after_registration",
        tier=SignalTier.MODERATE,
        weight=1.5,
        evidence=f"{len(shown)} address(es) shown to a registered account on its deposit pages",
        source="navigation",
    )


async def analyze(
    ctx: RunContext,
    site: Site,
    triage: TriageResult,
    snapshots: list[PageSnapshot],
    *,
    partial: bool = False,
) -> Analysis:
    """Extraction + classification from saved snapshots (or the dead-site policy if none).

    After navigation (2026-10-07, pilot sites 012 and 021): the non-content check runs on the
    capture snapshots only (a maintenance page the agent reached is a gate, not the site's
    status); signals come from every snapshot; the judge sees the landing page *and* the agent's
    best page; addresses shown to a registered account add a signal."""
    settings = ctx.settings
    threshold = settings.classify.scam_threshold
    usage = TokenUsage()
    notes: list[str] = []
    revised: TriageResult | None = None
    capture = [s for s in snapshots if not _is_agent_snapshot(s)]
    if found := rendered_non_content(ctx.run_dir, capture):
        revised = triage = mark_non_content(triage, *found)
        notes.append(f"{non_content_note(*found)}: dead-site rule applies")
        snapshots = capture = []
    base_signals = domain_signals(site.host, site.registrable_domain, ctx.brands) + triage_signals(
        triage
    )

    if not snapshots or not _has_content(ctx, capture or snapshots):
        return Analysis(
            score_without_content(base_signals, threshold, _status_note(triage)),
            [],
            notes,
            usage,
            triage=revised,
        )

    addresses: list[CryptoAddress] = []
    ignored: list[str] = []
    contents = {}
    for snap in snapshots:
        contents[snap.snapshot_id] = load_snapshot_content(snap, ctx.run_dir)
        addresses = merge_all(
            addresses, extract(contents[snap.snapshot_id], ctx.blocklist, ignored)
        )
    addresses = _apply_highlights(addresses, ctx.site_dir(site), snapshots)
    if ignored:
        notes.append(
            f"ignored {len(set(ignored))} token-contract address(es) "
            f"(labelled contract on the page or under contract keys in API/script data)"
        )

    # The landing page: the last capture snapshot (after a mobile retry or a warning
    # click-through it is the real page); the agent's best page goes alongside it.
    landing = (capture or snapshots)[-1]
    content = contents[landing.snapshot_id]
    nav_page = _best_navigation_page(snapshots, addresses)
    signals = base_signals + merge_signals(
        [
            content_signals(c.visible_text, c.html, site.host)
            for c in (contents[s.snapshot_id] for s in snapshots)
        ]
    )
    if sig := address_signal(len(addresses)):
        signals.append(sig)
    if sig := deposit_flow_signal(addresses):
        signals.append(sig)
    navigation = None
    if nav_page is not None:
        on_page = [
            a
            for a in addresses
            if a.tier == AddressTier.PRIMARY
            and any(sg.page_url == nav_page.url for sg in a.sightings)
        ]
        navigation = {
            "url": nav_page.url,
            "title": nav_page.title,
            "text": contents[nav_page.snapshot_id].visible_text,
            "screenshot_png": (ctx.run_dir / nav_page.screenshot_path).read_bytes()
            if nav_page.screenshot_path
            else None,
            "note": f"stage {nav_page.stage.value}; {len(on_page)} primary address(es) on it",
        }
    judgment = None
    try:
        judgment = await judge(
            ctx.llm,
            site.site_id,
            usage,
            url=site.url,
            final_url=landing.url,
            title=landing.title,
            status_note=_status_note(triage),
            page_text=content.visible_text,
            screenshot_png=(ctx.run_dir / landing.screenshot_path).read_bytes()
            if landing.screenshot_path
            else None,
            signals=signals,
            addresses=addresses,
            effort=settings.llm.judge_effort,
            archived_note=_archived_note(landing, triage) if content.archived else "",
            navigation=navigation,
        )
    except LLMError as exc:
        notes.append(f"LLM judgment unavailable, heuristics only: {exc}")
    classification, score_notes = score_content(
        signals, judgment, threshold, partial=partial, archived=content.archived
    )
    app_downloads = merge_targets(*(find_app_downloads(c) for c in contents.values()))
    return Analysis(
        classification,
        addresses,
        notes + score_notes,
        usage,
        landing.url,
        revised,
        app_downloads,
    )


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
    navigation: NavigationTrace | None = None,
    identity_id: str | None = None,
) -> SiteResult:
    # Every record lists its addresses whatever the verdict (output contract, 2026-10-07: pilot
    # site 012's deposit addresses vanished when the verdict fell to not_scam at p=0.44).
    primary = [a for a in analysis.addresses if a.tier == AddressTier.PRIMARY]
    low = [a for a in analysis.addresses if a.tier == AddressTier.LOW_CONFIDENCE]
    return SiteResult(
        site=site,
        triage=analysis.triage or triage,  # analysis may have revised the status (parked)
        processing_status=processing,
        classification=analysis.classification,
        addresses=primary,
        low_confidence_addresses=low,
        other_addresses=[],
        navigation=navigation,
        app_downloads=analysis.app_downloads,
        identity_used=identity_id,
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
    brands: list[BrandToken],
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


async def _navigate(
    ctx: RunContext,
    site: Site,
    triage: TriageResult,
    first: Analysis,
    *,
    partial: bool,
    mobile: bool,
) -> tuple[Analysis, NavigationTrace | None, str | None, list[str]]:
    """The navigation agent, if the first judgment calls for it (DESIGN §5.5 trigger and
    budgets), then a second judgment over everything saved: landing capture plus the agent's
    snapshots. Any failure keeps the first judgment and says so in the notes."""
    nav = ctx.nav
    assert nav is not None
    settings = ctx.settings
    nav.spend.add(first.usage, settings.llm.judge_model)
    if first.triage is not None:  # revised to non-content: nothing to navigate
        return first, None, None, []
    c = first.classification
    seen = f"first judgment: {c.verdict.value}, p={c.scam_probability:.2f}"
    band = (settings.classify.uncertain_band[0], settings.classify.uncertain_band[1])
    landing_snapshots = load_snapshots(ctx.site_dir(site))
    landing_text = (
        load_snapshot_content(landing_snapshots[-1], ctx.run_dir).visible_text
        if landing_snapshots
        else ""
    )
    if not (
        nav.force
        or should_navigate(c, band, landing_text=landing_text, has_address=bool(first.addresses))
    ):
        return (
            first,
            None,
            None,
            [f"navigation skipped ({seen}; no scam/uncertain verdict or account flow)"],
        )
    if nav.stop_file is not None and nav.stop_file.exists():
        return first, None, None, [f"navigation skipped: stop file present ({seen})"]
    if reason := spend_blocks(nav, settings.llm.navigator_model):
        return first, None, None, [f"navigation skipped: {reason} ({seen})"]
    assert ctx.browser is not None
    try:
        run, nav_notes, identity_id = await navigate_site(
            settings=settings,
            run_dir=ctx.run_dir,
            site_dir=ctx.site_dir(site),
            site=site,
            triage=triage,
            browser=ctx.browser,
            blocklist=ctx.blocklist,
            mobile=mobile,
            opts=nav,
            factory=nav.mailbox_factory or mailtm_factory(ctx.proxy or ""),
            brands=ctx.brands,
        )
    except Exception as exc:  # noqa: BLE001 - keep the first judgment, record why
        traceback.print_exc()
        return first, None, None, [f"navigation failed: {type(exc).__name__}: {exc}"]
    nav_notes = [seen, *nav_notes]
    if run is None:
        return first, None, identity_id, nav_notes
    nav.spend.add(run.usage, settings.llm.navigator_model)
    second = await analyze(ctx, site, triage, load_snapshots(ctx.site_dir(site)), partial=partial)
    nav.spend.add(second.usage, settings.llm.judge_model)
    total = first.usage.plus(run.usage).plus(second.usage)
    return replace(second, usage=total), run.trace, identity_id, nav_notes


async def process_site(ctx: RunContext, site: Site, triage: TriageResult) -> SiteResult:
    started = datetime.now(UTC)
    site_dir = ctx.site_dir(site)
    if site_dir.exists():
        shutil.rmtree(site_dir)  # a resumed site starts clean
    site_dir.mkdir(parents=True)
    notes: list[str] = []
    snapshots: list[PageSnapshot] = []
    partial = False
    mobile = False
    captured_live = False

    if needs_visit(triage):
        capture = await capture_site(ctx, site, triage)
        notes += capture.notes
        snapshots = capture.snapshots
        partial = capture.partial
        captured_live = True
        mobile = (
            ctx.force_mobile
            or _is_mobile(ctx.settings, site.url)
            or any("mobile viewport" in n for n in capture.notes)
        )
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

    if found := rendered_non_content(ctx.run_dir, snapshots):
        # Dead-site policy: a parked or empty page is no evidence about the site, so try Wayback.
        triage = mark_non_content(triage, *found)
        notes.append(non_content_note(*found))
        snapshots = []
        captured_live = False

    if not snapshots and ctx.settings.features.archive_fallback:
        snapshots, wayback_notes = await recover_from_wayback(ctx, site)
        notes += wayback_notes

    # Capture-time facts that rescore must keep (it re-derives everything else).
    (site_dir / "capture.json").write_text(json.dumps({"notes": notes, "partial": partial}))
    analysis = await analyze(ctx, site, triage, snapshots, partial=partial)
    navigation: NavigationTrace | None = None
    identity_id: str | None = None
    if ctx.nav is not None and captured_live and snapshots:
        analysis, navigation, identity_id, nav_notes = await _navigate(
            ctx, site, triage, analysis, partial=partial, mobile=mobile
        )
        notes += nav_notes
        (site_dir / "capture.json").write_text(
            json.dumps({"notes": notes, "partial": partial, "identity_id": identity_id})
        )
    processing = ProcessingStatus.PARTIAL if partial else ProcessingStatus.COMPLETED
    result = build_result(
        site,
        triage,
        analysis,
        processing=processing,
        notes=notes,
        started=started,
        trace_path=None,
        navigation=navigation,
        identity_id=identity_id,
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


def browser_was_lost(result: SiteResult) -> bool:
    """A shared Chromium crash is transient and must not make `--resume` skip the site."""
    return any(
        "TargetClosedError" in note or "browser has been closed" in note for note in result.notes
    )


def retry_on_resume(result: SiteResult) -> bool:
    """Resume heals failed records as well as completed records damaged by browser loss."""
    return result.processing_status == ProcessingStatus.ERROR or browser_was_lost(result)


class NoSitesVisited(RuntimeError):
    """A run that should have loaded sites loaded none (a wiring bug or a dead network)."""


def count_visited(run_dir: Path, sites: list[Site]) -> int:
    """Sites with at least one saved snapshot, i.e. a page that really loaded."""
    return sum(
        1
        for s in sites
        if (run_dir / "sites" / s.site_id / "snapshots.jsonl").exists()
        and (run_dir / "sites" / s.site_id / "snapshots.jsonl").stat().st_size > 0
    )


def check_visited(expected: int, visited: int) -> None:
    """Fail loudly instead of reporting a clean run (capture-1 and capture-3 both "finished"
    without visiting anything). `expected` is how many sites the run set out to load."""
    if expected > 0 and visited == 0:
        raise NoSitesVisited(f"0 of {expected} sites were visited: no page loaded in this run")


def needs_visit(triage: TriageResult) -> bool:
    """Whether the run loads this site in a browser (live, a status worth rechecking, or a
    browser's phishing-warning page)."""
    is_warning_page = any(
        s.name == "cloudflare_phishing_interstitial" for s in triage_signals(triage)
    )
    return triage.status == SiteStatus.LIVE or triage.status in RECHECK_STATUSES or is_warning_page


async def run_pipeline(
    settings: Settings,
    sites: list[Site],
    run_dir: Path,
    *,
    resume: bool,
    nav: NavigationOptions | None = None,
    concurrency: int | None = None,
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
    retry_ids = {site_id for site_id, result in done.items() if retry_on_resume(result)}
    todo = [s for s in sites if s.site_id not in done or s.site_id in retry_ids]
    finished = len(done) - len(retry_ids)
    print(
        f"{len(sites)} sites, {finished} already done, {len(todo)} to process"
        f" ({len(retry_ids)} browser-loss retries)"
    )

    llm = LLMClient(settings.llm.gateway_url)
    lock = asyncio.Lock()
    requested_concurrency = concurrency or settings.run.concurrency
    # Wall-clock cap per site. With navigation it adds the agent's own budget; with operator
    # confirmation a person is in the loop, so only the agent's watchdog and stop file bound it.
    site_timeout: float | None = settings.run.site_timeout_s
    if nav is not None:
        site_timeout = None if nav.confirm else site_timeout + nav.limits.max_seconds
    async with async_playwright() as pw:

        async def process_group(group: list[Site], group_concurrency: int) -> list[SiteResult]:
            """Process a group in one browser; callers isolate crash retries one site at a time."""
            browser = await launch_browser(pw, proxy)
            ctx = RunContext(
                settings=settings, run_dir=run_dir, llm=llm, proxy=proxy, browser=browser, nav=nav
            )
            semaphore = asyncio.Semaphore(group_concurrency)

            async def one(site: Site) -> SiteResult | None:
                started = datetime.now(UTC)
                if nav is not None and nav.stop_file is not None and nav.stop_file.exists():
                    print(f"  {site.site_id} skipped: stop file present", flush=True)
                    return None
                async with semaphore:
                    try:
                        result = await asyncio.wait_for(
                            process_site(ctx, site, triage[site.site_id]), timeout=site_timeout
                        )
                    except TimeoutError:
                        result = _error_result(
                            site,
                            triage[site.site_id],
                            "site timeout",
                            started,
                            settings,
                            ctx.brands,
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

            try:
                attempted = await asyncio.gather(*(one(s) for s in group))
            finally:
                try:
                    await browser.close()
                except PlaywrightError:
                    pass
            return [result for result in attempted if result is not None]

        first_results = await process_group(todo, requested_concurrency) if todo else []
        lost_ids = {r.site.site_id for r in first_results if browser_was_lost(r)}
        if lost_ids:
            print(
                f"retrying {len(lost_ids)} browser-loss sites in fresh isolated browsers",
                flush=True,
            )
        for site in (s for s in todo if s.site_id in lost_ids):
            await process_group([site], 1)
    await llm.aclose()
    check_visited(
        sum(1 for s in todo if needs_visit(triage[s.site_id])), count_visited(run_dir, todo)
    )
    results = load_checkpoint(checkpoint)
    return [results[s.site_id] for s in sites if s.site_id in results]


async def run_capture_only(
    settings: Settings,
    sites: list[Site],
    run_dir: Path,
    *,
    settle_ms: int = 8000,
    force_mobile: bool = False,
) -> list[dict[str, object]]:
    """Evidence only: for each site triage called live, load the landing page (desktop, plus the
    mobile retry for an empty shell) and save snapshot, HTML, text and network log. No clicks, no
    navigation agent, no model calls, no Wayback, no verdicts. Needs triage.jsonl in the run dir."""
    proxy = require_egress_proxy()
    triage = load_triage(run_dir / "triage.jsonl")
    todo = [s for s in sites if s.site_id in triage and triage[s.site_id].status == SiteStatus.LIVE]
    print(f"{len(todo)} live sites to capture (landing only, no clicks, no model calls)")
    semaphore = asyncio.Semaphore(settings.run.concurrency)
    rows: list[dict[str, object]] = []
    async with async_playwright() as pw:
        browser = await launch_browser(pw, proxy)
        # The context needs an LLM client by type; nothing here ever calls it.
        llm = LLMClient(settings.llm.gateway_url)
        ctx = RunContext(
            settings=settings,
            run_dir=run_dir,
            llm=llm,
            proxy=proxy,
            browser=browser,
            settle_ms=settle_ms,
            force_mobile=force_mobile,
        )

        async def one(site: Site) -> None:
            started = datetime.now(UTC)
            site_dir = ctx.site_dir(site)
            if site_dir.exists():
                shutil.rmtree(site_dir)
            site_dir.mkdir(parents=True)
            row: dict[str, object] = {"site_id": site.site_id, "url": site.url}
            async with semaphore:
                try:
                    cap = await asyncio.wait_for(
                        capture_site(ctx, site, triage[site.site_id], click_interstitial=False),
                        timeout=settings.run.site_timeout_s,
                    )
                    (site_dir / "capture.json").write_text(
                        json.dumps({"notes": cap.notes, "partial": cap.partial})
                    )
                    row |= {
                        "loaded": cap.loaded,
                        "snapshots": len(cap.snapshots),
                        "notes": cap.notes,
                    }
                except TimeoutError:
                    row["error"] = "site timeout"
                except Exception as exc:  # noqa: BLE001 - one site never crashes the run
                    row["error"] = f"{type(exc).__name__}: {exc}"
            row["seconds"] = round((datetime.now(UTC) - started).total_seconds(), 1)
            rows.append(row)
            print(f"  {site.site_id} {row}", flush=True)

        await asyncio.gather(*(one(s) for s in todo))
        await browser.close()
    await ctx.llm.aclose()
    (run_dir / "capture.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    check_visited(len(todo), count_visited(run_dir, todo))
    return rows


def original_triage(run_dir: Path) -> dict[str, TriageResult]:
    """The run's probe results (`triage.jsonl`, then `triage_extra/triage.jsonl` from a resume)."""
    out: dict[str, TriageResult] = {}
    for path in (run_dir / "triage.jsonl", run_dir / "triage_extra" / "triage.jsonl"):
        if path.exists():
            out.update(load_triage(path))
    return out


async def classify_from_evidence(
    settings: Settings, sites: list[Site], run_dir: Path
) -> list[SiteResult]:
    """Judge every site from the evidence a run saved, with no checkpoint needed: for a
    capture-only run (`scamhunter capture`), which saved snapshots and no verdicts. Sites with
    no snapshots (dead, or not captured) take the dead-site policy without Wayback. Nothing is
    visited and the navigation agent does not run; the checkpoint written here lets `rescore`,
    `report` and `review` work on the run afterwards."""
    triage = load_triage(run_dir / "triage.jsonl")
    llm = LLMClient(settings.llm.gateway_url)
    ctx = RunContext(settings=settings, run_dir=run_dir, llm=llm)
    semaphore = asyncio.Semaphore(settings.run.concurrency)

    async def one(site: Site) -> SiteResult:
        started = datetime.now(UTC)
        async with semaphore:
            snapshots = load_snapshots(ctx.site_dir(site))
            analysis = await analyze(ctx, site, triage[site.site_id], snapshots)
        capture_file = ctx.site_dir(site) / "capture.json"
        notes = json.loads(capture_file.read_text())["notes"] if capture_file.exists() else []
        print(
            f"  {site.site_id} {analysis.classification.verdict.value:<8} "
            f"p={analysis.classification.scam_probability:.2f} "
            f"{analysis.classification.evidence_source.value:<12} {site.url}",
            flush=True,
        )
        return build_result(
            site,
            triage[site.site_id],
            analysis,
            processing=ProcessingStatus.COMPLETED,
            notes=notes,
            started=started,
            trace_path=None,
        )

    results = await asyncio.gather(*(one(s) for s in sites if s.site_id in triage))
    await llm.aclose()
    write_jsonl(run_dir / "checkpoint.jsonl", results)
    return list(results)


async def rescore(settings: Settings, sites: list[Site], run_dir: Path) -> list[SiteResult]:
    """Re-run extraction + classification from saved evidence. No site is visited."""
    checkpoint = load_checkpoint(run_dir / "checkpoint.jsonl")
    original = original_triage(run_dir)
    llm = LLMClient(settings.llm.gateway_url)
    ctx = RunContext(settings=settings, run_dir=run_dir, llm=llm)
    results = []
    for site in sites:
        old = checkpoint.get(site.site_id)
        if old is None:
            continue
        snapshots = load_snapshots(ctx.site_dir(site))
        # The probe's status, not the one the old analysis revised (2026-10-07: pilot site 021
        # kept "empty" from a maintenance page the agent reached, after the rule changed).
        triage = original.get(site.site_id, old.triage)
        analysis = await analyze(
            ctx,
            site,
            triage,
            snapshots,
            partial=old.processing_status == ProcessingStatus.PARTIAL,
        )
        capture_file = ctx.site_dir(site) / "capture.json"
        capture_info = json.loads(capture_file.read_text()) if capture_file.exists() else {}
        capture_notes = capture_info.get("notes", [])
        trace_file = ctx.site_dir(site) / "agent_trace.json"
        navigation = (
            NavigationTrace.model_validate_json(trace_file.read_text())
            if trace_file.exists()
            else None
        )
        result = build_result(
            site,
            triage,
            analysis,
            processing=old.processing_status,
            notes=capture_notes,
            started=old.started_at,
            trace_path=old.trace_path,
            navigation=navigation,
            identity_id=capture_info.get("identity_id"),
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
