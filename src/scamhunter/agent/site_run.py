"""The navigator on a real site (DESIGN §5.5): when to run it, what it needs, and what it leaves.

`process_site` calls `navigate_site` after the first judgment. The agent gets its own browser
context (desktop or phone, as capture chose), a disposable mailbox and the site's registrable
domain as the only place it may go. Every action still goes through `Policy`; the stop file and
the optional submit confirmation are the operator's controls (`NavigationLoop`)."""

import asyncio
import logging
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import httpx
from playwright.async_api import Browser
from playwright.async_api import Error as PlaywrightError

from scamhunter.agent.identity import MailTmMailbox, new_identity
from scamhunter.agent.loop import (
    AgentLimits,
    AgentRun,
    ClaudeDecider,
    Confirm,
    Decider,
    Evidence,
    Mailbox,
    NavigationLoop,
)
from scamhunter.agent.policy import WALLET_CONNECT, Policy, registrable
from scamhunter.agent.prompts import GOAL, system_prompt
from scamhunter.browser.nav_guard import PageNavigationGuard
from scamhunter.browser.sandbox import new_context
from scamhunter.classify.domain import BrandToken
from scamhunter.config import Settings
from scamhunter.llm.client import PRICES_PER_MTOK, LLMClient, TokenUsage
from scamhunter.models import Classification, Identity, Site, TriageResult, Verdict

log = logging.getLogger(__name__)
MAILBOX_ATTEMPTS = 3  # creating the inbox: tries, with 2 s and 4 s waits between them
ACCOUNT_FLOW = re.compile(
    r"\b(?:log ?in|sign ?in|sign ?up|register|create (?:an )?account|recharge|withdraw|"
    r"assets|my account|deposit)\b|\u767b\u5f55|\u767b\u9304|\u6ce8\u518c|\u8a3b\u518a|"
    r"\u5145\u503c|\u63d0\u73fe",
    re.I,
)

# (identity, mailbox, close) for one site. Real runs use mail.tm through the egress proxy; the
# mock regression plugs in the mock exchange's inbox.
MailboxFactory = Callable[
    [Site], Awaitable[tuple[Identity, Mailbox | None, Callable[[], Awaitable[None]]]]
]


@dataclass
class Spend:
    """Estimated session spend (USD), shared by every site. Estimates, not billing."""

    usd: float = 0.0

    def add(self, usage: TokenUsage, model: str) -> None:
        self.usd += usage.cost_usd(model)


@dataclass
class NavigationOptions:
    limits: AgentLimits
    llm: LLMClient
    stop_file: Path | None = None
    confirm: Confirm | None = None
    spend_cap_usd: float | None = None
    spend: Spend = field(default_factory=Spend)
    force: bool = False  # navigate whatever the first judgment says (mock regression only)
    loopback_only: bool = False  # mock mode: the browser can reach loopback and nothing else
    progress: Callable[[str], None] | None = None
    mailbox_factory: MailboxFactory | None = None
    decider_factory: Callable[[Policy, Site], Decider] | None = None  # tests; default is Claude
    runs: dict[str, AgentRun] = field(default_factory=dict)  # site id → run, for evaluation
    blocked: dict[str, list[str]] = field(default_factory=dict)  # loopback guard hits per site


def worst_case_usd(limits: AgentLimits, model: str) -> float:
    """The most one site's navigation can cost: both token caps reached, nothing cached."""
    price_in, price_out = PRICES_PER_MTOK[model]
    return (limits.max_tokens_in * price_in + limits.max_tokens_out * price_out) / 1_000_000


def should_navigate(
    c: Classification,
    uncertain_band: tuple[float, float],
    *,
    landing_text: str = "",
    has_address: bool = False,
) -> bool:
    """Navigate a scam/uncertain verdict or a landing page with an account/deposit flow.

    The union keeps scam-looking pages with hidden account controls while also reaching low-scored
    login flows and pages that already expose an address (LOG 2026-10-07 18:30)."""
    low, high = uncertain_band
    verdict_trigger = c.verdict == Verdict.SCAM or low <= c.scam_probability <= high
    account_trigger = (
        has_address
        or bool(ACCOUNT_FLOW.search(landing_text))
        or bool(WALLET_CONNECT.search(landing_text))
    )
    return verdict_trigger or account_trigger


def spend_blocks(opts: NavigationOptions, model: str) -> str | None:
    """A reason not to start, if the session cap could be crossed by one more site."""
    if opts.spend_cap_usd is None:
        return None
    worst = worst_case_usd(opts.limits, model)
    if opts.spend.usd + worst > opts.spend_cap_usd:
        return (
            f"session spend cap: ${opts.spend.usd:.2f} spent, the next site could cost "
            f"${worst:.2f} against a ${opts.spend_cap_usd:.2f} cap"
        )
    return None


def mailtm_factory(proxy: str) -> MailboxFactory:
    async def make(site: Site) -> tuple[Identity, Mailbox | None, Callable[[], Awaitable[None]]]:
        client = httpx.AsyncClient(proxy=proxy, timeout=20)
        box = MailTmMailbox(client)
        for attempt in range(MAILBOX_ATTEMPTS):  # a transient error is retried with backoff
            try:
                address = await box.create()
                return new_identity(address), box, client.aclose
            except Exception as exc:  # noqa: BLE001 - no mailbox is a gate, not a crash
                log.warning(
                    "mail.tm unavailable (%s: %s), attempt %d of %d",
                    type(exc).__name__,
                    exc,
                    attempt + 1,
                    MAILBOX_ATTEMPTS,
                )
                if attempt + 1 < MAILBOX_ATTEMPTS:
                    await asyncio.sleep(2**attempt * 2)
        return new_identity("mailbox-unavailable@invalid.example"), None, client.aclose

    return make


async def navigate_site(
    *,
    settings: Settings,
    run_dir: Path,
    site_dir: Path,
    site: Site,
    triage: TriageResult,
    browser: Browser,
    blocklist: frozenset[str],
    mobile: bool,
    opts: NavigationOptions,
    factory: MailboxFactory,
    brands: list[BrandToken] | None = None,
) -> tuple[AgentRun | None, list[str], str | None]:
    """Run the navigation loop on one site. Returns the run (None if it could not start), notes
    for the site record and the identity id used. Evidence goes to the site's snapshots.jsonl."""
    notes: list[str] = []
    identity, mailbox, close_mail = await factory(site)
    if mailbox is None:
        notes.append("no disposable mailbox (mail.tm unavailable): email verification is a gate")
    ignore_tls = triage.tls_valid is False
    context = await new_context(
        browser,
        settings.browser,
        mobile=mobile,
        ignore_https_errors=ignore_tls,
        accept_language=settings.http.accept_language,
        loopback_only=opts.loopback_only,
    )
    await context.tracing.start(screenshots=True, snapshots=True)
    run: AgentRun | None = None
    try:
        page = await context.new_page()
        try:
            await page.goto(site.url, wait_until="domcontentloaded")
        except PlaywrightError as exc:
            notes.append(f"navigation could not load the site: {str(exc).splitlines()[0][:160]}")
            return None, notes, identity.identity_id
        host = urlparse(page.url).hostname or site.host
        domain = registrable(host)
        if domain != site.registrable_domain:
            notes.append(f"navigation runs on {domain} (the site redirected from {site.host})")
        policy = Policy(domain, identity, mock_wallet_active=False, brands=brands)  # no wallet v1
        decider = (
            opts.decider_factory(policy, site)
            if opts.decider_factory
            else ClaudeDecider(
                opts.llm, site.site_id, system_prompt(policy.mock_wallet_active), False
            )
        )
        site_id = site.site_id
        progress = opts.progress
        loop = NavigationLoop(
            page=page,
            decider=decider,
            policy=policy,
            limits=opts.limits,
            evidence=Evidence(page, site_dir, run_dir, blocklist),
            goal=GOAL,
            identity=identity,
            mailbox=mailbox,
            stop_file=opts.stop_file,
            confirm=opts.confirm,
            progress=(lambda line: progress(f"{site_id} {line}")) if progress else None,
            page_guard=PageNavigationGuard(page),
        )
        run = await loop.run()
        (site_dir / "agent_trace.json").write_text(run.trace.model_dump_json(indent=2))
        opts.runs[site.site_id] = run
        if opts.loopback_only:
            opts.blocked[site.site_id] = list(getattr(context, "blocked_urls", []))
        return run, notes, identity.identity_id
    finally:
        try:
            await context.tracing.stop(path=str(site_dir / "trace_nav.zip"))
        except PlaywrightError as exc:
            notes.append(f"browser trace unavailable: {str(exc).splitlines()[0][:160]}")
        try:
            await context.close()
        except PlaywrightError as exc:
            notes.append(f"browser context close failed: {str(exc).splitlines()[0][:160]}")
        await close_mail()
