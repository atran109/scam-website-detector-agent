"""Observe → decide → policy check → act → extract loop (DESIGN §5.5), producing a NavigationTrace.

The decision-maker is anything with `decide(view) -> Reply`: Claude through the gateway, or a
script in tests. Both return Anthropic-shaped content blocks, so every decision goes through the
same parsing (tools.py) and the same policy check (policy.py) before anything touches the page.

A *step* is one model reply (DESIGN §5.5, decided 2026-10-06). A reply may carry several
fill/select calls and one final action; each is checked and run in order, and the batch stops at
the first refusal or failure. Every refused action is kept in the trace with the policy's reason.
"""

import asyncio
import json
import logging
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import Page

from scamhunter.agent.identity import MailMessage, describe_message, resolve_placeholders
from scamhunter.agent.policy import LoopDetector, Policy, registrable
from scamhunter.agent.tools import TOOLS, ParsedCall, ToolError, calls_after, pick_tool_calls
from scamhunter.browser.capture import NetworkRecorder, load_snapshot_content, take_snapshot
from scamhunter.browser.elements import ActionResult, perform
from scamhunter.browser.page_state import (
    Coverage,
    PageState,
    gate_hints,
    labelled_deposit_page,
    observe,
)
from scamhunter.config import AgentSettings
from scamhunter.extract.extractor import extract, merge_all
from scamhunter.llm.client import LLMClient, LLMError, TokenUsage
from scamhunter.llm.sanitize import untrusted
from scamhunter.models import (
    ActionType,
    AddressTier,
    AgentAction,
    AgentStep,
    Asset,
    BlockedReason,
    CryptoAddress,
    DiscoveryStage,
    Identity,
    NavigationTrace,
    Network,
    StopReason,
)
from scamhunter.report.screenshots import highlight_address

log = logging.getLogger(__name__)

# Hard per-site LLM token caps, checked before every model call (DESIGN §5.5 budgets).
MAX_SITE_TOKENS_IN = 250_000
MAX_SITE_TOKENS_OUT = 25_000
HISTORY_LINES = 12  # recent steps shown to the decider, one line per step
CYCLE_MAX_PERIOD = 6  # page cycles up to this many distinct pages are detected
CYCLE_WARN, CYCLE_STOP = 3, 4  # repeats of the same page cycle: warn the model, then stop
WATCHDOG_SECONDS = 1.0
MAILBOX_POLLS = 4
MAILBOX_POLL_SECONDS = 3.0
SNAPSHOT_IDLE_MS = 2000  # deposit widgets are small XHRs; the snapshot also waits 1.5 s
LABEL_CONFIDENCE_FOR_COVERAGE = 0.6

# What a logged-in page tends to show; used with "a password was submitted" to set logged_in.
ACCOUNT_MARKERS = re.compile(
    r"log ?out|sign ?out|balance|my assets|my account|退出|余额|资产", re.I
)
COIN_OR_NETWORK = re.compile(
    r"\b(?:USDT|USDC|BTC|ETH|TRX|BNB|LTC|DOGE|SOL|XRP|TRC-?20|ERC-?20|BEP-?20|BSC|OMNI"
    r"|Bitcoin|Ethereum|Tron)\b",
    re.I,
)


# Asks the operator before the first form submission on a site; True = go ahead.
Confirm = Callable[[str], Awaitable[bool]]
# The actions that can submit a form after fields were filled.
SUBMITTING = {ActionType.CLICK, ActionType.CLICK_AT, ActionType.PRESS}
NOT_A_SUBMIT_ROLES = {"checkbox", "radio", "switch", "combobox", "tab"}


class Mailbox(Protocol):
    async def next_message(self) -> MailMessage | None: ...


@dataclass(frozen=True)
class StepView:
    """Everything the decider sees for one step."""

    goal: str
    state: PageState
    history: list[str]  # recent actions and their results, oldest first
    turn: int
    max_steps: int
    gates: list[str] = field(default_factory=list)  # "captcha (CAPTCHA widget on /register)"


@dataclass
class Reply:
    content: list[dict[str, Any]]  # Anthropic content blocks (text, tool_use)
    usage: dict[str, int] = field(default_factory=dict)
    cached: bool = False


class Decider(Protocol):
    async def decide(self, view: StepView) -> Reply: ...


@dataclass(frozen=True)
class AgentLimits:
    max_steps: int
    max_seconds: int
    max_consecutive_failures: int
    target_assets: tuple[str, ...]
    max_tokens_in: int = MAX_SITE_TOKENS_IN
    max_tokens_out: int = MAX_SITE_TOKENS_OUT

    @classmethod
    def from_settings(cls, s: AgentSettings, **overrides: Any) -> "AgentLimits":
        base = {
            "max_steps": s.max_steps,
            "max_seconds": s.max_seconds,
            "max_consecutive_failures": s.max_consecutive_failures,
            "target_assets": tuple(s.target_assets),
        }
        return cls(**(base | overrides))


@dataclass(frozen=True)
class Refusal:
    turn: int
    action: str  # short description, e.g. 'click [7] "I have paid"'
    reason: str
    blocked_at: BlockedReason | None


@dataclass
class AgentRun:
    """The trace (output contract) plus what evaluation needs."""

    trace: NavigationTrace
    addresses: list[CryptoAddress]
    usage: TokenUsage
    turns: int
    refusals: list[Refusal]
    found_assets: set[str]
    first_address_turn: int | None  # step at which the first deposit address appeared
    full_coverage_turn: int | None  # step at which every target asset had an address
    seconds: float  # wall clock
    call_usage: list[dict[str, int]] = field(default_factory=list)  # API usage per step


def asset_keys(address: CryptoAddress) -> set[str]:
    """Target-asset keys ("BTC", "USDT-TRC20", …) an address counts toward."""
    keys = set()
    for label in address.labels:
        if label.confidence < LABEL_CONFIDENCE_FOR_COVERAGE:
            continue
        if label.asset in (Asset.BTC, Asset.ETH):
            keys.add(label.asset.value)
        elif label.asset in (Asset.USDT, Asset.USDC):
            network = {Network.ETHEREUM: "ERC20", Network.TRON: "TRC20"}.get(label.network)
            if network:
                keys.add(f"{label.asset.value}-{network}")
    return keys


def describe_action(action: AgentAction, state: PageState | None = None) -> str:
    element = None
    if state is not None and action.element_id is not None:
        element = next((e for e in state.elements if e.id == action.element_id), None)
    name = f' "{element.name[:40]}"' if element else ""
    match action.type:
        case ActionType.CLICK:
            return f"click [{action.element_id}]{name}"
        case ActionType.FILL:
            return f"fill [{action.element_id}]{name} = {action.value!r}"
        case ActionType.SELECT:
            return f"select [{action.element_id}]{name} = {action.value!r}"
        case ActionType.CLICK_AT:
            return f"click_at ({action.x}, {action.y})"
        case ActionType.GOTO:
            return f"goto {action.url}"
        case ActionType.DONE:
            return f"done: {action.rationale[:80]}"
        case _:
            return f"{action.type.value} {action.value or ''}".strip()


class Evidence:
    """Snapshots, extraction and highlight screenshots for one site. Writes the same files as the
    capture stage (snapshots.jsonl, highlights.json), so rescore and review read them as usual."""

    def __init__(self, page: Page, site_dir: Path, run_dir: Path, blocklist: frozenset[str]):
        self.page = page
        self.site_dir = site_dir
        self.run_dir = run_dir
        self.blocklist = blocklist
        self.recorder = NetworkRecorder(site_dir, run_dir)
        self.recorder.attach(page)
        self.addresses: list[CryptoAddress] = []
        self._count = 0
        self._highlights_path = site_dir / "highlights.json"

    async def capture(self, stage: DiscoveryStage) -> tuple[str, list[CryptoAddress]]:
        """Snapshot the page and extract. Returns the screenshot path and the new addresses."""
        self._count += 1
        snapshot = await take_snapshot(
            self.page,
            self.recorder,
            stage,
            f"a{self._count:03d}",
            self.site_dir,
            self.run_dir,
            network_idle_ms=SNAPSHOT_IDLE_MS,
        )
        found = extract(load_snapshot_content(snapshot, self.run_dir), self.blocklist)
        known = {a.dedupe_key for a in self.addresses}
        new = [a for a in found if a.dedupe_key not in known]
        self.addresses = merge_all(self.addresses, found)
        if new:
            await self._highlight(new)
        return snapshot.screenshot_path, new

    async def _highlight(self, addresses: list[CryptoAddress]) -> None:
        path = self._highlights_path
        highlights = json.loads(path.read_text()) if path.exists() else {}
        for address in addresses:
            out = self.site_dir / "screenshots" / f"agent_{address.address[:12]}.png"
            out.parent.mkdir(parents=True, exist_ok=True)
            box = await highlight_address(self.page, address.address, out)
            if box and address.dedupe_key not in highlights:
                highlights[address.dedupe_key] = {
                    "screenshot_path": str(out.relative_to(self.run_dir)),
                    "bbox": list(box),
                }
        path.write_text(json.dumps(highlights, indent=2))


class NavigationLoop:
    def __init__(
        self,
        page: Page,
        decider: Decider,
        policy: Policy,
        limits: AgentLimits,
        evidence: Evidence,
        goal: str,
        identity: Identity | None = None,
        mailbox: Mailbox | None = None,
        *,
        stop_file: Path | None = None,
        confirm: Confirm | None = None,
        progress: Callable[[str], None] | None = None,
    ) -> None:
        self.page = page
        self.decider = decider
        self.policy = policy
        self.limits = limits
        self.evidence = evidence
        self.goal = goal
        self.identity = identity
        self.mailbox = mailbox

        self.usage = TokenUsage()
        self.steps: list[AgentStep] = []
        self.history: list[str] = []
        self.refusals: list[Refusal] = []
        self.loop_detector = LoopDetector()
        self.found: set[str] = set()
        self.assets_tried: list[str] = []
        self.last_gate: BlockedReason | None = None
        self.gates: dict[BlockedReason, str] = {}  # gate → how it was seen, latest last
        self.linked: list[str] = []  # refused or undone targets on other sites
        self.pages: list[str] = []  # URLs seen, consecutive repeats collapsed
        self._cycle_warned: set[int] = set()
        self.cycle_warning_steps: list[int] = []  # for the trace: did the warning fire, and when
        self.password_submitted = False
        self.confirm_password_submitted = False
        self.logged_in = False
        self.registered = False
        self.reached_deposit = False
        self.first_address_turn: int | None = None
        self.full_coverage_turn: int | None = None
        self.call_usage: list[dict[str, int]] = []
        self._turns = 0
        self._started = 0.0  # wall clock (time.time): host sleep counts (2026-10-06 stall)
        self._last_call_tokens_in = 0
        self._timed_out = False
        # Operator controls (real-site runs). The stop file ends the run at once; `confirm` is
        # asked before the first submit-type action that follows a fill, and the time spent
        # waiting for the operator does not count against the wall-clock budget.
        self.stop_file = stop_file
        self.confirm = confirm
        self.progress = progress
        self._user_stopped = False
        self._paused = 0.0
        self._filled = False
        self._submit_confirmed = False

    # ---------- public ----------

    async def run(self) -> AgentRun:
        self._started = time.time()
        steps = asyncio.create_task(self._steps())
        watchdog = asyncio.create_task(self._watchdog(steps))
        try:
            stop, blocked_at = await steps
        except asyncio.CancelledError:
            if self._user_stopped:
                self.history.append("stopped: the operator stopped the run")
                stop, blocked_at = StopReason.USER_STOP, None
            elif self._timed_out:
                self.history.append(f"stopped: {self.limits.max_seconds} s wall-clock budget")
                stop, blocked_at = StopReason.BUDGET_TIME, None
            else:
                raise  # cancelled from outside, not by our time budget or the operator
        finally:
            watchdog.cancel()
        if (
            blocked_at is None
            and stop not in (StopReason.GOAL_REACHED, StopReason.USER_STOP)
            and not self.found
        ):
            blocked_at = self.last_gate  # ended another way at a gate it had hit (§5.5 Gates)
            if blocked_at and stop in (StopReason.NOT_APPLICABLE, StopReason.NO_PROGRESS):
                stop = StopReason.BLOCKED
        trace = NavigationTrace(
            goal=self.goal,
            steps=self.steps,
            stop_reason=stop,
            blocked_at=blocked_at,
            registered=self.registered,
            logged_in=self.logged_in,
            reached_deposit=self.reached_deposit,
            assets_tried=self.assets_tried,
            linked_domains=self.linked,
            cycle_warning_steps=self.cycle_warning_steps,
        )
        log.info(
            "agent stopped: %s%s after %d steps, %d refusals, found %s",
            stop.value,
            f" ({blocked_at.value})" if blocked_at else "",
            self._turns,
            len(self.refusals),
            sorted(self.found) or "nothing",
        )
        return AgentRun(
            trace=trace,
            addresses=self.evidence.addresses,
            usage=self.usage,
            turns=self._turns,
            refusals=self.refusals,
            found_assets=set(self.found),
            first_address_turn=self.first_address_turn,
            full_coverage_turn=self.full_coverage_turn,
            seconds=self._elapsed(),
            call_usage=self.call_usage,
        )

    # ---------- the loop ----------

    async def _watchdog(self, steps: asyncio.Task) -> None:
        """Hard wall-clock limit for the whole run, including an in-flight model call or browser
        action. Uses time.time(), which, unlike the monotonic clock, keeps counting while the
        host sleeps (the 2026-10-06 stall: a closed lid paused the Docker VM for 10 minutes)."""
        while not steps.done():
            if self.stop_file is not None and self.stop_file.exists():
                self._user_stopped = True
                steps.cancel()
                return
            if self._elapsed() >= self.limits.max_seconds:
                self._timed_out = True
                steps.cancel()
                return
            await asyncio.sleep(WATCHDOG_SECONDS)

    async def _steps(self) -> tuple[StopReason, BlockedReason | None]:
        _, new = await self.evidence.capture(DiscoveryStage.LANDING)
        self._count_found(new, turn=0)
        failures = 0
        for turn in range(1, self.limits.max_steps + 1):
            if self._elapsed() >= self.limits.max_seconds:
                return StopReason.BUDGET_TIME, None
            if self._over_token_cap():
                return StopReason.BUDGET_TOKENS, None
            self._turns = turn
            state = await self._observe(turn)
            if self._page_cycle(turn):
                return StopReason.NO_PROGRESS, None
            gates = [f"{g.value} ({how})" for g, how in self.gates.items()]
            view = StepView(self.goal, state, self._recent(), turn, self.limits.max_steps, gates)
            reply = await self.decider.decide(view)
            self.usage.add(reply.usage, reply.cached)
            self.call_usage.append(dict(reply.usage))
            self._last_call_tokens_in = sum(
                reply.usage.get(k, 0)
                for k in ("input_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")
            )
            batch = pick_tool_calls(reply.content)
            outcome = await self._run_batch(turn, state, batch, calls_after(reply.content, batch))
            if isinstance(outcome, tuple):
                return outcome
            failures = 0 if outcome else failures + 1
            if failures >= self.limits.max_consecutive_failures:
                self.history.append(f"{turn + 1}. stopping: {failures} failed steps in a row")
                return StopReason.NO_PROGRESS, None
        return StopReason.BUDGET_STEPS, None

    async def _run_batch(
        self,
        turn: int,
        state: PageState,
        batch: list[ParsedCall | ToolError],
        dropped: list[str],
    ) -> bool | tuple[StopReason, BlockedReason | None]:
        """Run one reply's calls. True if at least one action ran, False if the step failed,
        or a (stop reason, blocked_at) pair to end the run. `dropped` are calls after the batch
        ended; they and any batch calls skipped after a refusal are reported as not run."""
        tokens = (self.usage.tokens_in, self.usage.tokens_out)
        ran_any = False
        new_addresses: list[str] = []
        recorded_from = len(self.steps)
        parts: list[str] = []  # this step's actions and results, joined into one history line
        finished = 0  # batch calls handled (run, refused or failed)
        stop: tuple[StopReason, BlockedReason | None] | None = None
        for call in batch:
            finished += 1
            if isinstance(call, ToolError):
                parts.append(f"ERROR: {call.message}")
                break
            action = call.action
            what = describe_action(action, state)
            if action.type in (ActionType.FILL, ActionType.SELECT):
                self._filled = (
                    self._filled or self.policy.check(action, state.elements, state.facts).allowed
                )
            if action.type == ActionType.DONE:
                self._record(turn, state, action, True, None, "done")
                parts.append(what)
                stop = self._finish(call)
                break
            decision = self.policy.check(action, state.elements, state.facts)
            if not decision.allowed:
                self.refusals.append(Refusal(turn, what, decision.reason, decision.blocked_at))
                if decision.blocked_at:
                    self._note_gate(decision.blocked_at, f"refused: {what[:60]}")
                if decision.linked_url:
                    self._note_linked(decision.linked_url)
                log.info("policy refused %s: %s", what, decision.reason)
                self._record(turn, state, action, False, decision.reason, "refused")
                parts.append(f"{what} → REFUSED by policy: {decision.reason}")
                break
            if await self._declined_submit(action, what, state):
                self._record(turn, state, action, False, "declined by the operator", "refused")
                parts.append(f"{what} → declined by the operator")
                stop = (StopReason.USER_STOP, None)
                break
            result = await self._execute(action, state)
            self._record(turn, state, action, True, result.detail or None, result.result)
            parts.append(f"{what} → {result.result}{_detail(result)}")
            if not result.ok:
                break
            ran_any = True
            self._note_progress(action, state)
            if self.loop_detector.record(state.url, action):
                parts.append("stopping: the same action keeps repeating")
                stop = (StopReason.NO_PROGRESS, None)
                break
        skipped = [
            describe_action(c.action, state) if isinstance(c, ParsedCall) else "malformed call"
            for c in batch[finished:]
        ]
        if not_run := skipped + dropped:
            parts.append("not run: " + "; ".join(not_run))
        self.history.append(f"{turn}. " + " | ".join(parts))
        if self.progress is not None:
            self.progress(self.history[-1].replace("\n", " ")[:300])
        if stop is not None:
            return stop
        if ran_any:
            stage = self._base_stage()
            if await labelled_deposit_page(self.page):
                stage = DiscoveryStage.DEPOSIT_PAGE
            screenshot, new = await self.evidence.capture(stage)
            self._count_found(new, turn)
            new_addresses = [a.address for a in new]
            for step in self.steps[recorded_from:]:
                if step.allowed:
                    step.screenshot_path = screenshot
            if new_addresses and len(self.steps) > recorded_from:
                self.steps[-1].new_addresses = new_addresses
        if len(self.steps) > recorded_from:  # the reply's tokens go on its first action
            self.steps[recorded_from].tokens_in = self.usage.tokens_in - tokens[0]
            self.steps[recorded_from].tokens_out = self.usage.tokens_out - tokens[1]
        return ran_any

    async def _declined_submit(self, action: AgentAction, what: str, state: PageState) -> bool:
        """With confirmation on, ask once per site before the first submit-type action that
        follows a fill. True if the operator says no (or no answer can be given)."""
        if (
            self.confirm is None
            or self._submit_confirmed
            or not self._filled
            or action.type not in SUBMITTING
        ):
            return False
        element = next((e for e in state.elements if e.id == action.element_id), None)
        if element is not None and element.role in NOT_A_SUBMIT_ROLES:
            return False  # ticking "I agree" submits nothing; ask at the button
        self._submit_confirmed = True
        shot_dir = self.evidence.site_dir / "snapshots" / f"a{self.evidence._count:03d}"
        # as seen from the repo on the host (the container mounts runs/ at /app/runs)
        shot = Path("runs") / self.evidence.run_dir.name
        shot /= (shot_dir / "screenshot.png").relative_to(self.evidence.run_dir)
        question = (
            f"step {self._turns} on {state.url}\nabout to run: {what}\n"
            "typed so far this site (placeholders, never the real values):\n"
            + "\n".join(f"  {h[:240]}" for h in self.history if " fill " in h or "fill [" in h)
            + "\n"
            f"latest screenshot: {shot}"
        )
        started = time.time()
        try:
            return not await self.confirm(question)
        finally:
            self._paused += time.time() - started

    def _finish(self, call: ParsedCall) -> tuple[StopReason, BlockedReason | None]:
        if call.blocked_at is not None:
            return StopReason.BLOCKED, call.blocked_at
        if self.found:
            return StopReason.GOAL_REACHED, None
        return StopReason.NOT_APPLICABLE, None  # nothing found and no gate named

    # ---------- acting ----------

    async def _execute(self, action: AgentAction, state: PageState) -> ActionResult:
        if action.type == ActionType.CHECK_EMAIL:
            return await self._check_email()
        if action.type == ActionType.FILL and action.value and self.identity:
            action = action.model_copy(
                update={"value": resolve_placeholders(action.value, self.identity)}
            )
        result = await perform(self.page, action, state.elements)
        if result.ok and not self._on_site():
            left_to = self.page.url
            try:
                await self.page.go_back(wait_until="domcontentloaded")
            except PlaywrightError:
                pass
            if not left_to.startswith("chrome-error://"):
                self._note_linked(left_to)
            return ActionResult(False, "left_site", f"went to {left_to[:120]}; went back")
        return result

    async def _check_email(self) -> ActionResult:
        if self.mailbox is None:
            return ActionResult(False, "error: no mailbox")
        for attempt in range(MAILBOX_POLLS):
            message = await self.mailbox.next_message()
            if message is not None:
                return ActionResult(True, "mail", describe_message(message.subject, message.body))
            if attempt < MAILBOX_POLLS - 1:
                await self.page.wait_for_timeout(MAILBOX_POLL_SECONDS * 1000)
        return ActionResult(True, "no_mail", "the mailbox has no new message")

    def _on_site(self) -> bool:
        url = self.page.url
        if url.startswith("chrome-error://"):
            return False
        host = urlparse(url).hostname
        if not host:  # about:blank, data:
            return True
        return registrable(host) == self.policy.site_domain

    # ---------- state ----------

    async def _observe(self, turn: int) -> PageState:
        stage = self._base_stage()
        coverage = Coverage(
            target_assets=self.limits.target_assets,
            found_assets=frozenset(self.found),
            steps_left=self.limits.max_steps - turn + 1,
            seconds_left=max(0, int(self.limits.max_seconds - self._elapsed())),
        )
        state = await observe(self.page, stage, coverage)
        where = urlparse(state.url)
        path = (where.path or "/") + (f"#{where.fragment}" if where.fragment else "")
        if state.facts.captcha:
            shown = "challenge showing" if state.facts.captcha_challenge else "widget"
            self._note_gate(BlockedReason.CAPTCHA, f"CAPTCHA {shown} on {path[:40]}")
        for gate in gate_hints(state.text):
            self._note_gate(gate, f"page text on {path[:40]}")
        if not self.pages or self.pages[-1] != state.url:
            self.pages.append(state.url)
        if state.facts.is_deposit_page:
            state.stage = DiscoveryStage.DEPOSIT_PAGE
            self.reached_deposit = True
        if self.password_submitted and not any(e.input_type == "password" for e in state.elements):
            if ACCOUNT_MARKERS.search(state.text) or state.facts.is_deposit_page:
                self.logged_in = True
                self.registered = self.registered or self.confirm_password_submitted
        return state

    def _note_gate(self, gate: BlockedReason, how: str) -> None:
        self.gates.pop(gate, None)  # re-insert so the most recent gate is last
        self.gates[gate] = how
        self.last_gate = gate

    def _note_linked(self, url: str) -> None:
        if url not in self.linked:
            self.linked.append(url[:500])

    def _page_cycle(self, turn: int) -> bool:
        """The same short sequence of pages visited over and over (register → home → login →
        register …). Warn the model at CYCLE_WARN repeats; stop at CYCLE_STOP. True = stop."""
        period, repeats = page_cycle(self.pages)
        if repeats >= CYCLE_STOP:
            self.history.append(
                f"{turn}. stopping: the same {period} pages repeated {repeats} times"
            )
            return True
        if repeats >= CYCLE_WARN and period not in self._cycle_warned:
            self._cycle_warned.add(period)
            self.cycle_warning_steps.append(turn)
            self.history.append(
                f"{turn}. WARNING: you have gone through the same {period} pages {repeats} times. "
                "If a gate stops you, call done with blocked_at; otherwise try something different."
            )
        return False

    def _base_stage(self) -> DiscoveryStage:
        """The stage before deposit detection; a page labelled as a deposit page is upgraded
        to DEPOSIT_PAGE by the caller."""
        if self.logged_in:
            return DiscoveryStage.AUTHENTICATED
        return DiscoveryStage.NAVIGATION if self._turns > 0 else DiscoveryStage.LANDING

    def _note_progress(self, action: AgentAction, state: PageState) -> None:
        element = next((e for e in state.elements if e.id == action.element_id), None)
        if action.type == ActionType.FILL and element and element.input_type == "password":
            if self.password_submitted:
                self.confirm_password_submitted = True
            self.password_submitted = True
        if action.type == ActionType.CLICK and element and state.facts.is_deposit_page:
            if COIN_OR_NETWORK.search(element.name) and element.name not in self.assets_tried:
                self.assets_tried.append(element.name[:40])

    def _count_found(self, new: list[CryptoAddress], turn: int) -> None:
        for address in new:
            if address.tier != AddressTier.PRIMARY:
                continue
            keys = asset_keys(address) & set(self.limits.target_assets)
            if keys and self.first_address_turn is None:
                self.first_address_turn = turn
            self.found |= keys
        if self.full_coverage_turn is None and set(self.limits.target_assets) <= self.found:
            self.full_coverage_turn = turn

    def _record(
        self,
        turn: int,
        state: PageState,
        action: AgentAction,
        allowed: bool,
        note: str | None,
        result: str,
    ) -> None:
        self.steps.append(
            AgentStep(
                index=turn,
                page_url=state.url,
                action=action,
                allowed=allowed,
                policy_note=note[:300] if note else None,
                result=result,
                screenshot_path="",
                tokens_in=0,
                tokens_out=0,
                elapsed_ms=int(self._elapsed() * 1000),
            )
        )

    def _recent(self) -> list[str]:
        return self.history[-HISTORY_LINES:]

    def _elapsed(self) -> float:
        return time.time() - self._started - self._paused

    def _over_token_cap(self) -> bool:
        """True if the next call could cross a cap (estimated from the previous call)."""
        projected_in = self.usage.tokens_in + self._last_call_tokens_in
        return (
            projected_in > self.limits.max_tokens_in
            or self.usage.tokens_out >= self.limits.max_tokens_out
        )


def page_cycle(pages: list[str]) -> tuple[int, int]:
    """(period, repeats) of the longest run of one repeated block at the end of `pages`
    (consecutive duplicates already collapsed), for periods 2..CYCLE_MAX_PERIOD."""
    best = (0, 0)
    for period in range(2, CYCLE_MAX_PERIOD + 1):
        block = pages[-period:]
        if len(block) < period:
            break
        repeats = 1
        while pages[-period * (repeats + 1) : len(pages) - period * repeats] == block:
            repeats += 1
        if repeats > best[1]:
            best = (period, repeats)
    return best


def _detail(result: ActionResult) -> str:
    if not result.detail:
        return ""
    return "\n" + result.detail if result.result == "mail" else f" ({result.detail[:200]})"


# ---------- scripted decider (tests, and the "evil model" check) ----------


class ScriptedDecider:
    """Turns a script's (tool name, arguments) list into a model-shaped reply. A script may
    return plain text (a str) to stand for a reply with no tool call."""

    def __init__(self, script: Any) -> None:
        self.script = script  # callable: StepView -> list[tuple[str, dict]] | str
        self.calls = 0

    async def decide(self, view: StepView) -> Reply:
        self.calls += 1
        planned = self.script(view)
        if isinstance(planned, str):
            return Reply([{"type": "text", "text": planned}])
        content = [
            {
                "type": "tool_use",
                "id": f"s{self.calls}_{i}",
                "name": name,
                "input": {"rationale": "scripted", **args},
            }
            for i, (name, args) in enumerate(planned)
        ]
        return Reply(content)


# ---------- Claude through the gateway ----------

NAVIGATOR_MAX_TOKENS = 4000
NAVIGATOR_EFFORT = "medium"


def render_view(view: StepView) -> str:
    """The text of one step's user message. The recent-actions block quotes element names and
    mail from the page, so it is an untrusted block like the page itself."""
    history = "\n".join(view.history) or "(none yet)"
    return "\n".join(
        [
            f"Goal: {view.goal}",
            f"Step {view.turn} of {view.max_steps} ({view.max_steps - view.turn} left after this).",
            "Gates seen so far: " + ("; ".join(view.gates) or "none"),
            "Your recent actions and their results (element names come from the page):",
            untrusted("recent_actions", history, 4000),
            view.state.render(),
        ]
    )


class ClaudeDecider:
    """One gateway call per step: a fresh single-turn request with the system prompt and tools
    (prompt-cached), the current observation and a compact history. Keeping each request
    self-contained bounds its size; the history carries what the model needs from earlier."""

    def __init__(
        self,
        llm: LLMClient,
        site_id: str,
        system_prompt: str,
        response_cache: bool = True,
    ) -> None:
        self.llm = llm
        self.site_id = site_id
        self.system_prompt = system_prompt
        self.response_cache = response_cache

    def request(self, view: StepView) -> dict[str, Any]:
        content: list[dict[str, Any]] = []
        if screenshot := view.state.screenshot_b64():
            content.append(
                {
                    "type": "image",
                    "source": {"type": "base64", "media_type": "image/png", "data": screenshot},
                }
            )
        content.append({"type": "text", "text": render_view(view)})
        return {
            "system": [
                {
                    "type": "text",
                    "text": self.system_prompt,
                    "cache_control": {"type": "ephemeral"},  # covers tools + system
                }
            ],
            "tools": TOOLS,
            "tool_choice": {"type": "auto"},  # forced tool use is a 400 on this model family
            "messages": [{"role": "user", "content": content}],
            "max_tokens": NAVIGATOR_MAX_TOKENS,
            "output_config": {"effort": NAVIGATOR_EFFORT},
        }

    async def decide(self, view: StepView) -> Reply:
        try:
            response = await self.llm.call(
                "navigator",
                self.site_id,
                f"navigate:{view.turn}",
                self.request(view),
                TokenUsage(),  # the loop counts usage from the Reply
                cache=self.response_cache,
            )
        except LLMError as exc:  # gateway down, refusal: a failed step, not a crash
            log.warning("navigator call failed: %s", exc)
            return Reply([{"type": "text", "text": f"(navigator call failed: {exc})"}])
        u = response.usage
        log.info(
            "%s step %d: in %d (cache read %d, write %d), out %d",
            self.site_id,
            view.turn,
            u.get("input_tokens", 0),
            u.get("cache_read_input_tokens", 0),
            u.get("cache_creation_input_tokens", 0),
            u.get("output_tokens", 0),
        )
        return Reply(response.content, response.usage, response.cached)
