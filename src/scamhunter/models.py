"""All Pydantic models and enums: the ontology (DESIGN §3)."""

from datetime import datetime
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

# ============================================================
# Enums (DESIGN §3.2)
# ============================================================


class SiteStatus(StrEnum):
    LIVE = "live"
    DNS_FAILURE = "dns_failure"
    TIMEOUT = "timeout"
    CONNECTION_ERROR = "connection_error"
    TLS_ERROR = "tls_error"
    HTTP_ERROR = "http_error"  # 4xx/5xx
    PARKED = "parked"  # domain-for-sale / registrar page
    SUSPENDED = "suspended"  # hosting takedown / phishing warning page
    CHALLENGE_BLOCKED = "challenge_blocked"  # Cloudflare/CAPTCHA wall we can't pass
    GEO_BLOCKED = "geo_blocked"  # site refuses our country/IP (A13)
    EMPTY = "empty"  # live but blank / default server page


class Verdict(StrEnum):
    SCAM = "scam"
    NOT_SCAM = "not_scam"


class ScamType(StrEnum):
    FAKE_EXCHANGE = "fake_exchange"
    INVESTMENT_HYIP = "investment_hyip"  # incl. fake cloud mining, "x% daily"
    PIG_BUTCHERING = "pig_butchering"  # invite-code trading apps
    PHISHING = "phishing"  # impersonates a real service for credentials/seed
    WALLET_DRAINER = "wallet_drainer"
    GIVEAWAY = "giveaway"  # send X get 2X
    FAKE_RECOVERY = "fake_recovery"
    FAKE_SHOP = "fake_shop"  # non-delivery e-commerce
    FAKE_TOKEN = "fake_token"  # rug-pull / fake presale
    OTHER = "other"


class AddressFormat(StrEnum):
    BTC_P2PKH = "btc_p2pkh"  # 1…
    BTC_P2SH = "btc_p2sh"  # 3…
    BTC_BECH32 = "btc_bech32"  # bc1q…
    BTC_TAPROOT = "btc_taproot"  # bc1p… (bech32m)
    EVM = "evm"  # 0x + 40 hex
    TRON = "tron"  # T + 33 base58
    # bonus formats
    LTC = "ltc"
    DOGE = "doge"
    SOL = "sol"
    XRP = "xrp"


class Network(StrEnum):
    BITCOIN = "bitcoin"
    ETHEREUM = "ethereum"
    TRON = "tron"
    BSC = "bsc"
    POLYGON = "polygon"
    ARBITRUM = "arbitrum"
    SOLANA = "solana"
    LITECOIN = "litecoin"
    DOGECOIN = "dogecoin"
    XRPL = "xrpl"
    UNKNOWN = "unknown"


class Asset(StrEnum):
    BTC = "BTC"
    ETH = "ETH"
    USDT = "USDT"
    USDC = "USDC"
    TRX = "TRX"
    BNB = "BNB"
    LTC = "LTC"
    DOGE = "DOGE"
    SOL = "SOL"
    XRP = "XRP"
    OTHER = "OTHER"
    UNKNOWN = "UNKNOWN"


class AddressSource(StrEnum):
    DOM_TEXT = "dom_text"  # visible text
    DOM_ATTRIBUTE = "dom_attribute"  # data-clipboard-text, value=, href=
    SCRIPT = "script"  # inline/bundled JS
    NETWORK_RESPONSE = "network_response"  # XHR/fetch body
    QR_CODE = "qr_code"  # decoded image/canvas
    OCR = "ocr"  # text in images
    WALLET_MOCK = "wallet_mock"  # recipient in a tx the site tried to request
    ARCHIVE = "archive"  # Wayback snapshot (flagged separately)


class DiscoveryStage(StrEnum):
    LANDING = "landing"
    NAVIGATION = "navigation"  # reached by clicking, not logged in
    AUTHENTICATED = "authenticated"  # after register/login
    DEPOSIT_PAGE = "deposit_page"


class ActionType(StrEnum):
    CLICK = "click"
    FILL = "fill"
    SELECT = "select"
    PRESS = "press"
    SCROLL = "scroll"
    GOTO = "goto"
    BACK = "back"
    WAIT = "wait"
    CLICK_AT = "click_at"  # coordinate fallback for non-semantic widgets
    CHECK_EMAIL = "check_email"
    DONE = "done"


class StopReason(StrEnum):
    GOAL_REACHED = "goal_reached"  # all deposit options tried
    BUDGET_STEPS = "budget_steps"
    BUDGET_TIME = "budget_time"
    BUDGET_TOKENS = "budget_tokens"  # per-site LLM token cap hit
    BLOCKED = "blocked"  # gate we won't pass; see BlockedReason
    NO_PROGRESS = "no_progress"  # loop detected
    NOT_APPLICABLE = "not_applicable"  # site has no account/deposit concept
    USER_STOP = "user_stop"  # the operator stopped the run (stop file) or declined a submit
    ERROR = "error"


class BlockedReason(StrEnum):  # NavigationTrace.blocked_at
    INVITE_CODE = "invite_code"  # required and none visible on the page
    SMS_VERIFICATION = "sms_verification"
    EMAIL_VERIFICATION = "email_verification"
    CAPTCHA = "captcha"
    KYC = "kyc"
    GEO_BLOCK = "geo_block"
    PAYMENT_REQUIRED = "payment_required"  # e.g. "deposit to activate account"
    WALLET_REQUIRED = "wallet_required"  # needs a connected wallet; mock wallet not built yet
    MAINTENANCE = "maintenance"  # a page the flow needs (register, login, deposit) is "under maintenance"
    OTHER = "other"


class EvidenceSource(StrEnum):  # what the verdict was based on (dead-site policy, DESIGN §5.2a)
    LIVE = "live"  # the site itself, rendered now
    WAYBACK = "wayback"  # an archived snapshot; scam_probability shrunk toward 0.5
    SIGNALS_ONLY = "signals_only"  # domain, sibling-site or warning-page signals, no content
    NONE = "none"  # nothing to go on: not_scam, low confidence


class ProcessingStatus(StrEnum):  # did OUR pipeline finish? (separate from SiteStatus)
    COMPLETED = "completed"
    PARTIAL = "partial"  # timed out / blocked mid-way; evidence so far kept
    ERROR = "error"  # pipeline failed; record still written


class SignalTier(StrEnum):
    STRONG = "strong"  # near-decisive alone
    MODERATE = "moderate"  # several together make a case
    WEAK = "weak"  # never decisive alone


class AddressTier(StrEnum):
    PRIMARY = "primary"  # checksum-valid AND seen in a deposit/payment context
    # Format/checksum-valid but no such context (e.g. only in a JS bundle).
    # Lowercase EVM (unverifiable checksum) follows the same rule (A17):
    # primary with deposit context, low_confidence otherwise.
    LOW_CONFIDENCE = "low_confidence"


# ============================================================
# Shared checks
# ============================================================

# Output values may be rounded independently to 2 decimals, so allow a little slack.
CONFIDENCE_TOLERANCE = 0.01


def check_confidence(verdict: Verdict, scam_probability: float, confidence: float) -> None:
    """confidence = P(verdict is correct): scam_probability for scam, 1 - it for not_scam."""
    expected = scam_probability if verdict == Verdict.SCAM else 1 - scam_probability
    if abs(confidence - expected) > CONFIDENCE_TOLERANCE:
        raise ValueError(
            f"confidence {confidence} inconsistent with verdict {verdict.value} "
            f"and scam_probability {scam_probability} (expected {expected:.2f})"
        )


# ============================================================
# Models (DESIGN §3.3)
# ============================================================

# ---------- Input & triage ----------


class Site(BaseModel):
    site_id: str  # zero-padded index, e.g. "017"
    url: str  # exactly as given (keep paths)
    host: str
    registrable_domain: str  # via tldextract, e.g. "bitgettwallet.shop"


class TriageResult(BaseModel):
    status: SiteStatus
    http_status: int | None = None
    final_url: str | None = None
    redirect_chain: list[str] = []
    title: str | None = None
    reason: str | None = None  # why this status, e.g. 'parked marker "domain is for sale"'
    tls_valid: bool | None = None  # False: cert invalid, content fetched unverified (weak signal)
    error: str | None = None  # exception / proxy error text, if any
    elapsed_ms: int


class TriageRecord(BaseModel):  # one line of runs/<ts>/triage.jsonl
    site: Site
    triage: TriageResult


# ---------- Capture ----------


class NetworkRecord(BaseModel):
    url: str
    method: str
    status: int | None
    resource_type: str  # xhr, fetch, document, script…
    content_type: str | None
    body_path: str | None  # saved to disk if text and < size cap
    body_excerpt: str | None = None  # first N chars, for debugging only


class PageSnapshot(BaseModel):
    snapshot_id: str
    stage: DiscoveryStage
    url: str
    title: str
    taken_at: datetime
    html_path: str
    visible_text: str  # truncated
    a11y_tree_path: str
    screenshot_path: str
    network: list[NetworkRecord]  # responses since previous snapshot
    image_paths: list[str] = []  # for QR/OCR


# ---------- Addresses ----------


class AddressCandidate(BaseModel):  # pre-validation, internal only
    raw: str
    format_guess: AddressFormat
    source: AddressSource
    context: str  # ~200 chars around the match
    snapshot_id: str


class Sighting(BaseModel):
    source: AddressSource
    stage: DiscoveryStage
    page_url: str
    context_snippet: str
    screenshot_path: str | None = None  # annotated, address highlighted
    bbox: tuple[int, int, int, int] | None = None


class AssetLabel(BaseModel):
    asset: Asset
    network: Network
    confidence: float = Field(ge=0, le=1)
    evidence: str  # e.g. 'selected tab "USDT" + "TRC20" above address'


class CryptoAddress(BaseModel):
    address: str  # EXACTLY as shown on the site (case preserved)
    normalized: str  # canonical form for dedupe (EVM: EIP-55 checksummed; bech32: lowercase)
    tier: AddressTier
    format: AddressFormat
    checksum_valid: bool  # always True in output; False ones dropped (True for lowercase EVM)
    checksum_verifiable: bool  # False for all-lowercase EVM (EIP-55 can't verify)
    labels: list[AssetLabel]  # inferred; may be several (ETH + USDT-ERC20 on one 0x address)
    sightings: list[Sighting]
    first_seen_stage: DiscoveryStage

    @property
    def dedupe_key(self) -> str:
        # `normalized` is already canonical; the EVM key is lowercased defensively.
        # Base58 formats are case-sensitive and stay as they are.
        if self.format == AddressFormat.EVM:
            return self.normalized.lower()
        return self.normalized


# ---------- Classification ----------


class Signal(BaseModel):
    name: str  # "guaranteed_returns", "brand_typosquat:binance"
    tier: SignalTier
    weight: float  # + toward scam, - toward legit
    evidence: str  # quote or measurement
    source: str  # "domain", "content", "navigation", "llm"


class LLMJudgment(BaseModel):  # structured output from llm_judge
    verdict: Verdict
    scam_type: ScamType | None
    probability_scam: float = Field(ge=0, le=1)
    key_evidence: list[str]  # must quote page content
    impersonated_brand: str | None
    reasoning: str


class Classification(BaseModel):
    verdict: Verdict  # scam iff scam_probability >= scam_threshold (0.45)
    scam_type: ScamType | None
    scam_probability: float = Field(ge=0, le=1)  # fused score (§5.4)
    confidence: float = Field(ge=0, le=1)  # P(verdict is correct), see check_confidence
    evidence_source: EvidenceSource
    reasoning: str  # human-readable, 1-3 sentences
    signals: list[Signal]
    judgment: LLMJudgment | None  # None if site dead and no content
    method: str  # "heuristic+llm", "heuristic_only", "status_rule"

    @model_validator(mode="after")
    def _confidence_matches_probability(self) -> Self:
        check_confidence(self.verdict, self.scam_probability, self.confidence)
        return self


# ---------- Agent ----------


class Identity(BaseModel):
    identity_id: str  # referenced by SiteResult.identity_used
    first_name: str
    last_name: str
    email: str  # disposable mailbox
    password: str
    phone: str | None = None  # fake format-valid number; never real
    username: str


class AgentAction(BaseModel):
    type: ActionType
    element_id: int | None = None  # index into page_state element list
    x: int | None = None  # only for CLICK_AT
    y: int | None = None
    value: str | None = None  # literal text, or a placeholder like "{identity.email}"
    url: str | None = None
    rationale: str  # model's one-line reason


class AgentStep(BaseModel):
    index: int
    page_url: str
    action: AgentAction
    allowed: bool  # policy verdict
    policy_note: str | None = None
    result: str  # "ok", "element_not_found", "navigated", …
    new_addresses: list[str] = []
    screenshot_path: str
    tokens_in: int
    tokens_out: int
    elapsed_ms: int


class NavigationHop(BaseModel):
    """The one cross-domain link the operator let the agent follow (DESIGN §5.5, 2026-10-07)."""

    step: int
    source_url: str  # the page the link was on
    link_text: str  # as shown on the page (page-controlled text)
    target_url: str  # where the browser landed
    target_domain: str  # registrable domain the agent is locked to from then on


class NavigationTrace(BaseModel):
    goal: str
    steps: list[AgentStep]
    stop_reason: StopReason
    blocked_at: BlockedReason | None = None
    registered: bool
    logged_in: bool
    reached_deposit: bool
    assets_tried: list[str]  # coins/networks selected on deposit page
    linked_domains: list[str] = []  # refused or undone target URLs on other sites
    cycle_warning_steps: list[int] = []  # steps where the page-cycle warning was shown to the model
    hops: list[NavigationHop] = []  # cross-domain links followed (at most one)


# ---------- Result ----------


class SiteResult(BaseModel):
    site: Site
    triage: TriageResult
    processing_status: ProcessingStatus
    classification: Classification
    addresses: list[CryptoAddress]  # tier PRIMARY, reported for scam sites
    low_confidence_addresses: list[CryptoAddress] = []  # tier LOW_CONFIDENCE, scam sites
    other_addresses: list[CryptoAddress] = []  # seen on not_scam sites; not in output lists
    navigation: NavigationTrace | None
    identity_used: str | None = None  # Identity.identity_id, not the secrets
    notes: list[str] = []  # oddities worth a human look
    cluster_id: str | None = None  # (P2) shared operator group
    trace_path: str | None = None  # Playwright trace.zip (scam sites + failures)
    cost: dict[str, int] = {}  # tokens_in, tokens_out, llm_calls
    started_at: datetime
    finished_at: datetime
    pipeline_version: str


class RunSummary(BaseModel):
    run_id: str
    started_at: datetime
    finished_at: datetime
    config_hash: str
    counts_by_status: dict[str, int]
    counts_by_verdict: dict[str, int]
    counts_by_scam_type: dict[str, int]
    sites_with_addresses: int
    addresses_by_format: dict[str, int]
    navigation_stop_reasons: dict[str, int]
    total_tokens_in: int
    total_tokens_out: int


# ---------- Output file (§3.4) ----------
# Flattened view of SiteResult for graders. Strict: unknown fields are rejected.


class OutputModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AddressDetail(OutputModel):
    address: str  # exactly as shown on the site
    normalized: str
    tier: AddressTier
    format: AddressFormat
    labels: list[AssetLabel]
    # source/stage/screenshot come from the primary sighting: the earliest
    # deposit_page sighting if any, else the earliest sighting overall.
    source: AddressSource
    stage: DiscoveryStage
    screenshot: str | None
    sighting_count: int = Field(ge=1)


class NavigationSummary(OutputModel):
    registered: bool
    reached_deposit: bool
    steps: int = Field(ge=0)
    stop_reason: StopReason
    blocked_at: BlockedReason | None
    linked_domains: list[str] = []  # off-site targets: refused, sent back from, or the hop target
    hops: list[NavigationHop] = []  # the one followed cross-domain link, with its source page


class OutputRecord(OutputModel):
    url: str  # exactly as given in data/urls.txt
    final_url: str | None
    status: SiteStatus
    processing_status: ProcessingStatus
    classification: Verdict
    is_scam: bool  # must equal classification == "scam"
    scam_type: ScamType | None
    scam_probability: float = Field(ge=0, le=1)
    confidence: float = Field(ge=0, le=1)  # see check_confidence
    evidence_source: EvidenceSource
    reasoning: str
    signals: list[str]  # Signal.name values
    crypto_addresses: list[str]  # tier primary, strings as shown
    low_confidence_addresses: list[str]
    address_details: list[AddressDetail]
    navigation: NavigationSummary | None
    notes: list[str]

    @model_validator(mode="after")
    def _verdict_fields_agree(self) -> Self:
        if self.is_scam != (self.classification == Verdict.SCAM):
            raise ValueError(
                f"is_scam={self.is_scam} disagrees with classification={self.classification.value}"
            )
        check_confidence(self.classification, self.scam_probability, self.confidence)
        return self


class ResultsMeta(OutputModel):
    run_id: str
    generated_at: datetime
    total_urls: int
    pipeline_version: str
    scam_definition: str


class ResultsFile(OutputModel):  # output/results.json
    meta: ResultsMeta
    results: list[OutputRecord]
