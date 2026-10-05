"""Content heuristics → list[Signal] (pure)."""

import re

from scamhunter.models import Signal, SignalTier, TriageResult

WEIGHTS = {SignalTier.STRONG: 3.0, SignalTier.MODERATE: 1.5, SignalTier.WEAK: 0.5}


def _rx(*patterns: str) -> re.Pattern[str]:
    return re.compile("|".join(patterns), re.I)


# (name, tier, pattern over visible text). Multilingual where scam kits commonly are.
TEXT_RULES: list[tuple[str, SignalTier, re.Pattern[str]]] = [
    (
        "guaranteed_returns",
        SignalTier.STRONG,
        _rx(
            r"\d+(?:\.\d+)?\s?%\s*(?:daily|per day|a day|/day|every day|per hour|hourly|/h\b)",
            r"(?:daily|hourly)\s+(?:profit|return|income|interest)s?\s+(?:of\s+)?\d+(?:\.\d+)?\s?%",
            r"guaranteed\s+(?:profit|return|income|payout)s?",
            r"risk[- ]free\s+(?:profit|return|invest)",
            r"日收益",
            r"每日收益",
            r"保本",
            r"稳赚",
        ),
    ),
    (
        "giveaway_send_to_receive",
        SignalTier.STRONG,
        _rx(
            r"send\s+(?:any amount|\d[\d.,]*\s*\w+)\b.{0,80}"
            r"(?:receive|get)\s+(?:back\s+)?(?:2x|double|twice)",
            r"(?:double|2x)\s+your\s+(?:btc|eth|bitcoin|crypto|coins?)",
        ),
    ),
    (
        "invite_code_required",
        SignalTier.MODERATE,
        _rx(
            r"invit(?:e|ation)\s+code",
            r"邀请码",
            r"mã giới thiệu",
            r"รหัสเชิญ",
        ),
    ),
    (
        "contract_or_quant_trading",
        SignalTier.MODERATE,
        _rx(
            r"seconds?\s+contract",
            r"秒合约",
            r"(?:ai|smart)\s+quant(?:itative)?\s+trad",
            r"arbitrage\s+(?:robot|bot)",
            r"copy\s+trading\s+(?:profit|signal)s?\s+\d",
            r"cloud\s+mining\s+(?:contract|plan)",
        ),
    ),
    (
        "withdrawal_conditions",
        SignalTier.MODERATE,
        _rx(
            r"withdrawal\s+fee",
            r"unlock\s+(?:your\s+)?(?:funds|withdrawal|account)",
            r"(?:tax|fee)\s+before\s+(?:you\s+can\s+)?withdraw",
            r"deposit\s+to\s+activate",
            r"activation\s+(?:fee|deposit)",
        ),
    ),
    (
        "license_claims",
        SignalTier.MODERATE,
        _rx(
            r"(?:licensed|regulated|authori[sz]ed)\s+by\s+(?:the\s+)?(?:fca|sec|asic|cysec|nfa|finra|fincen)",
            r"\bmsb\s+licen[cs]e",
            r"us\s+msb",
        ),
    ),
    (
        "urgency",
        SignalTier.MODERATE,
        _rx(
            r"limited\s+(?:time|spots|slots)",
            r"only\s+\d+\s+(?:spots|slots|places)\s+left",
            r"offer\s+ends\s+in",
            r"act\s+now",
        ),
    ),
    (
        "customer_service_deposit",
        SignalTier.MODERATE,
        _rx(
            r"contact\s+(?:online\s+)?customer\s+service\s+to\s+(?:deposit|recharge|top\s?up)",
            r"在线客服",
            r"联系客服充值",
        ),
    ),
]

_SEED_INPUT = _rx(
    r"<(?:input|textarea)[^>]*(?:seed|mnemonic|recovery\s?phrase|private\s?key|secret\s?phrase)",
    r"(?:seed|recovery|secret)\s+phrase.{0,200}<(?:input|textarea)",
    r"(?:12|24)[- ]word.{0,120}<(?:input|textarea)",
    r"助记词",
    r"私钥",
)
_WALLET_PROVIDERS = ("metamask.io", "trustwallet.com", "ledger.com", "trezor.io")


def content_signals(visible_text: str, html: str, host: str) -> list[Signal]:
    signals: list[Signal] = []
    for name, tier, pattern in TEXT_RULES:
        if m := pattern.search(visible_text):
            signals.append(
                Signal(
                    name=name,
                    tier=tier,
                    weight=WEIGHTS[tier],
                    evidence=f'"{m.group()[:120]}"',
                    source="content",
                )
            )
    if (m := _SEED_INPUT.search(html)) and not host.endswith(_WALLET_PROVIDERS):
        signals.append(
            Signal(
                name="seed_phrase_input",
                tier=SignalTier.STRONG,
                weight=WEIGHTS[SignalTier.STRONG],
                evidence=f'"{m.group()[:120]}"',
                source="content",
            )
        )
    return signals


def triage_signals(triage: TriageResult) -> list[Signal]:
    """Signals from the HTTP probe: third-party warning pages, invalid TLS."""
    signals: list[Signal] = []
    reason = (triage.reason or "").lower()
    if "suspected phishing" in reason or "potential phishing" in reason:
        signals.append(
            Signal(
                name="cloudflare_phishing_interstitial",
                tier=SignalTier.STRONG,
                weight=WEIGHTS[SignalTier.STRONG],
                evidence=triage.reason or "",
                source="status",
            )
        )
    elif triage.status.value == "suspended":
        signals.append(
            Signal(
                name="hosting_suspended",
                tier=SignalTier.MODERATE,
                weight=1.0,
                evidence=triage.reason or "",
                source="status",
            )
        )
    if triage.tls_valid is False:
        signals.append(
            Signal(
                name="invalid_tls_cert",
                tier=SignalTier.WEAK,
                weight=0.5,
                evidence="certificate failed verification",
                source="status",
            )
        )
    return signals


def address_signal(n_addresses: int) -> Signal | None:
    """A3: showing a crypto address is not evidence of a scam; recorded at ~zero weight."""
    if not n_addresses:
        return None
    return Signal(
        name="shows_crypto_address",
        tier=SignalTier.WEAK,
        weight=0.0,
        evidence=f"{n_addresses} validated address(es)",
        source="content",
    )
