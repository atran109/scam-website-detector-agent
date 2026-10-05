"""Fuse signals and the LLM judgment into a Classification.

M2 formula (to be calibrated on hand labels in M4, then documented in the README):
  heuristic p_h = sigmoid(sum(signal weights) - 2)
  with a judgment: p = 0.7 * p_llm + 0.3 * p_h, else p = p_h
  hard rules raise p to a floor; partial visits keep p within [0.2, 0.8]
  verdict = scam iff p >= scam_threshold; confidence = P(verdict correct)
"""

import math

from scamhunter.models import (
    Classification,
    EvidenceSource,
    LLMJudgment,
    ScamType,
    Signal,
    Verdict,
)

LLM_WEIGHT = 0.7
HEURISTIC_OFFSET = 2.0
DISAGREEMENT = 0.5
PARTIAL_BOUNDS = (0.2, 0.8)
WAYBACK_SHRINK = 0.8  # DESIGN §5.2a
SIGNALS_ONLY_BAND = (0.5, 0.65)
NOTHING_P = 0.4

# Hard rules (DESIGN §5.4): signal name → (floor on scam probability, scam type).
HARD_RULES: dict[str, tuple[float, ScamType]] = {
    "seed_phrase_input": (0.92, ScamType.PHISHING),
    "cloudflare_phishing_interstitial": (0.85, ScamType.PHISHING),
}
# Fallback scam type when there's no LLM judgment.
SIGNAL_SCAM_TYPES: dict[str, ScamType] = {
    "giveaway_send_to_receive": ScamType.GIVEAWAY,
    "guaranteed_returns": ScamType.INVESTMENT_HYIP,
    "contract_or_quant_trading": ScamType.PIG_BUTCHERING,
    "invite_code_required": ScamType.PIG_BUTCHERING,
}


def heuristic_probability(signals: list[Signal]) -> float:
    total = sum(s.weight for s in signals)
    return 1 / (1 + math.exp(-(total - HEURISTIC_OFFSET)))


def _confidence(verdict: Verdict, p: float) -> float:
    return round(p if verdict == Verdict.SCAM else 1 - p, 3)


def _finish(
    p: float,
    threshold: float,
    scam_type: ScamType | None,
    reasoning: str,
    signals: list[Signal],
    judgment: LLMJudgment | None,
    method: str,
    source: EvidenceSource,
) -> Classification:
    p = round(min(max(p, 0.0), 1.0), 3)
    verdict = Verdict.SCAM if p >= threshold else Verdict.NOT_SCAM
    return Classification(
        verdict=verdict,
        scam_type=(scam_type or ScamType.OTHER) if verdict == Verdict.SCAM else None,
        scam_probability=p,
        confidence=_confidence(verdict, p),
        evidence_source=source,
        reasoning=reasoning,
        signals=signals,
        judgment=judgment,
        method=method,
    )


def _signal_summary(signals: list[Signal]) -> str:
    strong = [s.name for s in sorted(signals, key=lambda s: -s.weight) if s.weight > 0][:4]
    return ", ".join(strong) if strong else "no scam signals"


def _type_from_signals(signals: list[Signal]) -> ScamType | None:
    for s in signals:
        if s.name in SIGNAL_SCAM_TYPES:
            return SIGNAL_SCAM_TYPES[s.name]
    return None


def score_content(
    signals: list[Signal],
    judgment: LLMJudgment | None,
    threshold: float,
    *,
    partial: bool = False,
    archived: bool = False,
) -> tuple[Classification, list[str]]:
    """Classify from page content (live or a Wayback snapshot). Returns notes for the record."""
    notes: list[str] = []
    p_h = heuristic_probability(signals)
    if judgment is not None:
        p = LLM_WEIGHT * judgment.probability_scam + (1 - LLM_WEIGHT) * p_h
        method = "heuristic+llm"
        scam_type = judgment.scam_type
        reasoning = judgment.reasoning
        if abs(judgment.probability_scam - p_h) > DISAGREEMENT:
            notes.append(
                f"LLM ({judgment.probability_scam:.2f}) and heuristics ({p_h:.2f}) "
                f"disagree; worth a human look"
            )
    else:
        p, method = p_h, "heuristic_only"
        scam_type = _type_from_signals(signals)
        reasoning = f"Heuristic signals only (no LLM judgment): {_signal_summary(signals)}."

    for s in signals:
        if s.name in HARD_RULES:
            floor, rule_type = HARD_RULES[s.name]
            if p < floor:
                p = floor
                scam_type = scam_type or rule_type
                notes.append(f"hard rule: {s.name}")

    if partial:
        p = min(max(p, PARTIAL_BOUNDS[0]), PARTIAL_BOUNDS[1])
    source = EvidenceSource.LIVE
    if archived:
        p = 0.5 + WAYBACK_SHRINK * (p - 0.5)
        method, source = method.replace("heuristic", "wayback+heuristic"), EvidenceSource.WAYBACK
    return _finish(p, threshold, scam_type, reasoning, signals, judgment, method, source), notes


# Signals that do not count as evidence when there is no page content to judge. A finance word in
# a domain name fired on 3 of the 4 sites confirmed legitimate in pilot-5 (cryptotrackerapp,
# keystonevaults, bradfordtradeins…), so on its own it says nothing about a dead site. Still
# used for live sites, where it is one weak signal among many (to be re-measured, see PLAN M4).
DEAD_SITE_IGNORED = frozenset({"finance_terms_in_domain"})


def score_without_content(
    signals: list[Signal], threshold: float, status_note: str
) -> Classification:
    """Dead-site policy steps 2-3 (DESIGN §5.2a): no page content to judge."""
    signals = [s for s in signals if s.name not in DEAD_SITE_IGNORED]
    for s in signals:
        if s.name in HARD_RULES:
            floor, rule_type = HARD_RULES[s.name]
            return _finish(
                floor,
                threshold,
                rule_type,
                f"{status_note}; {s.evidence} (third-party warning page).",
                signals,
                None,
                "status_rule",
                EvidenceSource.SIGNALS_ONLY,
            )
    scored = [s for s in signals if s.weight > 0]
    if scored:
        total = sum(s.weight for s in scored)
        p = min(SIGNALS_ONLY_BAND[0] + 0.05 * total, SIGNALS_ONLY_BAND[1])
        return _finish(
            p,
            threshold,
            _type_from_signals(signals),
            f"{status_note}; no content to assess. Leans scam on indirect signals: "
            f"{_signal_summary(scored)}.",
            signals,
            None,
            "status_rule",
            EvidenceSource.SIGNALS_ONLY,
        )
    return _finish(
        NOTHING_P,
        threshold,
        None,
        f"{status_note}; no archived snapshot and no domain, sibling or warning-page signals.",
        signals,
        None,
        "status_rule",
        EvidenceSource.NONE,
    )
