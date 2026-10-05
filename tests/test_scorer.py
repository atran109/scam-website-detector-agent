"""Tests for classify.scorer, classify.signals and classify.domain (pure)."""

import pytest

from scamhunter.classify.domain import domain_signals, load_brands
from scamhunter.classify.scorer import score_content, score_without_content
from scamhunter.classify.signals import content_signals, triage_signals
from scamhunter.models import (
    EvidenceSource,
    LLMJudgment,
    ScamType,
    SiteStatus,
    TriageResult,
    Verdict,
)

T = 0.45
BRANDS = load_brands()


def names(signals) -> set[str]:
    return {s.name for s in signals}


def judgment(p: float, verdict: Verdict = Verdict.SCAM) -> LLMJudgment:
    return LLMJudgment(
        verdict=verdict,
        scam_type=ScamType.FAKE_EXCHANGE,
        probability_scam=p,
        key_evidence=['"2% daily"'],
        impersonated_brand=None,
        reasoning="r",
    )


# ---------- domain ----------


@pytest.mark.parametrize(
    ("host", "domain", "expected"),
    [
        (
            "web3.bitgettwallet.shop",
            "bitgettwallet.shop",
            {
                "cheap_tld:.shop",
                "brand_in_domain:bitget",
                "finance_terms_in_domain",
                "mobile_app_host",
            },
        ),
        (
            "www.coinmarkcapzwh.com",
            "coinmarkcapzwh.com",
            {"brand_typosquat:coinmarketcap", "finance_terms_in_domain"},
        ),
        (
            "bian-gold.globalonline.workers.dev",
            "workers.dev",
            {"free_hosting", "finance_terms_in_domain"},
        ),
        ("keystonevaults.com", "keystonevaults.com", {"finance_terms_in_domain"}),
        ("binance.com", "binance.com", set()),  # the brand's own name: no lookalike signal
    ],
)
def test_domain_signals(host: str, domain: str, expected: set[str]) -> None:
    assert names(domain_signals(host, domain, BRANDS)) == expected


# ---------- content ----------


def test_content_signals() -> None:
    text = "Earn 2.5% daily! Enter your invitation code. Contract trading: 60 seconds contract."
    found = names(content_signals(text, "", "x.test"))
    assert {"guaranteed_returns", "invite_code_required", "contract_or_quant_trading"} <= found


def test_seed_phrase_input() -> None:
    html = '<label>Enter your 12-word recovery phrase</label><textarea name="seed"></textarea>'
    assert "seed_phrase_input" in names(content_signals("", html, "phish.test"))
    assert "seed_phrase_input" not in names(content_signals("", html, "metamask.io"))


def test_triage_signals() -> None:
    cf = TriageResult(
        status=SiteStatus.SUSPENDED,
        reason='suspended marker "suspected phishing"',
        elapsed_ms=1,
        tls_valid=False,
    )
    assert names(triage_signals(cf)) == {"cloudflare_phishing_interstitial", "invalid_tls_cert"}


# ---------- scorer ----------


def test_llm_and_heuristics_fused() -> None:
    signals = content_signals("Earn 3% daily", "", "x.test")
    c, notes = score_content(signals, judgment(0.9), T)
    assert c.verdict == Verdict.SCAM and c.evidence_source == EvidenceSource.LIVE
    assert c.method == "heuristic+llm" and c.confidence == c.scam_probability


def test_disagreement_noted() -> None:
    _, notes = score_content([], judgment(0.95), T)
    assert any("disagree" in n for n in notes)


def test_heuristic_only_when_llm_failed() -> None:
    c, _ = score_content(content_signals("Earn 3% daily", "", "x"), None, T)
    assert c.method == "heuristic_only" and c.scam_type == ScamType.INVESTMENT_HYIP


def test_hard_rule_floor() -> None:
    signals = content_signals("", '<input placeholder="seed phrase">', "x.test")
    c, notes = score_content(signals, judgment(0.1, Verdict.NOT_SCAM), T)
    assert c.verdict == Verdict.SCAM and c.scam_probability >= 0.92
    assert "hard rule: seed_phrase_input" in notes


def test_wayback_shrinks_toward_half() -> None:
    live, _ = score_content([], judgment(0.9), T)
    archived, _ = score_content([], judgment(0.9), T, archived=True)
    assert 0.5 < archived.scam_probability < live.scam_probability
    assert archived.evidence_source == EvidenceSource.WAYBACK


def test_recall_band_gives_scam_below_half_confidence() -> None:
    c, _ = score_content([], judgment(0.55), T)  # 0.7*0.55 + 0.3*0.12 ≈ 0.42 → not scam
    c2, _ = score_content([], judgment(0.62), T)  # ≈ 0.47 → scam, confidence < 0.5
    assert c.verdict == Verdict.NOT_SCAM
    assert c2.verdict == Verdict.SCAM and c2.confidence < 0.5


def test_dead_site_policy() -> None:
    signals = domain_signals("bitocitex.com", "bitocitex.com", BRANDS)
    lean = score_without_content(signals, T, "DNS does not resolve")
    assert lean.verdict == Verdict.SCAM and lean.evidence_source == EvidenceSource.SIGNALS_ONLY
    assert 0.5 <= lean.scam_probability <= 0.65
    nothing = score_without_content([], T, "DNS does not resolve")
    assert nothing.verdict == Verdict.NOT_SCAM and nothing.scam_probability == 0.4
    assert nothing.evidence_source == EvidenceSource.NONE
    cf = triage_signals(
        TriageResult(status=SiteStatus.SUSPENDED, elapsed_ms=1, reason="suspected phishing")
    )
    warned = score_without_content(cf, T, "Cloudflare warning page")
    assert warned.verdict == Verdict.SCAM and warned.scam_probability >= 0.85
