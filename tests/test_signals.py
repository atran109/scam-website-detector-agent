"""Content-signal detectors, tested on texts saved from the pilot run (tests/fixtures/pilot_texts)
plus negatives that must stay quiet."""

import json
from pathlib import Path

import pytest

from scamhunter.classify.signals import content_signals, crypto_only_payments
from scamhunter.models import SignalTier

FIXTURES = Path(__file__).parent / "fixtures" / "pilot_texts"


def names(text: str) -> set[str]:
    return {s.name for s in content_signals(text, "", "x.test")}


def pilot(site_id: str) -> str:
    return (FIXTURES / f"{site_id}.txt").read_text()


def test_012_weekly_returns_and_profit_plus_capital() -> None:
    # "Platinum Return 6.5 % Weekly For 2 Weeks, Total profit + Capital"
    assert {"guaranteed_returns", "profit_plus_capital"} <= names(pilot("012"))


def test_087_plan_returns_and_sec_claim() -> None:
    # "Silver - 10% Min: $5,000 Max: $9,999 Duration: 1 Week"; "registered with and duly
    # regulated by the US's Securities and Exchange Commission (SEC)"
    assert {"guaranteed_returns", "license_claims"} <= names(pilot("087"))


def test_021_crypto_only_deposits_for_stock_trading() -> None:
    found = [s for s in content_signals(pilot("021"), "", "x.test")]
    assert "crypto_only_payments" in {s.name for s in found}


def test_027_activation_wallet() -> None:
    assert "withdrawal_conditions" in names(pilot("027"))


@pytest.mark.parametrize("site_id", ["022", "051"])
def test_legitimate_pilot_pages_fire_nothing(site_id: str) -> None:
    assert names(pilot(site_id)) == set()


@pytest.mark.parametrize(
    "text",
    [
        "AAPL 333.69 +3.37 (+1.02%)  TSLA 370.59 +16.48 (+4.65%)  S&P 500 +0.15%",  # quotes
        "Our weekly newsletter. Save 20% on annual plans. Mon-Fri 9am-5pm.",
        "The fund grew 12% in 2023 according to its annual report.",
    ],
)
def test_plain_percentages_do_not_look_like_returns(text: str) -> None:
    assert "guaranteed_returns" not in names(text)


@pytest.mark.parametrize(
    "text",
    [
        "Earn 3% daily",
        "Returns of 15 % per month",
        "Plan A: 8% weekly for 4 weeks",
        "Gold - 12%\nMin: $500\nDuration: 30 days",
    ],
)
def test_periodic_returns_variants(text: str) -> None:
    assert "guaranteed_returns" in names(text)


@pytest.mark.parametrize(
    "text",
    [
        "Regulated by the Financial Conduct Authority (FCA), reg no. 123",
        "We are SEC registered and licensed with ASIC.",
    ],
)
def test_regulator_claim_variants(text: str) -> None:
    assert "license_claims" in names(text)


def test_crypto_only_payments_needs_non_crypto_product_and_no_fiat_option() -> None:
    crypto = "Deposit with Bitcoin, Ethereum, Tether or Tron."
    assert crypto_only_payments("Trade stocks like a pro. " + crypto)
    assert crypto_only_payments("Add to cart. Pay with Bitcoin, Ethereum, Tether or Tron.")
    # a crypto exchange's deposit page is not "crypto-only for a non-crypto product"
    assert crypto_only_payments("Crypto exchange. " + crypto) is None
    # a card/bank option next to the payment text clears it
    assert (
        crypto_only_payments("Buy stocks. Deposit with Visa, PayPal, Bitcoin, Ethereum, Tether")
        is None
    )
    # a ticker widget naming Visa far from the deposit text must not
    far = "Trade stocks. " + crypto + (" filler" * 80) + " Visa 360.66 +0.81 (+0.2%)"
    assert crypto_only_payments(far)


# ---------- M4 (2026-10-07): mobile exchange template and domain/content mismatch ----------


def test_mobile_exchange_template_on_the_real_kit_pages() -> None:
    from scamhunter.classify.signals import mobile_exchange_template

    for site_id in ("100", "057"):  # 5 and 4 of the distinctive words
        signal = mobile_exchange_template(pilot(site_id))
        assert signal is not None and signal.tier == SignalTier.MODERATE, site_id
    assert "AI Quant" in mobile_exchange_template(pilot("100")).evidence


@pytest.mark.parametrize("site_id", ["012", "021", "022", "027", "051", "087"])
def test_no_template_signal_on_ordinary_pages(site_id: str) -> None:
    """027 has Contract, Assets, Team and Follow (generic words, left out of the cluster); 087 has
    Finance, Service and Team."""
    from scamhunter.classify.signals import mobile_exchange_template

    assert mobile_exchange_template(pilot(site_id)) is None


def test_one_cluster_word_is_not_a_template() -> None:
    from scamhunter.classify.signals import mobile_exchange_template

    assert mobile_exchange_template("Connect Wallet to continue. Withdraw anytime.") is None
    assert mobile_exchange_template("Recharge Withdraw Finance Loan") is not None


CAPTURES = json.loads((Path(__file__).parent / "fixtures" / "capture_pages.json").read_text())


@pytest.mark.parametrize("site_id", ["003", "145", "071"])
def test_the_mismatch_signal_fires_on_the_labelled_scam_pages(site_id: str) -> None:
    """003 an immigration site on a whisky name, 145 a friday購物 clone on tatung-world.com, 071 a
    live-cam page on openai9315.com (the user's hand labels, eval/human_labels.csv)."""
    from scamhunter.classify.signals import domain_content_mismatch

    page = CAPTURES[site_id]
    signal = domain_content_mismatch(page["host"], page["title"], page["text"])
    assert signal is not None and signal.tier == SignalTier.WEAK and signal.weight == 0.5


@pytest.mark.parametrize("site_id", ["051", "081", "102", "117"])
def test_the_mismatch_signal_stays_quiet_on_normal_shops_and_a_brand_clone(site_id: str) -> None:
    """051, 081 and 102 are the user's three probably-legitimate shops; 117 is a BTCC clone whose
    page does say BTCC (a clone matches its brand, so no mismatch)."""
    from scamhunter.classify.signals import domain_content_mismatch

    page = CAPTURES[site_id]
    assert domain_content_mismatch(page["host"], page["title"], page["text"]) is None


def test_mismatch_needs_enough_text_and_uses_the_subdomain_on_free_hosting() -> None:
    from scamhunter.classify.domain import name_label
    from scamhunter.classify.signals import domain_content_mismatch

    assert domain_content_mismatch("unrelatedname.com", "", "a few words only") is None
    assert name_label("drops-marketplace.netlify.app") == "drops-marketplace"
    assert name_label("www.addmklwhisky.com") == "addmklwhisky"
    assert name_label("m.bit-ligne.sbs") == "bit-ligne"
    text = "Drops marketplace lists new token launches every day. " * 10
    assert domain_content_mismatch("drops-marketplace.netlify.app", "Drops", text) is None
