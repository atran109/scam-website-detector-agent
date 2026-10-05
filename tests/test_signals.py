"""Content-signal detectors, tested on texts saved from the pilot run (tests/fixtures/pilot_texts)
plus negatives that must stay quiet."""

from pathlib import Path

import pytest

from scamhunter.classify.signals import content_signals, crypto_only_payments

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
