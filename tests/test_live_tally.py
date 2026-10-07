"""Bucket rules of eval/live_tally.py (analysis script, loaded by path like the mock exchange)."""

import importlib.util

from scamhunter.config import REPO_ROOT

spec = importlib.util.spec_from_file_location("live_tally", REPO_ROOT / "eval" / "live_tally.py")
tally = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
spec.loader.exec_module(tally)  # type: ignore[union-attr]


def bucket(text: str) -> str:
    return tally.bucket_site("000", text, []).bucket


def test_wallet_wording_without_login_is_wallet_gated() -> None:
    text = "Markets\nConnect Wallet\nPlease first download the following wallet: MetaMask"
    assert bucket(text) == "wallet_gated"


def test_login_wording_wins_over_a_wallet_button() -> None:
    result = tally.bucket_site("000", "Connect Wallet\nLogin\nRegister", [])
    assert result.bucket == "registration_gated"
    assert any(e.startswith("also wallet:") for e in result.evidence)


def test_account_menu_alone_counts_as_registration_gated() -> None:
    assert bucket("Service\nRecharge\nWithdraw\nBTC/USDT 86467") == "registration_gated"


def test_shops_and_parked_pages_are_unclear() -> None:
    assert bucket("This page has been created by ParkLogic.") == "unclear"
    assert bucket("Shop\nCart\nContact us") == "unclear"


def test_chinese_login_words_count() -> None:
    assert bucket("客服中心 登录 注册") == "registration_gated"
