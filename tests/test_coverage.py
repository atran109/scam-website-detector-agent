"""Coverage by selection and by sharing (`agent/coverage.py`, LOG 2026-10-07)."""

from scamhunter.agent.coverage import (
    FAMILY_ASSETS,
    CoverageTracker,
    coin_and_network,
    family_of,
    key_for_selection,
)
from scamhunter.models import AddressFormat

TARGETS = ("BTC", "ETH", "USDT-ERC20", "USDT-TRC20", "USDC-ERC20", "USDC-TRC20")
EVM = ("evm", "0x76b10e09316c4c36c13bdb8b834953edb01659dc")
TRON = ("tron", "TTaaQJnZZt2rUZc7dbgwWXMzeXRXktYtQU")
BTC = ("btc", "bc1qwmustjfdvxe48l9tgjdez8v5lee40x6ak8g5fg")


def test_coin_and_network_from_012s_labels() -> None:
    assert coin_and_network("Tether (USDT - ERC20)") == ("USDT", "ERC20")
    assert coin_and_network("Tether (USDT - TRC20)") == ("USDT", "TRC20")
    assert coin_and_network("Tether (USDT - BEP20)") == ("USDT", "BEP20")
    assert coin_and_network("Ethereum (ETH)") == ("ETH", None)
    assert coin_and_network("USDC (USD Coin)") == ("USDC", None)
    assert coin_and_network("Bitcoin (BTC)") == ("BTC", None)
    assert coin_and_network("TRC20") == (None, "TRC20")


def test_families_of_formats() -> None:
    assert family_of(AddressFormat.EVM) == "evm" and family_of(AddressFormat.TRON) == "tron"
    assert family_of(AddressFormat.BTC_BECH32) == "btc" and family_of(AddressFormat.SOL) is None


def test_selection_keys() -> None:
    assert key_for_selection("evm", "ETH", None) == "ETH"
    assert key_for_selection("evm", "USDT", None) == "USDT-ERC20"
    assert key_for_selection("evm", "USDT", "ERC20") == "USDT-ERC20"
    assert key_for_selection("evm", "USDT", "BEP20") is None  # another EVM network: not a target
    assert key_for_selection("evm", "BNB", None) is None
    assert key_for_selection("tron", "USDT", "TRC20") == "USDT-TRC20"
    assert key_for_selection("tron", "USDC", None) == "USDC-TRC20"
    assert key_for_selection("btc", "BTC", None) == "BTC"


def test_one_address_for_one_coin_covers_only_that_coin() -> None:
    """The mock exchange (and many kits) derive one address per coin: a single sighting must
    not cover the family."""
    t = CoverageTracker(TARGETS)
    assert t.observe("USDT", "ERC20", [EVM]) == {"USDT-ERC20"}
    assert t.observe("USDT", "ERC20", [EVM]) == {"USDT-ERC20"}  # the same selection again
    assert not t.shared


def test_the_same_address_for_two_coins_is_shared_and_covers_the_family() -> None:
    t = CoverageTracker(TARGETS)
    assert t.observe("ETH", None, [EVM]) == {"ETH"}
    covered = t.observe("USDT", "ERC20", [EVM])
    assert covered == set(FAMILY_ASSETS["evm"]) and EVM[1] in {k[1] for k in t.shared}
    # a later sighting for any selection keeps covering the family
    assert t.observe("BNB", "BEP20", [EVM]) == set(FAMILY_ASSETS["evm"])


def test_sharing_counts_a_non_target_coin_as_a_second_selection() -> None:
    t = CoverageTracker(TARGETS)
    t.observe("USDT", "BEP20", [EVM])  # BEP20 is no target, but it is a second selection
    assert t.observe("USDT", "ERC20", [EVM]) == set(FAMILY_ASSETS["evm"])


def test_nothing_selected_covers_nothing() -> None:
    assert CoverageTracker(TARGETS).observe(None, None, [EVM, TRON]) == set()


def test_each_family_is_tracked_on_its_own() -> None:
    t = CoverageTracker(TARGETS)
    t.observe("ETH", None, [EVM])
    t.observe("USDT", "ERC20", [EVM])  # EVM shared
    assert t.observe("USDT", "TRC20", [TRON]) == {"USDT-TRC20"}  # TRON seen once: not shared
    assert t.observe("BTC", None, [BTC]) == {"BTC"}


def test_targets_limit_what_is_reported() -> None:
    t = CoverageTracker(("BTC", "USDT-TRC20"))
    t.observe("ETH", None, [EVM])
    assert t.observe("USDT", "ERC20", [EVM]) == set()  # EVM family covered, none is a target
