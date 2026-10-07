"""Which target assets an address covers (LOG 2026-10-07).

Label confidence alone left coverage empty on pilot site 012: one EVM address was shown for ETH,
USDT and USDC with labels at 0.4, so the agent kept re-selecting coins until the step budget.
Two rules, both about what the agent had selected when a deposit page showed the address:

1. **Selection:** a primary address shown in the page text while the agent had selected a coin
   covers that coin's target asset in the address's family (ETH, USDT or USDC on ERC-20 for an
   EVM address; USDT or USDC on TRC-20 for a TRON address; BTC for a Bitcoin address).
2. **Sharing:** an address seen for two different selections is shared, and covers every target
   asset in its family at once. One address for one coin proves nothing about the others (the
   mock exchange and many real kits derive one address per coin), so a single sighting never
   does this."""

import re
from collections.abc import Iterable

from scamhunter.models import AddressFormat

FAMILY_ASSETS: dict[str, tuple[str, ...]] = {
    "evm": ("ETH", "USDT-ERC20", "USDC-ERC20"),
    "tron": ("USDT-TRC20", "USDC-TRC20"),
    "btc": ("BTC",),
}
_BTC = {
    AddressFormat.BTC_P2PKH,
    AddressFormat.BTC_P2SH,
    AddressFormat.BTC_BECH32,
    AddressFormat.BTC_TAPROOT,
}


def family_of(fmt: AddressFormat) -> str | None:
    if fmt == AddressFormat.EVM:
        return "evm"
    if fmt == AddressFormat.TRON:
        return "tron"
    if fmt in _BTC:
        return "btc"
    return None


# The coin and network a deposit-page control names ("USDT", "TRC20", "Tether (USDT - ERC20)",
# "Ethereum (ETH)").
_COIN = re.compile(
    r"(?<![A-Za-z])(USDT|USDC|BTC|ETH|TRX|BNB)(?![A-Za-z])|\b(Bitcoin|Ethereum|Tron)\b"
)
_NETWORK = re.compile(r"(?<![A-Za-z])(TRC-?20|ERC-?20|BEP-?20|BSC|OMNI)(?![A-Za-z0-9])", re.I)
_COIN_NAMES = {"BITCOIN": "BTC", "ETHEREUM": "ETH", "TRON": "TRX"}


def coin_and_network(label: str) -> tuple[str | None, str | None]:
    coin = _COIN.search(label)
    network = _NETWORK.search(label)
    name = (coin.group(1) or _COIN_NAMES[coin.group(2).upper()]) if coin else None
    net = network.group(1).upper().replace("-", "") if network else None
    return name, net


def key_for_selection(family: str, coin: str | None, network: str | None) -> str | None:
    """The target asset a family's address counts for, given the selected coin and network.
    An EVM address with no network named is taken as ERC-20, a TRON address as TRC-20; a
    network that does not fit the address's family counts nothing."""
    if family == "evm":
        if network not in (None, "ERC20"):
            return None
        if coin == "ETH":
            return "ETH"
        if coin in ("USDT", "USDC"):
            return f"{coin}-ERC20"
    elif family == "tron":
        if network not in (None, "TRC20"):
            return None
        if coin in ("USDT", "USDC"):
            return f"{coin}-TRC20"
    elif family == "btc" and coin == "BTC":
        return "BTC"
    return None


class CoverageTracker:
    def __init__(self, targets: Iterable[str]) -> None:
        self.targets = set(targets)
        # (family, lowercase address) -> selections it was shown with, as "COIN/NETWORK"
        self._seen: dict[tuple[str, str], set[str]] = {}
        self.shared: set[tuple[str, str]] = set()

    def observe(
        self,
        coin: str | None,
        network: str | None,
        shown: Iterable[tuple[str, str]],
    ) -> set[str]:
        """`shown` are (family, address) pairs for the primary addresses visible in the page
        text. Returns the target assets this observation covers (a caller keeps the union)."""
        if coin is None:
            return set()  # nothing selected: the address is not shown "for" anything
        selection = f"{coin}/{network or '-'}"
        covered: set[str] = set()
        for family, address in shown:
            key = (family, address.lower())
            seen = self._seen.setdefault(key, set())
            seen.add(selection)
            if len(seen) >= 2:
                self.shared.add(key)
            if key in self.shared:
                covered.update(FAMILY_ASSETS[family])
            elif (asset := key_for_selection(family, coin, network)) is not None:
                covered.add(asset)
        return covered & self.targets
