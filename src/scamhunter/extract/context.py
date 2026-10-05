"""Label asset + network (with confidence) from text near an address."""

import re

from scamhunter.models import AddressFormat, Asset, AssetLabel, Network

# ---------- Vocabulary (multilingual where scam sites commonly are) ----------


def _terms(*words: str) -> re.Pattern[str]:
    # ASCII terms need word boundaries; CJK terms don't have them.
    parts = [
        rf"(?<![a-z0-9]){re.escape(w)}(?![a-z0-9])" if w.isascii() else re.escape(w) for w in words
    ]
    return re.compile("|".join(parts), re.I)


COIN_TERMS: dict[Asset, re.Pattern[str]] = {
    Asset.USDT: _terms("usdt", "tether", "泰达币"),
    Asset.USDC: _terms("usdc"),
    Asset.BTC: _terms("btc", "bitcoin", "比特币"),
    Asset.ETH: _terms("eth", "ether", "以太币"),
    Asset.TRX: _terms("trx", "波场币"),
    Asset.BNB: _terms("bnb"),
    Asset.LTC: _terms("ltc", "litecoin", "莱特币"),
    Asset.DOGE: _terms("doge", "dogecoin", "狗狗币"),
    Asset.SOL: _terms("sol", "solana"),
    Asset.XRP: _terms("xrp", "ripple", "瑞波币"),
}

NETWORK_TERMS: dict[Network, re.Pattern[str]] = {
    Network.TRON: _terms("trc20", "trc-20", "tron", "波场"),
    Network.ETHEREUM: _terms("erc20", "erc-20", "ethereum", "以太坊"),
    Network.BSC: _terms("bep20", "bep-20", "bsc", "bnb smart chain", "binance smart chain"),
    Network.POLYGON: _terms("polygon", "matic"),
    Network.ARBITRUM: _terms("arbitrum"),
    Network.SOLANA: _terms("solana", "spl"),
    Network.BITCOIN: _terms("bitcoin", "btc network"),
    Network.LITECOIN: _terms("litecoin"),
    Network.DOGECOIN: _terms("dogecoin"),
    Network.XRPL: _terms("xrpl", "xrp ledger", "ripple"),
}

PAYMENT_TERMS = _terms(
    "deposit",
    "recharge",
    "top up",
    "top-up",
    "pay",
    "payment",
    "send",
    "transfer",
    "wallet address",
    "receiving address",
    "receive",
    "donate",
    "donation",
    "充值",
    "收款",
    "转账",
    "入金",
    "存款",
    "nạp tiền",
    "ฝาก",
    "입금",
)

# ---------- Compatibility: networks a format can be on, assets a network carries ----------

_EVM_NETWORKS = {Network.ETHEREUM, Network.BSC, Network.POLYGON, Network.ARBITRUM}
FORMAT_NETWORKS: dict[AddressFormat, set[Network]] = {
    AddressFormat.EVM: _EVM_NETWORKS,
    AddressFormat.TRON: {Network.TRON},
    AddressFormat.BTC_P2PKH: {Network.BITCOIN},
    AddressFormat.BTC_P2SH: {Network.BITCOIN},
    AddressFormat.BTC_BECH32: {Network.BITCOIN},
    AddressFormat.BTC_TAPROOT: {Network.BITCOIN},
    AddressFormat.LTC: {Network.LITECOIN},
    AddressFormat.DOGE: {Network.DOGECOIN},
    AddressFormat.SOL: {Network.SOLANA},
    AddressFormat.XRP: {Network.XRPL},
}
# Network assumed when context names the coin but not the network (§3.1: "inferred from format").
DEFAULT_NETWORK: dict[AddressFormat, Network] = {
    fmt: (Network.ETHEREUM if fmt == AddressFormat.EVM else next(iter(nets)))
    for fmt, nets in FORMAT_NETWORKS.items()
}
_STABLE_NETWORKS = _EVM_NETWORKS | {Network.TRON, Network.SOLANA}
ASSET_NETWORKS: dict[Asset, set[Network]] = {
    Asset.BTC: {Network.BITCOIN},
    Asset.ETH: {Network.ETHEREUM, Network.ARBITRUM},
    Asset.USDT: _STABLE_NETWORKS,
    Asset.USDC: _STABLE_NETWORKS,
    Asset.TRX: {Network.TRON},
    Asset.BNB: {Network.BSC},
    Asset.LTC: {Network.LITECOIN},
    Asset.DOGE: {Network.DOGECOIN},
    Asset.SOL: {Network.SOLANA},
    Asset.XRP: {Network.XRPL},
}
# Formats that can only hold one asset (A32: legacy BTC strings are also valid BCH, so ~0.9).
NATIVE_ASSET: dict[AddressFormat, tuple[Asset, float]] = {
    AddressFormat.BTC_P2PKH: (Asset.BTC, 0.9),
    AddressFormat.BTC_P2SH: (Asset.BTC, 0.9),
    AddressFormat.BTC_BECH32: (Asset.BTC, 0.95),
    AddressFormat.BTC_TAPROOT: (Asset.BTC, 0.95),
    AddressFormat.LTC: (Asset.LTC, 0.9),
    AddressFormat.DOGE: (Asset.DOGE, 0.9),
    AddressFormat.XRP: (Asset.XRP, 0.95),
    AddressFormat.SOL: (Asset.SOL, 0.6),  # also holds SPL tokens (USDT/USDC on Solana)
}

# §3.1 confidence table.
CONF_COIN_AND_NETWORK = 0.9
CONF_COIN_ONLY = 0.65
CONF_NETWORK_ONLY = 0.6
CONF_PAGE_MENTION = 0.4


def _found(patterns: dict, text: str) -> dict:
    return {key: m.group() for key, p in patterns.items() if (m := p.search(text))}


def coins_in(text: str) -> set[Asset]:
    return set(_found(COIN_TERMS, text))


def has_payment_context(context: str) -> bool:
    return PAYMENT_TERMS.search(context) is not None


def mentions_solana(context: str) -> bool:
    return COIN_TERMS[Asset.SOL].search(context) is not None


def label(
    fmt: AddressFormat, context: str, page_coins: set[Asset] = frozenset()
) -> list[AssetLabel]:
    """Asset/network labels for one sighting, strongest evidence first (DESIGN §3.1)."""
    possible = FORMAT_NETWORKS[fmt]
    coins = {a: t for a, t in _found(COIN_TERMS, context).items() if ASSET_NETWORKS[a] & possible}
    nets = {n: t for n, t in _found(NETWORK_TERMS, context).items() if n in possible}

    labels: list[AssetLabel] = []
    for asset, coin_term in coins.items():
        paired = {n: t for n, t in nets.items() if n in ASSET_NETWORKS[asset]}
        for network, net_term in paired.items():
            labels.append(
                AssetLabel(
                    asset=asset,
                    network=network,
                    confidence=CONF_COIN_AND_NETWORK,
                    evidence=f'"{coin_term}" + "{net_term}" near address',
                )
            )
        if not paired:
            network = DEFAULT_NETWORK[fmt]
            if network not in ASSET_NETWORKS[asset]:
                network = next(iter(ASSET_NETWORKS[asset] & possible))
            labels.append(
                AssetLabel(
                    asset=asset,
                    network=network,
                    confidence=CONF_COIN_ONLY,
                    evidence=f'"{coin_term}" near address; network inferred',
                )
            )
    if labels:
        return _dedupe(labels)

    native = NATIVE_ASSET.get(fmt)
    if native:
        asset, conf = native
        return [
            AssetLabel(
                asset=asset,
                network=DEFAULT_NETWORK[fmt],
                confidence=conf,
                evidence=f"address format implies {asset.value}",
            )
        ]
    for network, net_term in nets.items():
        labels.append(
            AssetLabel(
                asset=Asset.UNKNOWN,
                network=network,
                confidence=CONF_NETWORK_ONLY,
                evidence=f'"{net_term}" near address, coin not named',
            )
        )
    if labels:
        return _dedupe(labels)
    for asset in sorted(page_coins):
        if ASSET_NETWORKS[asset] & possible:
            network = (
                DEFAULT_NETWORK[fmt]
                if DEFAULT_NETWORK[fmt] in ASSET_NETWORKS[asset]
                else next(iter(ASSET_NETWORKS[asset] & possible))
            )
            labels.append(
                AssetLabel(
                    asset=asset,
                    network=network,
                    confidence=CONF_PAGE_MENTION,
                    evidence=f"{asset.value} mentioned elsewhere on the page",
                )
            )
    if labels:
        return _dedupe(labels)
    network = DEFAULT_NETWORK[fmt] if len(possible) == 1 else Network.UNKNOWN
    return [
        AssetLabel(
            asset=Asset.UNKNOWN, network=network, confidence=0.0, evidence="no asset context"
        )
    ]


def _dedupe(labels: list[AssetLabel]) -> list[AssetLabel]:
    best: dict[tuple[Asset, Network], AssetLabel] = {}
    for lab in labels:
        key = (lab.asset, lab.network)
        if key not in best or lab.confidence > best[key].confidence:
            best[key] = lab
    return sorted(best.values(), key=lambda lab: -lab.confidence)


def merge_labels(a: list[AssetLabel], b: list[AssetLabel]) -> list[AssetLabel]:
    """Union of two label lists; an UNKNOWN placeholder is dropped once real labels exist."""
    merged = _dedupe(a + b)
    known = [lab for lab in merged if lab.asset != Asset.UNKNOWN or lab.confidence > 0]
    return known or merged
