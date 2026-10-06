"""Brand-lookalike rules (classify/domain.py): what must fire and what must not."""

import pytest
import tldextract

from scamhunter.classify.domain import domain_signals, load_brands

BRANDS = load_brands()
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())  # bundled snapshot, no network


def brand_names(host: str) -> set[str]:
    domain = _EXTRACT(host).top_domain_under_public_suffix
    return {s.name for s in domain_signals(host, domain, BRANDS) if s.name.startswith("brand_")}


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("openai9315.com", "brand_in_domain:openai"),
        ("h5.mitrade-store.com", "brand_in_domain:mitrade"),
        ("www.coinhako01.com", "brand_in_domain:coinhako"),
        ("www.coinmarkcapzwh.com", "brand_typosquat:coinmarketcap"),
        ("xtbcopy.com", "brand_in_domain:xtb"),  # 3-letter brand at the edge of the name
        ("h5.bit-main.cc", "brand_in_domain:bitmain"),  # hyphen-normalized label equals brand
        ("h5.bitmain-ex.co", "brand_in_domain:bitmain"),
        ("tiktoksig-f4dbexefdvh4faev.a01.azurefd.net", "brand_in_domain:tiktok"),  # free hosting
        ("bitgettwallet.shop", "brand_in_domain:bitget"),
        ("web.rocupbitoffice.com", "brand_in_domain:upbit"),
        ("www.btcctw.help", "brand_in_domain:btcc"),
        ("www.coinexvto.com", "brand_in_domain:coinex"),
        ("www.bigonelfj.com", "brand_in_domain:bigone"),
        ("www.bitkanusca.com", "brand_in_domain:bitkan"),
        ("market3.bfxtrade.top", "brand_in_domain:bfx"),
        ("www.zfxfa.vip", "brand_in_domain:zfx"),
        ("www.tatung-world.com", "brand_in_domain:tatung"),
        ("poizvip.com", "brand_in_domain:poizvip"),  # manual alias; a lookalike, not the real name
        ("h5.bitxex.quest", "brand_in_domain:bitxex"),
        ("binance.workers.dev", "brand_in_domain:binance"),  # subdomain is the site name
        ("login.binance.example.com", "brand_in_domain:binance"),  # any label counts
        # all-words rule: both words at the edge of name parts, split apart (#048)
        ("interactivemining-brokers.com", "brand_in_domain:interactive+brokers"),
        ("brokers-interactive.top", "brand_in_domain:interactive+brokers"),
    ],
)
def test_detected(host: str, expected: str) -> None:
    assert expected in brand_names(host)


@pytest.mark.parametrize(
    "host",
    [
        # whole words that sit one edit from a brand, or contain one
        "primesuccessfinance.com",  # "inance" is one edit from Binance
        "bifinancegdb.vip",
        "finance.com",
        "bitcoin.org",
        "coin.com",
        "trade.com",
        "market.com",
        "global.com",
        "globalmarkets.com",
        "bitcoinexchange.com",  # contains "coinex"
        "gateway.io",  # starts with "gate"
        "navigate.com",
        "oxford.com",
        "bitmex.com",  # BitMEX lists only the lookalike "bitxex", no fuzzy
        "bitmax.com",
        "interactive-media.com",  # only one of the all-words words
        "brokers-online.com",
        "interactivebrokers.com",  # the real name in one part: the plain token's own-name rule
        # brand names on their own real-looking domains
        "binance.com",
        "www.coinbase.com",
        "support.okx.com",
        # provider labels on free hosting are not site names
        "mysite.workers.dev",
        "shop.netlify.app",
    ],
)
def test_not_flagged(host: str) -> None:
    assert brand_names(host) == set()


def test_three_letter_brands_never_fuzzy() -> None:
    assert brand_names("okz.com") == set()
    assert brand_names("xtc.com") == set()
    assert brand_names("okxtrade.com") == {"brand_in_domain:okx"}
