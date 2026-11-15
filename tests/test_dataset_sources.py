"""eval/dataset_v1/sources.py: one parser per provider format (DESIGN §8.2 step 1).

Fixtures are hand-written miniatures in each provider's real shape (checked against one
downloaded sample per provider on 2026-11-15, LOG). Names are invented; none is a real scam site."""

import json
from datetime import date

import pytest

from eval.dataset_v1.sources import (
    normalise_host,
    parse_coingecko_exchanges,
    parse_dfpi,
    parse_metamask_config,
    parse_scamsniffer_day,
    parse_tranco,
)

DAY = date(2026, 11, 1)


@pytest.mark.parametrize(
    ("raw", "want"),
    [
        ("Example.TEST", "example.test"),
        ("*.example.test", "example.test"),
        ("https://example.test/path?q=1", "example.test"),
        ("example.test:8443", "example.test"),
        ("www.shop.example.test/", "www.shop.example.test"),
        ("bücher.example", "xn--bcher-kva.example"),
        ("192.0.2.7", None),
        ("[2001:db8::1]", None),
        ("probe-1.invalid", None),
        ("localhost", None),
        ("", None),
        ("not a host", None),
        ("a..example", None),
    ],
)
def test_normalise_host(raw: str, want: str | None) -> None:
    assert normalise_host(raw) == want


def test_scamsniffer_day() -> None:
    text = json.dumps({"domains": ["Drainer-One.example", "claim.drainer-two.example"]})
    result = parse_scamsniffer_day(text, DAY)
    assert [(c.url, c.registrable_domain) for c in result.candidates] == [
        ("https://drainer-one.example/", "drainer-one.example"),
        ("https://claim.drainer-two.example/", "drainer-two.example"),
    ]
    first = result.candidates[0]
    assert (first.source, first.expected, first.listed_on) == ("scamsniffer", "scam", DAY)


def test_bad_lines_are_counted_not_raised() -> None:
    text = json.dumps({"domains": ["good.example", "192.0.2.7", "", 5, "probe.invalid"]})
    result = parse_scamsniffer_day(text, DAY)
    assert [c.registrable_domain for c in result.candidates] == ["good.example"]
    assert sum(result.skipped.values()) == 4


@pytest.mark.parametrize("text", ["", "not json", "[]", '{"domains": "x"}', '{"other": []}'])
def test_scamsniffer_unusable_file_gives_no_candidates(text: str) -> None:
    result = parse_scamsniffer_day(text, DAY)
    assert result.candidates == [] and result.skipped


def test_duplicates_within_a_file_are_dropped() -> None:
    text = json.dumps({"domains": ["a.example", "A.example", "www.a.example"]})
    result = parse_scamsniffer_day(text, DAY)
    assert [c.url for c in result.candidates] == ["https://a.example/"]
    assert result.skipped == {"duplicate domain": 2}


def test_metamask_config() -> None:
    text = json.dumps(
        {
            "version": 2,
            "tolerance": 1,
            "fuzzylist": ["wallet.example"],
            "whitelist": ["real-swap.example"],
            "blacklist": ["fake-swap.example", "10.0.0.1"],
        }
    )
    block, allow = parse_metamask_config(text)
    assert [(c.registrable_domain, c.source, c.expected) for c in block.candidates] == [
        ("fake-swap.example", "metamask_block", "scam")
    ]
    assert [(c.registrable_domain, c.source, c.expected) for c in allow.candidates] == [
        ("real-swap.example", "metamask_allow", "not_scam")
    ]
    assert block.candidates[0].listed_on is None


DFPI_HTML = """
<table id="tablepress-20"><thead><tr class="row-1"><th class="column-1">Primary Subject</th>
<th class="column-2">Complaint Narrative</th><th class="column-3">Scam Type</th>
<th class="column-4">Website</th><th class="column-5">Screenshot</th></tr></thead>
<tbody>
<tr class="row-2"><td class="column-1">Fake Exchange One</td>
<td class="column-2">A resident sent funds to 0x9952E129A85a939fc6b29430B640dF0261E07Ca7 and
later to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq.<br />
This is not to be confused with legitimate company, Real-Exchange.example.</td>
<td class="column-3"><a href="#fra">Fraudulent Trading Platform</a><br />
<a href="#pig">Pig Butchering Scam</a></td>
<td class="column-4">fake-one.example<br /> https://m.fake-one-app.example/#/home</td>
<td class="column-5"></td></tr>
<tr class="row-3"><td class="column-1">Fake Miner</td>
<td class="column-2">The website is no longer operational.</td>
<td class="column-3">Liquidity Mining Scam</td>
<td class="column-4">Fake-Miner.example/coin</td><td class="column-5"></td></tr>
<tr class="row-4"><td class="column-1">No Site Scam</td><td class="column-2">By phone.</td>
<td class="column-3">Imposter Scam</td><td class="column-4"></td><td class="column-5"></td></tr>
</tbody></table>
"""


def test_dfpi_extracts_sites_addresses_and_lookalikes() -> None:
    scams, legit = parse_dfpi(DFPI_HTML)
    assert [c.url for c in scams.candidates] == [
        "https://fake-one.example/",
        "https://m.fake-one-app.example/#/home",
        "https://fake-miner.example/coin",
    ]
    first = scams.candidates[0]
    assert (first.source, first.expected, first.listed_on) == ("dfpi", "scam", None)
    assert "Fraudulent Trading Platform" in first.source_note
    assert "0x9952E129A85a939fc6b29430B640dF0261E07Ca7" in first.source_note
    assert "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq" in first.source_note
    assert [(c.registrable_domain, c.source, c.expected) for c in legit.candidates] == [
        ("real-exchange.example", "dfpi_lookalike", "not_scam")
    ]
    assert scams.skipped == {"row without a website": 1}


def test_dfpi_page_without_the_table() -> None:
    scams, legit = parse_dfpi("<html><body>Maintenance</body></html>")
    assert scams.candidates == [] and legit.candidates == []
    assert scams.skipped == {"table not found": 1}


def test_tranco_keeps_rank_and_respects_top() -> None:
    result = parse_tranco(
        "1,first.example\r\n2,second.example\r\n3,third.example\r\nx,bad\r\n", top=2
    )
    assert [(c.registrable_domain, c.source_note) for c in result.candidates] == [
        ("first.example", "rank 1"),
        ("second.example", "rank 2"),
    ]
    assert all(c.source == "tranco" and c.expected == "not_scam" for c in result.candidates)


def test_coingecko_exchanges() -> None:
    text = json.dumps(
        [
            {"id": "one", "name": "Exchange One", "url": "https://www.exchange-one.example/"},
            {"id": "two", "name": "No Url", "url": ""},
            {"id": "three", "name": "Missing"},
        ]
    )
    result = parse_coingecko_exchanges(text)
    assert [(c.url, c.source, c.expected, c.source_note) for c in result.candidates] == [
        ("https://www.exchange-one.example/", "coingecko", "not_scam", "Exchange One")
    ]
    assert sum(result.skipped.values()) == 2


def test_coingecko_error_body() -> None:
    result = parse_coingecko_exchanges('{"status": {"error_code": 429}}')
    assert result.candidates == [] and result.skipped
