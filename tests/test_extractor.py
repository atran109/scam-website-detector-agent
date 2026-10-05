"""Tests for extract.extractor on fixture pages with planted and decoy addresses."""

import io
import json
from pathlib import Path

import pytest
import zxingcpp
from PIL import Image

from scamhunter.extract.blocklist import load_blocklist
from scamhunter.extract.extractor import (
    NetworkBody,
    SnapshotContent,
    extract,
    html_to_text,
    merge_all,
)
from scamhunter.extract.patterns import find_candidates
from scamhunter.extract.qr import decode_qr
from scamhunter.models import AddressSource, AddressTier, Asset, DiscoveryStage, Network

FIXTURES = Path(__file__).parent / "fixtures" / "pages"
HTML = (FIXTURES / "deposit_mixed.html").read_text()
A = json.loads((FIXTURES / "deposit_mixed.addresses.json").read_text())
BLOCKLIST = load_blocklist()


def snapshot(
    html: str = HTML, stage: DiscoveryStage = DiscoveryStage.LANDING, **kw
) -> SnapshotContent:
    return SnapshotContent("s1", stage, "https://fixture.test/", html, html_to_text(html), **kw)


@pytest.fixture(scope="module")
def found() -> dict:
    return {a.address: a for a in extract(snapshot(), BLOCKLIST)}


def test_reports_exactly_the_planted_addresses(found: dict) -> None:
    assert set(found) == {A["tron1"], A["btc"], A["evm"], A["evm_lower"], A["sol"], A["taproot"]}


def test_decoys_rejected(found: dict) -> None:
    for decoy in (A["btc_bad"], A["evm_bad"], A["random_b58"], A["txhash"]):
        assert decoy not in found
    assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" not in found  # blocklisted example
    assert not any(a.lower() == "0xdac17f958d2ee523a2206206994597c13d831ec7" for a in found)


def test_tiers(found: dict) -> None:
    primary = {a for a, v in found.items() if v.tier == AddressTier.PRIMARY}
    assert primary == {A["tron1"], A["btc"], A["evm"], A["sol"]}
    assert found[A["taproot"]].tier == AddressTier.LOW_CONFIDENCE  # only in a script
    assert found[A["evm_lower"]].tier == AddressTier.LOW_CONFIDENCE  # no deposit context


def test_labels(found: dict) -> None:
    tron = found[A["tron1"]].labels
    assert (tron[0].asset, tron[0].network, tron[0].confidence) == (Asset.USDT, Network.TRON, 0.9)
    evm = {(lab.asset, lab.network) for lab in found[A["evm"]].labels if lab.confidence >= 0.9}
    assert {
        (Asset.ETH, Network.ETHEREUM),
        (Asset.USDT, Network.ETHEREUM),
        (Asset.BNB, Network.BSC),
    } <= evm
    assert found[A["btc"]].labels[0].asset == Asset.BTC


def test_same_address_in_text_and_attribute_is_one_address(found: dict) -> None:
    sources = [s.source for s in found[A["evm"]].sightings]
    assert sources == [AddressSource.DOM_TEXT, AddressSource.DOM_ATTRIBUTE]


def test_lowercase_evm_reported_as_shown(found: dict) -> None:
    addr = found[A["evm_lower"]]
    assert addr.address == A["evm_lower"] and addr.address.islower()
    assert addr.normalized != addr.address and not addr.checksum_verifiable


def test_lowercase_evm_primary_with_deposit_context() -> None:  # A17
    html = f"<p>USDT ERC20 deposit address</p><p>{A['evm_lower']}</p>"
    [addr] = extract(snapshot(html), BLOCKLIST)
    assert addr.tier == AddressTier.PRIMARY


def test_vertical_tab_layout_labels() -> None:
    html = f"<div>USDT</div><div>TRC20</div><div>Deposit address</div><div>{A['tron1']}</div>"
    [addr] = extract(snapshot(html), BLOCKLIST)
    assert addr.labels[0].confidence == 0.9 and addr.tier == AddressTier.PRIMARY


def test_network_response_json_labels_and_tier() -> None:
    body = json.dumps({"data": {"coin": "USDT", "network": "TRC20", "address": A["tron2"]}})
    content = snapshot("<p>Loading…</p>", network=[NetworkBody("https://x/api/addr", "xhr", body)])
    [addr] = extract(content, BLOCKLIST)
    assert addr.sightings[0].source == AddressSource.NETWORK_RESPONSE
    assert addr.tier == AddressTier.PRIMARY and addr.labels[0].network == Network.TRON


def test_qr_payment_uri() -> None:
    content = snapshot("<p></p>", qr_texts=[f"bitcoin:{A['btc']}?amount=0.1"])
    [addr] = extract(content, BLOCKLIST)
    assert addr.address == A["btc"] and addr.sightings[0].source == AddressSource.QR_CODE
    assert addr.tier == AddressTier.PRIMARY


def test_archived_snapshot_source() -> None:
    sightings = [s for a in extract(snapshot(archived=True), BLOCKLIST) for s in a.sightings]
    assert {s.source for s in sightings} == {AddressSource.ARCHIVE}


def test_merge_across_snapshots_upgrades_tier() -> None:
    landing = extract(snapshot(f"<p>Partner {A['evm'].lower()}</p>"), BLOCKLIST)
    deposit = extract(snapshot(f"<p>{A['evm']}</p>", stage=DiscoveryStage.DEPOSIT_PAGE), BLOCKLIST)
    assert landing[0].tier == AddressTier.LOW_CONFIDENCE
    [merged] = merge_all(landing, deposit)  # same address, different case → one entry
    assert merged.tier == AddressTier.PRIMARY
    assert merged.first_seen_stage == DiscoveryStage.LANDING
    assert len(merged.sightings) == 2


def test_tx_hash_not_matched_as_evm() -> None:
    assert not [m for m in find_candidates(A["txhash"]) if m.format_guess.value == "evm"]


def test_decode_qr_round_trip() -> None:
    text = f"ethereum:{A['evm']}"
    view = memoryview(
        zxingcpp.create_barcode(text, zxingcpp.BarcodeFormat.QRCode).to_image(scale=4)
    )
    buf = io.BytesIO()
    Image.frombytes("L", (view.shape[1], view.shape[0]), view.tobytes()).save(buf, "PNG")
    assert decode_qr(buf.getvalue()) == [text]
    assert decode_qr(b"not an image") == []


def test_json_keys_drop_contracts_and_promote_spenders() -> None:
    """Pilot finding (site 100): a coin-list API lists token contracts; a config API lists
    the approval spender wallets per chain."""
    coins = json.dumps(
        [
            {
                "title": "SHIB",
                "contract_address": A["evm"],
                "withdrawal_threshold": "0",
                "deposit_min": "1",
            }
        ]
    )
    config = json.dumps({"approve_address": {"TRX": A["tron1"], "ETH": A["evm_lower"]}})
    ignored: list[str] = []
    content = snapshot(
        "<p></p>",
        network=[
            NetworkBody("https://x/api/coins", "xhr", coins),
            NetworkBody("https://x/api/config", "xhr", config),
        ],
    )
    found = {a.address: a for a in extract(content, BLOCKLIST, ignored)}
    assert A["evm"] not in found and ignored == [A["evm"]]
    assert found[A["tron1"]].tier == AddressTier.PRIMARY
    assert found[A["evm_lower"]].tier == AddressTier.PRIMARY
    assert any(lab.asset == Asset.TRX for lab in found[A["tron1"]].labels)


PILOT = Path(__file__).parent / "fixtures" / "pilot_texts"


def test_027_labelled_contract_dropped_wallet_kept() -> None:
    """Pilot #027: 'Wallet Address' → 0xD499… is the site's wallet; 'Contract Address: 0xe90D…'
    is the project's own token contract (the page says so)."""
    text = (PILOT / "027.txt").read_text()
    ignored: list[str] = []
    content = SnapshotContent("s1", DiscoveryStage.LANDING, "https://x.test/", "", text)
    found = {a.address for a in extract(content, BLOCKLIST, ignored)}
    assert found == {"0xD499F95a6605550161cB9725A79c569bD3482F21"}
    assert ignored == ["0xe90D5F442D651E32E95f71Da0a39f22f4c5E0bD5"]


@pytest.mark.parametrize(
    "layout",
    [
        "Contract Address: {a}",
        "Token address: {a}",
        "Smart Contract (BEP-20): {a}",
        "Token Contract\n{a}",  # label on the line above
        "合约地址：{a}",
    ],
)
def test_contract_label_layouts_are_dropped(layout: str) -> None:
    ignored: list[str] = []
    content = snapshot("<p></p>")
    content.visible_text = layout.format(a=A["evm"])
    assert extract(content, BLOCKLIST, ignored) == [] and ignored == [A["evm"]]


@pytest.mark.parametrize(
    "line",
    [
        "Wallet Address\n{a}",  # not a contract label
        "Deposit address: {a}",
        "Send ETH to the presale contract: {a}",  # told to send funds there: could be theirs
        "Contract trading deposit address: {a}",
    ],
)
def test_other_labels_keep_the_address(line: str) -> None:
    content = snapshot("<p></p>")
    content.visible_text = line.format(a=A["evm"])
    assert [a.address for a in extract(content, BLOCKLIST)] == [A["evm"]]


def test_contract_status_applies_across_sources() -> None:
    """The page labels the address a contract in its text; the same address in a 'Copy' button
    attribute (no label there) must not come back as a low-confidence address."""
    html = (
        f"<p>Contract Address: {A['evm']}</p>"
        f'<button data-clipboard-text="{A["evm"]}">Copy Address</button>'
    )
    ignored: list[str] = []
    assert extract(snapshot(html), BLOCKLIST, ignored) == []
    assert ignored == [A["evm"]]  # reported once, not once per source
