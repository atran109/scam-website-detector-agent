"""Tests for extract.validators against published test vectors and known addresses."""

import pytest

from scamhunter.extract.validators import b58check_decode, b58check_encode, eip55, validate
from scamhunter.models import AddressFormat as F

VALID = [
    ("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", F.BTC_P2PKH),  # Bitcoin wiki example
    ("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", F.BTC_P2SH),  # Bitcoin wiki example
    ("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", F.BTC_BECH32),  # BIP-173 vector
    ("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", F.BTC_TAPROOT),  # BIP-350
    ("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", F.EVM),  # EIP-55 vectors
    ("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359", F.EVM),
    ("0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", F.EVM),
    ("0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb", F.EVM),
    ("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", F.TRON),  # USDT TRC-20 contract
    ("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh", F.XRP),  # XRPL genesis account
    ("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", F.SOL),  # USDC mint (32 bytes)
]

INVALID = [
    ("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3", F.BTC_P2PKH),  # last char changed
    ("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD", F.EVM),  # one letter's case flipped
    ("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj1", F.BTC_TAPROOT),
    ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".replace("q", "Q", 1), F.BTC_BECH32),  # mixed
    ("BC1SW50QGDZ25J", F.BTC_BECH32),  # BIP-350 v16: not a v0 address
    ("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", F.TRON),  # valid BTC, wrong version byte
    ("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", F.SOL),  # 25 bytes, not 32
]


@pytest.mark.parametrize(("raw", "fmt"), VALID)
def test_valid(raw: str, fmt: F) -> None:
    assert validate(raw, fmt).valid


@pytest.mark.parametrize(("raw", "fmt"), INVALID)
def test_invalid(raw: str, fmt: F) -> None:
    assert not validate(raw, fmt).valid


def test_lowercase_evm_is_valid_but_unverifiable() -> None:
    result = validate("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", F.EVM)
    assert result.valid and not result.verifiable
    assert result.normalized == "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"


def test_bech32_normalized_lowercase() -> None:
    result = validate("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", F.BTC_BECH32)
    assert result.normalized == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"


def test_sol_has_no_checksum() -> None:
    assert not validate("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", F.SOL).verifiable


def test_b58check_round_trip() -> None:
    payload = b"\x41" + bytes(range(20))
    assert b58check_decode(b58check_encode(payload)) == payload


def test_eip55_known() -> None:
    assert eip55("0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359") == (
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
    )
