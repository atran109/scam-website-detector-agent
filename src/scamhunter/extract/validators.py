"""Checksum and format validation per chain."""

import hashlib
from dataclasses import dataclass

from Crypto.Hash import keccak

from scamhunter.models import AddressFormat

# ============================================================
# Base58 / Base58Check
# ============================================================

BITCOIN_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
RIPPLE_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"


def b58decode(s: str, alphabet: str = BITCOIN_ALPHABET) -> bytes | None:
    num = 0
    for char in s:
        index = alphabet.find(char)
        if index < 0:
            return None
        num = num * 58 + index
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    leading_zeros = len(s) - len(s.lstrip(alphabet[0]))
    return b"\x00" * leading_zeros + body


def b58encode(data: bytes, alphabet: str = BITCOIN_ALPHABET) -> str:
    num = int.from_bytes(data, "big")
    out = ""
    while num:
        num, rem = divmod(num, 58)
        out = alphabet[rem] + out
    leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    return alphabet[0] * leading_zeros + out


def _sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def b58check_decode(s: str, alphabet: str = BITCOIN_ALPHABET) -> bytes | None:
    """Payload (version byte + data) if the 4-byte double-SHA256 checksum matches, else None."""
    raw = b58decode(s, alphabet)
    if raw is None or len(raw) < 5:
        return None
    payload, checksum = raw[:-4], raw[-4:]
    return payload if _sha256d(payload)[:4] == checksum else None


def b58check_encode(payload: bytes, alphabet: str = BITCOIN_ALPHABET) -> str:
    return b58encode(payload + _sha256d(payload)[:4], alphabet)


# ============================================================
# Bech32 / Bech32m (BIP-173, BIP-350 reference implementation)
# ============================================================

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_CONST = 1
BECH32M_CONST = 0x2BC830A3


def _bech32_polymod(values: list[int]) -> int:
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def bech32_decode(s: str) -> tuple[str, list[int], int] | None:
    """(hrp, data without checksum, checksum constant) or None. Mixed case is invalid."""
    if s.lower() != s and s.upper() != s:
        return None
    s = s.lower()
    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s) or len(s) > 90:
        return None
    hrp = s[:pos]
    if any(c not in BECH32_CHARSET for c in s[pos + 1 :]):
        return None
    data = [BECH32_CHARSET.find(c) for c in s[pos + 1 :]]
    const = _bech32_polymod(_hrp_expand(hrp) + data)
    if const not in (BECH32_CONST, BECH32M_CONST):
        return None
    return hrp, data[:-6], const


def _convertbits(data: list[int], frombits: int, tobits: int) -> list[int] | None:
    acc, bits, ret = 0, 0, []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or value >> frombits:
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def segwit_decode(hrp: str, addr: str) -> tuple[int, bytes] | None:
    """(witness version, program) for a valid segwit address with this hrp, else None."""
    decoded = bech32_decode(addr)
    if decoded is None or decoded[0] != hrp or not decoded[1]:
        return None
    _, data, const = decoded
    version = data[0]
    program = _convertbits(data[1:], 5, 8)
    if program is None or not 2 <= len(program) <= 40 or version > 16:
        return None
    if version == 0 and len(program) not in (20, 32):
        return None
    # BIP-350: v0 uses bech32, v1+ uses bech32m.
    if (version == 0) != (const == BECH32_CONST):
        return None
    return version, bytes(program)


# ============================================================
# EIP-55
# ============================================================


def _keccak256_hex(text: str) -> str:
    return keccak.new(digest_bits=256, data=text.encode("ascii")).hexdigest()


def eip55(address: str) -> str:
    """Checksummed form of a 0x-prefixed 40-hex address."""
    hex_part = address[2:].lower()
    digest = _keccak256_hex(hex_part)
    return "0x" + "".join(
        c.upper() if c.isalpha() and int(digest[i], 16) >= 8 else c for i, c in enumerate(hex_part)
    )


# ============================================================
# Per-format validation
# ============================================================


@dataclass(frozen=True)
class Validation:
    valid: bool
    verifiable: bool = True  # False when the format has no checksum to check
    normalized: str | None = None


INVALID = Validation(valid=False)

# Base58Check version bytes per format.
_VERSIONS: dict[AddressFormat, set[int]] = {
    AddressFormat.BTC_P2PKH: {0x00},
    AddressFormat.BTC_P2SH: {0x05},
    AddressFormat.TRON: {0x41},
    AddressFormat.LTC: {0x30, 0x32},  # L…, M… (legacy 3… is indistinguishable from BTC P2SH)
    AddressFormat.DOGE: {0x1E, 0x16},  # D…, 9…/A…
}


def _validate_base58check(raw: str, fmt: AddressFormat) -> Validation:
    payload = b58check_decode(raw)
    if payload is None or len(payload) != 21 or payload[0] not in _VERSIONS[fmt]:
        return INVALID
    return Validation(valid=True, normalized=raw)


def _validate_evm(raw: str) -> Validation:
    hex_part = raw[2:]
    if (
        len(raw) != 42
        or not raw.startswith("0x")
        or any(c not in "0123456789abcdefABCDEF" for c in hex_part)
    ):
        return INVALID
    checksummed = eip55(raw)
    if hex_part in (hex_part.lower(), hex_part.upper()):
        # Single-case: valid format, but EIP-55 can't verify it (A17).
        return Validation(valid=True, verifiable=False, normalized=checksummed)
    if raw != checksummed:
        return INVALID
    return Validation(valid=True, normalized=checksummed)


def _validate_segwit(raw: str, hrp: str, fmt: AddressFormat) -> Validation:
    decoded = segwit_decode(hrp, raw)
    if decoded is None:
        return INVALID
    version, program = decoded
    if fmt == AddressFormat.BTC_BECH32 and version != 0:
        return INVALID
    if fmt == AddressFormat.BTC_TAPROOT and (version != 1 or len(program) != 32):
        return INVALID
    return Validation(valid=True, normalized=raw.lower())


def _validate_sol(raw: str) -> Validation:
    decoded = b58decode(raw)
    if decoded is None or len(decoded) != 32:
        return INVALID
    # Solana addresses have no checksum: only the format can be checked.
    return Validation(valid=True, verifiable=False, normalized=raw)


def _validate_xrp(raw: str) -> Validation:
    payload = b58check_decode(raw, RIPPLE_ALPHABET)
    if payload is None or len(payload) != 21 or payload[0] != 0x00:
        return INVALID
    return Validation(valid=True, normalized=raw)


def validate(raw: str, fmt: AddressFormat) -> Validation:
    """Validate a candidate string as the given format; normalized form for dedupe if valid."""
    match fmt:
        case AddressFormat.EVM:
            return _validate_evm(raw)
        case AddressFormat.BTC_BECH32 | AddressFormat.BTC_TAPROOT:
            return _validate_segwit(raw, "bc", fmt)
        case AddressFormat.LTC if raw.lower().startswith("ltc1"):
            return _validate_segwit(raw, "ltc", fmt)
        case AddressFormat.SOL:
            return _validate_sol(raw)
        case AddressFormat.XRP:
            return _validate_xrp(raw)
        case _:
            return _validate_base58check(raw, fmt)
