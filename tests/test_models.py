"""The DESIGN §3.4 example output validates against the output models."""

import json
import re
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from scamhunter.models import (
    AddressFormat,
    AddressTier,
    CryptoAddress,
    DiscoveryStage,
    ResultsFile,
    Verdict,
)

DESIGN = Path(__file__).resolve().parents[1] / "docs" / "DESIGN.md"


def design_example() -> dict[str, Any]:
    """The first ```json block under '### 3.4' in DESIGN.md, so doc and schema can't drift."""
    text = DESIGN.read_text()
    section = text[text.index("### 3.4") :]
    match = re.search(r"```json\n(.*?)```", section, re.S)
    assert match, "no JSON example found under DESIGN §3.4"
    return json.loads(match.group(1))


def test_design_example_validates() -> None:
    results = ResultsFile.model_validate(design_example())

    scam, dead = results.results
    assert scam.is_scam and scam.classification == Verdict.SCAM
    assert scam.address_details[0].tier == AddressTier.PRIMARY
    assert scam.crypto_addresses == [scam.address_details[0].address]
    assert not dead.is_scam and dead.navigation is None


def test_design_example_round_trips() -> None:
    data = design_example()
    dumped = ResultsFile.model_validate(data).model_dump(mode="json")
    assert ResultsFile.model_validate(dumped) == ResultsFile.model_validate(data)


def test_unknown_field_rejected() -> None:
    data = design_example()
    data["results"][0]["_comment"] = "not part of the contract"
    with pytest.raises(ValidationError, match="extra"):
        ResultsFile.model_validate(data)


def test_is_scam_must_match_classification() -> None:
    data = design_example()
    data["results"][0]["is_scam"] = False
    with pytest.raises(ValidationError, match="is_scam"):
        ResultsFile.model_validate(data)


def test_confidence_must_match_scam_probability() -> None:
    data = design_example()
    data["results"][1]["confidence"] = 0.2  # not_scam with p=0.4 must have confidence 0.6
    with pytest.raises(ValidationError, match="confidence"):
        ResultsFile.model_validate(data)


def test_scam_below_half_confidence_is_allowed() -> None:
    # Recall bias: scam_probability in [0.45, 0.5) gives "scam" with confidence < 0.5.
    data = design_example()
    record = data["results"][0]
    record["scam_probability"] = record["confidence"] = 0.47
    ResultsFile.model_validate(data)


def test_unknown_blocked_reason_rejected() -> None:
    data = design_example()
    data["results"][0]["navigation"]["blocked_at"] = "guessed_invite_code"
    with pytest.raises(ValidationError):
        ResultsFile.model_validate(data)


def _address(fmt: AddressFormat, address: str, normalized: str) -> CryptoAddress:
    return CryptoAddress(
        address=address,
        normalized=normalized,
        tier=AddressTier.LOW_CONFIDENCE,
        format=fmt,
        checksum_valid=True,
        checksum_verifiable=address != address.lower(),
        labels=[],
        sightings=[],
        first_seen_stage=DiscoveryStage.LANDING,
    )


def test_dedupe_key_evm_case_insensitive() -> None:
    checksummed = "0x52908400098527886E0F7030069857D2E4169EE7"
    lower = _address(AddressFormat.EVM, checksummed.lower(), checksummed)
    mixed = _address(AddressFormat.EVM, checksummed, checksummed)
    assert lower.dedupe_key == mixed.dedupe_key


def test_dedupe_key_base58_case_sensitive() -> None:
    a = _address(AddressFormat.TRON, "TAbc", "TAbc")
    b = _address(AddressFormat.TRON, "Tabc", "Tabc")
    assert a.dedupe_key != b.dedupe_key
