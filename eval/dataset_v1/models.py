"""Records the dataset tooling passes around (DESIGN §8.2)."""

from datetime import date
from typing import Literal

from pydantic import BaseModel

Source = Literal[
    "dfpi",
    "scamsniffer",
    "metamask_block",
    "tranco",
    "coingecko",
    "metamask_allow",
    "dfpi_lookalike",
]
Expected = Literal["scam", "not_scam"]

SCAM_SOURCES: frozenset[str] = frozenset({"dfpi", "scamsniffer", "metamask_block"})


class Candidate(BaseModel):
    """One URL a provider listed. `expected` is the provider's claim, a lead and not a label."""

    url: str  # "https://<host>/" unless the provider gave a path
    registrable_domain: str
    source: Source
    expected: Expected
    listed_on: date | None = None
    source_note: str = ""  # DFPI: scam types and addresses in the narrative; Tranco: rank


class ParseResult(BaseModel):
    candidates: list[Candidate]
    skipped: dict[str, int]  # reason -> count


class ManifestRow(Candidate):
    """A candidate that was sampled: one line of data/dataset/v1/manifest.jsonl."""

    site_id: str  # four digits; equals the line number in data/dataset/v1/urls.txt
    batch: int
