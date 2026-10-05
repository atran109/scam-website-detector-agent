"""Drop token contracts, zero/burn, example and cross-site constant addresses."""

from pathlib import Path

import yaml

from scamhunter.config import REPO_ROOT

DEFAULT_PATH = REPO_ROOT / "config" / "address_blocklist.yaml"


def load_blocklist(path: Path = DEFAULT_PATH) -> frozenset[str]:
    """All listed addresses as lowercase keys (EVM is case-insensitive; base58 collisions
    across case are astronomically unlikely, so one lowercase set is enough)."""
    data = yaml.safe_load(path.read_text())
    entries = [addr for group in data.values() for addr in group]
    if bad := [a for a in entries if not isinstance(a, str)]:
        raise ValueError(f"{path}: unquoted entries parsed as non-strings (quote them): {bad}")
    return frozenset(addr.lower() for addr in entries)


def is_blocked(normalized: str, blocklist: frozenset[str]) -> bool:
    return normalized.lower() in blocklist
