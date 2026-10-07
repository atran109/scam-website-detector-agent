"""Secrets stay in `.env` (M5; DESIGN §5.6): nothing the repo tracks holds an API key."""

import re
import subprocess

import pytest

from scamhunter.config import REPO_ROOT

KEY = re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")


def tracked() -> list[str]:
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z"], cwd=REPO_ROOT, capture_output=True, check=True
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout")
    return [p for p in out.decode().split("\0") if p]


def test_env_is_ignored_and_not_tracked() -> None:
    assert ".env" not in tracked()
    assert re.search(r"^\.env$", (REPO_ROOT / ".gitignore").read_text(), re.M)
    assert "runs/" in (REPO_ROOT / ".gitignore").read_text()


def test_no_tracked_file_contains_an_api_key() -> None:
    hits = []
    for path in tracked():
        file = REPO_ROOT / path
        if file.suffix in {".png", ".jpg", ".zip", ".gz"} or not file.is_file():
            continue
        text = file.read_text(errors="ignore")
        if KEY.search(text):
            hits.append(path)
    assert hits == []


def test_the_example_env_holds_no_real_value() -> None:
    text = (REPO_ROOT / ".env.example").read_text()
    values = [ln.split("=", 1)[1].strip() for ln in text.splitlines() if "=" in ln and ln[0] != "#"]
    assert values and not any(KEY.search(v) or v.startswith("sk-") for v in values)
