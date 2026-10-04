"""JSONL checkpoint store, resume, and per-site artifact paths."""

from collections.abc import Iterable
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel

from scamhunter.config import REPO_ROOT

RUNS_DIR = REPO_ROOT / "runs"


def new_run_id() -> str:
    return datetime.now().strftime("%Y-%m-%dT%H-%M-%S")


def run_dir(run_id: str) -> Path:
    path = RUNS_DIR / run_id
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_jsonl(path: Path, records: Iterable[BaseModel]) -> None:
    with path.open("w") as f:
        for record in records:
            f.write(record.model_dump_json() + "\n")
