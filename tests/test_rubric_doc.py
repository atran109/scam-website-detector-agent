"""DESIGN §5.4's rubric table lists every signal the code can emit (M4, 2026-10-07)."""

import re

from scamhunter.classify.signals import TEXT_RULES, WEIGHTS
from scamhunter.config import REPO_ROOT

SRC = REPO_ROOT / "src" / "scamhunter"


def documented() -> dict[str, tuple[str, float]]:
    text = (REPO_ROOT / "docs" / "DESIGN.md").read_text()
    block = text.split("<!-- rubric:start -->")[1].split("<!-- rubric:end -->")[0]
    out = {}
    for line in block.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 4 and cells[0].startswith("`"):
            out[cells[0].strip("`")] = (cells[1], float(cells[2]))
    return out


def emitted_names() -> set[str]:
    names = {name for name, _, _ in TEXT_RULES}
    for path in [*SRC.glob("classify/*.py"), SRC / "pipeline.py"]:
        for m in re.finditer(r'name=f?"([a-z_]+)(?::[^"]*)?"', path.read_text()):
            names.add(m.group(1))
    return names


def test_every_emitted_signal_is_in_the_table() -> None:
    table = {n.split(":")[0].split("<")[0].rstrip(":") for n in documented()}
    assert emitted_names() <= table, emitted_names() - table


def test_the_text_rule_tiers_and_weights_match_the_table() -> None:
    table = documented()
    for name, tier, _ in TEXT_RULES:
        assert table[name] == (tier.value, WEIGHTS[tier]), name


def test_the_table_has_no_stale_rows() -> None:
    table = {n.split(":")[0].split("<")[0].rstrip(":") for n in documented()}
    assert table <= emitted_names(), table - emitted_names()
