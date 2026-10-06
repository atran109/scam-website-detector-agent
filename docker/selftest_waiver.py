"""Narrow selftest waiver for mock-only runs (`make agent-mock SELFTEST_WAIVER=rebind-probe`).

Decided 2026-10-06 for M3 step E only: on a network whose DNS rewrites 169.254.169.254.nip.io to
a public block page, the DNS-rebinding probe cannot run, so selftest ends 39/41. Mock runs reach
loopback and the gateway only, so they may proceed if, and only if, every failed check is that
probe. Real-site targets (run, triage) never read this waiver and keep the full gate.

Exit 0: selftest passed, or the only failures are the rebinding probe (a warning is printed and
recorded next to selftest.json). Exit 1 otherwise."""

import json
import sys
from pathlib import Path

WAIVED_TARGET = "http://169.254.169.254.nip.io/"
WAIVABLE = {f"proxy denies {WAIVED_TARGET}", f"chromium denied {WAIVED_TARGET}"}


def main(path: str) -> int:
    report = json.loads(Path(path).read_text())
    failed = [c for c in report["checks"] if not c["passed"]]
    if not failed:
        return 0
    names = {c["name"] for c in failed}
    if not names <= WAIVABLE:
        print(f"selftest waiver refused: other checks failed: {sorted(names - WAIVABLE)}")
        return 1
    note = (
        f"WAIVED for a mock-only run: {sorted(names)} "
        f"({'; '.join(c['detail'] for c in failed)}). Rebinding probe could not run on this "
        "network; real-site runs still require a full selftest pass.\n"
    )
    Path(path).with_name("selftest_waiver.txt").write_text(note)
    print(note, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
