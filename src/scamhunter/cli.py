"""Entrypoints: run, triage, rescore, eval, report."""

import argparse
import sys

COMMANDS = ("run", "triage", "rescore", "eval", "report")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scamhunter")
    parser.add_argument("command", choices=COMMANDS)
    args = parser.parse_args(argv)
    print(f"{args.command}: not implemented")
    return 1


if __name__ == "__main__":
    sys.exit(main())
