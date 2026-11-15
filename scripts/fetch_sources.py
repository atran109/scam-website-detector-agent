"""Download the providers' lists for the Stage A1 dataset (DESIGN §8.2 step 1). Host-side.

    .venv/bin/python scripts/fetch_sources.py [--days 60]

Contacts only the four list publishers in ALLOWED_HOSTS, never a listed site. Raw files go to
data/dataset/sources/ (gitignored, not republished); the parsed candidates go to
data/dataset/candidates.jsonl. Run it only with the operator's go-ahead: it downloads files."""

import argparse
import io
import sys
import time
import zipfile
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from eval.dataset_v1.models import ParseResult  # noqa: E402
from eval.dataset_v1.sources import (  # noqa: E402
    parse_coingecko_exchanges,
    parse_dfpi,
    parse_metamask_config,
    parse_scamsniffer_day,
    parse_tranco,
)

ALLOWED_HOSTS = {"raw.githubusercontent.com", "dfpi.ca.gov", "tranco-list.eu", "api.coingecko.com"}
MAX_BYTES = 60_000_000
USER_AGENT = "dataset-research-script/0.1"
SOURCES_DIR = REPO_ROOT / "data" / "dataset" / "sources"
CANDIDATES_PATH = REPO_ROOT / "data" / "dataset" / "candidates.jsonl"

SCAMSNIFFER_DAY = (
    "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/archive/{day}.json"
)
SCAMSNIFFER_DELAY_DAYS = 7  # the public list is published a week late
METAMASK = "https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json"
DFPI = "https://dfpi.ca.gov/consumers/crypto/crypto-scam-tracker/"
TRANCO = "https://tranco-list.eu/top-1m.csv.zip"
COINGECKO = "https://api.coingecko.com/api/v3/exchanges?per_page=250&page={page}"
COINGECKO_MAX_PAGES = 10
COINGECKO_PAUSE_S = 8  # the keyless API allows only a few calls a minute


def check_url(url: str) -> None:
    """Raise ValueError unless the URL is https on one of the four provider hosts."""
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS or parts.username:
        raise ValueError(f"refused: {url!r} is not https on an allowed provider host")


def _check_request(request: httpx.Request) -> None:
    check_url(str(request.url))  # also runs on every redirect hop


def download(client: httpx.Client, url: str) -> bytes | None:
    """The body, or None on 404. Stops with an error at MAX_BYTES."""
    check_url(url)
    with client.stream("GET", url) as response:
        if response.status_code == 404:
            return None
        response.raise_for_status()
        body = bytearray()
        for chunk in response.iter_bytes():
            body.extend(chunk)
            if len(body) > MAX_BYTES:
                raise RuntimeError(f"{url}: larger than {MAX_BYTES} bytes")
        return bytes(body)


def _report(name: str, result: ParseResult) -> None:
    print(f"  {name:<16}{len(result.candidates):>8} candidates   skipped: {result.skipped or '-'}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--days", type=int, default=60, help="ScamSniffer daily files to fetch")
    args = parser.parse_args(argv)
    SOURCES_DIR.mkdir(parents=True, exist_ok=True)
    results: list[ParseResult] = []

    with httpx.Client(
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
        timeout=60,
        event_hooks={"request": [_check_request]},
    ) as client:

        def save(name: str, url: str) -> bytes | None:
            body = download(client, url)
            if body is not None:
                (SOURCES_DIR / name).write_bytes(body)
            return body

        newest = datetime.now(UTC).date() - timedelta(days=SCAMSNIFFER_DELAY_DAYS)
        days = [newest - timedelta(days=i) for i in range(args.days)]
        sniffer = ParseResult(candidates=[], skipped={})
        for day in days:
            body = save(f"scamsniffer-{day}.json", SCAMSNIFFER_DAY.format(day=day))
            if body is None:
                sniffer.skipped["day file missing"] = sniffer.skipped.get("day file missing", 0) + 1
                continue
            parsed = parse_scamsniffer_day(body.decode("utf-8", "replace"), day)
            sniffer.candidates += parsed.candidates
            for reason, count in parsed.skipped.items():
                sniffer.skipped[reason] = sniffer.skipped.get(reason, 0) + count
        results.append(sniffer)
        _report("scamsniffer", sniffer)

        block, allow = parse_metamask_config((save("metamask.json", METAMASK) or b"").decode())
        results += [block, allow]
        _report("metamask_block", block)
        _report("metamask_allow", allow)

        scams, lookalikes = parse_dfpi((save("dfpi.html", DFPI) or b"").decode("utf-8", "replace"))
        results += [scams, lookalikes]
        _report("dfpi", scams)
        _report("dfpi_lookalike", lookalikes)

        archive = save("tranco.zip", TRANCO) or b""
        csv_text = zipfile.ZipFile(io.BytesIO(archive)).read("top-1m.csv").decode()
        tranco = parse_tranco(csv_text)
        results.append(tranco)
        _report("tranco", tranco)

        gecko = ParseResult(candidates=[], skipped={})
        for page in range(1, COINGECKO_MAX_PAGES + 1):
            body = save(f"coingecko-{page}.json", COINGECKO.format(page=page)) or b"[]"
            parsed = parse_coingecko_exchanges(body.decode("utf-8", "replace"))
            if not parsed.candidates:
                break
            gecko.candidates += parsed.candidates
            time.sleep(COINGECKO_PAUSE_S)
        results.append(gecko)
        _report("coingecko", gecko)

    with CANDIDATES_PATH.open("w") as out:
        for result in results:
            for cand in result.candidates:
                out.write(cand.model_dump_json() + "\n")
    total = sum(len(r.candidates) for r in results)
    print(f"\n{total} candidates → {CANDIDATES_PATH.relative_to(REPO_ROOT)}  ({date.today()})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
