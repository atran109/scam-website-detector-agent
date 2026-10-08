"""Check a published results file before it ships (the M6 quality gate, LOG 2026-10-07 20:20).

    python scripts/validate_run.py [output/results.json]

Fails (exit 1) unless: the file loads as the strict schema; it has exactly the URLs of
data/urls.txt, once each and in order; every address detail passes its format validator, is not
blocklisted, sits in the flat list of its tier and has an existing screenshot; and no recorded
URL carries a visitor IP in a query parameter (site 084's redirect did, LOG 2026-10-08).
Prints counts by verdict, evidence source and processing status. No network, no containers."""

import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from scamhunter.extract.blocklist import is_blocked, load_blocklist  # noqa: E402
from scamhunter.extract.validators import validate  # noqa: E402
from scamhunter.models import AddressTier, ResultsFile  # noqa: E402

# A query parameter that names a client IP and holds an IPv4 address (ip=, real_ip=, client_ip=…).
IP_PARAM = re.compile(r"[?&][a-z_]*ip=\d{1,3}(?:\.\d{1,3}){3}\b", re.I)


def problems(results_path: Path) -> tuple[list[str], ResultsFile]:
    out: list[str] = []
    data = ResultsFile.model_validate_json(results_path.read_text())
    urls = [u.strip() for u in (ROOT / "data" / "urls.txt").read_text().splitlines() if u.strip()]
    got = [r.url for r in data.results]
    if got != urls:
        out.append(f"URLs differ from data/urls.txt (got {len(got)}, expected {len(urls)})")
    if len(set(got)) != len(got):
        out.append("duplicate URL records")
    blocklist = load_blocklist()
    for r in data.results:
        flat = {AddressTier.PRIMARY: r.crypto_addresses, AddressTier.LOW_CONFIDENCE: []}
        flat[AddressTier.LOW_CONFIDENCE] = r.low_confidence_addresses
        for d in r.address_details:
            where = f"{r.url} {d.address}"
            if not validate(d.address, d.format).valid:
                out.append(f"fails its {d.format.value} validator: {where}")
            if is_blocked(d.normalized, blocklist):
                out.append(f"blocklisted: {where}")
            if d.address not in flat[d.tier]:
                out.append(f"not in the {d.tier.value} list: {where}")
            if not d.screenshot or not (results_path.parent / d.screenshot).exists():
                out.append(f"screenshot missing: {where}")
        for url in r.navigation.linked_domains if r.navigation else []:
            if IP_PARAM.search(url):
                out.append(f"visitor IP in a recorded URL: {r.url}")
    return out, data


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "output" / "results.json"
    found, data = problems(path)
    results = data.results
    print(f"{path}: {len(results)} records, run {data.meta.run_id}")
    print("  verdicts:", dict(Counter(r.classification.value for r in results)))
    by_source = Counter((r.evidence_source.value, r.classification.value) for r in results)
    print("  by evidence_source:", dict(sorted(by_source.items())))
    print("  processing:", dict(Counter(r.processing_status.value for r in results)))
    details = sum(len(r.address_details) for r in results)
    print(f"  address details checked: {details}")
    for p in found:
        print("FAIL", p)
    print("OK" if not found else f"{len(found)} problem(s)")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
