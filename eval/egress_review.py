"""Review the Squid egress logs for anything unexpected (M5; no visits).

Squid's `logformat egress`: time, client, result/status, method, url, dst=<ip>, err=…, bytes=….
Findings that need a human: an *allowed* request (not TCP_DENIED) whose destination is a private,
link-local, loopback, CGNAT or reserved address, or a port other than 80 and 443. Denied lines are
summarized: the selftest's own probes are expected, anything else is worth a look.
Usage: python eval/egress_review.py runs/*/egress.log"""

import ipaddress
import re
import sys
from collections import Counter
from pathlib import Path

LINE = re.compile(
    r"^(?P<time>\S+) (?P<client>\S+) (?P<result>[A-Z_]+)/(?P<status>\d+) (?P<method>\S+) "
    r"(?P<url>\S+) dst=(?P<dst>\S+) err=(?P<err>\S+)"
)
# Denied destinations that are expected noise: the selftest's own probes (including the old
# nip.io one and the DNS-independent rebinding names), a private address literal (the router probe
# or a page's attempt, refused either way), Chromium fetching the proxy's error-page icon from the
# proxy's container id, and Chrome's push channel on port 5228.
EXPECTED_DENIED = (
    "example.com",
    "169.254.169.254",
    "host.docker.internal",
    "gateway.docker.internal",
    "127.0.0.1",
    "egress-proxy",
    "localtest.me",
    "mtalk.google.com",
)
CONTAINER_ID = re.compile(r"^[0-9a-f]{12}$")


def expected_denied(host: str) -> bool:
    return (
        host.startswith(EXPECTED_DENIED)
        or host.endswith((".nip.io", ".selftest.test"))
        or bool(CONTAINER_ID.match(host))
        or risky_ip(host)
    )


def risky_ip(text: str) -> bool:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
    ) and not ip.is_global


def host_port(method: str, url: str) -> tuple[str, str]:
    if method == "CONNECT":
        host, _, port = url.rpartition(":")
        return host, port
    m = re.match(r"^(?:https?://)?([^/:]+)(?::(\d+))?", url)
    return (
        (m.group(1), m.group(2) or ("443" if url.startswith("https") else "80")) if m else (url, "")
    )


def review(path: Path) -> dict:
    allowed_risky, odd_ports, denied = [], [], Counter()
    hosts: Counter[str] = Counter()
    for raw in path.read_text(errors="replace").splitlines():
        m = LINE.match(raw)
        if not m:
            continue
        host, port = host_port(m["method"], m["url"])
        if m["result"].startswith("TCP_DENIED"):
            denied[host] += 1
            continue
        hosts[host] += 1
        if risky_ip(m["dst"]) or risky_ip(host):
            allowed_risky.append(raw)
        if port not in ("80", "443", ""):
            odd_ports.append(raw)
    unexpected_denied = {h: n for h, n in denied.items() if not expected_denied(h)}
    return {
        "path": str(path),
        "allowed_hosts": len(hosts),
        "allowed_requests": sum(hosts.values()),
        "denied_requests": sum(denied.values()),
        "allowed_to_risky_destinations": allowed_risky,
        "allowed_odd_ports": odd_ports,
        "denied_not_from_selftest": unexpected_denied,
    }


def main() -> int:
    bad = 0
    for arg in sys.argv[1:]:
        r = review(Path(arg))
        risky = r["allowed_to_risky_destinations"] + r["allowed_odd_ports"]
        bad += bool(risky)
        extra = r["denied_not_from_selftest"]
        print(
            f"{r['path']}: {r['allowed_requests']} allowed to {r['allowed_hosts']} hosts, "
            f"{r['denied_requests']} denied; risky-allowed={len(risky)}"
            + (f"; other denied: {extra}" if extra else "")
        )
        for line in risky[:5]:
            print("   !!", line)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
