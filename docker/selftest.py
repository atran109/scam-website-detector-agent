"""Egress and sandbox self-test, run inside the crawler container by `make selftest`.

Proves the isolation claims in DESIGN §5.6 before any real site is visited:
the container has no direct route out, the proxy denies private destinations (including
via DNS tricks), a normal site works through the proxy, Chromium runs with its sandbox on,
and every request is logged. Exits 1 if any check fails.
"""

import asyncio
import json
import os
import socket
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

import httpx
from playwright.async_api import async_playwright

from scamhunter.browser.sandbox import launch_browser, new_context
from scamhunter.config import load_settings, require_egress_proxy

ALLOWED_URL = "https://example.com/"
ALLOWED_HOST = "example.com"


@dataclass
class Check:
    name: str
    passed: bool
    detail: str


checks: list[Check] = []


def record(name: str, passed: bool, detail: str) -> None:
    checks.append(Check(name, passed, detail))
    print(f"  [{'PASS' if passed else 'FAIL'}] {name}: {detail}", flush=True)


def denied_targets() -> list[str]:
    """Destinations that must never be reachable through the proxy."""
    targets = [
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata
        "http://host.docker.internal/",  # the Mac itself
        "http://gateway.docker.internal/",
        "http://127.0.0.1/",
        "http://egress-proxy:3128/squid-internal-mgr/info",  # the proxy's own manager
        "http://localtest.me/",  # public name resolving to 127.0.0.1
        "http://169.254.169.254.nip.io/",  # public name resolving to the metadata IP
        "https://169.254.169.254/",  # CONNECT path, not just plain http
        "http://example.com:8080/",  # non-allowed port
    ]
    if router := os.environ.get("SELFTEST_ROUTER_IP"):
        targets.insert(0, f"http://{router}/")  # home router, from the Mac's default route
    return targets


# ---------- 1. Container hardening ----------


def check_container() -> None:
    record("non-root user", os.getuid() != 0, f"uid={os.getuid()}")
    cap_eff = next(
        line.split()[1]
        for line in Path("/proc/self/status").read_text().splitlines()
        if line.startswith("CapEff:")
    )
    record("no effective capabilities", int(cap_eff, 16) == 0, f"CapEff={cap_eff}")


# ---------- 2. No direct route out ----------


def check_direct_egress() -> None:
    try:
        socket.create_connection(("1.1.1.1", 443), timeout=5).close()
        record("no direct route (1.1.1.1:443)", False, "connected without the proxy")
    except OSError as exc:
        record("no direct route (1.1.1.1:443)", True, f"blocked: {exc}")
    try:
        addrs = {a[4][0] for a in socket.getaddrinfo(ALLOWED_HOST, 443)}
        # Not a route out (connections still fail), but recorded so it isn't a surprise.
        record("direct DNS (informational)", True, f"resolves to {sorted(addrs)}; no route")
    except OSError as exc:
        record("direct DNS (informational)", True, f"no external DNS: {exc}")


# ---------- 3. Proxy policy ----------


async def proxy_outcome(client: httpx.AsyncClient, url: str) -> tuple[int | None, str | None]:
    squid_error: list[str] = []

    async def trace(event: str, info: dict) -> None:
        if event.endswith("receive_response_headers.complete"):
            for name, value in info["return_value"][3]:
                if name.lower() == b"x-squid-error":
                    squid_error.append(value.decode())

    try:
        response = await client.send(client.build_request("GET", url, extensions={"trace": trace}))
        return response.status_code, response.headers.get("x-squid-error")
    except httpx.ProxyError as exc:
        return int(str(exc)[:3]), squid_error[-1] if squid_error else None
    except httpx.HTTPError as exc:
        return None, f"{type(exc).__name__}: {exc}"


async def check_proxy(proxy: str) -> None:
    async with httpx.AsyncClient(proxy=proxy, trust_env=False, timeout=20) as client:
        for url in denied_targets():
            status, squid_error = await proxy_outcome(client, url)
            blocked = status == 403 and (squid_error or "").startswith("ERR_ACCESS_DENIED")
            # A name the proxy can't resolve never gets a connection either.
            unresolvable = (squid_error or "").startswith("ERR_DNS_FAIL")
            record(
                f"proxy denies {url}",
                blocked or unresolvable,
                f"status={status} squid={squid_error}",
            )
        status, squid_error = await proxy_outcome(client, ALLOWED_URL)
        record(f"proxy allows {ALLOWED_URL}", status == 200, f"status={status} squid={squid_error}")


# ---------- 4. Chromium: same policy, sandbox on ----------


def chrome_processes() -> list[tuple[int, str]]:
    """(pid, command line) of Chromium processes.

    Chromium rewrites child process titles, so the command line may be one space-joined
    string rather than NUL-separated args; match on the joined text.
    """
    procs = []
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            cmdline = (proc / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
        except OSError:
            continue
        if "/ms-playwright/" in cmdline:
            procs.append((int(proc.name), cmdline))
    return procs


def check_sandbox_processes() -> None:
    procs = chrome_processes()
    flagged = [pid for pid, cmdline in procs if "--no-sandbox" in cmdline]
    record("no --no-sandbox flag", bool(procs) and not flagged, f"{len(procs)} chrome procs")

    renderers = [pid for pid, cmdline in procs if "--type=renderer" in cmdline]
    if not renderers:
        types = sorted({c.split("--type=")[1].split()[0] for _, c in procs if "--type=" in c})
        record("renderer sandboxed", False, f"no renderer process found; types seen: {types}")
        return
    pid = renderers[0]
    status = Path(f"/proc/{pid}/status").read_text()
    seccomp = next(line.split()[1] for line in status.splitlines() if line.startswith("Seccomp:"))
    own_userns = os.readlink(f"/proc/{pid}/ns/user") != os.readlink("/proc/self/ns/user")
    record(
        "renderer sandboxed",
        seccomp == "2" and own_userns,
        f"pid={pid} Seccomp={seccomp} (2=filter) separate_user_namespace={own_userns}",
    )


async def check_browser(proxy: str) -> None:
    settings = load_settings()
    async with async_playwright() as pw:
        browser = await launch_browser(pw, proxy)
        context = await new_context(browser, settings.browser)

        for url in denied_targets():
            page = await context.new_page()  # fresh page: error pages can trigger late navigations
            try:
                response = await page.goto(url, timeout=20000)
                squid = response.headers.get("x-squid-error", "") if response else ""
                ok = response is not None and response.status == 403
                ok = ok and squid.startswith("ERR_ACCESS_DENIED")
                ok = ok or squid.startswith("ERR_DNS_FAIL")
                detail = f"status={response.status if response else None} squid={squid}"
            except Exception as exc:  # navigation error = not reached
                ok, detail = True, f"navigation failed: {str(exc).splitlines()[0]}"
            record(f"chromium denied {url}", ok, detail)
            await page.close()

        page = await context.new_page()
        response = await page.goto(ALLOWED_URL, timeout=30000)
        title = await page.title()
        record(
            f"chromium loads {ALLOWED_URL}",
            response is not None and response.status == 200,
            f"status={response.status if response else None} title={title!r}",
        )
        check_sandbox_processes()  # while a renderer is alive

        await page.set_content('<a id="d" href="data:text/plain,x" download="x.txt">x</a>')
        try:
            async with page.expect_download(timeout=5000) as info:
                await page.click("#d")
            failure = await (await info.value).failure()
            record("downloads blocked", failure is not None, f"download failure={failure!r}")
        except Exception as exc:
            record("downloads blocked", True, f"no download started: {type(exc).__name__}")

        await context.close()
        await browser.close()


# ---------- 5. Egress log ----------


def check_egress_log(run_id: str) -> None:
    log = Path("/app/runs") / run_id / "egress.log"
    for _ in range(10):
        if log.exists() and ALLOWED_HOST in log.read_text():
            denied = sum("TCP_DENIED" in line for line in log.read_text().splitlines())
            record("egress log records requests", True, f"{log} ({denied} denied lines)")
            return
        time.sleep(1)
    record("egress log records requests", False, f"{ALLOWED_HOST} not found in {log}")


async def main() -> int:
    proxy = require_egress_proxy()
    run_id = os.environ.get("RUN_ID", "adhoc")
    print(f"Selftest (run {run_id}, proxy {proxy})")

    check_container()
    check_direct_egress()
    await check_proxy(proxy)
    await check_browser(proxy)
    check_egress_log(run_id)

    failed = [c for c in checks if not c.passed]
    out = Path("/app/runs") / run_id / "selftest.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps({"passed": not failed, "checks": [asdict(c) for c in checks]}, indent=2)
    )
    print(f"\n{len(checks) - len(failed)}/{len(checks)} checks passed → {out}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
