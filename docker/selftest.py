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
import socketserver
import sys
import threading
import time
from dataclasses import asdict, dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
from playwright.async_api import async_playwright

from scamhunter.browser.nav_guard import PageNavigationGuard
from scamhunter.browser.sandbox import launch_browser, launch_mock_browser, new_context
from scamhunter.config import (
    SandboxError,
    is_loopback_url,
    load_settings,
    require_egress_proxy,
    require_loopback_url,
)

ALLOWED_URL = "https://example.com/"
ALLOWED_HOST = "example.com"

# Names the proxy resolves through its own /etc/hosts (docker-compose `extra_hosts`) to an address
# it must never connect to. DNS-independent: no resolver, filtered or not, is involved, so the only
# acceptable answer is the proxy's own refusal (403 ERR_ACCESS_DENIED); "could not resolve" means
# the probe did not run and counts as a failure (fail closed). Replaces the nip.io probe.
REBIND_URLS = [
    "http://rebind-linklocal.selftest.test/",
    "http://rebind-private.selftest.test/",
    "http://rebind-loopback.selftest.test/",
    "https://rebind-linklocal.selftest.test/",  # the CONNECT path
]


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
        "https://169.254.169.254/",  # CONNECT path, not just plain http
        "http://example.com:8080/",  # non-allowed port
        *REBIND_URLS,
    ]
    if router := os.environ.get("SELFTEST_ROUTER_IP"):
        targets.insert(0, f"http://{router}/")  # home router, from the Mac's default route
    return targets


# ---------- 1. Container hardening ----------


def check_read_only_root() -> None:
    """The image is immutable: writes outside the mounts and tmpfs fail with EROFS."""
    import errno

    outcomes = {}
    for path in ("/app/.selftest-write", "/usr/local/.selftest-write", "/etc/.selftest-write"):
        try:
            Path(path).write_text("x")
            Path(path).unlink()
            outcomes[path] = "WRITABLE"
        except OSError as exc:
            outcomes[path] = "EROFS" if exc.errno == errno.EROFS else f"errno {exc.errno}"
    try:
        scratch = Path("/tmp/.selftest-write")
        scratch.write_text("x")
        scratch.unlink()
        tmp = "writable"
    except OSError as exc:
        tmp = f"errno {exc.errno}"
    record(
        "root filesystem is read-only",
        all(v == "EROFS" for v in outcomes.values()) and tmp == "writable",
        f"writes: {outcomes}; /tmp (tmpfs): {tmp}",
    )


def check_container() -> None:
    check_read_only_root()
    record("non-root user", os.getuid() != 0, f"uid={os.getuid()}")
    cap_eff = next(
        line.split()[1]
        for line in Path("/proc/self/status").read_text().splitlines()
        if line.startswith("CapEff:")
    )
    record("no effective capabilities", int(cap_eff, 16) == 0, f"CapEff={cap_eff}")


# ---------- 1b. Secrets stay in the gateway ----------


async def check_llm_isolation() -> None:
    leaked = [k for k in os.environ if k.startswith("ANTHROPIC") and "PROXY" not in k]
    record("no API key in crawler env", not leaked, f"ANTHROPIC* vars: {leaked or 'none'}")
    gateway = load_settings().llm.gateway_url
    async with httpx.AsyncClient(trust_env=False, timeout=10) as client:
        try:
            health = (await client.get(f"{gateway}/health")).status_code
        except httpx.HTTPError as exc:
            health = f"unreachable: {exc}"
        record("llm-gateway reachable", health == 200, f"GET /health → {health}")
        bad = {
            "role": "judge",
            "site_id": "selftest",
            "purpose": "selftest",
            "request": {
                "messages": [{"role": "user", "content": "x"}],
                "max_tokens": 10,
                "tools": [{"type": "web_fetch_20260209", "name": "web_fetch"}],
            },
        }
        try:
            resp = await client.post(f"{gateway}/v1/messages", json=bad)
            ok, detail = resp.status_code == 400, f"{resp.status_code} {resp.json().get('error')}"
        except httpx.HTTPError as exc:
            ok, detail = False, f"unreachable: {exc}"
        record("gateway rejects server tools", ok, detail)
    llm_proxy = proxy_url_for_llm()
    async with httpx.AsyncClient(proxy=llm_proxy, trust_env=False, timeout=20) as client:
        status, squid_error = await proxy_outcome(client, ALLOWED_URL)
        record(
            "LLM proxy port denies non-Anthropic hosts",
            status == 403,
            f"{ALLOWED_URL} via {llm_proxy}: status={status} squid={squid_error}",
        )


def proxy_url_for_llm() -> str:
    return require_egress_proxy().rsplit(":", 1)[0] + ":3129"


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
            # A name the proxy can't resolve never gets a connection either, except the rebinding
            # probes, which exist to prove the refusal itself.
            unresolvable = url not in REBIND_URLS and (squid_error or "").startswith("ERR_DNS_FAIL")
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

    # the browser process itself: no --type=, and not the crash-report helpers
    browser_procs = [
        cmdline
        for _, cmdline in procs
        if "--type=" not in cmdline and "chrome_crashpad_handler" not in cmdline
    ]
    record(
        "extensions disabled",
        bool(browser_procs) and all("--disable-extensions" in c for c in browser_procs),
        f"{len(browser_procs)} browser process(es) with --disable-extensions",
    )

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
                if url not in REBIND_URLS:
                    ok = ok or squid.startswith("ERR_DNS_FAIL")
                detail = f"status={response.status if response else None} squid={squid}"
            except Exception as exc:  # navigation error = not reached
                # A rebinding probe must end in the proxy's own refusal (a 403 page for http, a
                # failed tunnel for https); a DNS error there means the probe did not run.
                dns_error = "ERR_NAME_NOT_RESOLVED" in str(exc)
                ok = not (url in REBIND_URLS and dns_error)
                detail = f"navigation failed: {str(exc).splitlines()[0]}"
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


# ---------- 4b. The in-page navigation guard opens no connection ----------


async def check_page_guard(proxy: str, run_id: str) -> None:
    """A page that sends the browser to another site by itself: with the guard the navigation is
    cancelled in the page and the proxy logs no tunnel to the target; the same navigation without
    the guard does open one (the control, which also proves the log shows tunnels). The route
    layer alone does not pass this (LOG 2026-10-07, preconnect experiment)."""
    log = Path("/app/runs") / run_id / "egress.log"
    before = len(log.read_text()) if log.exists() else 0
    guarded_host, control_host = "example.net", "example.org"
    settings = load_settings()
    outcome: dict[str, tuple[str, list[str]]] = {}
    async with async_playwright() as pw:
        browser = await launch_browser(pw, proxy)
        for host, guarded in ((guarded_host, True), (control_host, False)):
            context = await new_context(browser, settings.browser)
            page = await context.new_page()
            await page.goto(ALLOWED_URL, timeout=30000)
            guard = PageNavigationGuard(page)
            if guarded:
                await guard.install(ALLOWED_HOST)
            await page.evaluate(f"setTimeout(() => {{ location.href = 'https://{host}/'; }}, 100)")
            await page.wait_for_timeout(3500)
            outcome[host] = (page.url, await guard.drain() if guarded else [])
            await context.close()
        await browser.close()
    new = ""
    for _ in range(12):  # Squid logs a tunnel when it closes
        new = log.read_text()[before:] if log.exists() else ""
        if f"CONNECT {control_host}:443" in new:
            break
        time.sleep(1)
    control_seen = f"CONNECT {control_host}:443" in new
    guarded_seen = f"CONNECT {guarded_host}:443" in new
    url, cancelled = outcome[guarded_host]
    record(
        "in-page guard opens no connection to an off-site target",
        control_seen and not guarded_seen and url.startswith(ALLOWED_URL) and bool(cancelled),
        f"guarded: tunnel={guarded_seen} cancelled={cancelled} stayed={url}; "
        f"control (no guard): tunnel={control_seen}",
    )


# ---------- 6. Mock mode stays on loopback ----------

NOT_LOOPBACK = [
    "https://example.com/",
    "http://10.0.0.5/",
    "http://192.168.0.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://llm-gateway:8080/health",
    "http://egress-proxy:3128/",
    "http://127.0.0.1.nip.io/",
    "http://127.0.0.1@evil.example/",
    "file:///etc/passwd",
]


class _LoopbackServer(ThreadingHTTPServer):
    daemon_threads = True

    def server_bind(self) -> None:  # skip the stdlib's reverse-DNS lookup (can stall)
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[0], self.server_address[1]


class _Local(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/redirect":  # a loopback page bouncing the browser to an internal service
            self.send_response(302)
            self.send_header("Location", "http://llm-gateway:8080/health")
            self.end_headers()
            return
        body = b"<html><title>local</title><body>loopback ok</body></html>"
        self.send_response(200)
        self.send_header("content-type", "text/html")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        return


async def check_mock_mode() -> None:
    accepted = []
    for url in NOT_LOOPBACK:
        try:
            require_loopback_url(url)
            accepted.append(url)
        except SandboxError:
            pass
    record(
        "--mock refuses non-loopback URLs",
        not accepted,
        f"{len(NOT_LOOPBACK)} URLs refused" if not accepted else f"ACCEPTED: {accepted}",
    )
    record(
        "--mock accepts loopback",
        is_loopback_url("http://127.0.0.1:1/") and is_loopback_url("http://localhost/"),
        "127.0.0.1 and localhost",
    )

    server = _LoopbackServer(("127.0.0.1", 0), _Local)
    threading.Thread(target=lambda: server.serve_forever(poll_interval=0.05), daemon=True).start()
    local = f"http://127.0.0.1:{server.server_port}/"
    settings = load_settings()
    try:
        async with async_playwright() as pw:
            # Control: a plain proxy-less browser CAN reach an internal service. That is why mock
            # mode needs its guards, and without this the checks below would be vacuous.
            plain = await pw.chromium.launch(
                channel="chromium", headless=True, chromium_sandbox=True
            )
            open_ctx = await plain.new_context()
            try:
                response = await (await open_ctx.new_page()).goto(
                    "http://llm-gateway:8080/health", timeout=15000
                )
                reached = response is not None and response.status == 200
            except Exception as exc:  # noqa: BLE001
                reached = False
                print(f"    control error: {str(exc).splitlines()[0]}")
            record(
                "control: unguarded proxy-less browser reaches llm-gateway",
                reached,
                "needed to prove the guard is what blocks it",
            )
            await open_ctx.close()
            await plain.close()

            browser = await launch_mock_browser(pw)
            context = await new_context(browser, settings.browser, loopback_only=True)
            page = await context.new_page()
            response = await page.goto(local, timeout=15000)
            record(
                "mock-mode browser reaches loopback",
                response is not None
                and response.status == 200
                and "loopback ok" in await page.content(),
                local,
            )

            not_blocked = []
            for url in NOT_LOOPBACK:
                if not url.startswith("http"):
                    continue
                try:
                    await (await context.new_page()).goto(url, timeout=15000)
                    not_blocked.append(url)  # navigation succeeded: should be impossible
                except Exception:  # noqa: BLE001 - a blocked navigation raises
                    if url not in context.blocked_urls:
                        not_blocked.append(url)
            record(
                "mock-mode browser blocks every non-loopback URL",
                not not_blocked,
                f"{len(NOT_LOOPBACK) - 1} navigations aborted by the route guard"
                if not not_blocked
                else f"NOT BLOCKED: {not_blocked}",
            )

            internal = "http://llm-gateway:8080/health"
            redirect_page = await context.new_page()
            try:
                await redirect_page.goto(local + "redirect", timeout=15000)
            except Exception as exc:  # noqa: BLE001 - the network layer should refuse the hop
                outcome = str(exc).splitlines()[0][:90]
            else:
                outcome = f"landed on {redirect_page.url}"
            try:
                landed = await redirect_page.evaluate(
                    "document.body ? document.body.innerText : ''"
                )
            except Exception:  # noqa: BLE001 - Chromium's error page can't be scripted
                landed = ""
            record(
                "redirect from loopback to an internal service is blocked",
                redirect_page.url != internal and '"ok": true' not in landed,
                outcome,
            )

            # no-cors: the promise resolves when the request is sent and rejects only when the
            # network layer blocks it, so CORS can't make this pass for the wrong reason.
            fetched = await page.evaluate(
                f"fetch('{internal}', {{mode: 'no-cors'}}).then(() => 'reached', () => 'blocked')"
            )
            record(
                "fetch() from page JS to an internal service is blocked",
                fetched == "blocked",
                f"fetch → {fetched}",
            )
            await context.close()
            await browser.close()
    finally:
        server.shutdown()
        server.server_close()


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
    await check_mock_mode()
    await check_llm_isolation()
    check_direct_egress()
    await check_proxy(proxy)
    await check_browser(proxy)
    await check_page_guard(proxy, run_id)
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
