"""Experiment (LOG 2026-10-07): does Chromium open a connection to a page's navigation target even
when the route guard answers the navigation with 204 before any request is sent?

For each configuration: load https://example.com/ through the egress proxy, install the guard
(main-frame navigation to another registrable domain gets a 204), make the page set location.href
to a different harmless IANA host, and wait. The Squid log then shows whether a tunnel to that
host was opened (a tunnel is logged when it closes, so the browser is closed first).
Run inside the crawler container: python docker/preconnect_probe.py "label|host|flag flag" ...
(the flag NOGUARD installs no guard: a control that shows what a full load looks like)."""

import asyncio
import sys
from urllib.parse import urlparse

from playwright.async_api import async_playwright

from scamhunter.agent.policy import registrable
from scamhunter.browser.sandbox import new_context
from scamhunter.config import load_settings, require_egress_proxy

START = "https://example.com/"


async def probe(label: str, target_host: str, flags: list[str], proxy: str) -> None:
    guarded = "NOGUARD" not in flags
    navapi = "NAVAPI" in flags  # also cancel off-site navigations inside the page (Navigation API)
    flags = [f for f in flags if f not in ("NOGUARD", "NAVAPI")]
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            channel="chromium",
            headless=True,
            chromium_sandbox=True,
            proxy={"server": proxy},
            args=flags,
        )
        context = await new_context(browser, load_settings().browser)
        blocked: list[str] = []

        async def guard(route) -> None:
            request = route.request
            host = urlparse(request.url).hostname or ""
            if (
                request.is_navigation_request()
                and request.frame.parent_frame is None
                and registrable(host) != registrable(urlparse(START).hostname or "")
            ):
                blocked.append(request.url)
                await route.fulfill(status=204, body="")
                return
            await route.fallback()

        if navapi:
            await context.add_init_script(
                """
                if (window.navigation) {
                  navigation.addEventListener('navigate', (e) => {
                    const host = new URL(e.destination.url).hostname;
                    if (host !== 'example.com' && !host.endsWith('.example.com') && e.cancelable) {
                      e.preventDefault();
                      window.__cancelled = (window.__cancelled || []).concat([e.destination.url]);
                    }
                  });
                }
                """
            )
        if guarded:
            await context.route("**/*", guard)
        page = await context.new_page()
        await page.goto(START, wait_until="domcontentloaded")
        await page.wait_for_timeout(2000)
        print(f"[{label}] start page loaded; now navigating to {target_host}", flush=True)
        await page.evaluate(
            f"setTimeout(() => {{ location.href = 'https://{target_host}/'; }}, 100)"
        )
        await page.wait_for_timeout(4000)
        cancelled = await page.evaluate("window.__cancelled || []")
        print(
            f"[{label}] route guard blocked: {blocked}; page-level cancel: {cancelled}; "
            f"page at {page.url}",
            flush=True,
        )
        await browser.close()
    await asyncio.sleep(3)  # let Squid log the closed tunnels


async def policy_check(proxy: str) -> None:
    """Print what chrome://policy says about network prediction (is the policy file read?)."""
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            channel="chromium", headless=True, chromium_sandbox=True, proxy={"server": proxy}
        )
        page = await (await browser.new_context()).new_page()
        try:
            await page.goto("chrome://policy", wait_until="load")
            await page.wait_for_timeout(1500)
            text = await page.evaluate("document.body.innerText")
            lines = [
                ln for ln in text.splitlines() if "NetworkPrediction" in ln or "Prediction" in ln
            ]
            print(
                "[policy-check] chrome://policy lines:",
                lines or "no NetworkPrediction policy listed",
            )
            print("[policy-check] text excerpt:", " ".join(text.split())[:300])
        except Exception as exc:  # noqa: BLE001
            print("[policy-check] could not read chrome://policy:", str(exc).splitlines()[0])
        await browser.close()


async def main() -> None:
    proxy = require_egress_proxy()
    if sys.argv[1:] == ["policy-check"]:
        await policy_check(proxy)
        return
    for spec in sys.argv[1:]:
        label, host, *rest = spec.split("|")
        flags = rest[0].split() if rest else []
        print(f"=== {label}: target {host}, flags {flags}", flush=True)
        await probe(label, host, flags, proxy)


asyncio.run(main())
