"""Cancel off-site navigations inside the page, before the browser starts them.

Why (LOG 2026-10-07, preconnect experiment): a route handler answers a navigation after Chromium
has already opened a connection to its target, so the off-site host still sees a TLS handshake.
Cancelling the navigation in the page with the Navigation API's `navigate` event
(`event.preventDefault()`) opened no tunnel in three proxy-logged runs. The script also makes
`window.open` to an off-site URL return null.

What it does not cover: server-side redirects (no page script runs), navigations the browser
starts itself (`page.goto`), form posts that the page does not route through the Navigation API,
and a page that removes or shadows `window.navigation`. The route guard in the loop and the
undo with `back` stay as the second and third lines.

The allowed domain changes after a confirmed hop (`set_allowed`). An init script cannot be
removed through Playwright, so the script is registered through CDP, which can: the script is
replaced for new documents and the current document's variable is updated in place."""

import json
from urllib.parse import urlparse

from playwright.async_api import CDPSession, Page
from playwright.async_api import Error as PlaywrightError

_SCRIPT = """
(() => {
  window.__allowedDomain = window.__allowedDomain || %(domain)s;
  const allowed = (host) => {
    const d = window.__allowedDomain;
    return host === d || host.endsWith('.' + d);
  };
  const offSite = (value) => {
    let u;
    try { u = new URL(value, location.href); } catch (e) { return null; }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    return allowed(u.hostname) ? null : u.href;
  };
  const record = (href) => { (window.__blockedNav = window.__blockedNav || []).push(href); };
  if (window.navigation && !window.__navGuard) {
    window.__navGuard = true;
    navigation.addEventListener('navigate', (e) => {
      const href = offSite(e.destination.url);
      if (href && e.cancelable) { e.preventDefault(); record(href); }
    });
    const realOpen = window.open;
    window.open = function (url, ...rest) {
      const href = url == null ? null : offSite(String(url));
      if (href) { record(href); return null; }
      return realOpen.call(this, url, ...rest);
    };
  }
})();
"""


def guard_script(domain: str) -> str:
    return _SCRIPT % {"domain": json.dumps(domain)}


class PageNavigationGuard:
    def __init__(self, page: Page) -> None:
        self.page = page
        self.allowed: str | None = None
        self._cdp: CDPSession | None = None
        self._script_id: str | None = None

    async def install(self, domain: str) -> None:
        """Guard new documents and the current one. Call before the agent's first action."""
        self._cdp = await self.page.context.new_cdp_session(self.page)
        await self._cdp.send("Page.enable")  # scripts registered on a session run only if enabled
        self.allowed = domain
        await self._register()
        await self._update_current()

    async def set_allowed(self, domain: str) -> None:
        """After a confirmed hop (or an undone one): the new registrable domain."""
        assert self._cdp is not None, "install() first"
        if self._script_id is not None:
            await self._cdp.send(
                "Page.removeScriptToEvaluateOnNewDocument", {"identifier": self._script_id}
            )
        self.allowed = domain
        await self._register()
        await self._update_current()

    async def drain(self) -> list[str]:
        """Off-site URLs the page tried to navigate to since the last call (this document's)."""
        try:
            urls = await self.page.evaluate("(window.__blockedNav || []).splice(0)")
        except PlaywrightError:  # navigating, or an error page
            return []
        return [str(u)[:500] for u in urls if urlparse(str(u)).scheme in ("http", "https")]

    async def _register(self) -> None:
        assert self._cdp is not None and self.allowed is not None
        result = await self._cdp.send(
            "Page.addScriptToEvaluateOnNewDocument", {"source": guard_script(self.allowed)}
        )
        self._script_id = result["identifier"]

    async def _update_current(self) -> None:
        assert self.allowed is not None
        try:
            await self.page.evaluate(
                f"window.__allowedDomain = {json.dumps(self.allowed)}; {guard_script(self.allowed)}"
            )
        except PlaywrightError:  # an error page cannot run scripts: the next document will
            pass
