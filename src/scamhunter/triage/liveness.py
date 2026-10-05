"""HTTP probe → SiteStatus: parked/suspended/challenge detection, no rendering or JS."""

import asyncio
import html
import re
import ssl
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import httpx

from scamhunter.config import HttpSettings, TriageSettings
from scamhunter.models import SiteStatus, TriageResult

# ============================================================
# Browser-like request headers
# ============================================================


def browser_headers(http: HttpSettings) -> dict[str, str]:
    """Headers of a current desktop Chrome on Windows (some scam sites cloak against bots)."""
    v = http.chrome_major_version
    return {
        "User-Agent": (
            f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36"
        ),
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,"
            "image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
        ),
        "Accept-Language": http.accept_language,
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Sec-Ch-Ua": f'"Google Chrome";v="{v}", "Chromium";v="{v}", "Not/A)Brand";v="24"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
    }


# ============================================================
# Proxy errors (pure)
# ============================================================

ETIMEDOUT = 110


def status_from_squid_error(squid_error: str | None, http_status: int) -> tuple[SiteStatus, str]:
    """Map Squid's X-Squid-Error value (e.g. "ERR_CONNECT_FAIL 111") to a status + reason."""
    if not squid_error:
        return SiteStatus.CONNECTION_ERROR, f"proxy error {http_status} without X-Squid-Error"
    code, _, detail = squid_error.partition(" ")
    if code == "ERR_DNS_FAIL":
        return SiteStatus.DNS_FAILURE, "host does not resolve"
    if code in ("ERR_READ_TIMEOUT", "ERR_LIFETIME_EXP"):
        return SiteStatus.TIMEOUT, f"proxy {code}"
    if code == "ERR_CONNECT_FAIL":
        if detail == str(ETIMEDOUT):
            return SiteStatus.TIMEOUT, "connect timed out"
        return SiteStatus.CONNECTION_ERROR, f"connect failed (errno {detail})"
    if code == "ERR_ACCESS_DENIED":
        return SiteStatus.CONNECTION_ERROR, "egress policy: destination denied (private IP or port)"
    return SiteStatus.CONNECTION_ERROR, f"proxy {squid_error}"


# ============================================================
# Status from page content (pure)
# ============================================================

# Generic phrases only count on short pages, so a real site that merely mentions
# "suspended" or "for sale" somewhere isn't misfiled.
SHORT_PAGE_CHARS = 3000

CHALLENGE_TITLES = ("just a moment...", "attention required! | cloudflare", "ddos-guard")
CHALLENGE_FINGERPRINTS = (
    "_cf_chl_opt",
    "cf-browser-verification",
    "/cdn-cgi/challenge-platform/h/",
)

SUSPENDED_PHRASES = (
    "account has been suspended",
    "account suspended",
    "website is suspended",
    "site has been suspended",
    "this domain has been suspended",
    "this site has been disabled",
    "suspected phishing",
    "reported for potential phishing",
    "deceptive site ahead",
    "this store is unavailable",
    "网站已关闭",
    "网站暂停",
)

PARKED_PHRASES = (
    "domain is for sale",
    "domain may be for sale",
    "buy this domain",
    "domain for sale",
    "this domain is parked",
    "domain is parked",
    "this web page is parked",
    "parked domain",
    "parked free, courtesy of",
    "domain parking",
    "domain name is for sale",
    "domain is available for purchase",
    "inquire about this domain",
    "make an offer on this domain",
)
# Parking providers recognizable by script or host, on any page length.
# ParkLogic's page ("This page has been created by ParkLogic.") is usually reached through a
# JS redirect, so HTTP triage sees only a stub; pipeline.rendered_parked() re-checks the
# rendered page with this same detector.
PARKED_FINGERPRINTS = (
    "window.park",
    "sedoparking",
    "parkingcrew",
    "parklogic",
    "bodis.com",
    "above.com/",
    "undeveloped.com",
    "hugedomains.com",
    "afternic.com/",
)
PARKING_HOSTS = (
    "sedo.com",
    "dan.com",
    "afternic.com",
    "hugedomains.com",
    "parkingcrew.net",
    "undeveloped.com",
    "bodis.com",
)

GEO_PHRASES = (
    "not available in your country",
    "not available in your region",
    "not available in your area",
    "access from your country",
    "restricted jurisdiction",
)

DEFAULT_PAGE_PHRASES = (
    "welcome to nginx!",
    "apache2 ubuntu default page",
    "apache2 debian default page",
    "test page for the apache",
    "iis windows server",
    "web server's default page",
    "恭喜，站点创建成功",  # BaoTa panel default page, common on cheap Asian hosting
    "site created successfully",
)

BLANK_PAGE_CHARS = 50

_SCRIPT_STYLE = re.compile(r"<(script|style|noscript)\b.*?</\1\s*>", re.S | re.I)
_TAG = re.compile(r"<[^>]+>")
_TITLE = re.compile(r"<title[^>]*>(.*?)</title\s*>", re.S | re.I)


def visible_text(body: str) -> str:
    text = _TAG.sub(" ", _SCRIPT_STYLE.sub(" ", body))
    return " ".join(html.unescape(text).split())


def extract_title(body: str) -> str | None:
    match = _TITLE.search(body)
    if not match:
        return None
    title = " ".join(html.unescape(match.group(1)).split())
    return title or None


def _first_match(haystack: str, needles: tuple[str, ...]) -> str | None:
    return next((n for n in needles if n in haystack), None)


def classify_response(
    http_status: int, headers: Mapping[str, str], body: str, final_url: str
) -> tuple[SiteStatus, str]:
    """Decide the SiteStatus of a fetched page from its status, headers and HTML."""
    lowered = body.lower()
    text = visible_text(body)
    short = len(text) < SHORT_PAGE_CHARS
    title = (extract_title(body) or "").lower()
    host = httpx.URL(final_url).host

    if headers.get("cf-mitigated", "").lower() == "challenge":
        return SiteStatus.CHALLENGE_BLOCKED, "cf-mitigated: challenge"
    if title in CHALLENGE_TITLES or (m := _first_match(lowered, CHALLENGE_FINGERPRINTS)):
        return SiteStatus.CHALLENGE_BLOCKED, f"challenge page ({title or m})"

    if http_status == 451:
        return SiteStatus.GEO_BLOCKED, "HTTP 451"
    if short and (m := _first_match(lowered, GEO_PHRASES)):
        return SiteStatus.GEO_BLOCKED, f'geo-block marker "{m}"'

    if short and (m := _first_match(lowered, SUSPENDED_PHRASES)):
        return SiteStatus.SUSPENDED, f'suspended marker "{m}"'

    if any(host == h or host.endswith("." + h) for h in PARKING_HOSTS):
        return SiteStatus.PARKED, f"redirected to parking host {host}"
    if m := _first_match(lowered, PARKED_FINGERPRINTS):
        return SiteStatus.PARKED, f'parking provider fingerprint "{m}"'
    if short and (m := _first_match(lowered, PARKED_PHRASES)):
        return SiteStatus.PARKED, f'parked marker "{m}"'

    if http_status == 402:  # "payment required": hosting/store account unpaid (e.g. Shopify)
        return SiteStatus.SUSPENDED, "HTTP 402 (hosting/store suspended)"
    if http_status >= 400:
        return SiteStatus.HTTP_ERROR, f"HTTP {http_status}"

    if short and (m := _first_match(lowered, DEFAULT_PAGE_PHRASES)):
        return SiteStatus.EMPTY, f'default server page "{m}"'
    if len(text) < BLANK_PAGE_CHARS:
        if "<script" in lowered:
            return SiteStatus.LIVE, "little static text but has scripts (likely SPA shell)"
        return SiteStatus.EMPTY, "blank page"

    return SiteStatus.LIVE, "content page"


# ============================================================
# Probe (I/O)
# ============================================================


@dataclass
class _Fetched:
    status: int
    headers: httpx.Headers
    body: str
    final_url: str
    redirect_chain: list[str]


class _SquidErrorTrace:
    """httpx `trace` hook that keeps the last X-Squid-Error header seen.

    For https URLs a proxy failure surfaces as a bare ProxyError("503 ..."); the header is
    only visible on the CONNECT response, which this hook sees.
    """

    def __init__(self) -> None:
        self.error: str | None = None

    async def __call__(self, event: str, info: dict[str, Any]) -> None:
        if event.endswith("receive_response_headers.complete"):
            _, _, _, raw_headers = info["return_value"]
            for name, value in raw_headers:
                if name.lower() == b"x-squid-error":
                    self.error = value.decode("latin-1")


def _is_cert_error(exc: BaseException) -> bool:
    while exc is not None:
        if isinstance(exc, ssl.SSLCertVerificationError):
            return True
        exc = exc.__cause__ or exc.__context__  # type: ignore[assignment]
    return False


def _is_tls_error(exc: BaseException) -> bool:
    while exc is not None:
        if isinstance(exc, ssl.SSLError):
            return True
        exc = exc.__cause__ or exc.__context__  # type: ignore[assignment]
    return False


def _decode(raw: bytes, response: httpx.Response) -> str:
    encoding = response.charset_encoding
    if not encoding:
        meta = re.search(rb"<meta[^>]+charset=[\"']?([\w-]+)", raw[:4096], re.I)
        encoding = meta.group(1).decode("ascii") if meta else "utf-8"
    try:
        return raw.decode(encoding, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


async def _fetch(client: httpx.AsyncClient, url: str, max_body_bytes: int) -> _Fetched:
    trace = _SquidErrorTrace()
    request = client.build_request("GET", url, extensions={"trace": trace})
    try:
        response = await client.send(request, stream=True)
    except httpx.ProxyError as exc:
        raise _ProxyFailure(trace.error, str(exc)) from exc
    try:
        if squid_error := response.headers.get("x-squid-error"):  # plain-http proxy errors
            raise _ProxyFailure(squid_error, f"{response.status_code} from proxy")
        raw = bytearray()
        async for chunk in response.aiter_bytes():
            raw.extend(chunk)
            if len(raw) >= max_body_bytes:
                break
    finally:
        await response.aclose()
    return _Fetched(
        status=response.status_code,
        headers=response.headers,
        body=_decode(bytes(raw[:max_body_bytes]), response),
        final_url=str(response.url),
        redirect_chain=[str(r.url) for r in response.history],
    )


class _ProxyFailure(Exception):
    def __init__(self, squid_error: str | None, message: str) -> None:
        super().__init__(message)
        self.squid_error = squid_error
        self.http_status = int(message[:3]) if message[:3].isdigit() else 0


@dataclass
class _Attempt:
    status: SiteStatus
    reason: str
    error: str | None = None
    fetched: _Fetched | None = None
    cert_error: bool = False


async def _attempt(client: httpx.AsyncClient, url: str, cfg: TriageSettings) -> _Attempt:
    """One fetch, with every failure mapped to a status. Never raises."""
    try:
        fetched = await asyncio.wait_for(
            _fetch(client, url, cfg.max_body_bytes), timeout=cfg.timeout_s * 2
        )
    except _ProxyFailure as exc:
        status, reason = status_from_squid_error(exc.squid_error, exc.http_status)
        return _Attempt(status, reason, error=f"{exc} [{exc.squid_error}]")
    except (TimeoutError, httpx.TimeoutException) as exc:
        return _Attempt(SiteStatus.TIMEOUT, "timed out", error=type(exc).__name__)
    except httpx.TooManyRedirects as exc:
        return _Attempt(SiteStatus.HTTP_ERROR, "too many redirects", error=str(exc))
    except httpx.HTTPError as exc:
        if _is_cert_error(exc):
            return _Attempt(SiteStatus.TLS_ERROR, "certificate invalid", str(exc), cert_error=True)
        if _is_tls_error(exc):
            return _Attempt(SiteStatus.TLS_ERROR, "TLS handshake failed", error=str(exc))
        return _Attempt(SiteStatus.CONNECTION_ERROR, type(exc).__name__, error=str(exc))
    except Exception as exc:  # noqa: BLE001 - triage must never crash the run
        return _Attempt(SiteStatus.CONNECTION_ERROR, "unexpected error", error=repr(exc))
    status, reason = classify_response(
        fetched.status, fetched.headers, fetched.body, fetched.final_url
    )
    return _Attempt(status, reason, fetched=fetched)


RETRYABLE = (SiteStatus.TIMEOUT, SiteStatus.CONNECTION_ERROR)


async def probe(
    url: str,
    verified: httpx.AsyncClient,
    unverified: httpx.AsyncClient,
    cfg: TriageSettings,
) -> TriageResult:
    """Probe one URL through the egress proxy and return its TriageResult."""
    start = time.monotonic()
    tls_valid: bool | None = None

    attempt = await _attempt(verified, url, cfg)
    for _ in range(cfg.retries):
        if attempt.status not in RETRYABLE or "egress policy" in attempt.reason:
            break
        attempt = await _attempt(verified, url, cfg)

    if attempt.cert_error:
        # Invalid cert: look at the content anyway (DESIGN §5.1a) and remember it.
        tls_valid = False
        retry = await _attempt(unverified, url, cfg)
        if retry.fetched is not None:
            retry.reason += "; TLS certificate invalid (fetched unverified)"
        attempt = retry if retry.fetched is not None else attempt
    elif attempt.fetched is not None and attempt.fetched.final_url.startswith("https://"):
        tls_valid = True

    fetched = attempt.fetched
    return TriageResult(
        status=attempt.status,
        http_status=fetched.status if fetched else None,
        final_url=fetched.final_url if fetched else None,
        redirect_chain=fetched.redirect_chain if fetched else [],
        title=extract_title(fetched.body) if fetched else None,
        reason=attempt.reason,
        tls_valid=tls_valid,
        error=attempt.error,
        elapsed_ms=int((time.monotonic() - start) * 1000),
    )


def make_client(
    proxy: str, http: HttpSettings, cfg: TriageSettings, *, verify: bool
) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        proxy=proxy,
        trust_env=False,  # only the explicit egress proxy, never ambient env settings
        verify=verify,
        headers=browser_headers(http),
        follow_redirects=True,
        max_redirects=cfg.max_redirects,
        timeout=httpx.Timeout(cfg.timeout_s),
    )
