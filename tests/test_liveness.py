"""Tests for triage.liveness pure functions (no network)."""

from pathlib import Path

import pytest

from scamhunter.config import load_settings
from scamhunter.models import SiteStatus
from scamhunter.triage.liveness import (
    browser_headers,
    classify_response,
    extract_title,
    status_from_squid_error,
    visible_text,
)

URL = "https://example-scam.test/"
FILLER = "<p>" + "Trade crypto with guaranteed daily profit. " * 100 + "</p>"  # > short-page cutoff


def page(body: str, title: str = "Site") -> str:
    return f"<html><head><title>{title}</title></head><body>{body}</body></html>"


@pytest.mark.parametrize(
    ("status", "headers", "body", "final_url", "expected"),
    [
        (403, {"cf-mitigated": "challenge"}, page("x"), URL, SiteStatus.CHALLENGE_BLOCKED),
        (
            503,
            {},
            page("Checking your browser", "Just a moment..."),
            URL,
            SiteStatus.CHALLENGE_BLOCKED,
        ),
        (
            200,
            {},
            page("<script>window._cf_chl_opt={}</script>"),
            URL,
            SiteStatus.CHALLENGE_BLOCKED,
        ),
        (451, {}, page("blocked"), URL, SiteStatus.GEO_BLOCKED),
        (
            200,
            {},
            page("This service is not available in your region."),
            URL,
            SiteStatus.GEO_BLOCKED,
        ),
        (
            200,
            {},
            page("Account Suspended. Contact your hosting provider."),
            URL,
            SiteStatus.SUSPENDED,
        ),
        (
            200,
            {},
            page("This website has been reported for potential phishing"),
            URL,
            SiteStatus.SUSPENDED,
        ),
        (200, {}, page("This domain is for sale! Make an offer."), URL, SiteStatus.PARKED),
        (200, {}, page("<script>window.park = 'abc';</script>" + FILLER), URL, SiteStatus.PARKED),
        (
            200,
            {},
            page("Make an offer"),
            "https://sedo.com/search/details/?domain=x",
            SiteStatus.PARKED,
        ),
        (402, {}, page("Payment Required"), URL, SiteStatus.SUSPENDED),
        (404, {}, page("Not Found"), URL, SiteStatus.HTTP_ERROR),
        (500, {}, page("Internal error"), URL, SiteStatus.HTTP_ERROR),
        (200, {}, page("<h1>Welcome to nginx!</h1>", "Welcome to nginx!"), URL, SiteStatus.EMPTY),
        (200, {}, page("恭喜，站点创建成功！"), URL, SiteStatus.EMPTY),
        (200, {}, "", URL, SiteStatus.EMPTY),
        (
            200,
            {},
            page('<div id="app"></div><script src="/app.js"></script>'),
            URL,
            SiteStatus.LIVE,
        ),
        (200, {}, page(FILLER), URL, SiteStatus.LIVE),
        # Generic phrases are ignored on long pages: a real site may mention them in passing.
        (
            200,
            {},
            page(FILLER + "<p>Your account suspended? Contact support.</p>"),
            URL,
            SiteStatus.LIVE,
        ),
    ],
)
def test_classify_response(status, headers, body, final_url, expected) -> None:
    got, reason = classify_response(status, headers, body, final_url)
    assert got == expected, reason
    assert reason


@pytest.mark.parametrize(
    ("squid_error", "expected"),
    [
        ("ERR_DNS_FAIL 0", SiteStatus.DNS_FAILURE),
        ("ERR_CONNECT_FAIL 110", SiteStatus.TIMEOUT),
        ("ERR_CONNECT_FAIL 111", SiteStatus.CONNECTION_ERROR),
        ("ERR_READ_TIMEOUT 0", SiteStatus.TIMEOUT),
        ("ERR_ACCESS_DENIED 0", SiteStatus.CONNECTION_ERROR),
        (None, SiteStatus.CONNECTION_ERROR),
    ],
)
def test_status_from_squid_error(squid_error, expected) -> None:
    got, reason = status_from_squid_error(squid_error, 503)
    assert got == expected
    assert reason


def test_access_denied_reason_mentions_policy() -> None:
    _, reason = status_from_squid_error("ERR_ACCESS_DENIED 0", 403)
    assert "egress policy" in reason


def test_browser_headers_are_consistent_chrome() -> None:
    http = load_settings().http
    headers = browser_headers(http)
    v = str(http.chrome_major_version)
    assert f"Chrome/{v}.0.0.0" in headers["User-Agent"]
    assert f'"Google Chrome";v="{v}"' in headers["Sec-Ch-Ua"]
    assert "Windows" in headers["User-Agent"] and headers["Sec-Ch-Ua-Platform"] == '"Windows"'
    assert headers["Accept-Language"] == http.accept_language
    assert headers["Accept"].startswith("text/html")


def test_visible_text_and_title() -> None:
    body = page(
        "<script>var x=1</script><style>p{}</style><p>Hello&nbsp;<b>world</b></p>",
        "  My &amp; Site ",
    )
    assert visible_text(body) == "My & Site Hello world"
    assert extract_title(body) == "My & Site"
    assert extract_title("<html></html>") is None


PILOT = Path(__file__).parent / "fixtures" / "pilot_texts"


def test_parklogic_rendered_page_is_parked() -> None:
    """#004 adnins.cloud: after the JS redirect the page says 'created by ParkLogic'."""
    html = (PILOT / "004.html").read_text()
    status, reason = classify_response(200, {}, html, "https://adnins.cloud/")
    assert status == SiteStatus.PARKED and "parklogic" in reason.lower()


def test_http_stub_before_the_redirect_is_not_visibly_parked() -> None:
    # What HTTP triage saw for #004: why the rendered page must be re-checked in the pipeline.
    stub = (
        "<html><head><title>Redirecting...</title></head><body><script>go()</script></body></html>"
    )
    status, _ = classify_response(200, {}, stub, "https://adnins.cloud/")
    assert status == SiteStatus.LIVE


@pytest.mark.parametrize(
    "body",
    [
        "<h1>This domain is available for purchase</h1>",
        "<p>This web page is parked free, courtesy of GoDaddy.com</p>",
        "<p>Inquire about this domain</p>",
        "<script src='https://sedoparking.com/x.js'></script>",
        "<p>Powered by ParkingCrew</p>",
        "<p>Domain parked. Visit hugedomains.com</p>",
    ],
)
def test_other_parking_providers(body: str) -> None:
    status, _ = classify_response(200, {}, f"<html><body>{body}</body></html>", URL)
    assert status == SiteStatus.PARKED


def test_real_page_mentioning_parked_is_not_parked() -> None:
    body = (
        "<html><body><p>"
        + "Trading platform with daily signals. " * 120
        + ("Our team parked the old branding.</p></body></html>")
    )
    assert classify_response(200, {}, body, URL)[0] == SiteStatus.LIVE


@pytest.mark.parametrize(
    ("body", "expected", "reason_part"),
    [
        # Texts and shapes taken from the capture-2 pages (LOG 2026-10-07).
        (
            page("<p>choxo.cc has expired and may be available at Dynadot auctions</p>"),
            SiteStatus.PARKED,
            "expired",
        ),
        (
            page("<p>Error. Page cannot be displayed. Please contact your service provider.</p>"),
            SiteStatus.PARKED,
            "cloaking",
        ),
        (page("<h1>Index of /</h1><pre>Name Last Modified Size</pre>"), SiteStatus.EMPTY, "index"),
        (page("<p>網站維護中</p>"), SiteStatus.EMPTY, "maintenance"),
        (page("<p>Our site is under maintenance, back soon.</p>"), SiteStatus.EMPTY, "maintenance"),
        # A real, long page that merely mentions maintenance stays live.
        (page("<p>Scheduled maintenance tonight.</p>" + FILLER), SiteStatus.LIVE, "content"),
    ],
)
def test_non_content_pages(body: str, expected: SiteStatus, reason_part: str) -> None:
    got, reason = classify_response(200, {}, body, URL)
    assert got == expected
    assert reason_part in reason.lower()
