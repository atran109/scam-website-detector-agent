"""--mock mode may only visit loopback (DESIGN §5.5, decision 2026-10-05)."""

import pytest

from scamhunter.config import SandboxError, is_loopback_url, require_loopback_url

ALLOWED = [
    "http://127.0.0.1:8000/",
    "http://127.0.0.1/",
    "http://127.1.2.3:80/x",  # whole 127.0.0.0/8 is loopback
    "http://localhost:9999/#/deposit",
    "https://localhost/",
    "http://[::1]:8080/",
]

REFUSED = [
    "https://example.com/",
    "http://10.0.0.5/",
    "http://192.168.0.1/",  # the home router
    "http://169.254.169.254/latest/meta-data/",
    "http://172.18.0.2:8080/health",  # an address on the Docker network
    "http://llm-gateway:8080/health",  # internal service names
    "http://egress-proxy:3128/",
    "http://127.0.0.1.nip.io/",  # a public name that resolves to loopback
    "http://localhost.evil.test/",
    "http://localhost./",  # trailing dot: not literally localhost
    "http://127.0.0.1@evil.example/",  # the host is evil.example
    "http://127.1/",  # shorthand the browser would resolve; not a literal IP
    "http://2130706433/",  # decimal form of 127.0.0.1
    "http://0.0.0.0/",
    "ftp://127.0.0.1/",
    "file:///etc/passwd",
    "javascript:alert(1)",
    "//127.0.0.1/",
    "127.0.0.1",
    "",
]


@pytest.mark.parametrize("url", ALLOWED)
def test_loopback_urls_allowed(url: str) -> None:
    assert is_loopback_url(url)
    assert require_loopback_url(url) == url


@pytest.mark.parametrize("url", REFUSED)
def test_everything_else_refused(url: str) -> None:
    assert not is_loopback_url(url)
    with pytest.raises(SandboxError, match="--mock refuses"):
        require_loopback_url(url)
