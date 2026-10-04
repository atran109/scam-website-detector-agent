"""Tests for URL loading (no network)."""

from pathlib import Path
from urllib.parse import urlsplit

import pytest

from scamhunter.cli import URLS_PATH
from scamhunter.pipeline import load_sites


def test_real_url_list_loads_all_160_in_order() -> None:
    sites = load_sites(URLS_PATH)
    lines = [line.strip() for line in URLS_PATH.read_text().splitlines() if line.strip()]
    assert len(sites) == 160
    assert [s.url for s in sites] == lines  # exact strings, file order
    assert [s.site_id for s in sites] == [f"{i:03d}" for i in range(1, 161)]
    paths = sorted(urlsplit(s.url).path for s in sites if urlsplit(s.url).path not in ("", "/"))
    assert paths == ["/h5", "/veiynl", "/wap", "/wap"]  # paths kept, duplicates not merged


def test_duplicates_kept_and_domains_extracted(tmp_path: Path) -> None:
    f = tmp_path / "urls.txt"
    f.write_text("https://h5.foo.co.uk/wap\n\nhttps://h5.foo.co.uk/wap\nhttps://a.b.shop")  # no \n
    sites = load_sites(f)
    assert [s.site_id for s in sites] == ["001", "002", "003"]
    assert sites[0].host == "h5.foo.co.uk"
    assert sites[0].registrable_domain == "foo.co.uk"
    assert sites[2].registrable_domain == "b.shop"


def test_invalid_line_rejected(tmp_path: Path) -> None:
    f = tmp_path / "urls.txt"
    f.write_text("https://ok.test\nftp://bad.test\n")
    with pytest.raises(ValueError, match=":2:"):
        load_sites(f)
