"""Tests for Wayback CDX parsing (no network)."""

from scamhunter.browser.wayback import parse_cdx


def test_parse_cdx_newest_first_and_raw_url() -> None:
    rows = [
        ["timestamp", "original"],
        ["20240101000000", "https://x.test/"],
        ["20250301120000", "https://x.test/"],
        ["20250301120000", "https://x.test/"],
    ]
    captures = parse_cdx(rows)
    assert [c.timestamp for c in captures] == ["20250301120000", "20240101000000"]
    assert captures[0].raw_url == "https://web.archive.org/web/20250301120000id_/https://x.test/"
    assert parse_cdx([]) == [] and parse_cdx([["timestamp", "original"]]) == []
