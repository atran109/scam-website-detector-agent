"""--urls: commands can read a URL file other than data/urls.txt (DESIGN §8.2)."""

from pathlib import Path

import pytest

from scamhunter.cli import _select, _selected, main
from scamhunter.models import Site
from scamhunter.pipeline import load_sites


def _write(tmp_path: Path, *urls: str) -> Path:
    path = tmp_path / "u.txt"
    path.write_text("".join(f"{u}\n" for u in urls))
    return path


def test_load_sites_width_four(tmp_path: Path) -> None:
    path = _write(tmp_path, "https://a.example", "https://b.example")
    assert [s.site_id for s in load_sites(path, id_width=4)] == ["0001", "0002"]


def test_load_sites_default_width_unchanged(tmp_path: Path) -> None:
    assert load_sites(_write(tmp_path, "https://a.example"))[0].site_id == "001"


def test_only_pads_to_loaded_width() -> None:
    sites = [
        Site(
            site_id="0012",
            url="https://a.example",
            host="a.example",
            registrable_domain="a.example",
        )
    ]
    assert _select(sites, "12") == sites


def test_urls_option_gives_four_digit_ids(tmp_path: Path) -> None:
    import argparse

    args = argparse.Namespace(urls=str(_write(tmp_path, "https://a.example")), only=None)
    assert [s.site_id for s in _selected(args)] == ["0001"]


def test_no_urls_option_reads_the_default_file() -> None:
    import argparse

    sites = _selected(argparse.Namespace(urls=None, only="1"))
    assert [s.site_id for s in sites] == ["001"]


def test_urls_option_missing_file_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="nope.txt"):
        main(["triage", "--urls", str(tmp_path / "nope.txt")])


def test_only_matching_nothing_names_the_file_used(tmp_path: Path) -> None:
    path = _write(tmp_path, "https://a.example")
    with pytest.raises(SystemExit, match="u.txt"):
        main(["triage", "--urls", str(path), "--only", "9"])
