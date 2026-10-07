"""App-download targets as evidence (M4 fix 8, LOG 2026-10-07): found, resolved, never fetched."""

from pathlib import Path

from scamhunter.extract.app_downloads import find_app_downloads, merge_targets
from scamhunter.extract.extractor import NetworkBody, SnapshotContent
from scamhunter.models import DiscoveryStage

FIXTURES = Path(__file__).parent / "fixtures" / "pages"


def content(html: str = "", url: str = "https://www.btcctw.help/download_zh-TW.html", **kw):
    return SnapshotContent("s1", DiscoveryStage.LANDING, url, html, "", **kw)


def test_117s_config_js_gives_the_apk_and_the_profile() -> None:
    """Pilot site 117: the names are relative strings in config.js, not links on the page."""
    config = NetworkBody(
        "https://www.btcctw.help/config.js", "script", (FIXTURES / "117_config.js").read_text()
    )
    html = "<button onclick='down()'>下載</button><script src='config.js'></script>"
    assert find_app_downloads(content(html, network=[config])) == [
        "https://www.btcctw.help/BTCC.apk",
        "https://www.btcctw.help/BTCC.mobileconfig",
    ]


def test_absolute_links_store_pages_and_itms_manifests() -> None:
    html = (
        '<a href="https://cdn.example-app.top/dl/App_v2.apk?x=1">Android</a>'
        '<a href="https://apps.apple.com/us/app/skylit-social/id6791417423">iOS</a>'
        '<a href="https://play.google.com/store/apps/details?id=com.fake.exchange&hl=en">Play</a>'
        '<a href="itms-services://?action=download-manifest&url=https://x.top/m.plist">enterprise</a>'
        '<a href="https://testflight.apple.com/join/AbC123xy">beta</a>'
    )
    found = find_app_downloads(content(html))
    assert "https://cdn.example-app.top/dl/App_v2.apk?x=1" in found
    assert "https://apps.apple.com/us/app/skylit-social/id6791417423" in found
    assert "https://play.google.com/store/apps/details?id=com.fake.exchange" in found
    assert any(u.startswith("itms-services://?action=download-manifest") for u in found)
    assert "https://testflight.apple.com/join/AbC123xy" in found
    assert len(found) == len(set(found))


def test_ordinary_scripts_and_images_are_not_app_files() -> None:
    html = (
        '<script src="/js/jquery.min.js"></script><img src="logo.png">'
        '<a href="/guide/how-to-install-an-apk.html">guide</a><p>app.apk is the file</p>'
    )
    assert find_app_downloads(content(html)) == []


def test_relative_names_resolve_against_the_page_and_the_list_is_capped() -> None:
    html = "".join(f"<script>var f{i} = 'pkg{i}.apk';</script>" for i in range(20))
    found = find_app_downloads(content(html, url="https://a.top/x/y.html"))
    assert found[0] == "https://a.top/x/pkg0.apk" and len(found) == 8


def test_merge_keeps_order_and_dedupes() -> None:
    assert merge_targets(["a", "b"], ["b", "c"]) == ["a", "b", "c"]
