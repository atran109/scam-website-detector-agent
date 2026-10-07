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


def test_rendered_parking_page_takes_dead_site_path(tmp_path: Path) -> None:
    """#004 adnins.cloud: HTTP triage said 'live' (a JS redirect stub); the saved rendered page
    is ParkLogic's. analyze() must flip the status to parked and use the dead-site rule, without
    calling the LLM (ctx.llm is None here, so any call would raise)."""
    import asyncio
    from datetime import UTC, datetime

    from scamhunter.config import load_settings
    from scamhunter.models import (
        DiscoveryStage,
        EvidenceSource,
        PageSnapshot,
        Site,
        SiteStatus,
        TriageResult,
    )
    from scamhunter.pipeline import RunContext, analyze

    snap_dir = tmp_path / "sites" / "004" / "snapshots" / "s01"
    snap_dir.mkdir(parents=True)
    fixture = Path(__file__).parent / "fixtures" / "pilot_texts" / "004.html"
    (snap_dir / "page.html").write_text(fixture.read_text())
    (snap_dir / "text.txt").write_text("This page has been created by ParkLogic.\n")
    snapshot = PageSnapshot(
        snapshot_id="s01",
        stage=DiscoveryStage.LANDING,
        url="https://adnins.cloud/",
        title="",
        taken_at=datetime.now(UTC),
        html_path="sites/004/snapshots/s01/page.html",
        visible_text="",
        a11y_tree_path="",
        screenshot_path="",
        network=[],
    )
    site = Site(
        site_id="004",
        url="https://adnins.cloud",
        host="adnins.cloud",
        registrable_domain="adnins.cloud",
    )
    triage = TriageResult(status=SiteStatus.LIVE, elapsed_ms=1, reason="SPA shell")
    ctx = RunContext(settings=load_settings(), run_dir=tmp_path, llm=None)  # type: ignore[arg-type]

    analysis = asyncio.run(analyze(ctx, site, triage, [snapshot]))

    assert analysis.triage is not None and analysis.triage.status == SiteStatus.PARKED
    assert analysis.classification.evidence_source in (
        EvidenceSource.SIGNALS_ONLY,
        EvidenceSource.NONE,
    )
    assert analysis.classification.method == "status_rule"
    assert any("parking page" in n for n in analysis.notes)
