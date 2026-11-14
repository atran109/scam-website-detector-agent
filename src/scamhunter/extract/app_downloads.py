"""App-download targets a page points at: Android packages, iOS profiles and apps, store links.

Evidence for investigators, found in the page's HTML, scripts and network responses and never
fetched (downloads stay blocked). Pilot site 117 is an app-download landing page whose
`config.js` says `apkName = 'BTCC.apk'` and `iPhoneName = 'BTCC.mobileconfig'`: the deposit flow
lives inside the app, and the file name and host are the only web-visible traces
(LOG 2026-10-07)."""

import re
from urllib.parse import urljoin

from scamhunter.extract.extractor import SnapshotContent

MAX_TARGETS = 8
_EXT = r"(?:apk|xapk|aab|ipa|mobileconfig)"
# A quoted string that ends in an app-file extension: relative names in scripts and configs.
_QUOTED = re.compile(rf"""['"]([^'"\s<>\\]{{1,200}}?\.{_EXT})(?:\?[^'"\s<>\\]*)?['"]""", re.I)
_ABSOLUTE = re.compile(rf"""https?://[^\s'"<>\\]+?\.{_EXT}(?:\?[^\s'"<>\\]*)?""", re.I)
_ITMS = re.compile(r"""itms-services://\?[^\s'"<>\\]+""", re.I)
_STORE = re.compile(
    r"""https?://(?:apps\.apple\.com/[^\s'"<>\\]+|play\.google\.com/store/apps/details\?id=[^\s'"<>\\&]+"""
    r"""|testflight\.apple\.com/join/[A-Za-z0-9]+|appgallery\.huawei\.com/[^\s'"<>\\]+)""",
    re.I,
)


def find_app_downloads(content: SnapshotContent) -> list[str]:
    """Absolute URLs of app files and store pages the snapshot refers to, first seen first."""
    sources = [content.html, *(body.text for body in content.network)]
    found: list[str] = []

    def add(url: str) -> None:
        url = url.rstrip(".,;)")
        if url not in found:
            found.append(url)

    for text in sources:
        for pattern in (_ABSOLUTE, _ITMS, _STORE):
            for m in pattern.finditer(text):
                add(m.group(0))
        for m in _QUOTED.finditer(text):
            name = m.group(1)
            if "://" in name:
                continue  # already taken whole by _ABSOLUTE
            add(urljoin(content.page_url, name))
    return found[:MAX_TARGETS]


def merge_targets(*groups: list[str]) -> list[str]:
    merged: list[str] = []
    for group in groups:
        for url in group:
            if url not in merged:
                merged.append(url)
    return merged[:MAX_TARGETS]
