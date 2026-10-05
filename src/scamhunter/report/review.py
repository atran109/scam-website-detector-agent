"""Read-only review page for a saved run: one card per site, built from saved evidence only.

Everything shown comes from checkpoint.jsonl and the saved screenshots; nothing is fetched and
no site is visited. Page text and LLM output are hostile, so every string is HTML-escaped, the
page has no JavaScript, iframes or external references, and it never embeds or links saved page
HTML, traces or network bodies.
"""

import csv
import html
import os
from pathlib import Path
from urllib.parse import quote

from scamhunter.browser.capture import load_snapshots
from scamhunter.llm.sanitize import strip_control
from scamhunter.models import CryptoAddress, SiteResult

BORDERLINE_BAND = 0.15  # |probability − scam_threshold| within this goes first, closest first
CSP = "default-src 'none'; img-src 'self'; style-src 'self'"
MAX_REASONING = 1200
MAX_EVIDENCE_ITEM = 300
MAX_NOTE = 300
MAX_URL = 200
MAX_ITEMS = 8

STYLE = """\
body { font: 15px/1.45 system-ui, sans-serif; margin: 0; background: #f4f4f6; color: #1c1c20; }
header { padding: 16px 24px; background: #1c1c20; color: #fff; }
header p { margin: 4px 0 0; color: #bbb; }
main { max-width: 1100px; margin: 0 auto; padding: 16px; }
h2.group { margin: 24px 0 8px; font-size: 16px; color: #555; }
.card { background: #fff; border: 1px solid #d8d8de; border-radius: 8px; margin: 12px 0;
        padding: 14px 16px; display: grid; grid-template-columns: 1fr 360px; gap: 16px; }
.card h3 { margin: 0 0 6px; font-size: 16px; overflow-wrap: anywhere; }
.verdict-scam { color: #b3261e; font-weight: 600; }
.verdict-not_scam { color: #1b6e3c; font-weight: 600; }
.meta span { display: inline-block; margin-right: 14px; color: #444; }
.meta b { color: #777; font-weight: 500; }
ul { margin: 4px 0 8px; padding-left: 20px; }
code { font: 12.5px ui-monospace, monospace; overflow-wrap: anywhere; }
.label { font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: #777;
         margin-top: 10px; }
.note { color: #7a5200; }
img { max-width: 100%; border: 1px solid #ccc; border-radius: 4px; }
.noshot { color: #888; font-style: italic; }
@media (max-width: 800px) { .card { grid-template-columns: 1fr; } }
"""


def clip(text: str, limit: int) -> str:
    """Strip hidden characters and truncate with an explicit marker."""
    text = strip_control(text)
    if len(text) <= limit:
        return text
    return f"{text[:limit]} … [truncated {len(text) - limit} more characters]"


def esc(text: str, limit: int) -> str:
    return html.escape(clip(text, limit), quote=True)


def order_results(results: list[SiteResult], threshold: float) -> list[SiteResult]:
    """Borderline first (closest to the threshold), then the rest by site id."""

    def distance(r: SiteResult) -> float:
        return abs(r.classification.scam_probability - threshold)

    borderline = sorted(
        (r for r in results if distance(r) <= BORDERLINE_BAND),
        key=lambda r: (distance(r), r.site.site_id),
    )
    rest = sorted(
        (r for r in results if distance(r) > BORDERLINE_BAND), key=lambda r: r.site.site_id
    )
    return borderline + rest


def screenshot_src(result: SiteResult, run_dir: Path, review_dir: Path) -> str | None:
    """Relative URL from review/ to the site's most recent saved screenshot, if any.
    Only PNGs under the run's sites/ folder are ever referenced."""
    sites_root = (run_dir / "sites").resolve()
    for snap in reversed(load_snapshots(run_dir / "sites" / result.site.site_id)):
        if not snap.screenshot_path:
            continue
        path = (run_dir / snap.screenshot_path).resolve()
        if path.suffix == ".png" and path.is_file() and sites_root in path.parents:
            return quote(os.path.relpath(path, review_dir.resolve()).replace(os.sep, "/"))
    return None


def _address_li(address: CryptoAddress) -> str:
    labels = (
        ", ".join(
            f"{lab.asset.value}/{lab.network.value} {lab.confidence:.2f}"
            for lab in address.labels[:3]
        )
        or "no label"
    )
    return (
        f"<li><code>{esc(address.address, 120)}</code> "
        f"[{esc(address.tier.value, 20)}, {esc(address.format.value, 20)}] "
        f"{esc(labels, 200)}</li>"
    )


def _list(items: list[str]) -> str:
    return "<ul>" + "".join(f"<li>{i}</li>" for i in items) + "</ul>" if items else ""


def card(result: SiteResult, run_dir: Path, review_dir: Path, threshold: float) -> str:
    c = result.classification
    judgment = c.judgment
    evidence = [esc(e, MAX_EVIDENCE_ITEM) for e in (judgment.key_evidence if judgment else [])]
    signals = [
        f"{esc(s.name, 80)} <small>[{esc(s.tier.value, 12)}] {esc(s.evidence, 160)}</small>"
        for s in sorted(c.signals, key=lambda s: -s.weight)
        if s.weight > 0
    ][:MAX_ITEMS]
    addresses = (result.addresses + result.low_confidence_addresses + result.other_addresses)[
        :MAX_ITEMS
    ]
    notes = [esc(n, MAX_NOTE) for n in result.notes[:MAX_ITEMS]]
    shot = screenshot_src(result, run_dir, review_dir)
    image = (
        f'<img src="{html.escape(shot, quote=True)}" alt="screenshot of site '
        f'{esc(result.site.site_id, 10)}">'
        if shot
        else '<p class="noshot">no screenshot saved</p>'
    )
    verdict = c.verdict.value
    scam_type = c.scam_type.value if c.scam_type else "–"
    return f"""\
<section class="card" id="site-{esc(result.site.site_id, 10)}">
<div>
<h3>{esc(result.site.site_id, 10)} · {esc(result.site.url, MAX_URL)}</h3>
<div class="meta">
<span><b>status</b> {esc(result.triage.status.value, 30)}</span>
<span><b>verdict</b> <span class="verdict-{esc(verdict, 20)}">{esc(verdict, 20)}</span></span>
<span><b>probability</b> {c.scam_probability:.2f} <small>(threshold {threshold:.2f})</small></span>
<span><b>confidence</b> {c.confidence:.2f}</span>
<span><b>type</b> {esc(scam_type, 30)}</span>
<span><b>basis</b> {esc(c.evidence_source.value, 20)} / {esc(c.method, 30)}</span>
</div>
<div class="label">Reasoning</div>
<p>{esc(c.reasoning, MAX_REASONING)}</p>
{'<div class="label">Quoted evidence</div>' + _list(evidence) if evidence else ""}
{'<div class="label">Top signals</div>' + _list(signals) if signals else ""}
{
        '<div class="label">Addresses</div><ul>'
        + "".join(_address_li(a) for a in addresses)
        + "</ul>"
        if addresses
        else ""
    }
{'<div class="label note">Notes</div>' + _list(notes) if notes else ""}
</div>
<div>{image}</div>
</section>"""


def render_index(
    results: list[SiteResult], run_id: str, run_dir: Path, review_dir: Path, threshold: float
) -> str:
    ordered = order_results(results, threshold)
    n_border = sum(
        1 for r in ordered if abs(r.classification.scam_probability - threshold) <= BORDERLINE_BAND
    )
    cards, seen_rest = [], False
    for i, result in enumerate(ordered):
        if i == 0 and n_border:
            cards.append(
                f'<h2 class="group">Borderline: within {BORDERLINE_BAND:.2f} of the '
                f"{threshold:.2f} threshold, closest first</h2>"
            )
        if i == n_border and not seen_rest:
            seen_rest = True
            cards.append('<h2 class="group">All other sites, by site id</h2>')
        cards.append(card(result, run_dir, review_dir, threshold))
    return f"""\
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{CSP}">
<title>Review: {esc(run_id, 80)}</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<header><h1>Run {esc(run_id, 80)}: {len(ordered)} sites</h1>
<p>Read-only view of saved evidence. Page text below is untrusted and shown escaped.</p></header>
<main>
{chr(10).join(cards)}
</main>
</body>
</html>
"""


def write_review(results: list[SiteResult], run_id: str, run_dir: Path, threshold: float) -> Path:
    """Write review/index.html, review/style.css and review/labels_template.csv in the run dir."""
    review_dir = run_dir / "review"
    review_dir.mkdir(parents=True, exist_ok=True)
    (review_dir / "style.css").write_text(STYLE)
    (review_dir / "index.html").write_text(
        render_index(results, run_id, run_dir, review_dir, threshold)
    )
    with (review_dir / "labels_template.csv").open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            ["site_id", "url", "my_label", "my_notes", "pipeline_verdict", "pipeline_probability"]
        )
        for r in sorted(results, key=lambda r: r.site.site_id):
            writer.writerow(
                [
                    r.site.site_id,
                    r.site.url,
                    "",
                    "",
                    r.classification.verdict.value,
                    f"{r.classification.scam_probability:.3f}",
                ]
            )
    return review_dir / "index.html"
