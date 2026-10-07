"""Contact sheet of the live sites the tally called "unclear", for hand review (no visits).

One HTML grid under runs/<id>/contact_sheet/. Each cell: screenshot(s), site ID, word count
(whitespace-split, as the tally counts; CJK text counts low, so characters are shown too), title
and the landing snapshot's final URL. Empty pages (at most one word) come first, then the rest
by word count. Everything from a page is HTML-escaped and the sheet carries a CSP with no script.
Usage: python eval/contact_sheet.py runs/capture-2 --triage runs/triage-1/triage.jsonl
Open runs/<id>/contact_sheet/index.html from that folder (images are relative links)."""

import argparse
import html
import os
from pathlib import Path

from live_tally import live_site_ids, tally_run

from scamhunter.browser.capture import load_snapshot_content, load_snapshots

EMPTY_WORDS = 1
CSS = """body{font:14px system-ui,sans-serif;margin:16px;background:#fafafa;color:#111}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:14px}
.cell{background:#fff;border:1px solid #ccc;border-radius:6px;padding:8px;overflow:hidden}
.shots{display:flex;gap:6px}.shots a{flex:1;min-width:0}
.shots img{width:100%;height:260px;object-fit:cover;object-position:top;
border:1px solid #ddd;display:block}
.id{font-weight:700;font-size:16px}.meta{color:#444}.url{word-break:break-all;font-size:12px}
.empty{border-color:#c33}h2{margin:18px 0 8px}"""


def _cell(run_dir: Path, site_id: str) -> tuple[int, str]:
    snaps = load_snapshots(run_dir / "sites" / site_id)
    text = load_snapshot_content(snaps[0], run_dir).visible_text
    words, chars = len(text.split()), len("".join(text.split()))
    shots = []
    for s in snaps:
        if s.screenshot_path:
            label = "desktop" if s is snaps[0] else "mobile retry"
            rel = os.path.relpath(run_dir / s.screenshot_path, run_dir / "contact_sheet")
            shots.append(
                f'<a href="{html.escape(rel)}"><img loading="lazy" src="{html.escape(rel)}" '
                f'alt="{html.escape(site_id)} {label}" title="{label}"></a>'
            )
    last = snaps[-1]
    page = (
        f'<div class="cell{" empty" if words <= EMPTY_WORDS else ""}">'
        f'<div class="shots">{"".join(shots)}</div>'
        f'<div><span class="id">{html.escape(site_id)}</span> '
        f'<span class="meta">{words} words · {chars} chars · {len(snaps)} snapshot(s)</span></div>'
        f'<div class="meta">title: {html.escape(snaps[0].title or "(none)")}</div>'
        f'<div class="url">{html.escape(last.url)}</div></div>'
    )
    return words, page


def build(run_dir: Path, triage: Path) -> Path:
    live = live_site_ids(triage)
    ids = [t.site_id for t in tally_run(run_dir) if t.bucket == "unclear" and t.site_id in live]
    cells = sorted((_cell(run_dir, i) + (i,) for i in ids), key=lambda c: (c[0], c[2]))
    empty = [c[1] for c in cells if c[0] <= EMPTY_WORDS]
    rest = [c[1] for c in cells if c[0] > EMPTY_WORDS]
    out = run_dir / "contact_sheet"
    out.mkdir(exist_ok=True)
    csp = "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'"
    (out / "index.html").write_text(
        f'<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" '
        f'content="{csp}"><title>Unclear sites</title><style>{CSS}</style>'
        f"<h1>Unclear live sites ({len(ids)})</h1>"
        f'<h2>Empty pages ({len(empty)})</h2><div class="grid">{"".join(empty)}</div>'
        f'<h2>Others, fewest words first ({len(rest)})</h2><div class="grid">{"".join(rest)}</div>'
    )
    return out / "index.html"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--triage", type=Path, required=True)
    args = parser.parse_args()
    print(build(args.run_dir, args.triage))


if __name__ == "__main__":
    main()
