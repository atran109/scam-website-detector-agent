"""Highlight address bounding boxes on screenshots."""

from pathlib import Path

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import Page

from scamhunter.browser.capture import safe_screenshot

HIGHLIGHT_ID = "__scamhunter_highlight"

# Finds the address in a text node or form field, draws a red box over it, scrolls it into
# view and returns its page-coordinate box [x, y, w, h] (or null if not rendered).
_HIGHLIGHT_JS = """
([address, id]) => {
  const targets = [];  // [range-or-element, element to scroll to]
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  for (let node; (node = walker.nextNode()); ) {
    const i = node.textContent.indexOf(address);
    if (i < 0) continue;
    const range = document.createRange();
    range.setStart(node, i);
    range.setEnd(node, i + address.length);
    targets.push([range, node.parentElement]);
  }
  for (const el of document.querySelectorAll("input, textarea")) {
    if ((el.value || "").includes(address)) targets.push([el, el]);
  }
  // First occurrence that is really visible on screen after scrolling to it: elements in
  // hidden panels (opacity 0, off-screen transforms) would give an empty, misleading shot.
  let r = null;
  for (const [t, el] of targets) {
    if (el.checkVisibility && !el.checkVisibility({ opacityProperty: true,
                                                     visibilityProperty: true })) continue;
    el.scrollIntoView({ block: "center" });
    const rect = t.getBoundingClientRect();  // measured after scrolling
    const inView = rect.width > 0 && rect.height > 0 && rect.bottom > 0 && rect.right > 0
                   && rect.top < innerHeight && rect.left < innerWidth;
    if (inView) { r = rect; break; }
  }
  if (!r) return null;
  const box = [Math.round(r.left + scrollX), Math.round(r.top + scrollY),
               Math.round(r.width), Math.round(r.height)];
  const div = document.createElement("div");
  div.id = id;
  Object.assign(div.style, {
    position: "absolute", left: (box[0] - 4) + "px", top: (box[1] - 4) + "px",
    width: (box[2] + 8) + "px", height: (box[3] + 8) + "px", border: "3px solid red",
    zIndex: "2147483647", pointerEvents: "none", boxSizing: "border-box",
  });
  document.body.appendChild(div);
  return box;
}
"""
_REMOVE_JS = "(id) => document.getElementById(id)?.remove()"


async def highlight_address(
    page: Page, address: str, out_path: Path
) -> tuple[int, int, int, int] | None:
    """Screenshot the viewport with `address` boxed in red. None if it isn't rendered as text
    (e.g. only in a network response); the caller keeps the plain snapshot screenshot."""
    try:
        box = await page.evaluate(_HIGHLIGHT_JS, [address, HIGHLIGHT_ID])
        if not box:
            return None
        png = await safe_screenshot(page, full_page=False)
        await page.evaluate(_REMOVE_JS, HIGHLIGHT_ID)
        if not png:
            return None
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(png)
        return (box[0], box[1], box[2], box[3])
    except PlaywrightError:
        return None
