"""Element provider for the navigation agent (DESIGN §5.5).

The loop calls two functions: `list_elements(page)` and `perform(page, action, elements)`. This is
the plain-Playwright implementation. It lists what a person could click or type into: standard
controls plus non-semantic clickables (`cursor: pointer` or an inline click handler), which is how
H5 app kits build their buttons. Only the main frame is listed (iframes and shadow DOM are not
reached; a known gap).

Page content is untrusted. This module only reads it as data; deciding whether an action is
allowed is policy.py's job."""

import asyncio
from dataclasses import dataclass

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import Page

from scamhunter.models import ActionType, AgentAction

MAX_ELEMENTS = 60  # token bound; elements in view come first
ACTION_TIMEOUT_MS = 5000
ID_ATTRIBUTE = "data-sh-id"  # set by the lister so an id can be turned back into a locator

# One pass over the DOM. Tags each kept element with data-sh-id and returns plain data.
_LIST_JS = r"""
(idAttr) => {
  document.querySelectorAll('[' + idAttr + ']').forEach(e => e.removeAttribute(idAttr));
  const SEMANTIC = 'a[href],button,input:not([type=hidden]),select,textarea,summary,' +
    '[role=button],[role=link],[role=tab],[role=menuitem],[role=checkbox],[role=radio],' +
    '[role=switch],[role=option],[role=combobox],[contenteditable=""],[contenteditable=true]';
  const text = s => (s || '').replace(/\s+/g, ' ').trim().slice(0, 80);
  const vw = window.innerWidth, vh = window.innerHeight;
  const out = [];
  for (const el of document.querySelectorAll('body *')) {
    if (out.length >= 400) break;
    const tag = el.tagName.toLowerCase();
    if (['script', 'style', 'noscript', 'svg', 'path', 'option'].includes(tag)) continue;
    const visible = e => e.checkVisibility({checkOpacity: true, checkVisibilityCSS: true});
    if (!visible(el)) continue;
    if (tag === 'label' && el.control && visible(el.control)) continue;  // the control is listed
    const r = el.getBoundingClientRect();
    if (r.width < 2 || r.height < 2) continue;
    const semantic = el.matches(SEMANTIC);
    const style = getComputedStyle(el);
    let clickableOnly = false;
    if (!semantic) {
      if (el.closest(SEMANTIC)) continue;  // a span inside a button is the button
      const parentPointer = el.parentElement && getComputedStyle(el.parentElement).cursor === 'pointer';
      const handler = el.hasAttribute('onclick') || typeof el.onclick === 'function';
      if (!(handler || (style.cursor === 'pointer' && !parentPointer))) continue;
      clickableOnly = true;
    }
    const cx = r.left + r.width / 2, cy = r.top + r.height / 2;
    const inView = cx >= 0 && cy >= 0 && cx < vw && cy < vh;
    if (inView) {  // skip what a modal or overlay covers
      const hit = document.elementFromPoint(cx, cy);
      const root = hit === document.body || hit === document.documentElement;
      if (!hit || root || !(el.contains(hit) || hit.contains(el))) continue;
    }
    const type = (el.getAttribute('type') || '').toLowerCase();
    let role = el.getAttribute('role') || '';
    if (!role) {
      if (tag === 'a') role = 'link';
      else if (tag === 'select') role = 'combobox';
      else if (tag === 'textarea') role = 'textbox';
      else if (tag === 'input') {
        role = ['checkbox', 'radio'].includes(type) ? type
          : ['button', 'submit', 'reset', 'image'].includes(type) ? 'button' : 'textbox';
      } else if (tag === 'button' || tag === 'summary') role = 'button';
      else role = 'clickable';
    }
    const label = el.labels && el.labels[0] ? text(el.labels[0].innerText) : '';
    const isButtonInput = tag === 'input' && ['button', 'submit', 'reset'].includes(type);
    const name = text(el.getAttribute('aria-label')) || label || text(el.getAttribute('placeholder'))
      || (isButtonInput ? text(el.value) : '') || text(el.innerText) || text(el.getAttribute('title'))
      || text(el.getAttribute('alt')) || text(el.querySelector('img[alt]') && el.querySelector('img[alt]').alt)
      || text(el.getAttribute('name'));
    const isField = ['input', 'textarea'].includes(tag) && !isButtonInput && !['checkbox', 'radio'].includes(type);
    out.push({
      tag, role, name, type, clickable_only: clickableOnly, in_view: inView,
      box: [Math.round(r.left), Math.round(r.top), Math.round(r.width), Math.round(r.height)],
      value: isField && type !== 'password' ? (el.value || '').slice(0, 40) : '',
      filled: isField ? (el.value || '').length > 0 : false,
      checked: ['checkbox', 'radio'].includes(type) ? el.checked : (el.getAttribute('aria-checked') === 'true'),
      disabled: !!el.disabled || el.getAttribute('aria-disabled') === 'true',
      href: tag === 'a' ? (el.href || '') : '',
      options: tag === 'select' ? Array.from(el.options).map(o => text(o.text)).slice(0, 30) : [],
      hints: [el.id, el.getAttribute('name'), el.getAttribute('autocomplete'),
              el.getAttribute('placeholder'), el.getAttribute('aria-label'), label].join(' ').toLowerCase(),
      _el: el,
    });
  }
  out.sort((a, b) => (b.in_view - a.in_view) || (a.box[1] - b.box[1]) || (a.box[0] - b.box[0]));
  return out.slice(0, %MAX%).map((o, i) => {
    o._el.setAttribute(idAttr, String(i + 1));
    delete o._el;
    o.id = i + 1;
    return o;
  });
}
""".replace("%MAX%", str(MAX_ELEMENTS))  # noqa: E501 (JavaScript)


@dataclass(frozen=True)
class Element:
    id: int
    role: str  # button, link, textbox, checkbox, combobox, ... or "clickable" (non-semantic)
    name: str  # accessible name or visible text, at most 80 characters, page-controlled
    box: tuple[int, int, int, int]  # x, y, width, height in viewport pixels (as in a screenshot)
    in_view: bool
    clickable_only: bool  # found by cursor/handler, not by its tag or role
    input_type: str = ""
    value: str = ""  # current text of a text field; never a password
    filled: bool = False
    checked: bool = False
    disabled: bool = False
    href: str = ""
    options: tuple[str, ...] = ()
    hints: str = ""  # id, name, autocomplete, placeholder, label (lowercase): for policy matching

    @property
    def is_text_field(self) -> bool:
        return self.role == "textbox"

    def describe(self) -> str:
        """One line for the model: `[12] button "Deposit"`, `[13] div "充值" (clickable)`."""
        label = self.name.replace('"', "'")
        parts = [f'[{self.id}] {self.role} "{label}"']
        if self.role == "textbox":
            parts.append(
                f"({self.input_type or 'text'}" + (", filled" if self.filled else "") + ")"
            )
        if self.role in {"checkbox", "radio", "switch"}:
            parts.append("(checked)" if self.checked else "(unchecked)")
        if self.options:
            parts.append("options: " + " | ".join(self.options[:8]))
        if self.clickable_only:
            parts.append("(clickable)")
        if self.disabled:
            parts.append("(disabled)")
        if not self.in_view:
            parts.append("(below/above the fold)")
        return " ".join(parts)


@dataclass(frozen=True)
class ActionResult:
    ok: bool
    result: str  # AgentStep.result: "ok", "navigated", "element_not_found", "error: ..."
    detail: str = ""


async def list_elements(page: Page) -> list[Element]:
    try:
        raw = await page.evaluate(_LIST_JS, ID_ATTRIBUTE)
    except PlaywrightError:  # page navigating or closed mid-call
        return []
    return [
        Element(
            id=r["id"],
            role=r["role"],
            name=r["name"],
            box=tuple(r["box"]),
            in_view=r["in_view"],
            clickable_only=r["clickable_only"],
            input_type=r["type"],
            value=r["value"],
            filled=r["filled"],
            checked=r["checked"],
            disabled=r["disabled"],
            href=r["href"],
            options=tuple(r["options"]),
            hints=r["hints"],
        )
        for r in raw
    ]


def _locator(page: Page, element_id: int):
    return page.locator(f'[{ID_ATTRIBUTE}="{element_id}"]').first


async def perform(page: Page, action: AgentAction, elements: list[Element]) -> ActionResult:
    """Run one action the policy already allowed. Never raises on page trouble: a failure is
    returned so the loop can count it as a failed step."""
    before = page.url
    try:
        outcome = await _run(page, action, elements)
    except PlaywrightError as e:
        first_line = str(e).strip().splitlines()[0][:200] if str(e).strip() else "playwright error"
        return ActionResult(False, f"error: {first_line}")
    if outcome.ok and page.url != before:
        return ActionResult(True, "navigated", page.url)
    return outcome


async def _run(page: Page, action: AgentAction, elements: list[Element]) -> ActionResult:
    kind = action.type
    if kind in {ActionType.CLICK, ActionType.FILL, ActionType.SELECT}:
        if not any(e.id == action.element_id for e in elements) or action.element_id is None:
            return ActionResult(False, "element_not_found", f"no element [{action.element_id}]")
        target = _locator(page, action.element_id)
        if await target.count() == 0:  # the page re-rendered since the list was made
            return ActionResult(False, "element_not_found", "element is gone; list again")
        if kind == ActionType.CLICK:
            await target.click(timeout=ACTION_TIMEOUT_MS)
        elif kind == ActionType.FILL:
            await target.fill(action.value or "", timeout=ACTION_TIMEOUT_MS)
        else:
            await target.select_option(label=action.value or "", timeout=ACTION_TIMEOUT_MS)
    elif kind == ActionType.CLICK_AT:
        if action.x is None or action.y is None:
            return ActionResult(False, "error: click_at needs x and y")
        await page.mouse.click(action.x, action.y)
    elif kind == ActionType.PRESS:
        await page.keyboard.press(action.value or "")
    elif kind == ActionType.SCROLL:
        sign = -1 if (action.value or "down") == "up" else 1
        height = page.viewport_size["height"] if page.viewport_size else 800
        await page.mouse.wheel(0, sign * int(height * 0.8))
        await page.wait_for_timeout(300)
    elif kind == ActionType.GOTO:
        await page.goto(action.url or "", wait_until="domcontentloaded")
    elif kind == ActionType.BACK:
        await page.go_back(wait_until="domcontentloaded")
    elif kind == ActionType.WAIT:
        try:
            seconds = float(action.value or 1)
        except ValueError:
            return ActionResult(False, "error: wait needs a number of seconds")
        await asyncio.sleep(min(seconds, 5))
    else:  # check_email and done belong to the loop, not the browser
        return ActionResult(False, f"error: {kind} is not a browser action")
    return ActionResult(True, "ok")
