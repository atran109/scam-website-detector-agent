"""The navigator's fixed tool menu (DESIGN §5.5) and the parsing of its replies.

Parsing only checks that a call is well-formed: right tool, right argument types and ranges. Whether
the action is *allowed* on this page is policy.py's job. Scalar arguments of the model-facing tools
map onto `AgentAction.value` (scroll direction, key, option text, wait seconds)."""

from dataclasses import dataclass
from typing import Any

from scamhunter.models import ActionType, AgentAction, BlockedReason

ALLOWED_KEYS = ("Enter", "Escape", "Tab")
MAX_WAIT_SECONDS = 5
MAX_ARG_CHARS = 300

_RATIONALE = {
    "type": "string",
    "description": "One short sentence: why this action moves toward the goal.",
}
_ELEMENT = {"type": "integer", "description": "Element number from the list."}


def _tool(name: str, description: str, **properties: dict[str, Any]) -> dict[str, Any]:
    required = [k for k in properties if k != "blocked_at"]
    return {
        "name": name,
        "description": description,
        "input_schema": {
            "type": "object",
            "properties": {**properties, "rationale": _RATIONALE},
            "required": [*required, "rationale"],
        },
    }


TOOLS: list[dict[str, Any]] = [
    _tool("click", "Click an element from the list.", element_id=_ELEMENT),
    _tool(
        "click_at",
        "Click screen coordinates. Only when the target is not in the element list "
        "(canvas, odd widgets). Read the position from the screenshot.",
        x={"type": "integer"},
        y={"type": "integer"},
    ),
    _tool(
        "fill",
        "Type into a text field. Use a placeholder such as {identity.email}, "
        "{identity.password}, {identity.username}, {identity.first_name}, "
        "{identity.last_name}; never invent personal data.",
        element_id=_ELEMENT,
        value={"type": "string", "maxLength": MAX_ARG_CHARS},
    ),
    _tool(
        "select",
        "Choose an option in a dropdown by its visible text.",
        element_id=_ELEMENT,
        option={"type": "string", "maxLength": MAX_ARG_CHARS},
    ),
    _tool("press", "Press a key.", key={"type": "string", "enum": list(ALLOWED_KEYS)}),
    _tool("scroll", "Scroll the page.", direction={"type": "string", "enum": ["up", "down"]}),
    _tool("goto", "Open a URL on the same website.", url={"type": "string", "maxLength": 2000}),
    _tool("back", "Go back one page."),
    _tool(
        "wait",
        f"Wait for the page to update (at most {MAX_WAIT_SECONDS} seconds).",
        seconds={"type": "number", "minimum": 0, "maximum": MAX_WAIT_SECONDS},
    ),
    _tool("check_email", "Check the disposable mailbox for a verification code or link."),
    _tool(
        "done",
        "End the run: every deposit option has been tried, or you are blocked.",
        reason={"type": "string", "maxLength": MAX_ARG_CHARS},
        blocked_at={
            "type": "string",
            "enum": [b.value for b in BlockedReason],
            "description": "Set only when a gate stops you.",
        },
    ),
]
TOOL_NAMES = {t["name"] for t in TOOLS}


@dataclass(frozen=True)
class ParsedCall:
    action: AgentAction
    blocked_at: BlockedReason | None = None  # only for `done`
    tool_use_id: str | None = None


@dataclass(frozen=True)
class ToolError:
    """A reply that cannot be run. Counts as a failed step; `message` goes back to the model."""

    message: str
    tool_use_id: str | None = None


def _int(args: dict[str, Any], key: str) -> int | str:
    value = args.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        return f"'{key}' must be an integer"
    return value


def _text(args: dict[str, Any], key: str, required: bool = True) -> str | None:
    value = args.get(key)
    if value is None and not required:
        return None
    if not isinstance(value, str) or (required and not value):
        return f"'{key}' must be a non-empty string"
    if len(value) > MAX_ARG_CHARS and key != "url":
        return f"'{key}' is too long (max {MAX_ARG_CHARS} characters)"
    return None


def _build(name: str, args: dict[str, Any]) -> AgentAction | str:
    """The action for a call, or a string describing what is wrong with the arguments."""
    rationale = args.get("rationale")
    base: dict[str, Any] = {"rationale": rationale if isinstance(rationale, str) else ""}
    if name in {"click", "fill", "select"}:
        element_id = _int(args, "element_id")
        if isinstance(element_id, str):
            return element_id
        base["element_id"] = element_id
    if name == "click_at":
        for axis in ("x", "y"):
            coordinate = _int(args, axis)
            if isinstance(coordinate, str):
                return coordinate
            base[axis] = coordinate
    if name == "fill":
        if bad := _text(args, "value"):
            return bad
        base["value"] = args["value"]
    if name == "select":
        if bad := _text(args, "option"):
            return bad
        base["value"] = args["option"]
    if name == "press":
        if args.get("key") not in ALLOWED_KEYS:
            return f"'key' must be one of {', '.join(ALLOWED_KEYS)}"
        base["value"] = args["key"]
    if name == "scroll":
        if args.get("direction") not in {"up", "down"}:
            return "'direction' must be 'up' or 'down'"
        base["value"] = args["direction"]
    if name == "goto":
        if bad := _text(args, "url"):
            return bad
        base["url"] = args["url"]
    if name == "wait":
        seconds = args.get("seconds")
        if isinstance(seconds, bool) or not isinstance(seconds, int | float):
            return "'seconds' must be a number"
        if not 0 <= seconds <= MAX_WAIT_SECONDS:
            return f"'seconds' must be between 0 and {MAX_WAIT_SECONDS}"
        base["value"] = str(seconds)
    if name == "done":
        if bad := _text(args, "reason"):
            return bad
        base["rationale"] = args["reason"]
    return AgentAction(type=ActionType(name), **base)


def parse_tool_call(name: str, args: Any, tool_use_id: str | None = None) -> ParsedCall | ToolError:
    if name not in TOOL_NAMES:
        return ToolError(
            f"unknown tool '{name}'; use one of: {', '.join(sorted(TOOL_NAMES))}", tool_use_id
        )
    if not isinstance(args, dict):
        return ToolError("tool arguments must be an object", tool_use_id)
    built = _build(name, args)
    if isinstance(built, str):
        return ToolError(f"bad arguments for {name}: {built}", tool_use_id)
    blocked_at = None
    if name == "done" and args.get("blocked_at") is not None:
        try:
            blocked_at = BlockedReason(args["blocked_at"])
        except ValueError:
            return ToolError("bad arguments for done: unknown 'blocked_at'", tool_use_id)
    return ParsedCall(built, blocked_at, tool_use_id)


def pick_tool_call(content: list[dict[str, Any]]) -> ParsedCall | ToolError:
    """The call to run from a model reply (the content blocks of an LLMResponse).

    A reply with text and no tool call is a failed step (DESIGN §5.5, decided 2026-10-05): the
    loop counts it toward `max_consecutive_failures`. If the model sent several calls, only the
    first runs; the page changes after each action, so later calls would act on a stale view."""
    for block in content:
        if block.get("type") == "tool_use":
            return parse_tool_call(block.get("name", ""), block.get("input"), block.get("id"))
    return ToolError("no tool call in the reply; call exactly one tool")
