"""Tool menu and reply parsing."""

import pytest

from scamhunter.agent.tools import (
    TOOL_NAMES,
    TOOLS,
    ParsedCall,
    ToolError,
    calls_after,
    parse_tool_call,
    pick_tool_calls,
)
from scamhunter.models import ActionType, BlockedReason


def test_menu_matches_design() -> None:
    assert TOOL_NAMES == {
        "click",
        "click_at",
        "fill",
        "select",
        "press",
        "scroll",
        "goto",
        "back",
        "wait",
        "check_email",
        "done",
    }
    for tool in TOOLS:
        schema = tool["input_schema"]
        assert schema["type"] == "object" and "rationale" in schema["required"]
        assert set(schema["required"]) <= set(schema["properties"])


@pytest.mark.parametrize(
    ("name", "args", "kind", "field", "expected"),
    [
        ("click", {"element_id": 3, "rationale": "r"}, ActionType.CLICK, "element_id", 3),
        ("click_at", {"x": 10, "y": 20, "rationale": "r"}, ActionType.CLICK_AT, "y", 20),
        (
            "fill",
            {"element_id": 1, "value": "{identity.email}", "rationale": "r"},
            ActionType.FILL,
            "value",
            "{identity.email}",
        ),
        (
            "select",
            {"element_id": 1, "option": "TRC20", "rationale": "r"},
            ActionType.SELECT,
            "value",
            "TRC20",
        ),
        ("press", {"key": "Enter", "rationale": "r"}, ActionType.PRESS, "value", "Enter"),
        ("scroll", {"direction": "up", "rationale": "r"}, ActionType.SCROLL, "value", "up"),
        (
            "goto",
            {"url": "https://a.test/x", "rationale": "r"},
            ActionType.GOTO,
            "url",
            "https://a.test/x",
        ),
        ("wait", {"seconds": 2, "rationale": "r"}, ActionType.WAIT, "value", "2"),
        ("back", {"rationale": "r"}, ActionType.BACK, "rationale", "r"),
        ("check_email", {"rationale": "r"}, ActionType.CHECK_EMAIL, "rationale", "r"),
    ],
)
def test_valid_calls(name: str, args: dict, kind: ActionType, field: str, expected) -> None:
    call = parse_tool_call(name, args, "toolu_1")
    assert isinstance(call, ParsedCall) and call.tool_use_id == "toolu_1"
    assert call.action.type == kind and getattr(call.action, field) == expected


def test_done_carries_reason_and_blocked_at() -> None:
    call = parse_tool_call("done", {"reason": "needs a wallet", "blocked_at": "wallet_required"})
    assert isinstance(call, ParsedCall)
    assert call.action.type == ActionType.DONE and call.action.rationale == "needs a wallet"
    assert call.blocked_at == BlockedReason.WALLET_REQUIRED
    assert parse_tool_call("done", {"reason": "all tried"}).blocked_at is None  # type: ignore[union-attr]


@pytest.mark.parametrize(
    ("name", "args"),
    [
        ("rm_rf", {}),
        ("click", {}),
        ("click", {"element_id": "3"}),
        ("click", {"element_id": True}),
        ("click", {"element_id": 3.5}),
        ("click_at", {"x": 1}),
        ("fill", {"element_id": 1}),
        ("fill", {"element_id": 1, "value": "x" * 301}),
        ("select", {"element_id": 1}),
        ("press", {"key": "F12"}),
        ("press", {"key": "Control+C"}),
        ("scroll", {"direction": "left"}),
        ("goto", {}),
        ("wait", {"seconds": 6}),
        ("wait", {"seconds": -1}),
        ("wait", {"seconds": "2"}),
        ("done", {}),
        ("done", {"reason": "x", "blocked_at": "because"}),
        ("click", "element 3"),
    ],
)
def test_malformed_calls_are_tool_errors(name: str, args) -> None:
    result = parse_tool_call(name, args, "toolu_9")
    assert isinstance(result, ToolError) and result.tool_use_id == "toolu_9" and result.message


def test_text_only_reply_is_a_failed_step() -> None:
    [result] = pick_tool_calls([{"type": "text", "text": "I will now click Register."}])
    assert isinstance(result, ToolError) and "no tool call" in result.message
    assert isinstance(pick_tool_calls([])[0], ToolError)


def _use(id: str, name: str, **args) -> dict:
    return {"type": "tool_use", "id": id, "name": name, "input": {"rationale": "r", **args}}


def test_a_non_fill_action_ends_the_batch_and_text_is_ignored() -> None:
    content = [
        {"type": "text", "text": "thinking"},
        _use("a", "back"),
        _use("b", "click", element_id=1),
    ]
    assert [c.tool_use_id for c in pick_tool_calls(content)] == ["a"]


def test_fills_and_selects_batch_up_to_one_click() -> None:
    content = [
        _use("a", "fill", element_id=1, value="{identity.email}"),
        _use("b", "select", element_id=2, option="USDT"),
        _use("c", "fill", element_id=3, value="{identity.password}"),
        _use("d", "click", element_id=4),
        _use("e", "click", element_id=5),
    ]
    batch = pick_tool_calls(content)
    assert [c.tool_use_id for c in batch] == ["a", "b", "c", "d"]
    assert all(isinstance(c, ParsedCall) for c in batch)


def test_a_malformed_call_ends_the_batch() -> None:
    content = [
        _use("a", "fill", element_id=1, value="x"),
        _use("b", "fill", element_id="one", value="y"),
        _use("c", "click", element_id=4),
    ]
    batch = pick_tool_calls(content)
    assert isinstance(batch[0], ParsedCall) and isinstance(batch[1], ToolError)
    assert len(batch) == 2


def test_calls_after_the_batch_are_listed_as_not_run() -> None:
    content = [
        _use("a", "fill", element_id=1, value="{identity.email}"),
        _use("b", "click", element_id=4),
        _use("c", "click", element_id=5),
        _use("d", "fill", element_id=6, value="x"),
    ]
    batch = pick_tool_calls(content)
    assert calls_after(content, batch) == ["click(element_id=5)", "fill(element_id=6, value='x')"]
    assert calls_after([{"type": "text", "text": "hi"}], pick_tool_calls([])) == []
