"""LLM gateway service: the only process holding the API key (DESIGN §5.6, Secrets layer).

Runs in its own container on the internal network. The crawler POSTs a constrained request;
the gateway picks the model from the caller's role, validates the request against a
whitelist, answers from its response cache when it can, calls the Claude API through the
egress proxy (which only lets it reach api.anthropic.com), and logs token usage. A
compromised crawler can spend through it, bounded by the console spend limit, but can't read
the key or use server-side tools as an egress channel.
"""

import hashlib
import json
import logging
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Literal

import anthropic
from anthropic import DefaultHttpxClient
from pydantic import BaseModel, ConfigDict, ValidationError

from scamhunter.config import Settings, load_settings

log = logging.getLogger("llm-gateway")

MAX_TOKENS_CAP = 16_000
# Per-request API timeout (seconds) and SDK retries by role. A navigator step normally answers
# in ~4 s; one request hung ~10 min on the SDK's 600 s default (2026-10-06), so navigator calls
# fail fast and the agent loop counts a failed step instead of waiting.
REQUEST_LIMITS = {
    "navigator": (60.0, 2),
    "judge": (300.0, 3),
    "helper": (120.0, 3),
    "labeller": (300.0, 3),  # dataset labelling pass (DESIGN §8.4); same rules as the judge
}
FALLBACK_BETA = "server-side-fallback-2026-07-01"
# Models that accept fallbacks="default" (refusal re-run server-side); Haiku 4.5 does not.
FALLBACK_MODELS = ("claude-sonnet-5-5", "claude-opus-5-5")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class MessagesRequest(_Strict):
    """The subset of Messages API parameters the crawler may send. No model (chosen by role),
    no server tools, MCP servers, containers or betas."""

    system: str | list[dict[str, Any]] | None = None
    messages: list[dict[str, Any]]
    max_tokens: int
    output_config: dict[str, Any] | None = None
    tools: list[dict[str, Any]] | None = None
    tool_choice: dict[str, Any] | None = None


class GatewayRequest(_Strict):
    role: Literal["judge", "helper", "navigator", "labeller"]
    site_id: str
    purpose: str
    request: MessagesRequest
    cache: bool = True  # False: skip the response cache (independent repeats in evaluation)


def validate_request(body: dict[str, Any]) -> GatewayRequest:
    """Parse and enforce the whitelist; raises ValueError with a reason on violation."""
    try:
        req = GatewayRequest.model_validate(body)
    except ValidationError as exc:
        raise ValueError(f"invalid request: {exc.errors()[0]['msg']}") from exc
    if not 1 <= req.request.max_tokens <= MAX_TOKENS_CAP:
        raise ValueError(f"max_tokens must be 1..{MAX_TOKENS_CAP}")
    for tool in req.request.tools or []:
        # Client tools only: a tool with a "type" (web_fetch, code_execution, …) runs on
        # Anthropic's side and could reach the internet on the crawler's behalf.
        if "type" in tool and tool["type"] != "custom":
            raise ValueError(f"server tool not allowed: {tool.get('type')}")
        if "input_schema" not in tool:
            raise ValueError("tools must be client tools with an input_schema")
    allowed_output = {"format", "effort"}
    if extra := set(req.request.output_config or {}) - allowed_output:
        raise ValueError(f"output_config keys not allowed: {sorted(extra)}")
    return req


def cache_key(model: str, request: MessagesRequest) -> str:
    canonical = json.dumps(
        {"model": model, **request.model_dump(exclude_none=True)},
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def role_models(settings: Settings) -> dict[str, str]:
    """The model each role is served by. Callers name a role, never a model."""
    return {
        "judge": settings.llm.judge_model,
        "helper": settings.llm.helper_model,
        "navigator": settings.llm.navigator_model,
        "labeller": settings.llm.labeller_model,
    }


class Gateway:
    def __init__(self, cache_dir: Path) -> None:
        settings = load_settings()
        self.models = role_models(settings)
        self.cache_enabled = settings.llm.cache_responses
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.usage_log = cache_dir / "usage.jsonl"
        self._lock = threading.Lock()
        # Only route out: the egress proxy's LLM port, which allows api.anthropic.com only.
        self.client = anthropic.Anthropic(
            http_client=DefaultHttpxClient(proxy=os.environ["ANTHROPIC_PROXY"]),
            max_retries=3,
        )

    def handle(self, body: dict[str, Any]) -> dict[str, Any]:
        req = validate_request(body)
        model = self.models[req.role]
        key = cache_key(model, req.request)
        cached_path = self.cache_dir / f"{key}.json"
        use_cache = self.cache_enabled and req.cache
        if use_cache and cached_path.exists():
            result = json.loads(cached_path.read_text())
            self._log_usage(req, model, result["usage"], cached=True)
            return {**result, "cached": True}

        params = req.request.model_dump(exclude_none=True)
        timeout, retries = REQUEST_LIMITS[req.role]
        client = self.client.with_options(timeout=timeout, max_retries=retries)
        if model in FALLBACK_MODELS:
            response = client.beta.messages.create(
                model=model, betas=[FALLBACK_BETA], fallbacks="default", **params
            )
        else:
            response = client.messages.create(model=model, **params)
        result = {
            "ok": True,
            "model": response.model,
            "stop_reason": response.stop_reason,
            "content": [block.to_dict() for block in response.content],
            "usage": {
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
                "cache_read_input_tokens": response.usage.cache_read_input_tokens or 0,
                "cache_creation_input_tokens": response.usage.cache_creation_input_tokens or 0,
            },
            "request_id": response._request_id,
        }
        # Refusals aren't cached: a later run may get through (or route via fallback).
        if use_cache and response.stop_reason != "refusal":
            cached_path.write_text(json.dumps(result))
        self._log_usage(req, model, result["usage"], cached=False)
        return {**result, "cached": False}

    def _log_usage(self, req: GatewayRequest, model: str, usage: dict, cached: bool) -> None:
        entry = {
            "site_id": req.site_id,
            "purpose": req.purpose,
            "role": req.role,
            "model": model,
            "cached": cached,
            **usage,
        }
        with self._lock, self.usage_log.open("a") as f:
            f.write(json.dumps(entry) + "\n")


def _make_handler(gateway: Gateway) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - http.server API
            if self.path != "/v1/messages":
                return self._send(404, {"ok": False, "error": "not found", "retryable": False})
            try:
                length = int(self.headers.get("content-length", 0))
                if length > 20_000_000:
                    raise ValueError("request too large")
                body = json.loads(self.rfile.read(length))
                self._send(200, gateway.handle(body))
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc), "retryable": False})
            except anthropic.RateLimitError as exc:
                self._send(
                    503, {"ok": False, "error": f"rate limited: {exc.message}", "retryable": True}
                )
            except anthropic.APIStatusError as exc:
                self._send(
                    502,
                    {
                        "ok": False,
                        "error": f"API {exc.status_code}: {exc.message}",
                        "retryable": exc.status_code >= 500,
                    },
                )
            except anthropic.APITimeoutError:
                self._send(504, {"ok": False, "error": "API timeout", "retryable": False})
            except anthropic.APIConnectionError:
                self._send(502, {"ok": False, "error": "API connection error", "retryable": True})

        def do_GET(self) -> None:  # noqa: N802
            self._send(200 if self.path == "/health" else 404, {"ok": self.path == "/health"})

        def _send(self, status: int, payload: dict) -> None:
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, fmt: str, *args: Any) -> None:  # no request bodies in logs
            log.info("%s %s", self.address_string(), fmt % args)

    return Handler


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise SystemExit("ANTHROPIC_API_KEY missing: create .env from .env.example")
    gateway = Gateway(Path(os.environ.get("LLM_CACHE_DIR", "/app/llm")))
    server = ThreadingHTTPServer(("0.0.0.0", 8080), _make_handler(gateway))
    log.info("llm-gateway listening on :8080 (models: %s)", gateway.models)
    server.serve_forever()


if __name__ == "__main__":
    main()
