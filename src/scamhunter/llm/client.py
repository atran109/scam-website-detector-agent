"""Crawler-side client for the llm-gateway: retries and per-site token accounting.
The crawler never holds the API key; it only talks to the gateway on the internal network."""

import asyncio
from dataclasses import dataclass, field
from typing import Any, Literal

import httpx

Role = Literal["judge", "helper", "navigator"]


class LLMError(RuntimeError):
    """The gateway or the API failed after retries, or the model refused."""


@dataclass
class TokenUsage:
    tokens_in: int = 0
    tokens_out: int = 0
    llm_calls: int = 0
    cached_calls: int = 0

    def add(self, usage: dict[str, int], cached: bool) -> None:
        self.llm_calls += 1
        if cached:  # answered from the gateway's response cache: no tokens spent
            self.cached_calls += 1
            return
        self.tokens_in += (
            usage.get("input_tokens", 0)
            + usage.get("cache_read_input_tokens", 0)
            + usage.get("cache_creation_input_tokens", 0)
        )
        self.tokens_out += usage.get("output_tokens", 0)

    def as_dict(self) -> dict[str, int]:
        return {
            "tokens_in": self.tokens_in,
            "tokens_out": self.tokens_out,
            "llm_calls": self.llm_calls,
            "cached_calls": self.cached_calls,
        }


@dataclass
class LLMResponse:
    text: str  # concatenated text blocks
    stop_reason: str
    model: str
    cached: bool
    content: list[dict[str, Any]] = field(default_factory=list)


class LLMClient:
    def __init__(self, gateway_url: str, timeout_s: float = 300, retries: int = 2) -> None:
        self._http = httpx.AsyncClient(
            base_url=gateway_url, trust_env=False, timeout=httpx.Timeout(timeout_s)
        )
        self._retries = retries

    async def aclose(self) -> None:
        await self._http.aclose()

    async def call(
        self, role: Role, site_id: str, purpose: str, request: dict[str, Any], usage: TokenUsage
    ) -> LLMResponse:
        body = {"role": role, "site_id": site_id, "purpose": purpose, "request": request}
        last_error = "no attempt"
        for attempt in range(self._retries + 1):
            try:
                resp = await self._http.post("/v1/messages", json=body)
                data = resp.json()
            except (httpx.HTTPError, ValueError) as exc:
                last_error, retryable = f"gateway unreachable: {exc}", True
            else:
                if data.get("ok"):
                    usage.add(data["usage"], data["cached"])
                    if data["stop_reason"] == "refusal":
                        raise LLMError("model refused (after server-side fallback)")
                    text = "".join(
                        b.get("text", "") for b in data["content"] if b.get("type") == "text"
                    )
                    return LLMResponse(
                        text, data["stop_reason"], data["model"], data["cached"], data["content"]
                    )
                last_error, retryable = data.get("error", "unknown"), data.get("retryable")
            if not retryable:
                break
            await asyncio.sleep(2**attempt * 5)
        raise LLMError(last_error)
