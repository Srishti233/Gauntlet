"""
Target interface. Adding a new target type means subclassing ``Target``
and implementing ``send`` -- nothing else in the search loop or CLI
needs to change.

VERIFICATION STATUS: this module needs httpx, which could not be
installed in the sandbox this repo was authored in (no network
access). The code has been checked with `python -m py_compile` only.
Run `pytest tests/test_targets.py` after `pip install -e .[dev]` and
bringing up the demo services to exercise this for real; the CI
`demo` job does exactly that against the live compose stack.
"""

from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import httpx

from gauntlet.targets.allowlist import assert_host_allowed


@dataclass
class TargetResponse:
    """Normalized response shape every Target.send() returns.

    Oracles and the search loop only ever look at this shape, never at
    raw httpx responses, which is what lets AegisTarget/AgentTarget/
    OpenAICompatibleTarget all plug into the same search loop.
    """

    blocked: bool
    decision: str | None = None
    risk_score: float | None = None
    rule_ids: list[str] = field(default_factory=list)
    explanation: str | None = None
    reply_text: str = ""
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    raw_status: int | None = None
    raw_body: dict[str, Any] | None = None
    latency_seconds: float = 0.0


class Target(ABC):
    def __init__(
        self,
        name: str,
        base_url: str,
        api_key: str | None = None,
        extra_headers: dict[str, str] | None = None,
        timeout_seconds: float = 30.0,
        max_concurrency: int = 4,
        max_requests_per_second: float = 10.0,
        max_retries: int = 2,
        i_own_this_target: bool = False,
    ) -> None:
        assert_host_allowed(base_url, i_own_this_target=i_own_this_target)
        self.name = name
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.extra_headers = extra_headers or {}
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._min_interval = 1.0 / max_requests_per_second if max_requests_per_second > 0 else 0.0
        self._last_request_at = 0.0
        self._rate_lock = asyncio.Lock()
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "Target":
        self._client = httpx.AsyncClient(timeout=self.timeout_seconds)
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _respect_rate_limit(self) -> None:
        if self._min_interval <= 0:
            return
        async with self._rate_lock:
            now = time.monotonic()
            wait = self._last_request_at + self._min_interval - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request_at = time.monotonic()

    async def _request_with_retries(
        self, method: str, url: str, **kwargs: Any
    ) -> httpx.Response:
        if self._client is None:
            raise RuntimeError(f"{self.name}: Target must be used as `async with target:`")
        last_exc: Exception | None = None
        for attempt in range(self.max_retries + 1):
            await self._respect_rate_limit()
            async with self._semaphore:
                try:
                    return await self._client.request(method, url, **kwargs)
                except httpx.TransportError as exc:
                    last_exc = exc
                    await asyncio.sleep(min(2**attempt * 0.5, 5.0))
        assert last_exc is not None
        raise last_exc

    @abstractmethod
    async def send(self, messages: list[dict[str, Any]]) -> TargetResponse:
        """Send a chat message list to the target, return a normalized response."""
        raise NotImplementedError


class OpenAICompatibleTarget(Target):
    """Any `/v1/chat/completions` endpoint with no Aegis-specific parsing."""

    def _headers(self) -> dict[str, str]:
        headers = dict(self.extra_headers)
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        headers.setdefault("Content-Type", "application/json")
        return headers

    async def send(self, messages: list[dict[str, Any]]) -> TargetResponse:
        start = time.monotonic()
        resp = await self._request_with_retries(
            "POST",
            f"{self.base_url}/v1/chat/completions",
            headers=self._headers(),
            json={"model": "gullible", "messages": messages},
        )
        latency = time.monotonic() - start

        if resp.status_code == 429:
            return TargetResponse(
                blocked=True,
                decision="rate_limited",
                raw_status=429,
                latency_seconds=latency,
            )
        if resp.status_code >= 400:
            return TargetResponse(
                blocked=True,
                decision="error",
                raw_status=resp.status_code,
                raw_body=_safe_json(resp),
                latency_seconds=latency,
            )

        body = _safe_json(resp) or {}
        choice = (body.get("choices") or [{}])[0]
        message = choice.get("message", {})
        reply_text = message.get("content") or ""
        tool_calls = message.get("tool_calls") or []

        return TargetResponse(
            blocked=False,
            decision="allow",
            reply_text=reply_text,
            tool_calls=tool_calls,
            raw_status=resp.status_code,
            raw_body=body,
            latency_seconds=latency,
        )


def _safe_json(resp: httpx.Response) -> dict[str, Any] | None:
    try:
        return resp.json()
    except ValueError:
        return None
