"""
AegisTarget: talks to Aegis's /v1/chat/completions and parses the
Aegis-specific decision headers and block-error body described in the
project brief (X-Aegis-Decision, X-Aegis-Risk-Score, X-Aegis-Would-Block,
and the X-Aegis-Debug / X-Aegis-Explanation pair).

VERIFICATION STATUS: needs httpx; see gauntlet/targets/base.py docstring.
"""

from __future__ import annotations

import time
from typing import Any

from gauntlet.targets.base import OpenAICompatibleTarget, TargetResponse, _safe_json


class AegisTarget(OpenAICompatibleTarget):
    def __init__(self, *args: Any, debug: bool = True, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.debug = debug

    def _headers(self) -> dict[str, str]:
        headers = super()._headers()
        if self.debug:
            headers["X-Aegis-Debug"] = "1"
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

        decision = resp.headers.get("X-Aegis-Decision")
        risk_score_raw = resp.headers.get("X-Aegis-Risk-Score")
        risk_score = float(risk_score_raw) if risk_score_raw is not None else None
        would_block = resp.headers.get("X-Aegis-Would-Block")
        explanation = resp.headers.get("X-Aegis-Explanation")

        if resp.status_code == 429:
            return TargetResponse(
                blocked=True,
                decision="rate_limited",
                risk_score=risk_score,
                raw_status=429,
                latency_seconds=latency,
            )

        if resp.status_code == 400:
            body = _safe_json(resp) or {}
            aegis_info = body.get("error", {}).get("aegis", {}) if isinstance(body, dict) else {}
            return TargetResponse(
                blocked=True,
                decision=decision or "block",
                risk_score=risk_score or aegis_info.get("risk_score"),
                rule_ids=aegis_info.get("rule_ids", []) or [],
                explanation=explanation or aegis_info.get("explanation"),
                raw_status=400,
                raw_body=body,
                latency_seconds=latency,
            )

        if resp.status_code >= 400:
            return TargetResponse(
                blocked=True,
                decision=decision or "error",
                risk_score=risk_score,
                raw_status=resp.status_code,
                raw_body=_safe_json(resp),
                latency_seconds=latency,
            )

        body = _safe_json(resp) or {}
        choice = (body.get("choices") or [{}])[0]
        message = choice.get("message", {})
        reply_text = message.get("content") or ""
        tool_calls = message.get("tool_calls") or []

        # A "redact" decision on an otherwise-200 response still counts
        # as the firewall interfering, but NOT as a block for the
        # evasion oracle (the request went through, content was
        # modified) -- that distinction is left to the oracle layer,
        # which reads `decision` directly, so we always report the
        # real decision rather than collapsing redact into either
        # allow or block here.
        blocked = (decision == "block") or bool(would_block == "true" and decision == "block")

        return TargetResponse(
            blocked=blocked,
            decision=decision or "allow",
            risk_score=risk_score,
            explanation=explanation,
            reply_text=reply_text,
            tool_calls=tool_calls,
            raw_status=resp.status_code,
            raw_body=body,
            latency_seconds=latency,
        )
