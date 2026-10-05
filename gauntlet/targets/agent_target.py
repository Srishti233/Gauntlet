"""
AgentTarget: talks to the bundled demo agent (services/agent), which
exposes POST /chat and GET /sessions/{id}/log.

Unlike the chat-completion targets, "blocked" here means the agent's
upstream LLM call itself was blocked (visible via the agent's own
passthrough of X-Aegis-* style fields, when it is wired through Aegis);
the oracle layer then separately checks the session's tool log for
actual harm (tool_misuse_oracle, canary_leak_oracle, exfiltration_oracle
from gauntlet/oracles/checks.py).

VERIFICATION STATUS: needs httpx; see gauntlet/targets/base.py docstring.
"""

from __future__ import annotations

import time
from typing import Any

from gauntlet.targets.base import Target, TargetResponse, _safe_json


class AgentTarget(Target):
    async def send(self, messages: list[dict[str, Any]]) -> TargetResponse:
        # The demo agent takes a single user message plus optional
        # "context" (used for document/webpage/tool_output delivery
        # modes); the caller is expected to have already folded the
        # attack payload into `messages` in the same shape the agent
        # expects. We pass the whole message list through as `turns`
        # so delivery_mode handling lives in one place (the agent
        # service), not duplicated in the attack harness.
        start = time.monotonic()
        headers = dict(self.extra_headers)
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        resp = await self._request_with_retries(
            "POST",
            f"{self.base_url}/chat",
            headers=headers,
            json={"turns": messages},
        )
        latency = time.monotonic() - start

        if resp.status_code == 429:
            return TargetResponse(blocked=True, decision="rate_limited", raw_status=429)
        if resp.status_code >= 400:
            return TargetResponse(
                blocked=True,
                decision="error",
                raw_status=resp.status_code,
                raw_body=_safe_json(resp),
                latency_seconds=latency,
            )

        body = _safe_json(resp) or {}
        upstream_blocked = bool(body.get("upstream_blocked", False))
        session_id = body.get("session_id")
        final_answer = body.get("final_answer", "")

        tool_log: list[dict[str, Any]] = []
        if session_id:
            log_resp = await self._request_with_retries(
                "GET", f"{self.base_url}/sessions/{session_id}/log"
            )
            if log_resp.status_code == 200:
                tool_log = (_safe_json(log_resp) or {}).get("tool_calls", [])

        return TargetResponse(
            blocked=upstream_blocked,
            decision="block" if upstream_blocked else "allow",
            reply_text=final_answer,
            tool_calls=tool_log,
            raw_status=resp.status_code,
            raw_body={**body, "tool_log": tool_log},
            latency_seconds=latency,
        )
