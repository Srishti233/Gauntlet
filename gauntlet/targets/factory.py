"""
Builds a Target instance from a TargetConfig. Adding a new target type
means adding one entry to _TARGET_CLASSES -- nothing else changes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from gauntlet.targets.aegis_target import AegisTarget
from gauntlet.targets.agent_target import AgentTarget
from gauntlet.targets.base import OpenAICompatibleTarget, Target

if TYPE_CHECKING:
    from gauntlet.models import TargetConfig

_TARGET_CLASSES = {
    "openai_compatible": OpenAICompatibleTarget,
    "aegis": AegisTarget,
    "agent": AgentTarget,
}


def build_target(config: "TargetConfig", i_own_this_target: bool = False) -> Target:
    cls = _TARGET_CLASSES.get(config.type)
    if cls is None:
        raise ValueError(
            f"Unknown target type {config.type!r}. "
            f"Known types: {sorted(_TARGET_CLASSES)}"
        )
    return cls(
        name=config.name,
        base_url=config.base_url,
        api_key=config.api_key,
        extra_headers=config.extra_headers,
        timeout_seconds=config.timeout_seconds,
        max_concurrency=config.max_concurrency,
        max_requests_per_second=config.max_requests_per_second,
        max_retries=config.max_retries,
        i_own_this_target=i_own_this_target,
    )
