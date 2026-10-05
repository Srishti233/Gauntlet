"""
Pydantic v2 data models shared across Gauntlet: attacks, run config,
target config, and results.

NOTE ON VERIFICATION: this module requires pydantic, which is not
installed in the environment this repo was authored in (no network
access was available to the author at write time; see README
"Verification status"). The syntax has been checked with
`python -m py_compile`, and the shapes mirror the stdlib dataclasses
used in gauntlet/oracles/checks.py and gauntlet/mutations/engine.py,
which ARE covered by executed tests. Run `pytest tests/test_models.py`
after `pip install -e .[dev]` to confirm this module imports and
validates correctly.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class AttackCategory(str, Enum):
    instruction_override = "instruction_override"
    system_prompt_extraction = "system_prompt_extraction"
    role_jailbreak = "role_jailbreak"
    delimiter_injection = "delimiter_injection"
    tool_hijacking = "tool_hijacking"
    indirect_injection = "indirect_injection"
    multilingual = "multilingual"
    encoded_payload = "encoded_payload"
    long_context = "long_context"
    tool_misuse = "tool_misuse"
    data_exfiltration = "data_exfiltration"
    goal_hijack = "goal_hijack"


DeliveryMode = Literal["user", "tool_output", "document", "email", "webpage"]


class GoalSpec(BaseModel):
    """What counts as success for this attack, consumed by the oracle layer."""

    kind: Literal[
        "compliance_marker",
        "tool_call",
        "canary_leak",
        "exfiltration",
    ]
    # kind == "compliance_marker"
    marker: str | None = None
    # kind == "tool_call"
    tool_name: str | None = None
    forbidden_args: dict[str, Any] | None = None
    # kind == "canary_leak"
    canary: str | None = None
    # kind == "exfiltration"
    attacker_domain: str | None = None

    @model_validator(mode="after")
    def _required_field_for_kind(self) -> "GoalSpec":
        """Each goal kind needs its own field set; mirrors the stdlib
        check in gauntlet/attacks/loader.py:validate_seed_dict, kept
        here too so constructing a GoalSpec directly (not via the
        loader) is still safe.
        """
        requirements = {
            "compliance_marker": ("marker", self.marker),
            "tool_call": ("tool_name", self.tool_name and self.forbidden_args),
            "canary_leak": ("canary", self.canary),
            "exfiltration": ("attacker_domain", self.attacker_domain),
        }
        field_name, value = requirements[self.kind]
        if not value:
            raise ValueError(f"goal kind {self.kind!r} requires {field_name!r} to be set")
        return self


class SeedAttack(BaseModel):
    id: str = Field(..., pattern=r"^[a-z0-9_\-]+$")
    category: AttackCategory
    description: str
    payload: str
    delivery_mode: DeliveryMode = "user"
    tags: list[str] = Field(default_factory=list)
    goal: GoalSpec

    @field_validator("id")
    @classmethod
    def _id_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("attack id must not be empty")
        return v


class RunBudget(BaseModel):
    max_requests_per_seed: int = 20
    max_total_requests: int = 2000
    max_wall_clock_seconds: int = 1800


class TargetConfig(BaseModel):
    name: str
    type: Literal["openai_compatible", "aegis", "agent"]
    base_url: str
    api_key: str | None = None
    extra_headers: dict[str, str] = Field(default_factory=dict)
    timeout_seconds: float = 30.0
    max_concurrency: int = 4
    max_requests_per_second: float = 10.0
    max_retries: int = 2

    # NOTE: the host allowlist is deliberately NOT checked here. A
    # TargetConfig doesn't know whether the enclosing RunConfig was
    # given --i-own-this-target, and a field_validator can't see
    # sibling fields on a different model, so checking at this level
    # would make the override permanently unreachable (every
    # non-local host would fail before RunConfig.i_own_this_target was
    # even read). See RunConfig._check_target_hosts below, which runs
    # after all fields -- including i_own_this_target -- are known.


class RunConfig(BaseModel):
    seed: int = 1337
    categories: list[AttackCategory] | None = None  # None = all
    mutation_depth: int = 2
    mutation_budget_per_seed: int = 40
    budget: RunBudget = Field(default_factory=RunBudget)
    targets: list[TargetConfig]
    i_own_this_target: bool = False

    @model_validator(mode="after")
    def _check_target_hosts(self) -> "RunConfig":
        """Enforce the host allowlist here, not on TargetConfig, because
        only here is i_own_this_target known alongside the target list.
        """
        from gauntlet.targets.allowlist import assert_host_allowed

        for target in self.targets:
            assert_host_allowed(target.base_url, i_own_this_target=self.i_own_this_target)
        return self


class AttemptRecord(BaseModel):
    attack_id: str
    category: str
    target_name: str
    variant_text: str
    lineage: list[str]
    request_number: int
    blocked: bool
    decision: str | None = None
    risk_score: float | None = None
    rule_ids: list[str] = Field(default_factory=list)
    evasion_success: bool = False
    harm_success: bool = False
    harm_reason: str = ""
    evidence: dict[str, Any] | None = None


class CategoryStats(BaseModel):
    category: str
    n: int
    evasion_successes: int
    harm_successes: int
    mean_requests_to_bypass: float | None = None


class TargetRunResult(BaseModel):
    target_name: str
    attempts: list[AttemptRecord]
    category_stats: list[CategoryStats]
    overall_evasion_n: int
    overall_evasion_successes: int
    overall_harm_n: int
    overall_harm_successes: int


class RunResults(BaseModel):
    gauntlet_version: str
    seed: int
    run_config: RunConfig
    started_at: datetime
    finished_at: datetime
    target_results: list[TargetRunResult]
