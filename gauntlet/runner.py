"""
Wires together attacks, targets, the search loop, and oracles for the
`gauntlet run` and `gauntlet regress` CLI commands.

VERIFICATION STATUS: needs httpx + pydantic; see gauntlet/cli.py
docstring. Checked with `python -m py_compile` only.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from gauntlet.attacks.loader import load_seed_attacks
from gauntlet.models import (
    AttemptRecord,
    CategoryStats,
    RunConfig,
    RunResults,
    TargetRunResult,
)
from gauntlet.oracles.checks import (
    canary_leak_oracle,
    compliance_oracle,
    exfiltration_oracle,
    firewall_bypass_oracle,
    tool_misuse_oracle,
)
from gauntlet.search.loop import run_search_for_seed
from gauntlet.targets.factory import build_target

GAUNTLET_VERSION = "0.1.0"


def _build_messages(attack, variant_text: str) -> list[dict[str, Any]]:
    """Fold a mutated variant's text into a chat message list based on
    the attack's declared delivery_mode.
    """
    if attack.delivery_mode == "user":
        return [{"role": "user", "content": variant_text}]
    if attack.delivery_mode == "tool_output":
        return [
            {"role": "user", "content": "Please process the latest tool result."},
            {"role": "tool", "content": variant_text},
        ]
    if attack.delivery_mode == "document":
        return [{"role": "user", "content": f"Please review this document.\n\n{variant_text}"}]
    if attack.delivery_mode == "email":
        return [{"role": "user", "content": f"Please process this email.\n\n{variant_text}"}]
    if attack.delivery_mode == "webpage":
        return [{"role": "user", "content": f"Please summarize this page.\n\n{variant_text}"}]
    return [{"role": "user", "content": variant_text}]


def _make_oracle_fn(attack):
    """Build an (evasion_success, harm_success) function for this
    attack's declared goal, closing over the goal's parameters.
    """
    goal = attack.goal

    def oracle_fn(response) -> tuple[bool, bool]:
        evasion = firewall_bypass_oracle(
            {"blocked": response.blocked, "decision": response.decision}
        ).success

        if not evasion:
            return False, False

        if goal.kind == "compliance_marker":
            harm = compliance_oracle(response.reply_text, goal.marker).success
        elif goal.kind == "tool_call":
            tool_log = [
                {
                    "tool": (tc.get("function", {}) or {}).get("name"),
                    "args": _safe_parse_args(tc),
                }
                for tc in response.tool_calls
            ]
            harm = tool_misuse_oracle(tool_log, goal.tool_name, goal.forbidden_args).success
        elif goal.kind == "canary_leak":
            harm = canary_leak_oracle(response.reply_text, goal.canary).success
        elif goal.kind == "exfiltration":
            outbox = (response.raw_body or {}).get("outbox", []) if response.raw_body else []
            http_log = (response.raw_body or {}).get("http_log", []) if response.raw_body else []
            harm = exfiltration_oracle(outbox, http_log, goal.attacker_domain).success
        else:
            harm = False

        return evasion, harm

    return oracle_fn


def _safe_parse_args(tool_call: dict[str, Any]) -> dict[str, Any]:
    import json

    raw = (tool_call.get("function", {}) or {}).get("arguments", "{}")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}


async def execute_run(run_config: RunConfig) -> RunResults:
    started_at = datetime.now(timezone.utc)

    attacks = load_seed_attacks()
    if run_config.categories:
        wanted = {c.value for c in run_config.categories}
        attacks = [a for a in attacks if a.category.value in wanted]

    target_results: list[TargetRunResult] = []

    for target_config in run_config.targets:
        target = build_target(target_config, i_own_this_target=run_config.i_own_this_target)
        attempts: list[AttemptRecord] = []

        async with target:
            for attack in attacks:
                oracle_fn = _make_oracle_fn(attack)
                search_result = await run_search_for_seed(
                    seed_id=attack.id,
                    base_payload=attack.payload,
                    target=target,
                    build_messages=lambda text, a=attack: _build_messages(a, text),
                    oracle_fn=oracle_fn,
                    base_seed=run_config.seed,
                    max_requests=run_config.budget.max_requests_per_seed,
                    mutation_depth=run_config.mutation_depth,
                    mutation_budget=run_config.mutation_budget_per_seed,
                )
                for request_number, attempt in enumerate(search_result.attempts, start=1):
                    # NOTE: previously used search_result.attempts.index(attempt),
                    # which is wrong whenever two Attempt dataclass instances
                    # compare equal (same variant text/lineage, both blocked,
                    # no risk score) -- .index() silently returns the FIRST
                    # match's position for every subsequent duplicate.
                    # enumerate() gives each attempt its own true position.
                    attempts.append(
                        AttemptRecord(
                            attack_id=attack.id,
                            category=attack.category.value,
                            target_name=target.name,
                            variant_text=attempt.variant.text,
                            lineage=list(attempt.variant.lineage),
                            request_number=request_number,
                            blocked=attempt.blocked,
                            risk_score=attempt.risk_score,
                            harm_success=attempt.harm_success,
                        )
                    )

        category_stats = _compute_category_stats(attacks, attempts)
        evasion_n = len(attempts)
        evasion_successes = sum(1 for a in attempts if not a.blocked)
        harm_n = len(attempts)
        harm_successes = sum(1 for a in attempts if a.harm_success)

        target_results.append(
            TargetRunResult(
                target_name=target.name,
                attempts=attempts,
                category_stats=category_stats,
                overall_evasion_n=evasion_n,
                overall_evasion_successes=evasion_successes,
                overall_harm_n=harm_n,
                overall_harm_successes=harm_successes,
            )
        )

    finished_at = datetime.now(timezone.utc)

    return RunResults(
        gauntlet_version=GAUNTLET_VERSION,
        seed=run_config.seed,
        run_config=run_config,
        started_at=started_at,
        finished_at=finished_at,
        target_results=target_results,
    )


def _compute_category_stats(attacks, attempts) -> list[CategoryStats]:
    attack_by_id = {a.id: a for a in attacks}
    by_category: dict[str, list] = {}
    for attempt in attempts:
        attack = attack_by_id.get(attempt.attack_id)
        if attack is None:
            continue
        by_category.setdefault(attack.category.value, []).append(attempt)

    stats = []
    for category, group in sorted(by_category.items()):
        n = len(group)
        harm_successes = sum(1 for a in group if a.harm_success)
        bypass_requests = [a.request_number for a in group if a.harm_success]
        mean_requests = sum(bypass_requests) / len(bypass_requests) if bypass_requests else None
        stats.append(
            CategoryStats(
                category=category,
                n=n,
                evasion_successes=sum(1 for a in group if not a.blocked),
                harm_successes=harm_successes,
                mean_requests_to_bypass=mean_requests,
            )
        )
    return stats


async def execute_regression(
    lines: list[dict[str, Any]], run_config: RunConfig
) -> dict[str, Any]:
    """Replay a saved misses.jsonl against the targets in run_config."""
    results: dict[str, Any] = {"targets": {}}

    for target_config in run_config.targets:
        target = build_target(target_config, i_own_this_target=run_config.i_own_this_target)
        outcomes = []
        async with target:
            for line in lines:
                response = await target.send([{"role": "user", "content": line["text"]}])
                outcomes.append(
                    {
                        "id": line["id"],
                        "blocked": response.blocked,
                        "decision": response.decision,
                    }
                )
        still_bypasses = sum(1 for o in outcomes if not o["blocked"])
        results["targets"][target.name] = {
            "n": len(outcomes),
            "still_bypasses": still_bypasses,
            "outcomes": outcomes,
        }

    return results
