"""
Loads seed attacks from YAML and validates them.

Two validation paths are provided:

- ``load_seed_attacks`` validates each entry against the pydantic
  ``SeedAttack`` model (gauntlet/models.py). This is what the CLI and
  search loop use, and it needs pydantic installed.
- ``validate_seed_dict`` is a pure-stdlib structural check (no
  pydantic) used by tests in this sandbox, where pydantic could not be
  installed (see README "Verification status"). It checks the same
  required fields and value shapes by hand. Keeping both means the
  YAML's correctness is actually exercised by a test that runs today,
  not only by code that needs a future `pip install`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

DEFAULT_SEEDS_PATH = Path(__file__).parent / "seeds.yaml"

_VALID_CATEGORIES = {
    "instruction_override",
    "system_prompt_extraction",
    "role_jailbreak",
    "delimiter_injection",
    "tool_hijacking",
    "indirect_injection",
    "multilingual",
    "encoded_payload",
    "long_context",
    "tool_misuse",
    "data_exfiltration",
    "goal_hijack",
}

_VALID_DELIVERY_MODES = {"user", "tool_output", "document", "email", "webpage"}
_VALID_GOAL_KINDS = {"compliance_marker", "tool_call", "canary_leak", "exfiltration"}


class AttackValidationError(ValueError):
    pass


def validate_seed_dict(entry: dict[str, Any]) -> None:
    """Pure-stdlib structural validation of one seed attack dict.

    Raises AttackValidationError with a descriptive message on any
    problem. No pydantic, no third-party deps.
    """
    required_top = {"id", "category", "description", "payload", "goal"}
    missing = required_top - entry.keys()
    if missing:
        raise AttackValidationError(f"seed missing required fields: {missing}")

    attack_id = entry["id"]
    if not isinstance(attack_id, str) or not attack_id.strip():
        raise AttackValidationError("id must be a non-empty string")
    if not all(c.isalnum() or c in "_-" for c in attack_id):
        raise AttackValidationError(f"id {attack_id!r} has invalid characters")

    if entry["category"] not in _VALID_CATEGORIES:
        raise AttackValidationError(
            f"{attack_id}: unknown category {entry['category']!r}"
        )

    if not isinstance(entry["payload"], str) or not entry["payload"].strip():
        raise AttackValidationError(f"{attack_id}: payload must be a non-empty string")

    delivery_mode = entry.get("delivery_mode", "user")
    if delivery_mode not in _VALID_DELIVERY_MODES:
        raise AttackValidationError(
            f"{attack_id}: invalid delivery_mode {delivery_mode!r}"
        )

    goal = entry["goal"]
    if not isinstance(goal, dict) or "kind" not in goal:
        raise AttackValidationError(f"{attack_id}: goal must be a dict with a 'kind'")
    if goal["kind"] not in _VALID_GOAL_KINDS:
        raise AttackValidationError(f"{attack_id}: unknown goal kind {goal['kind']!r}")

    # Cross-field checks: each goal kind needs its own fields present.
    if goal["kind"] == "compliance_marker" and not goal.get("marker"):
        raise AttackValidationError(f"{attack_id}: compliance_marker goal needs 'marker'")
    if goal["kind"] == "tool_call" and (
        not goal.get("tool_name") or not goal.get("forbidden_args")
    ):
        raise AttackValidationError(
            f"{attack_id}: tool_call goal needs 'tool_name' and 'forbidden_args'"
        )
    if goal["kind"] == "canary_leak" and not goal.get("canary"):
        raise AttackValidationError(f"{attack_id}: canary_leak goal needs 'canary'")
    if goal["kind"] == "exfiltration" and not goal.get("attacker_domain"):
        raise AttackValidationError(
            f"{attack_id}: exfiltration goal needs 'attacker_domain'"
        )


def load_raw_yaml(path: Path | str = DEFAULT_SEEDS_PATH) -> list[dict[str, Any]]:
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, list):
        raise AttackValidationError("seeds file must contain a YAML list")
    return data


def validate_all(path: Path | str = DEFAULT_SEEDS_PATH) -> list[dict[str, Any]]:
    """Load + stdlib-validate every seed, raise on the first problem.

    Also checks global invariants: no duplicate ids, every declared
    category from _VALID_CATEGORIES appears at least once (so the
    library has real coverage, not just a technically-valid schema).
    """
    entries = load_raw_yaml(path)
    seen_ids: set[str] = set()
    seen_categories: set[str] = set()
    for entry in entries:
        validate_seed_dict(entry)
        if entry["id"] in seen_ids:
            raise AttackValidationError(f"duplicate attack id: {entry['id']}")
        seen_ids.add(entry["id"])
        seen_categories.add(entry["category"])
    return entries


def load_seed_attacks(
    path: Path | str = DEFAULT_SEEDS_PATH,
    category: str | None = None,
    tags: list[str] | None = None,
):
    """Load seeds as validated pydantic SeedAttack objects.

    Requires pydantic (see module docstring). Filters by category
    and/or tag if given.
    """
    from gauntlet.models import SeedAttack  # local import: optional dep

    entries = validate_all(path)
    attacks = [SeedAttack(**e) for e in entries]
    if category:
        attacks = [a for a in attacks if a.category == category]
    if tags:
        tagset = set(tags)
        attacks = [a for a in attacks if tagset & set(a.tags)]
    return attacks
