"""
Aggregates raw attempt records into per-category and overall statistics.

Pure Python over plain dicts (no pydantic/httpx dependency), so it is
directly unit-testable in this sandbox and reused by both the live CLI
path (which converts pydantic AttemptRecord objects to dicts first) and
the in-process toy demo (results/report.md) committed in this repo.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from gauntlet.reporting.stats import wilson_interval


def aggregate_by_category(attempts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group attempts by category and compute evasion/harm stats per group.

    Each attempt dict is expected to have at least:
        category: str
        evasion_success: bool
        harm_success: bool
        requests_used: int (requests consumed to reach this seed's result)

    Returns a list of dicts, one per category, sorted by category name,
    each with n, evasion Wilson interval, harm Wilson interval, and mean
    requests-to-bypass among harm successes (None if there were none).
    """
    by_cat: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for a in attempts:
        by_cat[a["category"]].append(a)

    result = []
    for category in sorted(by_cat):
        group = by_cat[category]
        n = len(group)
        evasion_successes = sum(1 for a in group if a.get("evasion_success"))
        harm_successes = sum(1 for a in group if a.get("harm_success"))
        bypass_requests = [
            a["requests_used"] for a in group if a.get("harm_success") and "requests_used" in a
        ]
        mean_requests = (
            sum(bypass_requests) / len(bypass_requests) if bypass_requests else None
        )
        result.append(
            {
                "category": category,
                "n": n,
                "evasion": wilson_interval(evasion_successes, n),
                "harm": wilson_interval(harm_successes, n),
                "mean_requests_to_bypass": mean_requests,
            }
        )
    return result


def overall_stats(attempts: list[dict[str, Any]]) -> dict[str, Any]:
    n = len(attempts)
    evasion_successes = sum(1 for a in attempts if a.get("evasion_success"))
    harm_successes = sum(1 for a in attempts if a.get("harm_success"))
    return {
        "n": n,
        "evasion": wilson_interval(evasion_successes, n),
        "harm": wilson_interval(harm_successes, n),
    }


def compare_targets(
    unprotected_attempts: list[dict[str, Any]], protected_attempts: list[dict[str, Any]]
) -> dict[str, Any]:
    """Build the headline protected-vs-unprotected comparison numbers."""
    u = overall_stats(unprotected_attempts)
    p = overall_stats(protected_attempts)
    return {
        "unprotected_evasion": u["evasion"].as_pct_string(),
        "protected_evasion": p["evasion"].as_pct_string(),
        "evasion_change_pp": (p["evasion"].point_estimate - u["evasion"].point_estimate) * 100,
        "unprotected_harm": u["harm"].as_pct_string(),
        "protected_harm": p["harm"].as_pct_string(),
        "harm_change_pp": (p["harm"].point_estimate - u["harm"].point_estimate) * 100,
    }
