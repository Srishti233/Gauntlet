from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gauntlet.reporting.aggregate import (
    aggregate_by_category,
    compare_targets,
    overall_stats,
)


def _attempt(category, evasion_success, harm_success, requests_used=5):
    return {
        "category": category,
        "evasion_success": evasion_success,
        "harm_success": harm_success,
        "requests_used": requests_used,
    }


class TestAggregateByCategory(unittest.TestCase):
    def test_groups_by_category(self):
        attempts = [
            _attempt("instruction_override", True, True),
            _attempt("instruction_override", False, False),
            _attempt("role_jailbreak", True, False),
        ]
        result = aggregate_by_category(attempts)
        categories = [r["category"] for r in result]
        self.assertEqual(categories, ["instruction_override", "role_jailbreak"])

    def test_n_matches_group_size(self):
        attempts = [_attempt("x", True, True) for _ in range(7)]
        result = aggregate_by_category(attempts)
        self.assertEqual(result[0]["n"], 7)

    def test_evasion_and_harm_counts_correct(self):
        attempts = [
            _attempt("x", True, True),
            _attempt("x", True, False),
            _attempt("x", False, False),
        ]
        result = aggregate_by_category(attempts)[0]
        self.assertAlmostEqual(result["evasion"].point_estimate, 2 / 3)
        self.assertAlmostEqual(result["harm"].point_estimate, 1 / 3)

    def test_mean_requests_only_counts_harm_successes(self):
        attempts = [
            _attempt("x", True, True, requests_used=4),
            _attempt("x", True, True, requests_used=6),
            _attempt("x", True, False, requests_used=100),  # not a harm success
        ]
        result = aggregate_by_category(attempts)[0]
        self.assertEqual(result["mean_requests_to_bypass"], 5.0)

    def test_mean_requests_none_when_no_harm_successes(self):
        attempts = [_attempt("x", True, False) for _ in range(3)]
        result = aggregate_by_category(attempts)[0]
        self.assertIsNone(result["mean_requests_to_bypass"])

    def test_empty_attempts_returns_empty_list(self):
        self.assertEqual(aggregate_by_category([]), [])


class TestOverallStats(unittest.TestCase):
    def test_counts_across_all_categories(self):
        attempts = [
            _attempt("a", True, True),
            _attempt("b", True, False),
            _attempt("c", False, False),
        ]
        stats = overall_stats(attempts)
        self.assertEqual(stats["n"], 3)
        self.assertAlmostEqual(stats["evasion"].point_estimate, 2 / 3)
        self.assertAlmostEqual(stats["harm"].point_estimate, 1 / 3)


class TestCompareTargets(unittest.TestCase):
    def test_protected_has_lower_rates_than_unprotected(self):
        unprotected = [_attempt("x", True, True) for _ in range(10)]
        protected = [_attempt("x", False, False) for _ in range(10)]
        comparison = compare_targets(unprotected, protected)
        self.assertLess(comparison["harm_change_pp"], 0)
        self.assertLess(comparison["evasion_change_pp"], 0)

    def test_identical_distributions_give_zero_change(self):
        attempts = [_attempt("x", True, False) for _ in range(5)]
        comparison = compare_targets(attempts, attempts)
        self.assertAlmostEqual(comparison["harm_change_pp"], 0.0)
        self.assertAlmostEqual(comparison["evasion_change_pp"], 0.0)


if __name__ == "__main__":
    unittest.main()
