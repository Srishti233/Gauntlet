from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gauntlet.reporting.stats import wilson_interval


class TestWilsonInterval(unittest.TestCase):
    def test_zero_n_is_maximal_uncertainty(self):
        iv = wilson_interval(0, 0)
        self.assertEqual(iv.point_estimate, 0.0)
        self.assertEqual(iv.low, 0.0)
        self.assertEqual(iv.high, 1.0)

    def test_point_estimate_matches_ratio(self):
        iv = wilson_interval(5, 10)
        self.assertAlmostEqual(iv.point_estimate, 0.5)

    def test_interval_contains_point_estimate(self):
        iv = wilson_interval(7, 20)
        self.assertLessEqual(iv.low, iv.point_estimate)
        self.assertGreaterEqual(iv.high, iv.point_estimate)

    def test_bounds_within_0_and_1(self):
        for successes, n in [(0, 5), (5, 5), (1, 1), (0, 1), (50, 100)]:
            iv = wilson_interval(successes, n)
            self.assertGreaterEqual(iv.low, 0.0)
            self.assertLessEqual(iv.high, 1.0)

    def test_known_value_matches_reference_calculation(self):
        # Reference: Wilson score interval for 8 successes out of 10
        # trials, 95% confidence. Computed independently via the
        # standard formula (z=1.959963984540054):
        # center = (p + z^2/2n) / (1 + z^2/n)
        # p=0.8, n=10, z^2=3.8414588206941...
        iv = wilson_interval(8, 10)
        self.assertAlmostEqual(iv.point_estimate, 0.8, places=6)
        # Reference values for Wilson(8,10,95%), independently computed
        # from the formula above: low=0.4901624715..., high=0.9433178485...
        self.assertAlmostEqual(iv.low, 0.4901624715, places=6)
        self.assertAlmostEqual(iv.high, 0.9433178485, places=6)

    def test_more_data_narrows_interval_at_same_ratio(self):
        narrow = wilson_interval(50, 100)
        wide = wilson_interval(5, 10)
        self.assertLess(narrow.high - narrow.low, wide.high - wide.low)

    def test_rejects_invalid_successes(self):
        with self.assertRaises(ValueError):
            wilson_interval(-1, 10)
        with self.assertRaises(ValueError):
            wilson_interval(11, 10)
        with self.assertRaises(ValueError):
            wilson_interval(1, -5)

    def test_as_pct_string_format(self):
        iv = wilson_interval(5, 10)
        s = iv.as_pct_string()
        self.assertIn("%", s)
        self.assertIn("[", s)


if __name__ == "__main__":
    unittest.main()
