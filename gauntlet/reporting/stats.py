"""
Statistics used in Gauntlet reports. Pure math, no third-party deps,
so it is trivially unit-testable and dependency-free.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True)
class WilsonInterval:
    point_estimate: float
    low: float
    high: float
    n: int
    successes: int

    def as_pct_string(self, digits: int = 1) -> str:
        return (
            f"{self.point_estimate * 100:.{digits}f}% "
            f"[{self.low * 100:.{digits}f}%, {self.high * 100:.{digits}f}%]"
        )


def wilson_interval(successes: int, n: int, z: float = 1.959963984540054) -> WilsonInterval:
    """Wilson score interval for a binomial proportion.

    ``z`` defaults to 1.959963984540054, the two-sided 95% z-score.
    Formula: https://en.wikipedia.org/wiki/Binomial_proportion_confidence_interval#Wilson_score_interval

    With n == 0 the interval is defined as (0, 0, 1): no data means
    maximal uncertainty, point estimate 0 by convention.
    """
    if n < 0:
        raise ValueError("n must be >= 0")
    if successes < 0 or successes > n:
        raise ValueError("successes must be in [0, n]")

    if n == 0:
        return WilsonInterval(point_estimate=0.0, low=0.0, high=1.0, n=0, successes=0)

    p_hat = successes / n
    z2 = z * z
    denom = 1 + z2 / n
    centre = p_hat + z2 / (2 * n)
    margin = z * math.sqrt((p_hat * (1 - p_hat) + z2 / (4 * n)) / n)

    low = (centre - margin) / denom
    high = (centre + margin) / denom

    low = max(0.0, low)
    high = min(1.0, high)

    return WilsonInterval(point_estimate=p_hat, low=low, high=high, n=n, successes=successes)
