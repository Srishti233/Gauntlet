from __future__ import annotations

import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gauntlet.mutations.engine import Variant
from gauntlet.search.loop import select_next_beam, select_next_evolutionary


class TestSelectNextBeam(unittest.TestCase):
    def test_no_scores_yet_returns_first_n(self):
        candidates = [Variant(text=f"v{i}", lineage=(f"op{i}",)) for i in range(10)]
        result = select_next_beam(candidates, scored_so_far=[], beam_width=3)
        self.assertEqual(result, candidates[:3])

    def test_prioritizes_children_of_low_risk_parents(self):
        parent = Variant(text="parent", lineage=("enc_base64",))
        child = Variant(text="child", lineage=("enc_base64", "wrap_roleplay"))
        unrelated = Variant(text="unrelated", lineage=("enc_rot13",))

        candidates = [unrelated, child]
        scored_so_far = [(parent, 0.1)]  # low risk = good

        result = select_next_beam(candidates, scored_so_far, beam_width=5)
        # child should be prioritized ahead of the unrelated variant
        self.assertEqual(result[0], child)

    def test_respects_beam_width(self):
        candidates = [Variant(text=f"v{i}", lineage=(f"op{i}",)) for i in range(20)]
        scored_so_far = [(candidates[0], 0.05)]
        result = select_next_beam(candidates, scored_so_far, beam_width=4)
        self.assertEqual(len(result), 4)

    def test_keeps_only_lowest_risk_k_parents(self):
        # Three "parents" with different risk scores; only the best
        # `beam_width` should be used to decide which children count.
        p_good = Variant(text="good", lineage=("A",))
        p_mid = Variant(text="mid", lineage=("B",))
        p_bad = Variant(text="bad", lineage=("C",))
        child_of_bad = Variant(text="child_of_bad", lineage=("C", "X"))
        child_of_good = Variant(text="child_of_good", lineage=("A", "X"))

        scored = [(p_good, 0.1), (p_mid, 0.5), (p_bad, 0.9)]
        result = select_next_beam(
            [child_of_bad, child_of_good], scored, beam_width=1
        )
        # beam_width=1 keeps only p_good as the "best" parent, so only
        # child_of_good should be prioritized to the front.
        self.assertEqual(result[0], child_of_good)


class TestSelectNextEvolutionary(unittest.TestCase):
    def test_deterministic_given_same_rng_seed(self):
        candidates = [Variant(text=f"v{i}", lineage=(f"op{i}",)) for i in range(10)]
        result1 = select_next_evolutionary(
            candidates, near_misses=[], rng=random.Random(5), batch_size=5
        )
        result2 = select_next_evolutionary(
            candidates, near_misses=[], rng=random.Random(5), batch_size=5
        )
        self.assertEqual(result1, result2)

    def test_respects_batch_size(self):
        candidates = [Variant(text=f"v{i}", lineage=(f"op{i}",)) for i in range(10)]
        result = select_next_evolutionary(
            candidates, near_misses=[], rng=random.Random(1), batch_size=3
        )
        self.assertEqual(len(result), 3)

    def test_prioritizes_variants_sharing_lineage_with_near_miss(self):
        near_miss = Variant(text="nm", lineage=("enc_base64",))
        related = Variant(text="related", lineage=("enc_base64", "wrap_roleplay"))
        unrelated = Variant(text="unrelated", lineage=("enc_rot13",))

        candidates = [unrelated, related]
        result = select_next_evolutionary(
            candidates, near_misses=[near_miss], rng=random.Random(1), batch_size=5
        )
        self.assertEqual(result[0], related)

    def test_empty_candidates_returns_empty(self):
        result = select_next_evolutionary(
            [], near_misses=[], rng=random.Random(1), batch_size=5
        )
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
