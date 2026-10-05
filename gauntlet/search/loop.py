"""
Adaptive search loop: for a seed attack, search mutated variants for one
that gets past the target, using whatever feedback the target gives.

Two strategies, chosen automatically per attempt based on what the
target returned:

- Graded feedback (a risk score is present, e.g. Aegis's
  X-Aegis-Risk-Score): beam search that keeps the K lowest-risk
  variants seen so far and expands children from them (hill-climbing
  on risk score). This is implemented in ``select_next_beam``, which is
  pure Python over plain floats/lists and is covered by the stdlib
  tests in this sandbox.
- Binary feedback (blocked/not blocked, no score): falls back to
  seeded-random order plus a small evolutionary step that re-mutates
  the most recent near-misses, implemented in
  ``select_next_evolutionary``, also pure Python and tested directly.

The actual network loop (``run_search_for_seed``) wires these selection
functions to a live Target and the mutation engine; it needs httpx (via
Target) so it is not covered by the stdlib tests here, but every
decision it makes is delegated to the two pure functions above, which
ARE tested, so the search *logic* is verified even though the network
driving loop itself could not be executed in this sandbox (see
README "Verification status").
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any

from gauntlet.mutations.engine import Variant, generate_variants, minimal_bypass


@dataclass
class Attempt:
    variant: Variant
    blocked: bool
    risk_score: float | None
    harm_success: bool = False


@dataclass
class SearchResult:
    seed_id: str
    bypass: Variant | None
    attempts: list[Attempt] = field(default_factory=list)
    requests_used: int = 0

    @property
    def found_bypass(self) -> bool:
        return self.bypass is not None


def select_next_beam(
    candidates: list[Variant],
    scored_so_far: list[tuple[Variant, float]],
    beam_width: int = 5,
) -> list[Variant]:
    """Pick the next batch to try when we have graded (risk score) feedback.

    Strategy: hill-climb toward lower risk. We keep the ``beam_width``
    lowest-risk variants seen so far (``scored_so_far``), and prioritize
    candidates whose lineage extends one of those low-risk variants'
    lineage (i.e. children of good parents), falling back to any
    remaining candidates in their given order. This is pure selection
    logic over Variant/float pairs -- no I/O -- so it is deterministic
    and directly testable.
    """
    if not scored_so_far:
        return candidates[:beam_width]

    best = sorted(scored_so_far, key=lambda pair: pair[1])[:beam_width]
    best_lineages = [v.lineage for v, _ in best]

    def is_child_of_best(c: Variant) -> bool:
        return any(
            len(c.lineage) > len(bl) and c.lineage[: len(bl)] == bl
            for bl in best_lineages
        )

    children = [c for c in candidates if is_child_of_best(c)]
    others = [c for c in candidates if not is_child_of_best(c)]
    return (children + others)[:beam_width]


def select_next_evolutionary(
    candidates: list[Variant],
    near_misses: list[Variant],
    rng: random.Random,
    batch_size: int = 5,
) -> list[Variant]:
    """Pick the next batch when feedback is only blocked/not-blocked.

    Strategy: seeded-random shuffle of the remaining candidates (so
    results are reproducible given the same rng state), but with
    variants that share lineage with a past near-miss (a variant that
    was NOT blocked on a related attempt, or simply tried most
    recently) moved to the front, since composing further from a
    near-miss is more likely to pay off than starting cold.
    """
    near_miss_lineages = {v.lineage for v in near_misses}

    def shares_lineage_prefix(c: Variant) -> bool:
        return any(
            c.lineage[: len(nm)] == nm or nm[: len(c.lineage)] == c.lineage
            for nm in near_miss_lineages
        )

    pool = list(candidates)
    rng.shuffle(pool)
    prioritized = [c for c in pool if shares_lineage_prefix(c)]
    rest = [c for c in pool if not shares_lineage_prefix(c)]
    return (prioritized + rest)[:batch_size]


async def run_search_for_seed(
    seed_id: str,
    base_payload: str,
    target: Any,  # gauntlet.targets.base.Target, typed loosely to avoid
    #                a hard import of httpx-dependent code in this module
    build_messages: Any,  # Callable[[str], list[dict]] -- how to wrap the
    #                        variant text into a chat message list
    oracle_fn: Any,  # Callable[[TargetResponse], tuple[bool, bool]] ->
    #                   (evasion_success, harm_success)
    base_seed: int,
    max_requests: int = 20,
    mutation_depth: int = 2,
    mutation_budget: int = 40,
) -> SearchResult:
    """Drive the live search loop against a real Target.

    NOT covered by sandbox tests (needs a live target / httpx). The
    pure decision functions it calls (select_next_beam,
    select_next_evolutionary, generate_variants, minimal_bypass) ARE
    covered. See module docstring.
    """
    rng = random.Random(base_seed)
    all_variants = generate_variants(
        base_payload, base_seed=base_seed, max_depth=mutation_depth, budget=mutation_budget
    )

    attempts: list[Attempt] = []
    scored_so_far: list[tuple[Variant, float]] = []
    near_misses: list[Variant] = []
    successful: list[Variant] = []
    remaining = list(all_variants)
    requests_used = 0
    have_graded_feedback = False

    while remaining and requests_used < max_requests:
        if have_graded_feedback:
            batch = select_next_beam(remaining, scored_so_far, beam_width=5)
        else:
            batch = select_next_evolutionary(remaining, near_misses, rng, batch_size=5)

        for variant in batch:
            if requests_used >= max_requests:
                break
            remaining.remove(variant)
            messages = build_messages(variant.text)
            response = await target.send(messages)
            requests_used += 1

            if response.risk_score is not None:
                have_graded_feedback = True
                scored_so_far.append((variant, response.risk_score))

            evasion_success, harm_success = oracle_fn(response)
            attempts.append(
                Attempt(
                    variant=variant,
                    blocked=response.blocked,
                    risk_score=response.risk_score,
                    harm_success=harm_success,
                )
            )

            if evasion_success:
                near_misses.append(variant)
            if harm_success:
                successful.append(variant)

        if successful:
            break

    bypass = minimal_bypass(successful)
    return SearchResult(
        seed_id=seed_id,
        bypass=bypass,
        attempts=attempts,
        requests_used=requests_used,
    )
