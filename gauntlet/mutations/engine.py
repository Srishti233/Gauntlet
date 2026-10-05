"""
Deterministic mutation engine.

Given a seed attack's payload text and a random seed, generates variants
by composing operators from ``gauntlet.mutations.operators.OPERATORS`` up
to a configurable depth. Every variant records its own lineage: the
ordered list of operator names that produced it, so a report can show
exactly how a bypass was built.

Determinism contract: calling ``generate_variants`` twice with the same
``base_seed`` and the same attack text returns bit-for-bit identical
output, in the same order. This is relied on by tests and by the
"same seed gives the same variants" requirement.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from gauntlet.mutations.operators import OPERATORS, Operator


@dataclass(frozen=True)
class Variant:
    text: str
    lineage: tuple[str, ...] = field(default_factory=tuple)

    @property
    def depth(self) -> int:
        return len(self.lineage)


def _derive_rng(base_seed: int, *parts: str) -> random.Random:
    """A sub-rng derived deterministically from the base seed and a path.

    Using a fresh Random seeded from a stable hash of (base_seed, parts)
    means the order in which variants are generated never changes their
    individual outputs, which keeps "same seed -> same variants" true
    even if we later reorder the operator list.
    """
    key = f"{base_seed}:{':'.join(parts)}"
    # Stable, deterministic integer derived from the key without relying
    # on Python's randomized string hashing (PYTHONHASHSEED-independent).
    digest = 0
    for ch in key:
        digest = (digest * 131 + ord(ch)) % (2**61 - 1)
    return random.Random(digest)


def generate_variants(
    base_text: str,
    base_seed: int,
    operator_names: list[str] | None = None,
    max_depth: int = 2,
    budget: int | None = None,
) -> list[Variant]:
    """Generate variants of ``base_text`` by composing operators.

    Args:
        base_text: the original attack payload.
        base_seed: determinism seed; same seed -> same variants.
        operator_names: which operators to use (default: all of them).
        max_depth: maximum composition depth (depth 1 = single operator,
            depth 2 = two operators applied in sequence).
        budget: cap on the total number of variants returned. ``None``
            means unlimited. Depth-1 variants are always generated and
            listed before depth-2 variants, so truncating by budget
            keeps the simplest (most interpretable) variants first.

    Returns:
        A list of Variant, depth-1 variants first (in operator_names
        order), followed by depth-2 variants (in nested order).
    """
    names = operator_names or sorted(OPERATORS.keys())
    for name in names:
        if name not in OPERATORS:
            raise KeyError(f"Unknown mutation operator: {name}")

    variants: list[Variant] = []

    # Depth 1
    depth1_cache: dict[str, str] = {}
    for name in names:
        op: Operator = OPERATORS[name]
        rng = _derive_rng(base_seed, name)
        out_text = op(base_text, rng)
        depth1_cache[name] = out_text
        variants.append(Variant(text=out_text, lineage=(name,)))

    if max_depth >= 2:
        for first_name in names:
            first_text = depth1_cache[first_name]
            for second_name in names:
                if second_name == first_name:
                    continue
                op2: Operator = OPERATORS[second_name]
                rng2 = _derive_rng(base_seed, first_name, second_name)
                out_text = op2(first_text, rng2)
                variants.append(
                    Variant(text=out_text, lineage=(first_name, second_name))
                )

    if budget is not None:
        variants = variants[:budget]
    return variants


def minimal_bypass(successful_variants: list[Variant]) -> Variant | None:
    """Pick the variant with the fewest mutations (shortest lineage).

    Ties are broken by shorter resulting text, then by lexicographic
    lineage, so the choice is deterministic.
    """
    if not successful_variants:
        return None
    return min(
        successful_variants,
        key=lambda v: (v.depth, len(v.text), v.lineage),
    )
