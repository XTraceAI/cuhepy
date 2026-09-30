"""Finite ideal-field oracle for adaptive first-false-accept accounting.

Every nonzero error on the all-reject path is fixed independently of hidden
challenges; scalar-equivalent errors have the same event. Exhaustive policies
here are tiny mathematical controls, not a cryptographic protocol proof. The
oracle also shows why conditional per-attempt probabilities and epoch-local
budget resets are not interchangeable with a global first-failure bound.
"""

from __future__ import annotations

from fractions import Fraction
from itertools import product


def projective_errors(q):
    if q not in (3, 5):
        raise ValueError("This exact two-dimensional oracle is bounded to primes 3 or 5")
    return ((0, 1), *((1, y) for y in range(q)))


def events(q, rounds):
    if type(rounds) is not int or not 1 <= rounds <= 2:
        raise ValueError("Bounded ideal oracle rounds required")
    vectors = tuple(product(range(q), repeat=2))
    challenges = tuple(product(vectors, repeat=rounds))
    return tuple(frozenset(i for i, rows in enumerate(challenges)
                           if all(sum(a * b for a, b in zip(error, rho, strict=True)) % q == 0 for rho in rows))
                 for error in projective_errors(q)), len(challenges)


def enumerate_first_failure(q=3, rounds=2, budget=3):
    if type(budget) is not int or not 1 <= budget <= 3:
        raise ValueError("Bounded ideal oracle attempts required")
    family, total = events(q, rounds)
    maximum, checked = Fraction(0), 0
    for policy in product(range(len(family)), repeat=budget):
        # Before the first false acceptance, all non-honest candidates have
        # rejected. This is the policy's relevant branch; no independence of
        # later errors conditioned on the real rejection event is assumed.
        success = frozenset().union(*(family[i] for i in policy))
        probability = Fraction(len(success), total)
        assert probability <= Fraction(budget, q ** rounds)
        maximum, checked = max(maximum, probability), checked + 1
    return {"policies_checked": checked, "maximum_first_failure_probability": maximum,
            "global_union_bound": Fraction(budget, q ** rounds)}


def conditional_and_reset_counterexamples():
    family, total = events(3, 2)
    first_two = family[0] | family[1]
    remaining, third_only = total - len(first_two), len(family[2] - first_two)
    conditional = Fraction(third_only, remaining)
    first_epoch = Fraction(len(first_two | family[2]), total)
    reset_two_epochs = 1 - (1 - first_epoch) ** 2
    assert conditional == Fraction(1, 8) > Fraction(1, 9)
    assert reset_two_epochs > Fraction(3, 9)
    return {"third_conditional_probability_after_two_rejections": conditional,
            "fresh_unconditional_probability": Fraction(1, 9),
            "one_epoch_three_attempt_first_failure": first_epoch,
            "two_independent_epochs_with_three_attempts_each_first_failure": reset_two_epochs,
            "incorrect_epoch_reset_claimed_global_bound": Fraction(3, 9),
            "correct_six_attempt_global_bound": Fraction(6, 9)}
