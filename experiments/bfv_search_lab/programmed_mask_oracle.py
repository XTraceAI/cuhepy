"""E74 one-level public-code mask programming and structure-aware costs.

Exact toy algebra/count discriminator, not an encryption/mask API. r=A s+e
allows P=M A then M r=P s+M e, but densifies small row blocks. Fixed-weight
noise is not a parameter-approved PRG; sparse gathers expose private support
without implementation protection. Existing uniform masks/gates are intact.
No samples from this oracle should be used as production query pads.
"""

from __future__ import annotations

from fractions import Fraction
from itertools import combinations
from math import comb, log2

from gmpy2 import is_prime

from experiments.bfv_search_lab import crt_query_space as crt


def validate(matrix, prime):
    if (type(prime) is not int or not 3 <= prime <= 65537 or not is_prime(prime)
            or type(matrix) is not tuple or not 1 <= len(matrix) <= 256
            or type(matrix[0]) is not tuple or not 1 <= len(matrix[0]) <= 64
            or any(type(row) is not tuple or len(row) != len(matrix[0])
                   or any(type(x) is not int or not 0 <= x < prime for x in row) for row in matrix)):
        raise ValueError("Expected bounded canonical public field code")


def product(matrix, values, prime):
    validate(matrix, prime)
    if type(values) is not tuple or len(values) != len(matrix[0]) or any(type(x) is not int or not 0 <= x < prime for x in values):
        raise ValueError("Wrong canonical code input")
    return tuple(sum(a*b for a, b in zip(row, values, strict=True)) % prime for row in matrix)


def mask(matrix, secret, error, prime):
    coded = product(matrix, secret, prime)
    if type(error) is not tuple or len(error) != len(coded) or any(type(x) is not int or not 0 <= x < prime for x in error):
        raise ValueError("Wrong toy noise vector")
    return tuple((a+b) % prime for a, b in zip(coded, error, strict=True))


def compile_scores(space, groups, code):
    crt.validate_rows(space, groups)
    prime = space.layout.context.prime
    validate(code, prime)
    if len(code) != space.dimension:
        raise ValueError("Code must cover the actual private query coordinates")
    columns = tuple(crt.scores(space, groups, tuple(row[j] for row in code)) for j in range(len(code[0])))
    return tuple(tuple(tuple(column[group][row] for column in columns) for row in range(count))
                 for group, count in enumerate(space.layout.counts))


def programmed_scores(space, groups, compiled, secret, error):
    if len(error) != space.dimension:
        raise ValueError("Noise must cover the same query space")
    sparse = crt.scores(space, groups, error)
    prime = space.layout.context.prime
    return tuple(tuple((sum(a*b for a, b in zip(row, secret, strict=True))+value) % prime
                       for row, value in zip(block, noise, strict=True))
                 for block, noise in zip(compiled, sparse, strict=True))


def clean_set_probability(n, k, weight):
    if (type(n) is not int or not 2 <= n <= 8192 or type(k) is not int or not 1 <= k < n
            or type(weight) is not int or not 0 <= weight <= n):
        raise ValueError("Invalid information-set geometry")
    return Fraction(comb(n-weight, k), comb(n, k)) if n-weight >= k else Fraction(0)


def _solve(matrix, values, prime):
    """Tiny square Gaussian elimination; no asymptotic/attack timing claim."""
    width = len(values)
    augmented = [list(row)+[value] for row, value in zip(matrix, values, strict=True)]
    for column in range(width):
        pivot = next((i for i in range(column, width) if augmented[i][column] % prime), None)
        if pivot is None:
            return None
        augmented[column], augmented[pivot] = augmented[pivot], augmented[column]
        inverse = pow(augmented[column][column] % prime, -1, prime)
        augmented[column] = [x*inverse % prime for x in augmented[column]]
        for i in range(width):
            if i != column:
                factor = augmented[i][column]
                augmented[i] = [(a-factor*b) % prime for a, b in zip(augmented[i], augmented[column], strict=True)]
    return tuple(row[-1] for row in augmented)


def recover_tiny_sample(code, sample, prime, weight):
    """Exhaust tiny information sets only; an explanatory public-code control."""
    validate(code, prime)
    n, k = len(code), len(code[0])
    if (n > 12 or k > 4 or type(sample) is not tuple or len(sample) != n
            or any(type(x) is not int or not 0 <= x < prime for x in sample)
            or type(weight) is not int or not 0 <= weight <= n):
        raise ValueError("Outside tiny sample-recovery control")
    for trials, selected in enumerate(combinations(range(n), k), 1):
        secret = _solve(tuple(code[i] for i in selected), tuple(sample[i] for i in selected), prime)
        if secret is not None:
            coded = product(code, secret, prime)
            error = tuple((a-b) % prime for a, b in zip(sample, coded, strict=True))
            if sum(bool(x) for x in error) == weight:
                return {"secret": secret, "error": error, "sets_examined": trials}
    return None


def saving_frontier(n, row_width, prime, *, target_bits=128):
    """Exact monotone optimum over all recipes saving >=20% expected row work.

    Trial exponents EXCLUDE rank failures/inversion/residual checks and all
    other attacks. Neither this frontier nor guessing entropy assures security.
    row_width is an optimistic uniform row-width control, not the ambient n.
    """
    if (type(n) is not int or not 2 <= n <= 8192 or type(row_width) is not int
            or not 1 <= row_width <= n or type(prime) is not int or not is_prime(prime)
            or type(target_bits) is not int or not 1 <= target_bits <= 256):
        raise ValueError("Invalid bounded count frontier")
    candidates = []
    # For fixed k, expected work grows and clean-set success shrinks with tau.
    # Thus the maximum allowed tau attains that k's largest trial exponent.
    for k in range(1, min(n-1, 4*row_width//5)+1):
        tau = min(n-k, n*(4*row_width-5*k)//(5*row_width))
        probability = clean_set_probability(n, k, tau)
        work = Fraction(k*n+row_width*tau, n)
        candidates.append({"k": k, "weight": tau, "expected_row_products": float(work),
                           "row_product_ratio": float(work/row_width),
                           "clean_set_trial_exponent_excluding_polynomial_work": log2(probability.denominator)-log2(probability.numerator),
                           "clean_set_probability_exact": [str(probability.numerator), str(probability.denominator)],
                           "secret_guess_entropy_bits_necessary_only": k*log2(prime),
                           "secret_guessing_filter_passes": prime**k >= 1 << target_bits,
                           "clean_set_trial_filter_passes": probability.denominator >= (1 << target_bits)*probability.numerator})
    best = min(candidates, key=lambda c: Fraction(*(int(x) for x in c["clean_set_probability_exact"])), default=None)
    cheapest = None
    for k in range(1, n):
        if prime**k < 1 << target_bits or comb(n, k) < 1 << target_bits:
            continue
        lo, hi = 0, n-k
        while lo < hi:
            mid = (lo+hi)//2
            if comb(n, k) >= (1 << target_bits)*comb(n-mid, k):
                hi = mid
            else:
                lo = mid+1
        work = k*n+row_width*lo
        if cheapest is None or work < cheapest[0]:
            cheapest = (work, k, lo)
    return {"dimension": n, "optimistic_private_row_width": row_width, "field": prime,
            "trial_and_guess_filter_bits_not_security": target_bits,
            "all_at_least_20percent_saving_parameter_choices_screened_via_monotonicity": True,
            "maximal_noise_candidates": candidates, "largest_trial_exponent_saving_candidate": best,
            "cheapest_recipe_passing_both_incomplete_filters": None if cheapest is None else
                {"k": cheapest[1], "weight": cheapest[2], "expected_row_products": cheapest[0]/n,
                 "ratio_to_block_factory": cheapest[0]/(n*row_width)},
            "warning": "Filters do not assure LPN/security. Sparse-support private timing, total inversion work, improved ISD/BKW/multiple samples, setup/state/code generation and encryption are additional."}
