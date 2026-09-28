"""Scope and mutation controls for the conditional online linear check."""

from dataclasses import replace
import itertools
import random

import pytest

from experiments.bfv_search_lab import matrix_bgv_oracle as matrix
from experiments.bfv_search_lab import matrix_linear_check as check
from experiments.bfv_search_lab import matrix_masked_query as masked
from experiments.bfv_search_lab.test_matrix_masked_query import EPOCH, SEED, TOKEN, fixture


def prepared():
    ctx, rng, secret, out_secret, index, converted = fixture()
    ticket, packet = masked.prepare(ctx, secret, out_secret, SEED, EPOCH, TOKEN, rng, mask_space="constant")
    answer = masked.evaluate_offline(ctx, index, packet)
    request = ticket.consume((ctx.constant(1), ctx.constant(-1)), EPOCH)
    results = masked.evaluate_online(converted, answer, request)
    return ctx, converted, answer, request, results


def test_honest_online_relation_and_one_use():
    _, index, answer, request, result = prepared()
    ticket = check.LinearTicket(index, answer, random.Random(998))
    assert ticket.verify_once(request, result)
    with pytest.raises(RuntimeError, match="consumed"):
        ticket.verify_once(request, result)


def test_every_output_coefficient_and_bound_is_covered():
    ctx, index, answer, request, result = prepared()
    for r, cipher in enumerate(result):
        for c, poly in enumerate(cipher.components):
            for h in range(ctx.n):
                coefficient = list(poly)
                coefficient[h] = (coefficient[h] + 1) % ctx.q
                parts = list(cipher.components)
                parts[c] = tuple(coefficient)
                mutated = list(result)
                mutated[r] = replace(cipher, components=tuple(parts))
                assert not check.LinearTicket(index, answer, random.Random(900 + r + c + h)).verify_once(request, tuple(mutated))
    bad = (replace(result[0], phase_bound=result[0].phase_bound + 1), *result[1:])
    assert not check.LinearTicket(index, answer, random.Random(998)).verify_once(request, bad)


def test_wrong_request_noncanonical_output_and_failed_attempt_consumption():
    ctx, index, answer, request, result = prepared()
    ticket = check.LinearTicket(index, answer, random.Random(997))
    assert not ticket.verify_once(replace(request, token_id=b"x" * 16), result)
    with pytest.raises(RuntimeError):
        ticket.verify_once(request, result)
    bad_poly = (result[0].components[0][0] + ctx.q, *result[0].components[0][1:])
    bad = (replace(result[0], components=(bad_poly, *result[0].components[1:])), *result[1:])
    assert not check.LinearTicket(index, answer, random.Random(997)).verify_once(request, bad)
    assert not check.LinearTicket(index, answer, random.Random(997)).verify_once(request, result[:-1])


def test_field_soundness_by_exhaustion_and_composite_failure():
    # Every nonzero fixed error in F_5^2 has exactly 5 orthogonal challenges.
    for error in itertools.product(range(5), repeat=2):
        if error == (0, 0):
            continue
        accepted = sum(sum(a * b for a, b in zip(error, rho, strict=True)) % 5 == 0
                       for rho in itertools.product(range(5), repeat=2))
        assert accepted == 5
    # The same formula is false over a composite ring: 3*r=0 mod 15 has 3 roots.
    assert sum(3 * rho % 15 == 0 for rho in range(15)) == 3
    ctx, index, answer, _, _ = prepared()
    composite = replace(ctx, q=(1 << 61) - 7)  # Divisible by 5.
    with pytest.raises(ValueError, match="prime"):
        check.LinearTicket(replace(index, context=composite), replace(answer, context=composite), random.Random(1))


def test_poisoned_offline_state_is_not_authenticated_by_this_check():
    ctx, index, answer, request, _ = prepared()
    parts = list(answer.results[0].components)
    parts[0] = ctx.add(parts[0], ctx.constant(1))
    poisoned = replace(answer, results=(replace(answer.results[0], components=tuple(parts)), *answer.results[1:]))
    result = masked.evaluate_online(index, poisoned, request)
    # It faithfully checks a WRONG trusted premise. This retained failure
    # control prevents presenting the online relation as full HE verification.
    assert check.LinearTicket(index, poisoned, random.Random(998)).verify_once(request, result)
