"""Distinct-field, projection, norm and owner-binding registration controls."""

from dataclasses import replace
import random

import pytest

from experiments.bfv_search_lab import structured_operator_oracle as operator
from experiments.bfv_search_lab import structured_registration_oracle as registration


@pytest.mark.parametrize("n,degrees", ((8, (1, 2)), (16, (2, 4)), (32, (1, 4, 8))))
def test_implicit_registration_matches_independent_integer_matrix(n, degrees):
    rng, q, outer = random.Random(68071 + n), 97, 65537
    generators = tuple(tuple(tuple(rng.randrange(-q//2 + 1, q//2 + 1) for _ in range(n))
                             for _ in range(2)) for _ in degrees)
    op = operator.Operator(n, q, 1, degrees, generators)
    # Signed integer matrix independent of modular operator.forward.
    dense = []
    for output in range(op.rows):
        block, position = divmod(output, n)
        row = []
        for degree, column in zip(degrees, generators, strict=True):
            for k in range(degree):
                shift = k*(n//degree)
                original = (position-shift) % n
                row.append(column[block][original] * (1 if position >= shift else -1))
        dense.append(tuple(row))
    crs = tuple(tuple(rng.randrange(outer) for _ in range(3)) for _ in range(op.width))
    for rows in (tuple(range(op.rows)), tuple(i for i in range(op.rows) if i % 3 != 0)):
        c = tuple(tuple(rng.randrange(2) for _ in rows) for _ in range(4))
        state = registration.registration(op, crs, c, outer, b"r" * 32, selected_rows=rows)
        expected_h = tuple(tuple(sum(a*b for a, b in zip(dense[i], column, strict=True)) % outer
                                 for column in zip(*crs, strict=True)) for i in rows)
        expected_z = tuple(tuple(sum(beta*x[j] for beta, x in zip(row, (dense[i] for i in rows), strict=True))
                                 for j in range(op.width)) for row in c)
        assert state.hint == expected_h
        assert state.fingerprints == expected_z
        assert registration.check_registration(state, expected_z, state.binding)
        altered = (tuple(x + (j == 0) for j, x in enumerate(expected_z[0])), *expected_z[1:])
        assert not registration.check_registration(state, altered, state.binding)
        overflow = ((state.honest_norm_bound + 1, *expected_z[0][1:]), *expected_z[1:])
        assert not registration.check_registration(state, overflow, state.binding)
        for _ in range(8):
            u = tuple(rng.randrange(outer) for _ in range(op.width))
            output = tuple(sum(a*b for a, b in zip(dense[i], u, strict=True)) % outer for i in rows)
            assert registration.check_online_identity(state, u, output)
        stale = registration.registration(op, crs, c, outer, b"s" * 32, selected_rows=rows)
        assert not registration.check_registration(stale, stale.fingerprints, state.binding)


def test_inner_Q_residues_are_not_outer_integer_fingerprints():
    op = operator.Operator(8, 17, 1, (1,), (((-8,) * 8, (7,) * 8),))
    crs = ((5, 6),)
    c = ((1,) * 16,)
    state = registration.registration(op, crs, c, 65537, bytes(32))
    assert state.fingerprints == ((-8,),)
    assert operator.adjoint(op, c[0]) == (9,)
    assert not registration.check_registration(state, ((9,),), state.binding)
    with pytest.raises(ValueError, match="OUTER"):
        registration.registration(op, crs, c, 17, bytes(32))


def test_honest_registration_equations_do_not_enforce_integer_admissibility():
    # D and D+outer_q have the same outer field image. The prescribed INNER-Q
    # output differs. This is a domain counterexample, not an attack on vLHE's
    # bounded extraction/correctness theorem.
    inner, outer = 17, 65537
    canonical, huge = 3, 3 + outer
    assert canonical % outer == huge % outer
    assert canonical % inner != huge % inner
    screen = registration.count_screen(rows=32768, width=1024, columns=32,
                                       inner_q=4294955009, outer_q=2**61-1, d=2048)
    assert screen["literal_D_to_generator_ratio"] == 32
    assert screen["H_body_if_materialized_bytes"] == 511705088
    assert screen["Hprime_body_if_materialized_bytes"] == 1535115264
    assert screen["Hprime_known_norm_bitpacked_body_bytes"] == 830472192
    assert not screen["outer_parameter_choice_or_correctness_assured"]


@pytest.mark.parametrize("base", (4, 16))
def test_gadget_limb_cannot_be_factored_through_the_operator(base):
    example = registration.digit_factorization_counterexample(base, 97)
    assert example["factorization_fails"]
    for d in (1, base):
        assert sum(x*base**j for j, x in enumerate(operator.balanced_digits(d, base))) == d


def test_projection_is_fixed_by_the_owner_binding():
    op = operator.Operator(8, 17, 1, (1,), (((1,) * 8, (-1,) * 8),))
    one = registration.registration(op, ((1,),), ((1,) * 8,), 65537, bytes(32), selected_rows=tuple(range(8)))
    two = registration.registration(op, ((1,),), ((1,) * 8,), 65537, bytes(32), selected_rows=tuple(range(8, 16)))
    assert one.binding != two.binding
    assert not registration.check_registration(two, two.fingerprints, one.binding)
    with pytest.raises(ValueError, match="signed honest norm"):
        registration.registration(replace(op, q=97, generators=(((48,) * 8, (-48,) * 8),)),
                                  ((1,),), ((1,) * 16,), 101, bytes(32))
