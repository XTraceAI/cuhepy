"""Challenge order, cancellation, honesty and canonical batch controls."""

import itertools
import random

import pytest

from experiments.bfv_search_lab import convolution_batch_certificate as batching
from experiments.bfv_search_lab import convolution_certificate_oracle as primitive


def test_exact_batched_quotients_after_fixed_outputs():
    rng, q, n = random.Random(70021), 97, 8
    groups = tuple(tuple((tuple(rng.randrange(q) for _ in range(n)), tuple(rng.randrange(q) for _ in range(n)))
                         for _ in range(3)) for _ in range(6))
    outputs = tuple(primitive.certify(g, q).output for g in groups)
    frozen = batching.freeze(outputs, q)
    beta = batching.challenge(frozen, q, 4, rng)
    witnesses = batching.quotients(groups, beta, q)
    assert batching.verify_at_points(groups, frozen, beta, witnesses, (0, 1, 2, 96), q)
    for row, h in zip(beta, witnesses, strict=True):
        combined_output = tuple(sum(weight*c[i] for weight, c in zip(row, outputs, strict=True)) % q for i in range(n))
        # Independently sum each full ordinary polynomial product.
        full = [0]*(2*n-1)
        for weight, group in zip(row, groups, strict=True):
            for a, b in group:
                for i, x in enumerate(a):
                    for j, y in enumerate(b):
                        full[i+j] += weight*x*y
        assert h == tuple(x % q for x in full[n:])
        assert combined_output == tuple((full[i]-(full[i+n] if i+n < len(full) else 0)) % q for i in range(n))


def test_choosing_public_weights_before_output_allows_compensating_errors():
    groups = ((((1,)*8, (2,)*8),), (((3,)*8, (4,)*8),))
    outputs = tuple(primitive.certify(g, 97).output for g in groups)
    beta = ((3, 5),)
    # These wrong outputs are selected AFTER learning beta, which a correct
    # protocol must forbid. The same quotient passes for every private point.
    changed = ((outputs[0][0]+1) % 97, *outputs[0][1:]), ((outputs[1][0]-3*pow(5, -1, 97)) % 97, *outputs[1][1:])
    frozen = batching.freeze(changed, 97)
    witnesses = batching.quotients(groups, beta, 97)
    assert frozen.values != outputs
    assert all(batching.verify_at_points(groups, frozen, beta, witnesses, (point,), 97) for point in range(97))


def test_all_tiny_weights_and_points_expose_the_one_over_q_cancellation_term():
    q = 17
    groups = ((((1, 2), (3, 4)),), (((2, 3), (4, 5)),))
    outputs = tuple(primitive.certify(g, q).output for g in groups)
    changed = (((outputs[0][0]+1) % q, outputs[0][1]), outputs[1])
    frozen, accepts = batching.freeze(changed, q), 0
    for a, b in itertools.product(range(q), repeat=2):
        beta = ((a, b),)
        witnesses = batching.quotients(groups, beta, q)
        for point in range(q):
            ok = batching.verify_at_points(groups, frozen, beta, witnesses, (point,), q)
            assert ok == (a == 0)
            accepts += ok
    assert accepts == q*q


def test_batch_cost_includes_the_new_round_and_loses_on_few_outputs():
    large = batching.cost(n=2048, q=4294955009, outputs=32)
    small = batching.cost(n=16384, q=4294955009, outputs=2)
    assert large["point_and_weight_rounds"] == 7
    assert large["net_body_bytes_saved_before_compute_RTT_framing"] > 0
    assert small["net_body_bytes_saved_before_compute_RTT_framing"] < 0
    assert large["extra_feedback_round_trips"] == 1
    groups = ((((1, 2), (3, 4)),),)
    frozen = batching.freeze(((0, 0),), 17)
    with pytest.raises(ValueError, match="quotient"):
        batching.verify_at_points(groups, frozen, ((1,),), ((17,),), (2,), 17)
