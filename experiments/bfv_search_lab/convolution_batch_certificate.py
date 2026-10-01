"""E70 post-output batching algebra, not a protocol receiver or new proof.

The prover sees the random output weights only after the outputs are fixed.
Evaluation points are ideal hidden verifier state. No point is revealed, no
HE secret is used, and the local immutable object supplies no durable binding.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from experiments.bfv_search_lab import convolution_certificate_oracle as primitive


@dataclass(frozen=True)
class FrozenOutputs:
    values: tuple[tuple[int, ...], ...]
    digest: str


def freeze(outputs, q):
    # Reuse factor-shape validation solely for bounded canonical polynomials.
    primitive.validate(tuple((row, row) for row in outputs), q)
    if len(outputs) > 64:
        raise ValueError("Too many output polynomials")
    values = tuple(outputs)
    body = json.dumps({"q": q, "values": values}, separators=(",", ":")).encode()
    return FrozenOutputs(values, hashlib.sha256(body).hexdigest())


def _weights(weights, count, q):
    if (type(weights) is not tuple or not 1 <= len(weights) <= 32
            or any(type(row) is not tuple or len(row) != count
                   or any(type(x) is not int or not 0 <= x < q for x in row) for row in weights)):
        raise ValueError("Incorrect public batching weights")


def challenge(frozen, q, rounds, rng):
    if type(frozen) is not FrozenOutputs or type(rounds) is not int or not 1 <= rounds <= 32:
        raise ValueError("Freeze bounded outputs before choosing public weights")
    return tuple(tuple(rng.randrange(q) for _ in frozen.values) for _ in range(rounds))


def quotients(groups, weights, q):
    if type(groups) is not tuple or not 1 <= len(groups) <= 64:
        raise ValueError("Incorrect product groups")
    certificates = tuple(primitive.certify(pairs, q) for pairs in groups)
    if len({len(c.output) for c in certificates}) != 1:
        raise ValueError("Mixed quotient degree")
    _weights(weights, len(groups), q)
    return tuple(tuple(sum(beta*c.quotient[i] for beta, c in zip(row, certificates, strict=True)) % q
                       for i in range(len(certificates[0].quotient))) for row in weights)


def verify_at_points(groups, frozen, weights, witnesses, points, q):
    if type(frozen) is not FrozenOutputs or len(groups) != len(frozen.values):
        raise ValueError("Incorrect frozen statement")
    n = primitive.validate(groups[0], q)
    for group in groups:
        if primitive.validate(group, q) != n:
            raise ValueError("Mixed group degree")
    _weights(weights, len(groups), q)
    if (type(witnesses) is not tuple or len(witnesses) != len(weights)
            or any(type(h) is not tuple or len(h) != n-1
                   or any(type(x) is not int or not 0 <= x < q for x in h) for h in witnesses)
            or type(points) is not tuple or len(points) != len(weights)
            or any(type(x) is not int or not 0 <= x < q for x in points)):
        raise ValueError("Invalid bounded batched quotient/points")
    # Compute every equality and return only the combined decision. The
    # pure oracle is NOT a timing-safe hidden-state implementation.
    decisions = []
    for beta, witness, point in zip(weights, witnesses, points, strict=True):
        expected = sum(weight * sum(primitive.evaluate(a, point, q)*primitive.evaluate(b, point, q)
                                    for a, b in group)
                       for weight, group in zip(beta, groups, strict=True)) % q
        actual = (sum(weight*primitive.evaluate(c, point, q) for weight, c in zip(beta, frozen.values, strict=True))
                  + (pow(point, n, q)+1)*primitive.evaluate(witness, point, q)) % q
        decisions.append(actual == expected)
    return all(decisions)


def cost(*, n, q, outputs, budget=1024, target_bits=128):
    if type(n) is not int or n < 2 or n & (n-1) or type(outputs) is not int or outputs < 1:
        raise ValueError("Invalid batched certificate geometry")
    # A nonzero output-error vector averages to zero with probability <=1/q;
    # otherwise the quotient error has degree <=2N-2. Union bound per round.
    rounds = primitive.rounds_for(q, 2*n-1, budget, target_bits)
    bits = q.bit_length()
    plain = (outputs*(n-1)*bits+7)//8
    batched = (rounds*(n-1)*bits+7)//8
    public = (rounds*outputs*bits+7)//8
    return {"point_and_weight_rounds": rounds, "per_round_degree_plus_cancellation_bound": 2*n-1,
            "unbatched_quotient_body_bytes": plain, "batched_quotient_body_bytes": batched,
            "additional_public_weight_body_bytes": public,
            "net_body_bytes_saved_before_compute_RTT_framing": plain-batched-public,
            "extra_feedback_round_trips": 1,
            "output_weight_field_products": rounds*outputs*n,
            "reusable_receiver_or_full_protocol_implemented": False,
            "scope": "Known post-statement random linear batching and polynomial bound. Hidden points, ideal coefficient-field arithmetic, no latency/security assurance or per-query owner factory removal."}
