"""Exact family, complete coefficient, native, lifecycle and failed shortcut controls."""

from dataclasses import replace
from contextlib import closing
from fractions import Fraction
import itertools
import random
import struct

import pytest

from experiments.bfv_search_lab import crt_linear_check as check
from experiments.bfv_search_lab import coefficient_body as codec
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_query_space as crt
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import field_frontier as fields
from experiments.bfv_search_lab import native_linear_check as native
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import polynomial_fingerprint as poly
from experiments.bfv_search_lab import shallow_bgv as bgv


@pytest.mark.parametrize("q,degree", itertools.product((3, 5), (1, 2, 3, 4)))
def test_exact_family_count_and_independent_trial_division(q, degree):
    keys = poly.enumerate_keys(q, degree)
    assert len(keys) == poly.count(q, degree)
    divisors = tuple(lower + (1,) for d in range(1, degree // 2 + 1)
                     for lower in itertools.product(range(q), repeat=d))
    for lower in itertools.product(range(q), repeat=degree):
        f = lower + (1,)
        trial_irreducible = not any(not poly.remainder(f, divisor, q) for divisor in divisors)
        assert poly.irreducible(f, q) == trial_irreducible


def test_exact_collision_count_attains_factor_bound_and_checks_every_error():
    q, degree, length = 3, 2, 5
    keys = poly.enumerate_keys(q, degree)
    for delta in itertools.product(range(q), repeat=length):
        if not any(delta):
            continue
        collisions = sum(not any(poly.digest(delta, f, q)) for f in keys)
        assert Fraction(collisions, len(keys)) <= poly.collision(q, degree, length, budget=1)
    # Product of two irreducibles has exactly two colliding keys.
    f, g = keys[:2]
    product = [0] * length
    for i, a in enumerate(f):
        for j, b in enumerate(g):
            product[i + j] = (product[i + j] + a * b) % q
    assert sum(not any(poly.digest(tuple(product), k, q)) for k in keys) == 2


@pytest.mark.parametrize("bits", (32, 35, 40, 56))
def test_gmp_native_schoolbook_and_every_coefficient(bits):
    q = fields.modulus(128, bits)
    f = poly.sample(q, 5, rng=random.Random(bits))
    rng = random.Random(1000 + bits)
    values = tuple(rng.randrange(q) for _ in range(513))
    expected = poly.remainder(values, f, q) + (0,) * 5
    digest = poly.digest(values, f, q)
    assert digest == expected[:5]
    backend = native.backend()
    key = struct.pack("<5Q", *f[:-1])
    actual = struct.unpack("<5Q", backend.remainder(struct.pack("<513Q", *values), key, q))
    assert actual == digest
    rows = poly.powers(len(values), f, q)
    assert digest == tuple(sum(a * b for a, b in zip(values, row, strict=True)) % q for row in rows)
    body = backend.powers(len(values), key, q)
    assert struct.unpack(f"<{5 * len(values)}Q", body) == tuple(x for row in rows for x in row)
    # Every single-position error is detected, not just score locations.
    for i in range(len(values)):
        assert any(row[i] for row in rows)


@pytest.mark.parametrize("q", (3, 17, 4294475777, 1099510054913))
def test_exact_native_uniform_stream_including_rejection_and_offsets(q):
    rng, backend = random.Random(q), native.backend()
    bits, width = q.bit_length(), (q.bit_length() + 7) // 8
    values = tuple(rng.randrange(q) for _ in range(513))
    body = struct.pack("<513Q", *values)
    raw = rng.randbytes(900 * width)
    candidates = [int.from_bytes(raw[i:i + width], "little") & ((1 << bits) - 1)
                  for i in range(0, len(raw), width)]
    for offset in (0, 7, 512, 513):
        accepted = [x for x in candidates if x < q][:len(values) - offset]
        kept, actual = backend.uniform_dot(body, raw, width, bits, q, offset)
        assert kept == len(accepted)
        assert actual == sum(a * b for a, b in zip(values[offset:offset + kept], accepted, strict=True)) % q


def test_public_polynomial_and_single_scalar_batching_are_failed_controls():
    q = 5
    f = poly.sample(q, 2, rng=random.Random(12))
    # Public f gives a known nonzero colliding error f itself.
    assert any(f) and not any(poly.digest(f, f, q))
    # Reusing one pair of random batch weights across r=2 independent rounds
    # leaves a 1/q cancellation event, rather than a 1/q**r guarantee.
    accepted, total = 0, 0
    for a, b, rho0, rho1 in itertools.product(range(q), repeat=4):
        total += 1
        accepted += int(not ((a - b) * rho0 % q) and not ((a - b) * rho1 % q))
    assert Fraction(accepted, total) == Fraction(1, q) + (1 - Fraction(1, q)) / q ** 2
    assert Fraction(accepted, total) > Fraction(1, q ** 2)


def test_degree_policy_and_exact_length_budget():
    q = fields.modulus(16384, 32)
    d = poly.choose(q, 32768)
    assert d == 5
    assert poly.collision(q, d, 32768) <= Fraction(1, 1 << 128)
    assert poly.collision(q, d - 1, 32768) > Fraction(1, 1 << 128)
    assert poly.choose(fields.modulus(16384, 40), 32768) == 4
    assert poly.choose(fields.modulus(16384, 35), 32768) == 5
    assert poly.choose(q, 32768 * 256) == 6
    for call in (lambda: poly.collision(q, 5, 0), lambda: poly.collision(q, 5, 8, 0),
                 lambda: poly.enumerate_keys(q, 5), lambda: poly.digest((q,), (1, 1), q)):
        with pytest.raises(ValueError):
            call()


def test_native_buffer_guards():
    b = native.backend()
    for call in (lambda: b.remainder(b"", struct.pack("<Q", 1), 17),
                 lambda: b.remainder(struct.pack("<Q", 17), struct.pack("<Q", 1), 17),
                 lambda: b.remainder(struct.pack("<Q", 1), b"", 17),
                 lambda: b.remainder(struct.pack("<Q", 1), struct.pack("<9Q", *([1] * 9)), 17),
                 lambda: b.powers(0, struct.pack("<Q", 1), 17),
                 lambda: b.uniform_dot(struct.pack("<Q", 1), b"\x01", 1, 5, 17, -1),
                 lambda: b.uniform_dot(struct.pack("<Q", 1), b"\x01", 2, 5, 17, 0)):
        with pytest.raises(ValueError):
            call()


def test_uniform_max_body_reduces_before_u128_overflow():
    q, length = fields.modulus(128, 56), 1 << 20
    body = (q - 1).to_bytes(8, "little") * length
    raw = (q - 1).to_bytes(7, "little") * length
    kept, actual = native.backend().uniform_dot(body, raw, 7, 56, q, 0)
    assert kept == length and actual == length % q


@pytest.mark.parametrize("bits", (32, 35, 36, 39, 40, 56))
def test_lossless_bitcodec_independent_gmp_roundtrip_and_padding(bits):
    q = fields.modulus(128, bits)
    rng = random.Random(bits)
    for length in (1, 7, 8, 19, 513):
        values = (0, q - 1, *(rng.randrange(q) for _ in range(max(0, length - 2))))[:length]
        body = codec.pack(values, q)
        assert body == codec.reference_pack(values, q)
        assert len(body) == (length * bits + 7) // 8
        assert codec.unpack(body, length, q) == codec.reference_unpack(body, length, q) == values
        with pytest.raises(ValueError):
            codec.unpack(body + b"\0", length, q)
        if length * bits % 8:
            bad = bytearray(body)
            bad[-1] |= 0x80
            with pytest.raises(ValueError, match="padding"):
                codec.unpack(bytes(bad), length, q)
    with pytest.raises(ValueError, match="canonical"):
        codec.unpack(q.to_bytes((bits + 7) // 8, "little"), 1, q)


@pytest.mark.parametrize("kind", ("vector", "polynomial_gmp", "polynomial_native"))
def test_complete_gate_correctness_tampering_replay_and_pre_decrypt_order(kind):
    ctx = tree.context(128, ("0", "1"), 17)
    s = crt.space(tree.layout(ctx, (2, 3), (70, 70)), (0, 1))
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    epoch = b"E" * 32
    rng = random.Random(37)
    groups = [[[rng.randrange(17) for _ in range(f)] for _ in range(c)]
              for f, c in zip(s.layout.features, s.layout.counts, strict=True)]
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, groups, epoch, client)
        if kind == "vector":
            gate = native.NativeVectorCheck(index, pk, rounds=5, budget=8, rng=random.Random(38))
            reference = check.EpochCheck(index, pk, rounds=5, budget=8, rng=random.Random(38))
            assert gate._fingerprints == reference._fingerprints
        else:
            gate = native.PolynomialCheck(index, pk, budget=8, native_backend=kind.endswith("native"), rng=random.Random(38))
            reference = native.PolynomialCheck(index, pk, budget=8, native_backend=False, rng=random.Random(38))
            assert gate._polynomial == reference._polynomial
            assert gate._fingerprints == reference._fingerprints
        for i in range(7):
            ticket, answer, _ = masked.prepare(s, groups, epoch, i.to_bytes(16, "little"), rng.randbytes(32), client)
            weights = tuple(rng.randrange(17) for _ in range(s.dimension))
            request = ticket.consume(weights, epoch)
            output = masked.evaluate(index, answer, request, pk)
            assert gate._hash(output) == reference._hash(output)
            gate.prepare_answer(answer)
            if i < 4:
                reply, component = divmod(i, 2)
                c = output[reply]
                row = list(c.components[component])
                row[-1] = (row[-1] + 1) % pk.q
                components = list(c.components)
                components[component] = tuple(row)
                bad = list(output)
                bad[reply] = replace(c, components=tuple(components))
                assert not gate.verify_once(request, tuple(bad))
            elif i == 4:
                assert not gate.verify_once(replace(request, epoch=b"F" * 32), output)
            elif i == 5:
                bad = (replace(output[0], phase_bound=output[0].phase_bound + 1), *output[1:])
                assert not gate.verify_once(request, bad)
            else:
                assert gate.verify_once(request, output)  # Owner decryption is authorized only after this.
                assert tree.unpack(s.layout, [bgv.decrypt(c, pk, sk) for c in output]) == crt.scores(s, groups, weights)
            with pytest.raises(RuntimeError):
                gate.verify_once(request, output)
        assert not gate.verify_once(replace(request, token_id=b"?" * 16), output)
        with pytest.raises(RuntimeError):
            gate.verify_once(replace(request, token_id=b"!" * 16), output)
