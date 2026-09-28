"""Independent full-polynomial, encrypted-search and masking failure controls."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
import itertools
import random

from gmpy2 import mpz
import pytest

from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import crt_linear_check as check
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import reduction_oracles as reduction
from experiments.bfv_search_lab import shallow_bgv as bgv

EPOCH, TOKEN, SEED = b"e" * 32, b"t" * 16, b"s" * 32


def fixture():
    plan = tree.layout(tree.context(32, ("0", "10", "11"), 97), (2, 2, 1), (17, 9, 3))
    s = space.space(plan, (0, 0, 1))
    rng = random.Random(7100)
    rows = [[[rng.randrange(-1, 2) for _ in range(f)] for _ in range(c)] for f, c in zip(plan.features, plan.counts, strict=True)]
    return s, rows


@pytest.mark.parametrize("paths,features,counts,ids", [
    (("",), (3,), (19,), (0,)),
    (("0", "10", "11"), (3, 3, 1), (37, 17, 3), (0, 0, 1)),
    (("00", "01", "10", "11"), (1, 2, 3, 4), (0, 2, 35, 1), (0, 1, 2, 3)),
    (("0", "10", "11"), (1, 1, 1), (0, 0, 0), (0, 1, 0)),
])
def test_transposition_matches_original_full_polynomial_butterfly(paths, features, counts, ids):
    plan = tree.layout(tree.context(64, paths, 257), features, counts)
    s, rng = space.space(plan, ids), random.Random(7101)
    rows = [[[rng.randrange(-30, 31) for _ in range(f)] for _ in range(c)] for f, c in zip(features, counts, strict=True)]
    weights = tuple(rng.randrange(257) for _ in range(s.dimension))
    columns, corrections = space.columns(s, rows), space.corrections(s, weights)
    actual = [[0] * 64 for _ in range(plan.cost.response_ciphertexts)]
    for column, short in zip(columns, corrections, strict=True):
        for out, poly in zip(actual, column, strict=True):
            product = reduction.ring_product(tuple(poly), tuple(space.expand(s, short)))
            out[:] = [(a + b) % 257 for a, b in zip(out, product, strict=True)]
    assert tree.unpack(plan, actual) == space.scores(s, rows, weights)
    original = tree.index(plan, rows)
    qp = space.query(s, weights)
    expected = [[x % 257 for x in reduction.projected_phases(
        [reduction.ring_product(tuple(qp), tuple(p)) for p in original[start:start + plan.padded]], plan.padded)]
        for start in range(0, len(original), plan.padded)]
    assert actual == expected  # Includes all zero tails and unused coefficient positions.


def test_query_space_mod_t_embedding_and_non_linear_integer_lifts():
    s, _ = fixture()
    a, b = (90, 60, 3), (9, 50, 92)
    summed = tuple((x + y) % 97 for x, y in zip(a, b, strict=True))
    assert space.query(s, summed) == [((x + y + 48) % 97) - 48 for x, y in zip(space.query(s, a), space.query(s, b), strict=True)]
    ca, cb, cc = space.corrections(s, a), space.corrections(s, b), space.corrections(s, summed)
    assert any(x + y != z for p, q, r in zip(ca, cb, cc, strict=True) for x, y, z in zip(p, q, r, strict=True))
    assert all((x + y - z) % 97 == 0 for p, q, r in zip(ca, cb, cc, strict=True) for x, y, z in zip(p, q, r, strict=True))


def test_noisy_affine_hamming_with_shared_maps_and_all_binary_queries():
    words = [[0, 1, 6, 7] * 5, [0, 1, 6, 7] * 3, [8] * 5]
    maps = [affine.prepare(row, 4, 97) for row in words]
    assert maps[0] == maps[1]
    plan = tree.layout(tree.context(32, ("0", "10", "11"), 97), tuple(p.features for p in maps), tuple(map(len, words)))
    s = space.space(plan, (0, 0, 1))
    rows = [affine.index_features(p, group) for p, group in zip(maps, words, strict=True)]
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, rows, EPOCH, client)
        gate = check.EpochCheck(index, pk, budget=16, rng=random.Random(7102))
        pool = [masked.prepare(s, rows, EPOCH, i.to_bytes(16, "little"), (i + 1).to_bytes(32, "little"), client)
                for i in range(16)]
        for _, answer, _ in pool:
            gate.prepare_answer(answer)
        for query, (ticket, answer, _) in zip(range(16), pool, strict=True):
            transforms = [affine.query_features(p, query) for p in maps]
            weights = tuple(transforms[0][0] + transforms[2][0])
            request = ticket.consume(weights, EPOCH)
            out = masked.evaluate(index, answer, request, pk)
            assert gate.verify_once(request, out)  # Gate before the HE secret is used.
            dots = tree.unpack(plan, [bgv.decrypt(c, pk, sk) for c in out])
            actual = [d for p, ds, (_, offset) in zip(maps, dots, transforms, strict=True) for d in affine.decode(p, ds, offset)]
            expected = [(x ^ query).bit_count() for row in words for x in row]
            assert actual == expected
            assert sorted(zip(actual, range(len(actual)), strict=True))[:3] == sorted(zip(expected, range(len(expected)), strict=True))[:3]


def test_mask_lifecycle_concurrent_consumption_epoch_and_rollback_leak():
    s, _ = fixture()
    ticket = masked.MaskTicket(s, SEED, EPOCH, TOKEN)
    with pytest.raises(ValueError):
        ticket.consume((1, 2, 3), b"x" * 32)
    with ThreadPoolExecutor(2) as pool:
        calls = [pool.submit(ticket.consume, (1, 2, 3), EPOCH) for _ in range(2)]
    assert sum(c.exception() is None for c in calls) == 1
    assert sum(isinstance(c.exception(), RuntimeError) for c in calls) == 1
    first = next(c.result() for c in calls if c.exception() is None)
    # Recreating/rolling back private state is not prevented by an in-memory lock.
    second = masked.MaskTicket(s, SEED, EPOCH, TOKEN).consume((4, 8, 12), EPOCH)
    assert tuple((b - a) % 97 for a, b in zip(first.delta, second.delta, strict=True)) == (3, 6, 9)
    assert len(first.body()) == space.cost(s)["online_query_body_bytes"]


def solve(columns, output, q):
    """Independent tiny public Gaussian elimination for the rejected cache design."""
    a = [[int(c[i]) % q for c in columns] + [int(value) % q] for i, value in enumerate(output)]
    rank = 0
    for j in range(len(columns)):
        pivot = next((i for i in range(rank, len(a)) if a[i][j]), None)
        if pivot is None:
            raise ValueError("Rank-deficient public relation")
        a[rank], a[pivot] = a[pivot], a[rank]
        inverse = pow(a[rank][j], -1, q)
        a[rank] = [x * inverse % q for x in a[rank]]
        for i in range(len(a)):
            if i != rank:
                coefficient = a[i][j]
                a[i] = [(x - coefficient * y) % q for x, y in zip(a[i], a[rank], strict=True)]
        rank += 1
    if any(not any(row[:-1]) and row[-1] for row in a):
        raise ValueError("Inconsistent public relation")
    return tuple(a[i][-1] for i in range(rank))


def test_deterministic_public_ciphertext_cache_discloses_mask_but_fresh_answer_breaks_relation():
    s, rows = fixture()
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, rows, EPOCH, client)
        r = masked.mask(s, SEED, EPOCH, TOKEN)
        short = space.corrections(s, r)
        # Coefficient columns of multiplication by 1,Y,...,Y^(S-1), all public.
        columns = []
        for column in index.columns:
            for k in range(s.slots):
                monomial = tuple(int(i == k * s.stride) for i in range(pk.n))
                columns.append(tuple(x % pk.q for c in column for p in c.components
                                     for x in reduction.ring_product(tuple(map(int, p)), monomial)))
        coefficients = tuple(x % int(pk.q) for p in short for x in p)
        bad = tuple(sum(c[i] * x for c, x in zip(columns, coefficients, strict=True)) % pk.q for i in range(len(columns[0])))
        assert solve(columns, bad, int(pk.q)) == coefficients  # No HE secret needed.
        ticket, answer, _ = masked.prepare(s, rows, EPOCH, TOKEN, SEED, client)
        fresh = tuple(x for c in answer.ciphertexts for p in c.components for x in p)
        with pytest.raises(ValueError, match="Inconsistent"):
            solve(columns, fresh, int(pk.q))
        # This blocks this particular exact solve; it is not an IND-CPA proof.


def test_actual_cipher_phase_stays_within_derived_bound():
    s, rows = fixture()
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, rows, EPOCH, client)
        ticket, answer, _ = masked.prepare(s, rows, EPOCH, TOKEN, SEED, client)
        result = masked.evaluate(index, answer, ticket.consume((48, -48, 48), EPOCH), pk)
        for c in result:
            product = reduction.ring_product(tuple(map(int, c.components[1])), tuple(map(int, sk.s)))
            phase = [(a + b) % int(pk.q) for a, b in zip(c.components[0], product, strict=True)]
            assert max(abs(int(x if x <= pk.q // 2 else x - pk.q)) for x in phase) <= c.phase_bound


def test_parameter_and_space_boundary_failures():
    s, _ = fixture()
    with pytest.raises(ValueError):
        space.space(s.layout, (1, 1, 0))
    with pytest.raises(ValueError):
        space.space(s.layout, (0, 0, 0))
    with pytest.raises(ValueError):
        space.validate(replace(s, dimensions=(1, 1)))
    with pytest.raises(ValueError):
        masked.validate_request(masked.Request(s, EPOCH, TOKEN, (1, 2, 97)))
    large = space.space(tree.layout(tree.context(16384, tuple(format(i, "06b") for i in range(64))),
                                    (32,) * 64, (128,) * 64), tuple(range(64)))
    with pytest.raises(ValueError, match="complete masked"):
        masked.key_gen(large, q_bits=32)
    assert 2 * space.cost(large, q_bits=40)["worst_case_phase_bound"] < (1 << 39)
