"""Discovery/root separation, all-query exactness, field-rank and carry controls."""

from dataclasses import replace
import itertools

import pytest

from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import crt_linear_check as check
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import field_frontier as fields
from experiments.bfv_search_lab import integer_phase_audit as audit
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import rank_partition as partition
from experiments.bfv_search_lab import shallow_bgv as bgv


def deep_groups():
    # Private discovery has depth four. F_17 admits only three CRT split
    # levels, but eight final slots can pack all five groups independently.
    rows = [0, 1, 2, 4, 8]
    paths = ("0", "10", "110", "1110", "1111")
    blocks = tuple(partition.Block(path, (i,), affine.prepare([rows[i]], 4, 17)) for i, path in enumerate(paths))
    return rows, fields.Groups(blocks, (), partition.epoch_digest(rows, 4), 4, 128, 17, 1)


def test_private_discovery_depth_does_not_require_final_crt_roots():
    rows, groups = deep_groups()
    fields.validate(groups, rows)
    assert fields.max_slots(17) == 8
    with pytest.raises(ValueError, match="cannot split"):
        tree.context(128, tuple(b.path for b in groups.blocks), 17)
    candidate = fields.allocate(groups, rows, 8)
    partition.validate_epoch(candidate, rows)
    assert max(len(leaf.path) for leaf in candidate.layout.context.leaves) <= 3
    assert candidate.layout.cost.response_ciphertexts == 1
    with pytest.raises(ValueError, match="roots"):
        fields.allocate(groups, rows, 16)


@pytest.mark.parametrize("prime", (17, 97))
def test_all_binary_queries_and_independent_modulus_rebuild(prime):
    rows = [i for i in range(32) for _ in range(2)]
    g = fields.fit(rows, 5, tuple(range(len(rows))), prime=prime, n=128, target=2,
                   initial_parts=1, policy="median")
    c = fields.allocate(g, rows, 8)
    maps = tuple(dict.fromkeys(b.mapping for b in c.blocks))
    s = space.space(c.layout, tuple(maps.index(b.mapping) for b in c.blocks))
    groups = [affine.index_features(b.mapping, [rows[i] for i in b.positions]) for b in c.blocks]
    columns = space.columns(s, groups)
    for query in range(32):
        transformed = [affine.query_features(p, query) for p in maps]
        weights = tuple(x for values, _ in transformed for x in values)
        short = space.corrections(s, weights)
        # Independent schoolbook integer convolution; reduce only at output.
        from experiments.bfv_search_lab.reduction_oracles import ring_product
        outputs = [[sum(row[k] for row in products) % prime for k in range(s.layout.context.n)]
                   for products in ([ring_product(columns[j][r], tuple(space.expand(s, short[j])))
                                     for j in range(s.columns)] for r in range(s.layout.cost.response_ciphertexts))]
        decoded = tree.unpack(c.layout, outputs)
        actual = []
        for block, values, group in zip(c.blocks, decoded, s.map_ids, strict=True):
            actual.extend(zip(affine.decode(maps[group], values, transformed[group][1]), block.positions, strict=True))
        assert sorted(actual) == sorted(((x ^ query).bit_count(), i) for i, x in enumerate(rows))
    other = fields.refit(g, rows, 97 if prime == 17 else 17)
    assert other.prime != g.prime and all(b.mapping.prime == other.prime for b in other.blocks)
    assert other.cuts == ()  # Old field cut ranks do not certify new ones.


def test_independently_fitted_same_field_control_matches_original_grouping_and_allocation():
    rows = [i for i in range(32)] * 2
    order = tuple(range(len(rows)))
    old = partition.prepare(rows, 5, order, initial_parts=2, n=128, prime=97, target=2, policy="median")
    new = fields.fit(rows, 5, order, initial_parts=2, n=128, prime=97, target=2, policy="median")
    assert new.blocks == old.blocks and new.cuts == old.cuts
    assert fields.allocate(new, rows, 8) == partition.reallocate(old, rows, 8)


def test_rank_changes_with_field_and_modular_reduction_is_not_a_fresh_map_certificate():
    rows = [0, 56, 38, 22, 53, 9, 51]
    small, big = affine.prepare(rows, 6, 7), affine.prepare(rows, 6, 17)
    assert small.rank == 5 and big.rank == 6
    forged = replace(small, prime=17)
    with pytest.raises(ValueError, match="outside"):
        affine.index_features(forged, rows)
    assert all(affine.decode(big, [sum(a * b for a, b in zip(row, affine.query_features(big, q)[0], strict=True)) % 17
                                 for row in affine.index_features(big, rows)], affine.query_features(big, q)[1])
               == [(x ^ q).bit_count() for x in rows] for q in range(64))
    with pytest.raises(ValueError, match="covering exact distances"):
        affine.prepare(rows, 6, 5)


def test_deterministic_encrypted_queries_are_chosen_after_enrollment_and_answer_preparation():
    pytest.importorskip("experiments.bfv_search_lab._subring._crt_subring")
    rows = list(range(32)) * 2
    g = fields.fit(rows, 5, tuple(range(len(rows))), prime=17, n=128, target=2, initial_parts=1, policy="median")
    c = fields.allocate(g, rows, 8)
    maps = tuple(dict.fromkeys(b.mapping for b in c.blocks))
    s = space.space(c.layout, tuple(maps.index(b.mapping) for b in c.blocks))
    groups = [affine.index_features(b.mapping, [rows[i] for i in b.positions]) for b in c.blocks]
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    client = owner.OwnerClient(pk, sk)
    try:
        epoch = bytes.fromhex(c.source_digest)
        index, _ = masked.enroll(s, groups, epoch, client)
        phase_audit = audit.Audit(index, pk, sk)
        evaluator, gate = native.NativeIndex(index, pk), check.EpochCheck(index, pk, rounds=fields.rounds(int(pk.q)), budget=32)
        pool = [masked.prepare(s, groups, epoch, i.to_bytes(16, "little"), bytes([i]) * 32, client) for i in range(32)]
        for _, answer, _ in pool:
            gate.prepare_answer(answer)
        q = 0
        for i, (ticket, answer, _) in enumerate(pool):
            transformed = [affine.query_features(p, q) for p in maps]
            weights = tuple(x for values, _ in transformed for x in values)
            request = ticket.consume(weights, epoch)
            result = evaluator.evaluate(answer, request)
            assert result == masked.evaluate(index, answer, request, pk)
            assert gate.verify_once(request, result)
            measured = phase_audit.measure(request, answer, result)
            assert measured["maximum_unreduced_integer_phase"] <= result[0].phase_bound
            if i == 0:
                from experiments.bfv_search_lab.reduction_oracles import ring_product
                def independent_fresh(cipher):
                    product = ring_product(tuple(map(int, cipher.components[1])), tuple(map(int, sk.s)))
                    phase = tuple((int(a) + b) % int(pk.q) for a, b in zip(cipher.components[0], product, strict=True))
                    return tuple(x if x <= pk.q // 2 else x - int(pk.q) for x in phase)
                short = space.corrections(s, request.delta)
                maximum = 0
                for r, saved in enumerate(answer.ciphertexts):
                    expected_phase = list(independent_fresh(saved))
                    for column, correction in zip(index.columns, short, strict=True):
                        product = ring_product(independent_fresh(column[r]), tuple(space.expand(s, correction)))
                        expected_phase = [a + b for a, b in zip(expected_phase, product, strict=True)]
                    maximum = max(maximum, max(map(abs, expected_phase)))
                assert maximum == measured["maximum_unreduced_integer_phase"]
            decoded = tree.unpack(c.layout, [bgv.decrypt(cipher, pk, sk) for cipher in result])
            actual = []
            for block, values, group in zip(c.blocks, decoded, s.map_ids, strict=True):
                actual.extend(zip(affine.decode(maps[group], values, transformed[group][1]), block.positions, strict=True))
            assert sorted(actual) == sorted(((x ^ q).bit_count(), stable) for stable, x in enumerate(rows))
            # Depend on an authenticated previous result, after the index and
            # entire random-query answer pool already exist.
            q = (sorted(actual)[0][1] + i + 1) % 32
    finally:
        client.close()


def test_checking_in_a_different_field_without_q_carries_rejects_honest_and_accepts_wrong():
    q, p, ciphertext, correction = 5, 7, 4, 2
    honest = ciphertext * correction % q
    naive_expected = ciphertext * correction % p
    assert honest == 3 and naive_expected == 1
    assert honest % p != naive_expected  # False reject.
    assert naive_expected != honest and naive_expected % p == ciphertext * correction % p  # False accept.
    carry = (ciphertext * correction - honest) // q
    assert ciphertext * correction == honest + q * carry
    assert (ciphertext * correction - naive_expected) % q != 0


def test_field_budget_exact_round_count_and_invalid_grouping():
    assert fields.max_slots(193) == 32 and fields.max_slots(257) == 64
    for n, bits in itertools.product((8, 128, 16384), (32, 40)):
        q = fields.modulus(n, bits)
        count = fields.rounds(q)
        assert (q - 1) % (2 * n) == 0 and q.bit_length() == bits
        assert q ** count >= 1024 * 2 ** 128 and q ** (count - 1) < 1024 * 2 ** 128
    rows, groups = deep_groups()
    for bad in (replace(groups, source_digest="stale"), replace(groups, blocks=groups.blocks[:-1]),
                replace(groups, target=3), replace(groups, n=127)):
        with pytest.raises(ValueError):
            fields.validate(bad, rows)
    description = fields.describe(fields.allocate(groups, rows, 8))
    assert description["profiles"]["deterministic"]["implemented_api_minimum_q_bits"] == 32
    assert description["profiles"]["deterministic"]["minimum_analytic_q_bits_model"] < 32
