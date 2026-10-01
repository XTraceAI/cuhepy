"""Fixed-matrix conversion, recipient/carry and complete encrypted controls."""

from contextlib import closing
from dataclasses import replace
import itertools
import random

import pytest

from experiments.bfv_search_lab import correlation_conversion_oracle as conversion
from experiments.bfv_search_lab import crt_linear_check as check
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import shallow_bgv as bgv


def test_all_tiny_fixed_matrices_and_random_triples_convert_exactly():
    rng = random.Random(69001)
    for flattened in itertools.product(range(3), repeat=4):
        matrix = (flattened[:2], flattened[2:])
        for _ in range(3):
            triple = conversion.ideal_triple(2, 2, 3, rng)
            conversion.audit_ideal_triple(triple)
            assert conversion.convert(matrix, triple) == conversion.product(matrix, triple.mask, 3)
    assert conversion.cost(100, 32, tokens=16)["owner_correction_field_products"] == 100*32*16


def test_malformed_correlation_is_not_authenticated_by_conversion_alone():
    triple = conversion.ideal_triple(2, 2, 17, random.Random(69002))
    altered = replace(triple, product=((triple.product[0] + 1) % 17, triple.product[1]))
    with pytest.raises(ValueError, match="Malformed"):
        conversion.audit_ideal_triple(altered)
    assert conversion.convert(((1, 2), (3, 4)), altered) != conversion.product(((1, 2), (3, 4)), altered.mask, 17)


def test_ideal_conversion_still_encrypts_registers_and_full_checks_each_fresh_answer():
    pytest.importorskip("experiments.bfv_search_lab._subring._crt_subring")
    s = space.space(tree.layout(tree.context(32, ("0", "1"), 17), (2, 2), (4, 3)), (0, 1))
    groups = [[[1, 0], [0, 1], [1, 1], [0, 0]], [[1, 0], [0, 1], [1, 1]]]
    matrix = tuple(tuple(row[j] if group == leaf else 0 for group in range(2) for j in range(2))
                   for leaf, rows in enumerate(groups) for row in rows)
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    epoch, rng = b"i" * 32, random.Random(69003)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, groups, epoch, client)
        server, gate = native.NativeIndex(index, pk), check.EpochCheck(index, pk, budget=16)
        seen_c1 = set()
        for i, values in enumerate(itertools.product((0, 1), repeat=4)):
            triple = conversion.ideal_triple(7, 4, 17, rng)
            conversion.audit_ideal_triple(triple)
            converted = conversion.convert(matrix, triple)
            assert converted == conversion.product(matrix, triple.mask, 17)
            scores = [list(converted[:4]), list(converted[4:])]
            packets = tuple(client.encrypt(p) for p in space.outputs(s.layout, scores))
            answer = masked.Answer(s, epoch, i.to_bytes(16, "little"), tuple(owner.expand(p, pk) for p in packets))
            c1 = tuple(c.components[1] for c in answer.ciphertexts)
            assert c1 not in seen_c1
            seen_c1.add(c1)
            gate.prepare_answer(answer)
            delta = tuple((a-b) % 17 for a, b in zip(values, triple.mask, strict=True))
            request = masked.Request(s, epoch, answer.token_id, delta)
            result = server.evaluate(answer, request)
            assert result == masked.evaluate(index, answer, request, pk)
            assert gate.verify_once(request, result)
            assert tree.unpack(s.layout, [bgv.decrypt(c, pk, sk) for c in result]) == space.scores(s, groups, values)
            with pytest.raises(RuntimeError, match="consumed"):
                gate.verify_once(request, result)
