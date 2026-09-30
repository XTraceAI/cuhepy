"""Column width and record capacity are independent in the E29 score basis."""

from contextlib import closing
import itertools
import secrets

import pytest

from experiments.bfv_search_lab import crt_linear_check as checks
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import dyadic_crt as crt
from experiments.bfv_search_lab import field_frontier as fields
from experiments.bfv_search_lab import integer_phase_audit as audit
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import score_layout
from experiments.bfv_search_lab import shallow_bgv as bgv


def test_output_layout_removes_legacy_width_bound_but_keeps_whole_capacity():
    ctx = crt.context(32, ("00", "01", "1"), 17)
    features, counts = (17, 3, 9), (19, 1, 35)
    with pytest.raises(ValueError, match="padded features"):
        crt.layout(ctx, features, counts)
    layout = score_layout.layout(ctx, features, counts)
    assert layout.cost.response_ciphertexts == 3
    assert layout.cost.switches == 0
    values = [[(i + j) % 17 for i in range(c)] for j, c in enumerate(counts)]
    encoded = space.outputs(layout, values)
    assert crt.unpack(layout, [[x % 17 for x in p] for p in encoded]) == values
    with pytest.raises(ValueError, match="legacy input"):
        crt.query(layout, [[0] * f for f in features])
    with pytest.raises(ValueError, match="legacy input"):
        crt.index(layout, [[[0] * f for _ in range(c)] for c, f in zip(counts, features, strict=True)])


def test_exhaustive_component_linearity_independent_of_input_packing():
    ctx = crt.context(8, ("0", "1"), 5)
    layout = score_layout.layout(ctx, (1, 1), (5, 3))
    s = space.space(layout, (0, 1))
    groups = [[[0], [1], [2], [3], [4]], [[4], [2], [1]]]
    columns = space.columns(s, groups)
    for values in itertools.product(range(5), repeat=2):
        short = space.corrections(s, values)
        # Independent negacyclic schoolbook multiplication in the full ring.
        for reply in range(layout.cost.response_ciphertexts):
            total = [0] * ctx.n
            for column, correction in zip(columns, short, strict=True):
                weights = space.expand(s, correction)
                for i, a in enumerate(column[reply]):
                    for j, b in enumerate(weights):
                        degree = i + j
                        total[degree % ctx.n] += a * b * (1 if degree < ctx.n else -1)
            expected = space.outputs(layout, space.scores(s, groups, values))[reply]
            assert [x % 5 for x in total] == [x % 5 for x in expected]


def test_native_gmp_and_integer_phase_for_more_features_than_leaf_degree():
    pytest.importorskip("experiments.bfv_search_lab._subring._crt_subring")
    ctx = crt.context(32, ("0", "1"), 97)
    layout = score_layout.layout(ctx, (33, 33), (17, 11))
    s = space.space(layout, (0, 1))
    groups = [[[int((i + j) % 3 == 0) for j in range(33)] for i in range(c)] for c in layout.counts]
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    epoch = secrets.token_bytes(32)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, groups, epoch, client)
        server = native.NativeIndex(index, pk)
        gate = checks.EpochCheck(index, pk)
        phase = audit.Audit(index, pk, sk)
        for i in range(5):
            ticket, answer, _ = masked.prepare(s, groups, epoch, i.to_bytes(16, "little"), secrets.token_bytes(32), client)
            gate.prepare_answer(answer)
            values = tuple((i * 7 + j) % 97 for j in range(s.dimension))
            request = ticket.consume(values, epoch)
            result = server.evaluate(answer, request)
            assert result == masked.evaluate(index, answer, request, pk)
            assert gate.verify_once(request, result)
            assert phase.measure(request, answer, result)["all_integer_phase_coefficients_match_ciphertext"]
            plain = [bgv.decrypt(c, pk, sk) for c in result]
            assert crt.unpack(layout, plain) == space.scores(s, groups, values)


def test_bindings_distinguish_output_from_legacy_layout_even_at_width_one():
    ctx = crt.context(16, ("",), 17)
    legacy = space.space(crt.layout(ctx, (1,), (4,)), (0,))
    output = space.space(score_layout.layout(ctx, (1,), (4,)), (0,))
    assert legacy.binding != output.binding
    assert output.layout.cost.response_ciphertexts == legacy.layout.cost.response_ciphertexts


def test_output_allocation_keeps_fixed_private_maps_and_every_row():
    rows = list(range(32))
    groups = fields.fit(rows, 5, tuple(range(32)), prime=17, target=8, initial_parts=1)
    candidate = score_layout.allocate(groups, rows, 4, n=8)
    assert candidate.blocks[0].mapping == groups.blocks[0].mapping
    assert candidate.layout.cost.response_ciphertexts == 4
    assert tuple(i for b in candidate.blocks for i in b.positions) == tuple(range(32))
    # A legacy input query cannot hold 8 padded features in full N=8; the
    # same approved rank-five map works in the separate output-only path.
    with pytest.raises(ValueError, match="padded features"):
        crt.layout(candidate.layout.context, candidate.layout.features, candidate.layout.counts)
