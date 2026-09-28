"""Independent algebra, noisy encrypted search and rejected-shortcut controls."""

from dataclasses import replace
import itertools
import random

import pytest

from experiments.bfv_search_lab import matrix_bgv_oracle as matrix
from experiments.bfv_search_lab import matrix_search_cost as counts
from experiments.bfv_search_lab.reduction_oracles import ring_product

MODES = ("right", "right_symmetric", "left_independent", "left_transpose")


def secret_and_inputs(ctx, rng, mode, *, columns=1):
    secret = matrix.sample_matrix(ctx, ctx.rank, ctx.rank, rng, small=True)
    other = (matrix.sample_matrix(ctx, ctx.rank, ctx.rank, rng, small=True)
             if mode == "left_independent" else matrix.transpose(secret))
    plain_left = matrix.sample_matrix(ctx, 3, ctx.rank, rng, small=True)
    width = ctx.rank if mode.startswith("right") else columns
    plain_right = matrix.sample_matrix(ctx, ctx.rank, width, rng, small=True)
    left = matrix.encrypt(ctx, secret, plain_left, rng)
    right = matrix.encrypt(ctx, secret if mode.startswith("right") else other, plain_right, rng,
                           side="right" if mode.startswith("right") else "left")
    return secret, other, plain_left, plain_right, left, right


def source_set(forms):
    return {s for row in forms for form in row for s, _ in form.terms}


@pytest.mark.parametrize("n", [1, 2, 4, 8, 16])
def test_ring_against_independent_integer_schoolbook(n):
    ctx, rng = matrix.Context(n=n), random.Random(411)
    for _ in range(20):
        a, b = [tuple(rng.randint(-10, 10) for _ in range(n)) for _ in range(2)]
        assert ctx.mul(ctx.poly(a), ctx.poly(b)) == ctx.poly(ring_product(a, b))
        digits = ctx.decompose(ctx.poly(a))
        assert ctx.sum([ctx.scale(p, 1 << (j * ctx.digit_bits)) for j, p in enumerate(digits)]) == ctx.poly(a)


@pytest.mark.parametrize("n,rank", [(1, 1), (2, 2), (4, 3)])
@pytest.mark.parametrize("mode", MODES)
def test_entrywise_secret_expansion_and_noisy_switch(n, rank, mode):
    ctx, rng = matrix.Context(n=n, rank=rank), random.Random(700)
    secret, other, ml, mr, left, right = secret_and_inputs(ctx, rng, mode)
    forms = matrix.product_forms(ctx, left, right, mode=mode, columns=(0,))
    values = matrix.source_values(ctx, secret, source_set(forms), other)
    expected_phase = matrix.matmul(ctx, matrix.phase(ctx, left, secret),
                                   matrix.phase(ctx, right, secret if mode.startswith("right") else other))
    out_secret = matrix.sample_matrix(ctx, 1, rank, rng, small=True)[0]
    key = matrix.mask_sources(ctx, values, out_secret, rng)
    expected_plain = matrix.matmul(ctx, ml, mr)
    for i, row in enumerate(forms):
        assert matrix.evaluate_form(ctx, row[0], values) == expected_phase[i][0]
        result = matrix.decrypt(ctx, matrix.switch(ctx, row[0], key), out_secret)
        assert result == tuple(x % ctx.t for x in ctx.centered(expected_plain[i][0]))


@pytest.mark.parametrize("rank", [1, 2, 3, 4])
@pytest.mark.parametrize("mode", MODES)
def test_source_counts_and_projection_are_not_free(rank, mode):
    ctx, rng = matrix.Context(n=1, rank=rank), random.Random(611)
    for columns in range(1, rank + 1):
        secret, other, _, _, left, right = secret_and_inputs(ctx, rng, mode, columns=columns)
        forms = matrix.product_forms(ctx, left, right, mode=mode, columns=tuple(range(columns)))
        model = counts.cost(mode, rank, effective_dimension=rank, columns=columns, rows=3,
                            q_bits=ctx.q.bit_length(), digit_bits=ctx.digit_bits, t=ctx.t, eta=ctx.eta)
        assert len(source_set(forms)) == model.distinct_offline_sources
        assert len(forms[0][0].terms) == model.source_values_per_output
        values = matrix.source_values(ctx, secret, source_set(forms), other)
        key = matrix.mask_sources(ctx, values, matrix.sample_matrix(ctx, 1, rank, rng, small=True)[0], rng)
        assert key.coefficient_bytes == model.offline_gadget_bytes


def test_scalar_ciphertext_multiplication_is_wrong_for_matrices():
    ctx = matrix.Context(n=1, rank=2)
    def make(rows):
        return tuple(tuple(ctx.constant(x) for x in row) for row in rows)
    secret = make([[0, 1], [0, 0]])
    c0, c1 = make([[0, 0], [0, 0]]), make([[1, 0], [0, 1]])
    d0, d1 = make([[1, 0], [0, 0]]), c0
    # The tempting c1*d0*S is not c1*S*d0.
    wrong = matrix.matmul(ctx, matrix.matmul(ctx, c1, d0), secret)
    actual = matrix.matmul(ctx, matrix.matmul(ctx, c1, secret), d0)
    assert wrong != actual
    left, right = matrix.MatrixCipher(c0, c1, "right", 2), matrix.MatrixCipher(d0, d1, "right", 2)
    forms = matrix.product_forms(ctx, left, right)
    values = matrix.source_values(ctx, secret, source_set(forms))
    assert tuple(tuple(matrix.evaluate_form(ctx, f, values) for f in row) for row in forms) == actual


@pytest.mark.parametrize("n", [1, 2, 4, 8, 16])
def test_simd_basis_and_products(n):
    ctx = matrix.Context(n=n)
    for i in range(n):
        values = tuple(int(i == j) for j in range(n))
        encoded = matrix.simd_encode(ctx, values)
        assert matrix.simd_decode(ctx, tuple(x % ctx.t for x in ctx.centered(encoded))) == values
        assert matrix.simd_decode(ctx, tuple(x % ctx.t for x in ctx.centered(ctx.mul(encoded, encoded)))) == values


@pytest.mark.parametrize("mode", (*MODES, "gadget_query"))
def test_exhaustive_binary_search_with_ties_and_tail(mode):
    ctx, rng = matrix.Context(n=4, rank=3), random.Random(921)
    # A duplicate exercises stable-ID ties; 9 rows also exercises a partial SIMD tail.
    words, ids = list(range(8)) + [0], [30, 8, 55, 7, 21, 9, 1, 19, 0]
    secret = matrix.sample_matrix(ctx, 3, 3, rng, small=True)
    other = (matrix.sample_matrix(ctx, 3, 3, rng, small=True)
             if mode == "left_independent" else matrix.transpose(secret))
    out_secret = matrix.sample_matrix(ctx, 1, 3, rng, small=True)[0]
    plain = tuple(tuple(matrix.simd_encode(ctx, tuple((words[i] >> j) & 1 if i < len(words) else 0
                                                    for i in range(start, start + ctx.n)))
                        for j in range(ctx.rank)) for start in range(0, len(words), ctx.n))
    index = matrix.encrypt(ctx, secret, plain, rng)
    for query in range(8):
        weights = tuple(ctx.constant(1 - 2 * ((query >> j) & 1)) for j in range(ctx.rank))
        if mode == "gadget_query":
            key = matrix.gadget_query(ctx, secret, weights, out_secret, rng)
            forms = matrix.gadget_forms(ctx, index, 1)
        else:
            width = ctx.rank if mode.startswith("right") else 1
            message = tuple((p,) + (ctx.zero,) * (width - 1) for p in weights)
            cipher = matrix.encrypt(ctx, secret if mode.startswith("right") else other, message, rng,
                                    side="right" if mode.startswith("right") else "left")
            nested = matrix.product_forms(ctx, index, cipher, mode=mode, columns=(0,))
            key = matrix.mask_sources(ctx, matrix.source_values(ctx, secret, source_set(nested), other), out_secret, rng)
            forms = tuple(row[0] for row in nested)
        actual = []
        for form in forms:
            decoded = matrix.simd_decode(ctx, matrix.decrypt(ctx, matrix.switch(ctx, form, key), out_secret))
            actual.extend((score + query.bit_count()) % ctx.t for score in decoded)
        assert actual[:len(words)] == [(w ^ query).bit_count() for w in words]
        assert sorted(zip(actual[:len(words)], ids, strict=True))[:3] == sorted(
            ((w ^ query).bit_count(), i) for w, i in zip(words, ids, strict=True))[:3]


def test_bare_query_transfer_fails_without_noise_control():
    ctx = matrix.Context(n=1, rank=1, q=65537, t=17, digit_bits=2)
    a, c = ctx.constant(32768), ctx.constant(1 - 32768)
    # Both gadget families mask the value 1; only v's rows carry one noise unit.
    rows = tuple((source, tuple((ctx.constant((1 << (j * ctx.digit_bits)) + error), ctx.zero)
                               for j in range(ctx.digits)))
                 for source, error in ((("v", 0, 0), ctx.t), (("w", 0, 0), 0)))
    key = matrix.Gadget(ctx, rows)
    form = matrix.Form(ctx.zero, ((("v", 0, 0), c), (("w", 0, 0), a)), 1)
    assert matrix.decrypt(ctx, matrix.switch(ctx, form, key), (ctx.constant(1),)) == (1,)
    # Multiplying only the two unscaled masks by full ciphertext coefficients
    # gives a large noise term that wraps q and changes the decoded residue.
    bare = ctx.add(ctx.mul(c, rows[0][1][0][0]), ctx.mul(a, rows[1][1][0][0]))
    assert tuple(x % ctx.t for x in ctx.centered(bare)) != (1,)


def test_gadget_bound_and_source_rejections():
    ctx, rng = matrix.Context(), random.Random(88)
    out_secret = matrix.sample_matrix(ctx, 1, ctx.rank, rng, small=True)[0]
    key = matrix.mask_sources(ctx, {("s", 0, 0): ctx.constant(1)}, out_secret, rng)
    form = matrix.Form(ctx.constant(1), ((("s", 0, 0), ctx.constant(1)),), 2)
    for bad in (replace(form, phase_bound=ctx.q), replace(form, phase_bound=-1)):
        with pytest.raises(ValueError):
            matrix.switch(ctx, bad, key)
    with pytest.raises(ValueError, match="context"):
        matrix.switch(replace(ctx, digit_bits=4), form, key)
    with pytest.raises(ValueError, match="source"):
        matrix.switch(ctx, form, matrix.Gadget(ctx, ()))
    with pytest.raises(ValueError, match="source"):
        matrix.switch(ctx, form, matrix.Gadget(ctx, key.rows + key.rows))
    with pytest.raises(ValueError, match="digit"):
        matrix.switch(ctx, form, matrix.Gadget(ctx, ((key.rows[0][0], key.rows[0][1][:-1]),)))
    with pytest.raises(ValueError, match="projection"):
        s, _, _, _, left, right = secret_and_inputs(ctx, rng, "right")
        matrix.product_forms(ctx, left, right, columns=(0, 0))


@pytest.mark.parametrize("kwargs", [{"n": 3}, {"rank": 0}, {"rank": 5}, {"eta": -1}, {"digit_bits": 0}, {"q": 194}])
def test_invalid_toy_context(kwargs):
    with pytest.raises(ValueError):
        matrix.Context(**kwargs)


def test_hidden_support_classes_retain_joint_rank():
    result = counts.lookup_rank_bound(16, tuple(tuple(range(i, i + 4)) for i in range(0, 16, 4)))
    assert result["worst_class_features"] == 4
    assert result["hidden_class_joint_features"] == 16
    # Independent exhaustive selector values contain the identity matrix.
    selected = [[((1 << q) >> address) & 1 for address in range(16)] for q in range(16)]
    assert selected == [[int(i == j) for j in range(16)] for i in range(16)]
    with pytest.raises(ValueError):
        counts.lookup_rank_bound(4, ((0, 0),))


def test_gadget_count_matches_actual_packet():
    ctx, rng = matrix.Context(n=2, rank=3), random.Random(119)
    secret = matrix.sample_matrix(ctx, 3, 3, rng, small=True)
    out_secret = matrix.sample_matrix(ctx, 1, 3, rng, small=True)[0]
    key = matrix.gadget_query(ctx, secret, (ctx.constant(1),) * 3, out_secret, rng)
    model = counts.cost("gadget_query", 3, effective_dimension=6, q_bits=61, digit_bits=8)
    assert model.query_coefficient_bytes == key.coefficient_bytes
    assert model.offline_gadget_bytes == 0


def test_linear_affine_feature_contraction_before_gadget_query():
    # Private rank-two map for four-bit rows [u0,u1,u0,1-u1].
    ctx, rng = matrix.Context(n=4, rank=2), random.Random(58)
    secret = matrix.sample_matrix(ctx, 2, 2, rng, small=True)
    out_secret = matrix.sample_matrix(ctx, 1, 2, rng, small=True)[0]
    coordinates = list(itertools.product((0, 1), repeat=2))
    rows = [u + (u[0], 1 - u[1]) for u in coordinates]
    plain = (tuple(matrix.simd_encode(ctx, tuple(u[j] for u in coordinates)) for j in range(2)),)
    index = matrix.encrypt(ctx, secret, plain, rng)
    for query in itertools.product((0, 1), repeat=4):
        w = [1 - 2 * x for x in query]
        folded = (w[0] + w[2], w[1] - w[3])
        offset = sum(query) + w[3]
        packet = matrix.gadget_query(ctx, secret, tuple(ctx.constant(x) for x in folded), out_secret, rng)
        form = matrix.gadget_forms(ctx, index, max(map(abs, folded)))[0]
        scores = matrix.simd_decode(ctx, matrix.decrypt(ctx, matrix.switch(ctx, form, packet), out_secret))
        assert [(x + offset) % ctx.t for x in scores] == [
            sum(a != b for a, b in zip(row, query, strict=True)) for row in rows]
