"""Independent dense/ring/adjoint/digit, carry and public-release controls."""

from contextlib import closing
import itertools
import random

from gmpy2 import mpz
import pytest

from experiments.bfv_search_lab import ciphertext_linear_oracle as literal
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import decryption_support as support
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import structured_operator_oracle as structured
from experiments.bfv_search_lab import supported_decoder as decoder


CASES = ((8, ("0", "1"), (1, 1), (7, 1), (0, 1), ()),
         (16, ("00", "01", "10", "11"), (1, 1, 1, 1), (1, 2, 3, 1), (0, 0, 1, 1), ((0,), (1,))),
         (32, ("0", "10", "11"), (2, 1, 2), (4, 2, 3), (0, 1, 2), ()))


@pytest.mark.parametrize("n,paths,features,counts,map_ids,coordinate_ids", CASES)
def test_encrypted_index_implicit_adjoint_and_digits_match_independent_references(n, paths, features, counts, map_ids, coordinate_ids):
    layout = tree.layout(tree.context(n, paths, 17), features, counts)
    s = space.space(layout, map_ids, coordinate_ids=coordinate_ids)
    groups = [[[(-1)**(i + j) for j in range(f)] for i in range(count)] for count, f in zip(counts, features, strict=True)]
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, groups, b"s" * 32, client)
    op, matrix = structured.from_index(index, pk), literal.matrix(index, pk)
    beta = tuple(random.Random(68001 + i).randrange(int(pk.q)) for i in range(op.rows))
    expected_adjoint = tuple(sum(beta[i] * matrix.rows[i][j] for i in range(op.rows)) % op.q for j in range(op.width))
    assert structured.adjoint(op, beta) == expected_adjoint
    rows = structured.projected_rows(support.certify(layout))
    projected_beta = structured.project(beta, rows)
    extended = structured.projection_adjoint(projected_beta, rows, op.rows)
    for values in itertools.product((0, 1), repeat=s.dimension):
        forms = literal.alpha(s, values)
        result = structured.forward(op, forms)
        assert result == literal.evaluate(matrix, forms) == literal.independent(index, pk, values)
        # Exact literal equality is an IDEAL outer gate in this algebra test.
        corrections = space.corrections(s, values)
        bounds = tuple(sum(sum(map(abs, weights)) * column[r].phase_bound
                           for column, weights in zip(index.columns, corrections, strict=True))
                       for r in range(op.replies))
        full = tuple(bgv.Ciphertext((tuple(mpz(x) for x in result[2*r*n:(2*r+1)*n]),
                                     tuple(mpz(x) for x in result[(2*r+1)*n:(2*r+2)*n])),
                                    pk.key_id, bounds[r]) for r in range(op.replies))
        reply = decoder.project(full, s, pk, index.epoch)
        certificate = support.certify(layout)
        phases = decoder._field_carrier(reply, pk, sk, certificate)
        assert tree.unpack(layout, phases) == space.scores(s, groups, values)
        assert tree.unpack(layout, [bgv.decrypt(c, pk, sk) for c in full]) == space.scores(s, groups, values)
        assert sum(a * b for a, b in zip(beta, result, strict=True)) % op.q == sum(a * b for a, b in zip(expected_adjoint, forms, strict=True)) % op.q
        assert sum(a * b for a, b in zip(projected_beta, structured.project(result, rows), strict=True)) % op.q == sum(a * b for a, b in zip(structured.adjoint(op, extended), forms, strict=True)) % op.q
        for base in (4, 16, 256):
            outputs = structured.digit_products(op, forms, base)
            assert structured.reconstruct_digit_products(outputs, base, op.q) == result
            bound = op.width * (base // 2) * max(map(abs, forms), default=0)
            assert all(abs(x) <= bound for output in outputs for x in output)


@pytest.mark.parametrize("base", (4, 16, 256))
def test_balanced_digits_cover_negative_endpoints_and_signed_ties(base):
    for value in range(-1024, 1025):
        digits = structured.balanced_digits(value, base)
        assert sum(x * base**j for j, x in enumerate(digits)) == value
        assert all(abs(x) <= base // 2 for x in digits)
        assert len(digits) <= structured.digit_count(2049, base)


def test_digit_output_needs_integer_no_wrap_not_only_small_database_entries():
    op = structured.Operator(8, 97, 1, (1,), (((46,) * 8, (-46,) * 8),))
    outputs = structured.digit_products(op, (8,), 4)
    honest = structured.forward(op, (8,))
    # p=17 exceeds each digit's norm, but NOT the evaluated integer bound.
    wrapped = tuple(tuple((x % 17) if x % 17 <= 8 else x % 17 - 17 for x in output) for output in outputs)
    assert structured.reconstruct_digit_products(wrapped, 4, 97) != honest
    screen = structured.digit_screen(rows=16, width=1, columns=1, q=97, query_bound=8, base=4)
    p = screen["minimum_exact_outer_plaintext_modulus"]
    unwrapped = tuple(tuple((x % p) if x % p <= p // 2 else x % p - p for x in output) for output in outputs)
    assert structured.reconstruct_digit_products(unwrapped, 4, 97) == honest


def test_public_inner_result_and_mask_image_expose_full_rank_input():
    # Deterministic signed-shift basis; the condition does not assume HE fails.
    op = structured.Operator(8, 17, 1, (2,), (((1, 0, 0, 0, 0, 0, 0, 0), (0,) * 8),))
    rows = tuple(tuple(structured.forward(op, tuple(int(k == j) for k in range(2)))[i] for j in range(2)) for i in range(16))
    matrix = literal.Matrix(rows, 17, 8, 1)
    query, mask = (3, 8), (5, 6)
    assert structured.recover_public_input(matrix, structured.forward(op, query)) == query
    recovered_mask = structured.recover_public_input(matrix, structured.forward(op, mask))
    delta = tuple((a - b) % 17 for a, b in zip(query, mask, strict=True))
    assert tuple((a + b) % 17 for a, b in zip(recovered_mask, delta, strict=True)) == query
    deficient = literal.Matrix(((1, 1), (2, 2)), 17, 1, 1)
    with pytest.raises(ValueError, match="uniquely"):
        structured.recover_public_input(deficient, (3, 6))


def test_screen_keeps_unproved_costs_explicit_and_oracle_caps_precede_allocation():
    report = structured.digit_screen(rows=32768, width=1024, columns=32, q=4294955009, query_bound=288, base=256)
    assert report["literal_to_generator_expansion"] == 32
    assert report["optimistic_digit_output_body_bytes"] > report["inner_output_body_bytes"]
    assert not report["admissible_extracted_norm_correctness_established"]
    with pytest.raises(ValueError):
        structured.validate(structured.Operator(128, 17, 1, (1,), ()))
    with pytest.raises(ValueError):
        structured.balanced_digits(1, 2)
