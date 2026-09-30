"""Code floors and full-Q/carry oracle: exact positive and negative controls."""

from contextlib import closing
import itertools

import pytest

from experiments.bfv_search_lab import backend_frontier as frontier
from experiments.bfv_search_lab import ciphertext_linear_oracle as outer
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import dyadic_crt as tree


def test_security_dimension_floor_does_not_shrink_with_data_rank():
    for backend in (frontier.EMVP, frontier.BNTM):
        raw = frontier.code_cost(backend, (32,), (512,))
        small = frontier.code_cost(backend, (32,), (3,))
        assert small["query_body_bytes_model"] == raw["query_body_bytes_model"]
        assert small["response_body_bytes_model"] == raw["response_body_bytes_model"]
        assert small["server_index_word_bytes"] == raw["server_index_word_bytes"]
        split = frontier.code_cost(backend, (8, 8, 8, 8), (3, 3, 3, 3))
        assert split["query_body_bytes_model"] == 4 * small["query_body_bytes_model"]
        assert split["response_body_bytes_model"] == small["response_body_bytes_model"]
        assert not small["parameter_security_is_reviewed"]
    verified = frontier.code_cost(frontier.BNTM, (32,), (3,), verified=True)
    assert verified["client_verified_index_word_bytes_lower_bound"] == 32 * 1024 * 8
    with pytest.raises(ValueError, match="no verification mode"):
        frontier.code_cost(frontier.EMVP, (32,), (3,), verified=True)
    risky = frontier.code_cost(frontier.BNTM, (32,), (512,), query_bound=32768)
    assert not risky["quantized_dot_no_field_wrap"]


def test_literal_ciphertext_matrix_matches_integer_ring_for_all_tiny_inputs():
    s = space.space(tree.layout(tree.context(8, ("0", "1"), 17), (1, 1), (7, 1)), (0, 1))
    groups = [[[i % 2] for i in range(7)], [[-1]]]
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, groups, b"a" * 32, client)
    operator = outer.matrix(index, pk)
    assert outer.shape(s) == (32, 2)
    for values in itertools.product(range(17), repeat=s.dimension):
        actual = outer.evaluate(operator, outer.alpha(s, values))
        assert actual == outer.independent(index, pk, values)
        assert all(0 <= x < pk.q for x in actual)
    with pytest.raises(ValueError, match="work limit"):
        outer.matrix(index, pk, entry_limit=1)


def test_centering_carries_break_naive_outer_field_linearity():
    s = space.space(tree.layout(tree.context(8, ("0", "1"), 17), (1, 1), (1, 1)), (0, 1))
    q = 4294966657
    witness = None
    for a, b in itertools.product(range(17), repeat=2):
        left, right = outer.alpha(s, (a, 0)), outer.alpha(s, (b, 0))
        combined = outer.alpha(s, ((a + b) % 17, 0))
        if any((x + y - z) % q for x, y, z in zip(left, right, combined, strict=True)):
            witness = (a, b)
            break
    assert witness is not None
    # Output reduced to plaintext t loses the actual inner ciphertext residues.
    assert 123456789 % q != 123456789 % 17
    c = outer.cost(s, q)
    assert c["outer_plaintext_modulus_required"] == q
    assert not c["implicit_matrix_supported_by_outer_reference"]
