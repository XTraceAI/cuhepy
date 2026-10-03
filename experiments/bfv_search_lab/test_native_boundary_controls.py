"""E106 complete affine maps, external canonical gates and per-limb controls."""

from dataclasses import replace
from itertools import product
from random import Random

from gmpy2 import mpz
import pytest

from benchmarks.native_boundary_lab import load_fixture, make_fixture
from experiments.bfv_search_lab import native_boundary_controls as controls
from experiments.bfv_search_lab import native_boundary_oracle as oracle


@pytest.fixture(scope="module")
def fixture(tmp_path_factory):
    # A separate supported test setup; never overwrite/reuse the main fixture.
    path = tmp_path_factory.mktemp("native-boundary-affine-control")/"fixture.json"
    make_fixture(path)
    return load_fixture(path)


@pytest.fixture(scope="module")
def compiled(fixture):
    return controls.compile_residual(fixture[1])


@pytest.mark.parametrize("position", range(8))
def test_complete_affine_features_match_actual_integer_replay_all_queries_and_tail(fixture, compiled, position):
    data, ctx = fixture[:2]
    packet = bytes.fromhex(data["queries"][position]["packet_hex"])
    trace = oracle.replay(ctx, packet)
    query = oracle.expand_query(ctx, packet)
    flat = controls.features(ctx, tuple(tuple(map(mpz, poly)) for poly in query), trace.cuts, trace.preterminal)
    assert len(flat) == compiled.feature_count+compiled.output_count == 368
    assert not any(controls.residuals(compiled, flat))
    assert compiled.cut_labels == tuple(cut.label for cut in trace.cuts)
    assert compiled.feature_count == 336 and compiled.output_count == 32 and compiled.residual_count == 112
    assert compiled.cut_labels[-2:] == ("group1:stage0:node0", "group1:stage1:node0")
    rng = Random(10600+position)
    rows = controls.compile_private_rows(compiled, k=3, randbelow=rng.randrange)
    assert controls.check_rows(compiled, rows, flat)


def test_every_adjoint_is_literal_transpose_with_zero_RHS_weights_discarded(compiled):
    rng = Random(10610)
    values = tuple(rng.randrange(compiled.q) for _ in range(compiled.feature_count+compiled.output_count))
    errors = controls.residuals(compiled, values)
    for prime in compiled.primes:
        weights = tuple(rng.randrange(prime) for _ in range(compiled.residual_count))
        row = controls.compile_adjoint(compiled, prime, weights)
        observed = (sum(a*b for a, b in zip(row.hints, values[:compiled.feature_count], strict=True))
                    -sum(a*b for a, b in zip(row.output_weights, values[compiled.feature_count:], strict=True))) % prime
        assert observed == sum(a*b for a, b in zip(weights, errors, strict=True)) % prime
        assert row.output_weights == weights[-compiled.output_count:]
        assert not hasattr(row, "weights")  # No retained full source challenge.


def test_false_digit_kernel_with_honest_final_output_passes_affine_rows_only(fixture, compiled):
    data, ctx = fixture[:2]
    packet = bytes.fromhex(data["queries"][0]["packet_hex"])
    trace = oracle.replay(ctx, packet)
    fake, rank = oracle.false_digit_cut(ctx, trace.cuts[0], ctx.relin)
    bad = replace(trace, cuts=(fake,)+trace.cuts[1:])
    assert rank <= 3*ctx.n < ctx.levels*ctx.n
    assert oracle.replay(ctx, packet, bad, canonical=False).packet == trace.packet
    flat = controls.features(ctx, oracle.expand_query(ctx, packet), bad.cuts, bad.preterminal)
    assert not any(controls.residuals(compiled, flat))
    rows = controls.compile_private_rows(compiled, randbelow=Random(10611).randrange)
    assert controls.check_rows(compiled, rows, flat)
    with pytest.raises(ValueError, match="Noncanonical"):
        oracle.replay(ctx, packet, bad)


@pytest.mark.parametrize("limb", (0, 1))
def test_corruption_in_one_CRT_limb_requires_that_limb_not_an_honest_limb_bound(fixture, compiled, limb):
    data, ctx = fixture[:2]
    packet = bytes.fromhex(data["queries"][1]["packet_hex"])
    trace = oracle.replay(ctx, packet)
    flat = list(controls.features(ctx, oracle.expand_query(ctx, packet), trace.cuts, trace.preterminal))
    prime, other = ctx.primes[limb], ctx.primes[1-limb]
    delta = other*pow(other, -1, prime)
    flat[compiled.feature_count] = (flat[compiled.feature_count]+delta) % compiled.q
    flat = tuple(flat)
    errors = controls.residuals(compiled, flat)
    assert any(x % prime for x in errors) and not any(x % other for x in errors)
    weights = (0,)*(compiled.residual_count-compiled.output_count)+(1,)+(0,)*(compiled.output_count-1)
    wrong = controls.compile_adjoint(compiled, prime, weights)
    honest = controls.compile_adjoint(compiled, other, weights)
    assert not controls.check_adjoint(wrong, flat) and controls.check_adjoint(honest, flat)


def test_equal_weights_can_hide_coordinated_errors_but_independent_rows_do_not(fixture, compiled):
    data, ctx = fixture[:2]
    packet = bytes.fromhex(data["queries"][2]["packet_hex"])
    trace = oracle.replay(ctx, packet)
    flat = list(controls.features(ctx, oracle.expand_query(ctx, packet), trace.cuts, trace.preterminal))
    for i, delta in ((0, 1), (1, -1)):
        at = compiled.feature_count+i
        flat[at] = (flat[at]+delta) % compiled.q
    flat = tuple(flat)
    cut_rows = compiled.residual_count-compiled.output_count
    for prime in compiled.primes:
        linked = (0,)*cut_rows+(1, 1)+(0,)*(compiled.output_count-2)
        independent = (0,)*cut_rows+(1, 0)+(0,)*(compiled.output_count-2)
        assert controls.check_adjoint(controls.compile_adjoint(compiled, prime, linked), flat)
        assert not controls.check_adjoint(controls.compile_adjoint(compiled, prime, independent), flat)


def test_full_residual_rank_and_feature_rank_are_separate_inventory_not_entropy_lower_bounds(compiled):
    inventory = controls.rank_inventory(compiled)
    for prime in compiled.primes:
        row = inventory[str(prime)]
        assert row["complete_residual_map_rank"] == compiled.residual_count == 112
        assert 80 <= row["feature_only_map_rank"] <= 112
        assert row["including_terminal_preimage_columns"] == 368


def test_exhaustive_nonbasis_uniform_field_residuals_and_two_attempt_aggregate_feedback():
    counted = controls.uniform_residual_exhaustion()
    assert counted["checks"] == 15500 and counted["nonzero_residuals"] == 124
    assert counted["maximum_accept_count"] == 25 and counted["one_row_exact_miss_probability"] == [1, 5]
    # Each next false error on the all-reject branch is fixed; one aggregate bit.
    first_wrong = 0
    for entries in product(range(3), repeat=4):
        first = entries[0] == entries[2] == 0
        second = not first and entries[1] == entries[3] == 0
        first_wrong += first or second
    assert first_wrong == 17 and first_wrong*9 <= 2*81


def test_paid_actual_and_illustrative_counts_include_terminal_and_discardable_weights(fixture):
    ctx = fixture[1]
    card = controls.paidcost_cards(ctx)
    assert (card["tiles"], card["active_group_sizes"], card["replies"]) == (5, (4, 1), 2)
    assert (card["product_relinearization_cuts"], card["butterfly_cuts"], card["terminal_coordinate_relations"]) == (5, 5, 32)
    assert (card["source_and_terminal_witness_packed_bytes"], card["source_and_terminal_witness_two_uint64_RNS_bytes"]) == (1680, 1792)
    assert card["compact_response_coefficient_body_bytes"] == 128
    assert card["dense_hint_and_retained_weights_packed_bytes"] == 22080
    assert card["discardable_zero_RHS_source_weights_per_prime"] == 320
    assert (card["native_pointwise_ring_products_per_prime"], card["native_online_forward_NTTs_per_prime"],
            card["native_online_inverse_NTTs_per_prime"]) == (100, 42, 35)
    model = controls.cost_card(n=8192, padded=512, records=8192, q_bits=120, digit_bits=30, terminal_bits=32)
    assert (model["tiles"], model["butterfly_cuts"]) == (512, 511)
    assert model["source_witness_packed_bytes"] == 125706240
    assert model["terminal_coordinate_relations"] == 16384
    assert model["terminal_quotient_range_proof_bytes_or_prover_cost_unknown"]
    assert model["word_counts_are_not_RSS_hardware_cycles_or_witness_lower_bounds"]
    assert model["native_constructor_auxiliary_transforms_CRT_bases_and_allocations_additional_unpriced"]


def test_two_uint64_native_count_card_rejects_other_modulus_widths():
    # The selected two 60-bit-prime profile cannot price three/four-limb Q180/Q240.
    for q_bits in (32, 60, 119, 121, 180, 240):
        with pytest.raises(ValueError, match="native count geometry"):
            controls.cost_card(n=8, padded=4, records=9, q_bits=q_bits, digit_bits=30, terminal_bits=32)


def test_registration_draw_order_includes_every_residual_coordinate_in_both_primes(compiled):
    calls = []
    def zero_sampler(prime):
        calls.append(prime)
        return 0
    rows = controls.compile_private_rows(compiled, k=2, randbelow=zero_sampler)
    assert calls == [compiled.primes[0]]*(2*compiled.residual_count)+[compiled.primes[1]]*(2*compiled.residual_count)
    # Caller-selected zero rows are only an arithmetic test seam, not a gate.
    assert controls.check_rows(compiled, rows, (1,)*(compiled.feature_count+compiled.output_count))


@pytest.mark.parametrize("mutation", ("query_bool", "cut_order", "preterminal_shape"))
def test_malformed_structural_features_are_rejected_before_private_row_arithmetic(fixture, mutation):
    data, ctx = fixture[:2]
    packet = bytes.fromhex(data["queries"][0]["packet_hex"])
    trace, query = oracle.replay(ctx, packet), oracle.expand_query(ctx, packet)
    cuts, output = trace.cuts, trace.preterminal
    if mutation == "query_bool":
        query = ((True,)+query[0][1:], query[1])
    elif mutation == "cut_order":
        cuts = cuts[::-1]
    else:
        output = output[:-1]
    with pytest.raises(ValueError):
        controls.features(ctx, query, cuts, output)


def test_wrong_context_or_missing_prime_family_cannot_select_an_unguarded_check(compiled):
    rows = controls.compile_private_rows(compiled, k=1, randbelow=Random(10612).randrange)
    values = (0,)*(compiled.feature_count+compiled.output_count)
    with pytest.raises(ValueError, match="Both field"):
        controls.check_rows(compiled, rows[:1], values)
    bad = ((replace(rows[0][0], context_digest="00"*32),), rows[1])
    with pytest.raises(ValueError, match="context"):
        controls.check_rows(compiled, bad, values)
    with pytest.raises(ValueError, match="weights"):
        controls.compile_adjoint(compiled, compiled.primes[0], (True,)*compiled.residual_count)
    with pytest.raises(ValueError, match="prime"):
        controls.rank_mod(((1,),), 9)
