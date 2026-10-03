"""Complete tiny functional-gadget identities and release-boundary controls."""

from dataclasses import replace
from pathlib import Path

import pytest

from experiments.bfv_search_lab import functional_orbit as lab
from experiments.bfv_search_lab import native_boundary_oracle as ring


@pytest.fixture(scope="module")
def setup():
    path = Path(__file__).resolve().parents[3]/"research-data/native-boundary-20261003/frozen-fixture.json"
    fixture, ctx, secret = lab.load_fixture(path)
    return fixture, ctx, secret, lab.prepare(ctx, secret)


@pytest.mark.parametrize("query_number", range(8))
def test_all_coefficients_scores_partial_tail_ties_and_actual_error_identities(setup, query_number):
    fixture, ctx, secret, enrollment = setup
    item = fixture["queries"][query_number]
    query = bytes.fromhex(item["packet_hex"])
    results = [lab.evaluate(ctx, enrollment, query, mode) for mode in lab.MODES]
    plain = []
    truth = tuple(sum(a != b for a, b in zip(item["bits"], row, strict=True)) for row in fixture["rows"])
    for result in results:
        parsed = lab.checked_release(ctx, enrollment, query, result, lambda p: ring.parse_response(ctx, p))
        phases, scores, top = ring.decrypt_and_rank(ctx, parsed, secret)
        plain.append(tuple(tuple(x % ctx.t for x in p) for p in phases))
        assert scores == truth
        assert top == tuple((i, truth[i]) for i in sorted(ctx.ids, key=lambda i: (truth[i], i))[:3])
        assert len(result.preterminal) == 2 and len(parsed) == 2
    assert plain[0] == plain[1] == plain[2]
    assert [len(r.rotation_cuts) for r in results] == [10, 5, 0]
    assert [len(r.query_sources) for r in results] == [0, 1, 8]
    assert [dict(r.counts)["ring_products"] for r in results] == [100, 90, 128]
    card = lab.fresh_error_card(ctx, enrollment, query, secret)
    assert len(card["product_tiles"]) == 5 and len(card["full_orbit_responses"]) == 2
    assert all(row["actual_fresh_error_linf"] <= row["absolute_bound"] for rows in card.values() for row in rows)


def test_full_orbits_match_direct_phase_butterfly_without_switch_error(setup):
    _, ctx, secret, enrollment = setup
    expected = lab.compile_orbits(ctx, tuple(lab.phase(c, secret, ctx.q) for c in ctx.index))
    assert [[g for g, _ in terms] for terms in expected] == [[1, 5, 9, 13], [1, 5, 9, 13]]
    assert expected == tuple(tuple((o.exponent, o.coefficient) for o in family) for family in enrollment.responses)
    # The one-tile tail still has all four functional orbits; no tail omitted.
    assert len(enrollment.responses[1]) == 4


@pytest.mark.parametrize("tile,row", [(0, 0), (4, 3)])
def test_raw_Q_keys_target_index_phase_not_plaintext_API(setup, tile, row):
    _, ctx, secret, enrollment = setup
    key = enrollment.product[tile][row]
    target = ring.multiply(secret, lab.phase(ctx.index[tile], secret, ctx.q), ctx.q)
    target = tuple(x*(1 << (ctx.digit_bits*row)) % ctx.q for x in target)
    assert lab.phase(key.cipher, secret, ctx.q) == ring.add(target, tuple(ctx.t*x % ctx.q for x in key.error), ctx.q)
    if row:
        reduced = tuple(x % ctx.t for x in target)
        assert reduced != target
        assert lab.phase(key.cipher, secret, ctx.q) != ring.add(reduced, tuple(ctx.t*x % ctx.q for x in key.error), ctx.q)


def test_common_RNS_source_digits_reject_independent_limb_digits_and_numeric_alias(setup):
    _, ctx, _, _ = setup
    source = (ctx.q//2,)+(0,)*(ctx.n-1)
    rows = lab.digits(ctx, source)
    lab.validate_digits(ctx, source, rows)
    one_limb = lab.digits(ctx, tuple(x % ctx.primes[0] for x in source))
    assert one_limb != rows
    with pytest.raises(ValueError):
        lab.validate_digits(ctx, source, one_limb)
    zero = (0,)*ctx.n
    numeric_alias = ((False,)+(0,)*(ctx.n-1),)+lab.digits(ctx, zero)[1:]
    with pytest.raises(ValueError):
        lab.validate_digits(ctx, zero, numeric_alias)


def test_paid_storage_and_cut_model_gives_full_control_identical_sharing(setup):
    _, ctx, _, enrollment = setup
    card = lab.cost_card(ctx, enrollment)
    assert card["tiles"] == 5 and card["rotations"] == 5
    assert card["full_compiled_terms_after_equal_orbit_aggregation"] == 8
    assert card["terminal_coordinates"] == 32 and card["terminal_body_bytes"] == 128
    assert [v["active_server_packed_Q_bytes"] for v in card["models"].values()] == [4080, 7920, 15360]
    assert [v["E108_shared_source_terminal_boolean_input_model"] for v in card["models"].values()] == [26880, 17280, 7680]
    assert [v["fresh_raw_key_ciphertexts"] for v in card["models"].values()] == [0, 20, 64]


def test_fullQ_fresh_rotation_and_scaled_ordinary_key_noise_shortcuts_fail_bound(setup):
    _, ctx, secret, _ = setup
    card = lab.amplification_card(ctx, secret)
    bound = card["bounded_one_component_gadget_error_bound"]
    assert card["fresh_rotated_index_wide_coefficient_error_linf"] > bound*10**20
    assert max(row["scaled_key_error_linf"] for row in card["uniform_index_coefficient_times_ordinary_key_error"]) > bound*10**20


@pytest.mark.parametrize("mode", lab.MODES)
@pytest.mark.parametrize("change", ("query", "epoch", "key", "output", "packet", "mode"))
def test_substitution_rejected_before_private_callback(setup, mode, change):
    fixture, ctx, _, enrollment = setup
    query = bytes.fromhex(fixture["queries"][0]["packet_hex"])
    candidate = lab.evaluate(ctx, enrollment, query, mode)
    if change == "query":
        query = bytes.fromhex(fixture["queries"][1]["packet_hex"])
    elif change == "epoch":
        enrollment = replace(enrollment, epoch="wrong-epoch")
    elif change == "key":
        key = enrollment.product[0][0]
        c0 = ((key.cipher[0][0]+1) % ctx.q,)+key.cipher[0][1:]
        changed = replace(key, cipher=(c0, key.cipher[1]))
        enrollment = replace(enrollment, product=((changed,)+enrollment.product[0][1:],)+enrollment.product[1:])
    elif change == "output":
        cipher = candidate.preterminal[0]
        changed = (((cipher[0][0]+1) % ctx.q,)+cipher[0][1:], cipher[1])
        candidate = replace(candidate, preterminal=(changed,)+candidate.preterminal[1:])
    elif change == "packet":
        candidate = replace(candidate, packet=candidate.packet[:-1]+bytes([candidate.packet[-1] ^ 1]))
    else:
        candidate = replace(candidate, mode=lab.MODES[(lab.MODES.index(mode)+1) % 3])
    calls = []
    with pytest.raises(ValueError):
        lab.checked_release(ctx, enrollment, query, candidate, lambda p: calls.append(p))
    assert calls == []


@pytest.mark.parametrize("mode", ("product-only", "full-orbit"))
def test_false_query_digits_and_one_limb_source_mutation_rejected(setup, mode):
    fixture, ctx, _, enrollment = setup
    query = bytes.fromhex(fixture["queries"][0]["packet_hex"])
    result = lab.evaluate(ctx, enrollment, query, mode)
    label, source, rows = result.query_sources[0]
    wrong = (((rows[0][0]+1) % (1 << ctx.digit_bits),)+rows[0][1:],)+rows[1:]
    calls = []
    for changed in ((label, source, wrong), (label, ((source[0]+ctx.primes[0]) % ctx.q,)+source[1:], rows)):
        candidate = replace(result, query_sources=(changed,)+result.query_sources[1:])
        with pytest.raises(ValueError):
            lab.checked_release(ctx, enrollment, query, candidate, lambda p: calls.append(p))
    assert calls == []


def test_disclosed_coin_generation_reproducible_and_independent_key_families(setup):
    _, ctx, secret, enrollment = setup
    assert lab.prepare(ctx, secret) == enrollment
    assert enrollment.product[0][0].cipher != ctx.relin[0]
    assert enrollment.responses[0][0].left[0] != enrollment.responses[0][0].right[0]


def test_strict_output_and_count_aliases_rejected_before_callback(setup):
    fixture, ctx, _, enrollment = setup
    query = bytes.fromhex(fixture["queries"][0]["packet_hex"])
    result = lab.evaluate(ctx, enrollment, query, "full-orbit")
    bad_counts = tuple((key, float(value)) for key, value in result.counts)
    cipher = result.preterminal[0]
    alias = ((float(cipher[0][0]),)+cipher[0][1:], cipher[1])
    calls = []
    for candidate in (replace(result, counts=bad_counts), replace(result, preterminal=(alias,)+result.preterminal[1:])):
        with pytest.raises(ValueError):
            lab.checked_release(ctx, enrollment, query, candidate, lambda p: calls.append(p))
    assert calls == []


def test_product_only_false_canonical_rotation_preserves_output_but_rejects(setup):
    fixture, ctx, _, enrollment = setup
    query = bytes.fromhex(fixture["queries"][0]["packet_hex"])
    result = lab.evaluate(ctx, enrollment, query, "product-only")
    cut = result.rotation_cuts[0]
    false, _ = ring.false_digit_cut(ctx, cut, ctx.rotations[0][1])
    assert false.source == cut.source and false.output == cut.output and false.digits != cut.digits
    calls = []
    candidate = replace(result, rotation_cuts=(false,)+result.rotation_cuts[1:])
    with pytest.raises(ValueError):
        lab.checked_release(ctx, enrollment, query, candidate, lambda p: calls.append(p))
    assert calls == []


def test_full_complete_wire_rejects_unused_coefficient_despite_same_scores(setup):
    fixture, ctx, secret, enrollment = setup
    query = bytes.fromhex(fixture["queries"][0]["packet_hex"])
    result = lab.evaluate(ctx, enrollment, query, "full-orbit")
    compact = ring.parse_response(ctx, result.packet)
    tail = compact[1]
    changed = ((tail[0][0], (tail[0][1]+1) % ctx.p)+tail[0][2:], tail[1])
    modified = (compact[0], changed)
    assert ring.decrypt_and_rank(ctx, modified, secret)[1:] == ring.decrypt_and_rank(ctx, compact, secret)[1:]
    candidate = replace(result, packet=ring.serialize(ctx, modified))
    calls = []
    with pytest.raises(ValueError):
        lab.checked_release(ctx, enrollment, query, candidate, lambda p: calls.append(p))
    assert calls == []
