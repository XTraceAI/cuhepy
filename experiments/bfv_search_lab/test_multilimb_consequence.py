"""E120 small public controls; the registered N16384 profile is main-only."""

from dataclasses import replace

import msgpack
import pytest

from experiments.bfv_search_lab import multilimb_consequence as lab


def toy_context():
    # A public arithmetic fixture, not a source-selected RNS/HE key context.
    return lab.Context(lab.Graph(8, 2, 9, 5, 1, 4), 4294967291, 65521)


@pytest.mark.parametrize("value", [0, 127, 128, 255, 256, 65535, 65536, (1 << 32)-1, 1 << 32])
def test_unsigned_framing_matches_canonical_msgpack(value):
    assert lab.uint_size(value) == len(msgpack.packb(value, use_bin_type=True))


@pytest.mark.parametrize("length", [0, 31, 32, 255, 256, 65535, 65536])
def test_binary_and_utf8_framing_transitions_match_emitted_shapes(length):
    assert lab.binary_size(length) == len(msgpack.packb(bytes(length), use_bin_type=True))
    assert lab.string_size("x"*length) == len(msgpack.packb("x"*length, use_bin_type=True))


@pytest.mark.parametrize("length", [0, 15, 16, 65535, 65536])
def test_array_headers_match_serializer_without_allocating_arrays(length):
    assert lab.array_size(length) == len(msgpack.Packer().pack_array_header(length))


@pytest.mark.parametrize("drop", [0, 1, 7, 16, 31])
def test_full_query_schema_matches_fixed_dummyshape_frames(drop):
    ctx = toy_context()
    card = lab.query_schema(ctx, drop)
    fields = [lab.SEEDED_TAG if drop == 0 else lab.ROUNDED_TAG, b"k"*32, b"s"*32]
    if drop:
        fields.append(drop)
    fields.append(bytes(card["body_bytes"]))
    assert card["query_packet_bytes"] == len(msgpack.packb(fields, use_bin_type=True))
    assert card["field_count"] == len(fields)


def test_both_response_components_all_groups_and_terminal_bits_match_shape():
    ctx = toy_context()
    card = lab.response_schema(ctx)
    header = [lab.COMPACT_TAG, 8, 5, ctx.p.to_bytes(card["terminal_field_bytes"], "little"), b"k"*32, 9, 2]
    body = [[bytes(card["response_poly_bytes"])]*2 for _ in range(card["response_ciphertexts"])]
    assert card["response_packet_bytes"] == len(msgpack.packb([header, body], use_bin_type=True))
    assert card["response_ciphertexts"] == 2 and card["all_output_coefficients"] == 16
    assert card["response_poly_bytes"] == 16  #16-bit P, not four-byte staging.


def test_codec_word_monotonicity_and_support_with_last_radix_bin():
    ctx = toy_context()
    # Literal small coefficients, including high-part odd/even and a final bin.
    for c in (0, 1, 4, 31, 32, 33, ctx.q-1):
        for drop in (1, 7, 16, 30):
            word = (c//(1 << drop))*5+(c % (1 << drop)) % 5
            next_word = (c//(1 << (drop+1)))*5+(c % (1 << (drop+1))) % 5
            assert next_word <= word
            enc = lab.coefficient_encoding(ctx, drop)
            delta = 5*(enc["center"]//5-(c % (1 << drop))//5)
            assert abs(delta) <= enc["added_bound"]
    assert lab.query_schema(ctx, 31)["query_packet_bytes"] <= lab.query_schema(ctx, 30)["query_packet_bytes"]


def test_exact_integer_inversion_matches_small_toy_boundary_exhaustion():
    ctx = toy_context()
    for law in ("broad", "canonical"):
        admissible = []
        for drop in range(ctx.q.bit_length()):
            enc = lab.coefficient_encoding(ctx, drop)
            g, d = ctx.graph, 2
            switch = lab.switch_envelope(ctx, law)["switch_bound"]
            final = d*(2*6+8*5*6*(1+enc["added_error_units"]))+3*switch
            terminal = (ctx.p*final+ctx.q-1)//ctx.q+23
            if 2*final < ctx.q and 2*terminal < ctx.p:
                admissible.append(drop)
        baseline = lab.deterministic_baseline(ctx, law)
        assert baseline["drop"] == max(admissible)
        assert not baseline["immediate_successor"]["envelope_admitted"]


def test_safe_radius_equivalent_to_original_strict_terminal_at_adjacent_values():
    ctx = toy_context()
    safe = lab.terminal_safe(ctx)["safe_q_phase_radius"]
    rounding = lab.terminal_safe(ctx)["rounding_bound"]
    for final in (0, safe-1, safe, safe+1, (ctx.q-1)//2):
        strict = 2*final < ctx.q and 2*((ctx.p*final+ctx.q-1)//ctx.q+rounding) < ctx.p
        assert strict == (final <= safe)


def test_canonical_common_word_cap_exhaustion_is_not_broad_bounded_word_cap():
    q, bits = 257, 4
    values = [(sum((c >> j) & 15 for j in range(0, q.bit_length(), 4)), c) for c in range(q)]
    maximum, witness = lab.maximum_digit_sum(q, bits)
    assert maximum == max(v for v, _ in values)
    assert next(v for v, c in values if c == witness) == maximum
    assert maximum < 3*15  #The broad word4095 is validly bounded but not<Q.


def test_single_candidate_binary_boundary_matches_toy_format_control():
    #This positive arithmetic-shape branch uses N64; the N8 fixed headers can
    #erase every5% candidate. Neither toy is the registered main profile.
    ctx = replace(toy_context(), graph=lab.Graph(64, 2, 1, 5, 1, 4))
    baseline = lab.deterministic_baseline(ctx, "canonical")
    selected = lab.select_candidate(ctx, baseline)
    denom = selected["baseline_exchange_bytes"]
    candidates = [b for b in range(baseline["drop"]+1, ctx.q.bit_length())
                  if 20*(lab.query_schema(ctx, b)["query_packet_bytes"]+
                         lab.response_schema(ctx)["response_packet_bytes"]) <= 19*denom]
    assert selected["candidate"]["drop"] == min(candidates)
    assert not selected["immediate_predecessor"]["meets5percent"]
    assert selected["format_probe_count"] <= selected["format_probe_budget"]


def test_no_candidate_is_a_stop_and_forged_baseline_cannot_set_denominator():
    ctx = toy_context()
    #Response dominance on a larger tiny corpus can eliminate every format gain.
    large_reply = replace(ctx, graph=replace(ctx.graph, count=512))
    selected = lab.select_candidate(large_reply, lab.deterministic_baseline(large_reply, "canonical"))
    assert selected["candidate"] is None and selected["stop"]
    forged = lab.deterministic_baseline(ctx, "canonical")
    forged["drop"] -= 1
    with pytest.raises(ValueError):
        lab.select_candidate(ctx, forged)


def test_nonzero_ternary_prime_caps_preserve_source_order_and_reject_repeated_factors():
    certificate = lab.norm_prefix(8, (97, 17))
    assert certificate["limb_nullity_caps"] == (1, 2)
    assert certificate["prefix_length"] == 6
    assert certificate["source_order_primes"] == (97, 17)
    with pytest.raises(ValueError):
        lab.norm_prefix(8, (17, 17))
    with pytest.raises(ValueError):
        lab.norm_prefix(8, (17, 25))


def test_suffix_negative_is_stop_and_forged_certificate_rejects(monkeypatch):
    ctx = toy_context()
    cert = {"n": 8, "q_product": ctx.q, "source_order_primes": (17,), "common_nullity_cap": 2}
    monkeypatch.setattr(lab, "norm_prefix", lambda n, primes: cert)
    #Independent formula; no actual image/secret or main-profile norm work.
    actual = lab.suffix_screen(ctx, 31, cert)
    g = ctx.graph
    switch = lab.switch_envelope(ctx, "broad")["switch_bound"]
    h = (lab.terminal_safe(ctx)["safe_q_phase_radius"]-3*switch)//2-2*6+1
    suffix = 2*5*6*(1+lab.coefficient_encoding(ctx, 31)["added_error_units"])
    assert actual["retained_threshold"] == h-suffix
    assert actual["suffix_consumes_margin"] and not actual["probability_calculated"]
    cert["q_product"] += 2
    with pytest.raises(ValueError):
        lab.suffix_screen(ctx, 31, cert)


@pytest.mark.parametrize("margin,stopped", [(-1, True), (0, True), (1, False)])
def test_abstract_suffix_threshold_classification_preserves_strictness(monkeypatch, margin, stopped):
    #Arithmetic branch unit only: the synthetic radius is NOT a new profile.
    ctx = toy_context()
    cert = {"n": 8, "q_product": ctx.q, "source_order_primes": (17,), "common_nullity_cap": 2}
    monkeypatch.setattr(lab, "norm_prefix", lambda n, primes: cert)
    suffix = 2*5*6*(1+lab.coefficient_encoding(ctx, 7)["added_error_units"])
    maintenance = 3*lab.switch_envelope(ctx, "broad")["switch_bound"]
    monkeypatch.setattr(lab, "terminal_safe", lambda _: {"safe_q_phase_radius": maintenance+2*(suffix+margin+11)})
    actual = lab.suffix_screen(ctx, 7, cert)
    assert actual["retained_threshold"] == margin
    assert actual["suffix_consumes_margin"] == stopped and not actual["probability_calculated"]


def test_capped_source_selector_records_the_exact_call_contract(monkeypatch):
    calls = []
    monkeypatch.setattr(lab.gmpy2, "is_prime", lambda *args: calls.append(args) or False)
    with pytest.raises(RuntimeError):
        lab.reproduce_rns_primes(8, 60, cap=3)
    assert len(calls) == 3 and all(len(c) == 1 for c in calls)
    assert calls[0][0]-calls[1][0] == 16
    calls.clear()
    with pytest.raises(RuntimeError):
        lab.reproduce_terminal_modulus(4294967291, 5, 16, cap=3)
    assert len(calls) == 3 and all(c[1] == 32 for c in calls)
    assert calls[0][0]-calls[1][0] == 10


@pytest.mark.parametrize("value", [True, 1.0, -1, 1 << 32])
def test_framing_exact_integer_domains(value):
    for func in (lab.array_size, lab.binary_size):
        with pytest.raises(ValueError):
            func(value)


@pytest.mark.parametrize("value", [True, 1.0, -1, 1 << 64])
def test_unsigned_size_rejects_numeric_aliases_and_overflow(value):
    with pytest.raises(ValueError):
        lab.uint_size(value)


@pytest.mark.parametrize("mutation", ["float", "bool", "zero_count", "even_t", "dimension", "radix"])
def test_graph_strict_numbers_layout_and_error_law(mutation):
    changes = {"float": {"n": 8.0}, "bool": {"eta": True}, "zero_count": {"count": 0},
               "even_t": {"t": 6}, "dimension": {"dimension": 5}, "radix": {"digit_bits": 3}}[mutation]
    with pytest.raises(ValueError):
        replace(toy_context().graph, **changes).validate()


@pytest.mark.parametrize("changes", [{"q": True}, {"q": 4294967291.0}, {"p": 65521.0},
                                      {"p": 65525}, {"p": 4294967291}, {"q": 4294967295}])
def test_context_exact_odd_coprime_prime_terminal_and_congruence(changes):
    with pytest.raises(ValueError):
        replace(toy_context(), **changes).validate()


@pytest.mark.parametrize("drop", [True, 1.0, -1, 32])
def test_encoding_strict_drop_domain(drop):
    with pytest.raises(ValueError):
        lab.coefficient_encoding(toy_context(), drop)


def test_selector_and_norm_caps_reject_numeric_aliases_and_unregistered_caps():
    with pytest.raises(ValueError):
        lab.reproduce_rns_primes(True, 60)
    with pytest.raises(ValueError):
        lab.reproduce_rns_primes(8, 60, cap=4097)
    with pytest.raises(ValueError):
        lab.reproduce_terminal_modulus(4294967291, 5, True)
    with pytest.raises(ValueError):
        lab.norm_prefix(8, [17, 97])
    with pytest.raises(ValueError):
        lab.norm_prefix(8, (17, True))
    with pytest.raises(ValueError):
        lab.reproduce_terminal_modulus((1 << 241)+1, 5, 16)
