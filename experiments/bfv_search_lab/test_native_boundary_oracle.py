"""Complete native BGV byte boundary, false-trace and pre-private-use regressions."""

from dataclasses import replace
from itertools import product

from gmpy2 import mpz
import msgpack
import pytest

from benchmarks.native_boundary_lab import make_fixture, load_fixture, scalar_exhaustion, boundary_inputs
from experiments.bfv_search_lab import native_boundary_oracle as lab
from experiments.bfv_search_lab import compressed_query_bgv as codec, compact_bgv as compact
from experiments.bfv_search_lab import transport_bgv as wire, results_bgv as results
from experiments.bfv_search_lab.native_bgv import NativeServer
from experiments.bfv_search_lab.owner_bgv import OwnerClient
from experiments.bfv_search_lab.private_bgv import PrivateDecoder


@pytest.fixture(scope="module")
def fixture(tmp_path_factory):
    path = tmp_path_factory.mktemp("e106")/'frozen.json'
    make_fixture(path)
    return load_fixture(path)


@pytest.fixture(scope="module")
def honest(fixture):
    data, ctx, *_ = fixture
    packet = bytes.fromhex(data['queries'][0]['packet_hex'])
    return packet, lab.replay(ctx, packet)


def rejected_before_private(ctx, query, candidate):
    calls = []
    with pytest.raises(ValueError):
        lab.checked_release(ctx, query, candidate, lambda packet: calls.append(packet))
    assert calls == []


@pytest.mark.parametrize("query_number", range(8))
def test_original_packet_to_native_full_coefficients_wire_private_finish_and_ties(fixture, query_number):
    data, ctx, pk, sk, keys, index = fixture
    item = data['queries'][query_number]
    original = bytes.fromhex(item['packet_hex'])
    query = codec.expand(original, pk, dropped_bits=58, backend="native")
    assert lab.expand_query(ctx, original) == tuple(tuple(int(x) for x in p) for p in query.components)
    server = NativeServer(pk, keys, residue=True)
    prepared = server.prepare_index(index, 9)
    before = server.search(query, prepared)
    expected = lab.replay(ctx, original)
    assert expected.preterminal == tuple(tuple(tuple(int(x) for x in p) for p in c.components) for c in before)
    reduced = server.search_compact(query, prepared, bits=32)
    packet = compact.pack(reduced, 9, 3, pk)
    assert expected.packet == packet
    assert len(expected.cuts) == 10 and len(expected.rounding) == 32
    coefficients = lab.parse_response(ctx, packet)
    phases, scores, top = lab.decrypt_and_rank(ctx, coefficients, tuple(data['secret']))
    truth = tuple(sum(a != b for a, b in zip(item['bits'], row, strict=True)) for row in data['rows'])
    assert scores == truth
    assert top == tuple((i, truth[i]) for i in sorted(range(9), key=lambda i: (truth[i], i))[:3])
    pairs = wire._unpack_fields(packet, pk, count=9, dimension=3, modulus=mpz(ctx.p),
                                bounds=[c.phase_bound for c in reduced])
    with PrivateDecoder(pk, sk, bits=32) as decoder:
        plaintexts = lab.checked_release(ctx, original, expected, lambda _: decoder.decode_packed(pairs))
        assert tuple(tuple(x % ctx.t for x in p) for p in phases) == tuple(tuple(p) for p in plaintexts)
        finish = results.finish(plaintexts, 9, 3, pk, method="heap")
        assert finish.top == top and finish.distances == scores
    owner = OwnerClient(pk, sk, native=True, rns=True)
    try:
        assert owner.finish_packed_fixture(packet, expected.packet, 9, 3,
                                          bounds=[c.phase_bound for c in reduced], bits=32) == finish
    finally:
        owner.close()


@pytest.mark.parametrize("cut_number,field", product(range(10), ("source", "digits", "output")))
def test_every_switch_relation_is_checked_before_private_use(fixture, honest, cut_number, field):
    _, ctx, *_ = fixture
    query, transcript = honest
    cut = transcript.cuts[cut_number]
    if field == 'source':
        changed = replace(cut, source=((cut.source[0]+ctx.primes[0]) % ctx.q,)+cut.source[1:])
    elif field == 'digits':
        changed = replace(cut, digits=(((cut.digits[0][0]+1),)+cut.digits[0][1:],)+cut.digits[1:])
    else:
        changed = replace(cut, output=(((cut.output[0][0]+1) % ctx.q,)+cut.output[0][1:], cut.output[1]))
    cuts = transcript.cuts[:cut_number]+(changed,)+transcript.cuts[cut_number+1:]
    rejected_before_private(ctx, query, replace(transcript, cuts=cuts))


@pytest.mark.parametrize("coordinate,field", product(range(32), ("source", "lift", "output")))
def test_all_terminal_coordinates_and_padding_are_checked(fixture, honest, coordinate, field):
    _, ctx, *_ = fixture
    query, transcript = honest
    cell = transcript.rounding[coordinate]
    changed = replace(cell, **{field: getattr(cell, field)+1})
    cells = transcript.rounding[:coordinate]+(changed,)+transcript.rounding[coordinate+1:]
    rejected_before_private(ctx, query, replace(transcript, rounding=cells))


def test_honest_output_false_digit_kernel_passes_affine_only_but_not_complete_check(fixture, honest):
    _, ctx, *_ = fixture
    query, transcript = honest
    fake, rank = lab.false_digit_cut(ctx, transcript.cuts[0], ctx.relin)
    assert rank <= 3*ctx.n < ctx.levels*ctx.n
    bad = replace(transcript, cuts=(fake,)+transcript.cuts[1:])
    assert lab.replay(ctx, query, bad, canonical=False).packet == transcript.packet
    rejected_before_private(ctx, query, bad)


@pytest.mark.parametrize("change", ("epoch", "ids", "index_order", "key", "query"))
def test_original_owner_context_query_and_complete_coverage_binding(fixture, honest, change):
    data, ctx, *_ = fixture
    query, transcript = honest
    if change == 'epoch':
        ctx = replace(ctx, epoch='wrong-approved-epoch')
    elif change == 'ids':
        ctx = replace(ctx, ids=tuple(reversed(ctx.ids)))
    elif change == 'index_order':
        ctx = replace(ctx, index=ctx.index[::-1])
    elif change == 'key':
        ctx = replace(ctx, key_id='0'*64)
    else:
        query = bytes.fromhex(data['queries'][1]['packet_hex'])
    rejected_before_private(ctx, query, transcript)


@pytest.mark.parametrize("change", ("omit", "duplicate", "swap", "noncanonical", "modulus", "float_header"))
def test_complete_response_packet_grammar_and_group_coverage(fixture, honest, change):
    _, ctx, *_ = fixture
    _, transcript = honest
    fields = msgpack.unpackb(transcript.packet, raw=False)
    if change == 'omit':
        fields[1].pop()
    elif change == 'duplicate':
        fields[1].append(fields[1][0])
    elif change == 'swap':
        fields[1].reverse()
        # Structurally legal but bound complete bytes/trace must reject.
        bad = replace(transcript, packet=msgpack.packb(fields, use_bin_type=True))
        rejected_before_private(ctx, transcript.query, bad)
        return
    elif change == 'noncanonical':
        fields[1][0][0] = lab.pack_bits((ctx.p,)+(0,)*(ctx.n-1), ctx.p.bit_length())
    elif change == 'modulus':
        fields[0][3] = (ctx.p-2).to_bytes(4, 'little')
    else:
        fields[0][1] = float(ctx.n)
    with pytest.raises(ValueError):
        lab.parse_response(ctx, msgpack.packb(fields, use_bin_type=True))


def test_unused_score_coordinate_still_binds_the_complete_response(fixture, honest):
    data, ctx, *_ = fixture
    query, transcript = honest
    coefficients = list(lab.parse_response(ctx, transcript.packet))
    second = coefficients[1]
    coefficients[1] = ((second[0][0], (second[0][1]+1) % ctx.p)+second[0][2:], second[1])
    # Counterfactual toy algebra only; no native private receiver sees mutation.
    assert lab.decrypt_and_rank(ctx, tuple(coefficients), tuple(data['secret']))[1] == \
        lab.decrypt_and_rank(ctx, lab.parse_response(ctx, transcript.packet), tuple(data['secret']))[1]
    changed = replace(transcript, packet=lab.serialize(ctx, tuple(coefficients)))
    rejected_before_private(ctx, query, changed)


@pytest.mark.parametrize("field", ("cuts", "rounding", "preterminal", "cut_source", "cut_output", "round_source", "round_position"))
def test_strict_trace_types_reject_numeric_aliases_and_mutable_containers(fixture, honest, field):
    _, ctx, *_ = fixture
    query, transcript = honest
    if field in ('cuts', 'rounding', 'preterminal'):
        bad = replace(transcript, **{field: list(getattr(transcript, field))})
    elif field in ('cut_source', 'cut_output'):
        cut = transcript.cuts[0]
        if field == 'cut_source':
            cut = replace(cut, source=(float(cut.source[0]),)+cut.source[1:])
        else:
            cut = replace(cut, output=((float(cut.output[0][0]),)+cut.output[0][1:], cut.output[1]))
        bad = replace(transcript, cuts=(cut,)+transcript.cuts[1:])
    else:
        cell = transcript.rounding[0]
        cell = replace(cell, source=float(cell.source)) if field == 'round_source' else replace(cell, position=(False, 0, 0))
        bad = replace(transcript, rounding=(cell,)+transcript.rounding[1:])
    rejected_before_private(ctx, query, bad)


@pytest.mark.parametrize("field", ("seed", "drop", "key", "word"))
def test_original_query_grammar_rejects_substituted_context_and_illegal_words(fixture, honest, field):
    _, ctx, *_ = fixture
    query, _ = honest
    fields = msgpack.unpackb(query, raw=False)
    if field == 'seed':
        fields[2] = b'x'*31
    elif field == 'drop':
        fields[3] = float(ctx.query_drop)
    elif field == 'key':
        fields[1] = b'x'*32
    else:
        bits, maximum, _ = lab.query_encoding(ctx)
        fields[4] = lab.pack_bits((maximum+1,)+(0,)*(ctx.n-1), bits)
    with pytest.raises(ValueError):
        lab.expand_query(ctx, msgpack.packb(fields, use_bin_type=True))


def test_compressed_words_need_a_canonical_preimage_even_in_small_radix(fixture, honest):
    _, ctx, pk, *_ = fixture
    query, _ = honest
    changed_ctx = replace(ctx, query_drop=1)
    fields = msgpack.unpackb(query, raw=False)
    bits, _, _ = lab.query_encoding(changed_ctx)
    fields[3], fields[4] = 1, lab.pack_bits((2,)+(0,)*(ctx.n-1), bits)
    bad = msgpack.packb(fields, use_bin_type=True)
    with pytest.raises(ValueError, match='preimage'):
        lab.expand_query(changed_ctx, bad)
    with pytest.raises(ValueError):
        codec.expand(bad, pk, dropped_bits=1, backend='native')


def test_exact_congruent_rounding_exhaustion_and_actual_reachable_boundaries(fixture):
    _, ctx, *_ = fixture
    assert scalar_exhaustion() > 1000
    for c in boundary_inputs(ctx.q, ctx.p, ctx.t):
        lift = lab.round_lift(c, ctx.q, ctx.p, ctx.t)
        assert lift % ctx.t == c % ctx.t
        assert 2*abs(ctx.q*lift-ctx.p*c) < ctx.q*ctx.t
    # Negative nearest floor quotient is real; truncating it to zero is wrong.
    assert lab.round_lift(16, ctx.q, ctx.p, 17) == -1


def test_exact_CRT_one_limb_corruption_and_signed_secret_conversion(fixture, honest):
    data, ctx, *_ = fixture
    _, transcript = honest
    for c in transcript.cuts[0].source:
        assert lab.crt((c % ctx.primes[0], c % ctx.primes[1]), ctx.primes) == c
        changed = (c+ctx.primes[0]) % ctx.q
        assert c % ctx.primes[0] == changed % ctx.primes[0] and c % ctx.primes[1] != changed % ctx.primes[1]
    coefficients = lab.parse_response(ctx, transcript.packet)
    canonical = tuple(data['secret'])
    signed = tuple(-1 if x == ctx.q-1 else x for x in canonical)
    assert lab.decrypt_and_rank(ctx, coefficients, canonical) == lab.decrypt_and_rank(ctx, coefficients, signed)
    with pytest.raises(ValueError):
        lab.decrypt_and_rank(ctx, coefficients, (2,)+(0,)*(ctx.n-1))


def test_native_profile_admission_and_bit_padding_are_separate_from_generic_algebra(fixture):
    _, ctx, *_ = fixture
    ctx.admit_native_fixture()
    with pytest.raises(ValueError):
        replace(ctx, query_drop=1).admit_native_fixture()
    with pytest.raises(ValueError):
        lab.unpack_bits(b'\x80', 1, 7, 97)
