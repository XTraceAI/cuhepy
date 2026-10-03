"""E108 complete scalar-interface checks and independent omission controls."""

from dataclasses import replace

import msgpack
import pytest

from benchmarks.native_boundary_lab import load_fixture, make_fixture
from experiments.bfv_search_lab import native_boundary_controls as affine
from experiments.bfv_search_lab import native_boundary_oracle as oracle
from experiments.bfv_search_lab import native_opening_constraints as opening
from experiments.bfv_search_lab import target_prime_lift as terminal


@pytest.fixture(scope="module")
def fixture(tmp_path_factory):
    path = tmp_path_factory.mktemp("native-opening-constraints")/"fixture.json"
    make_fixture(path)
    return load_fixture(path)


@pytest.fixture(scope="module", params=(("baseline", True), ("folded", True), ("folded", False)),
                ids=("baseline-tight", "folded-tight", "folded-width"))
def compiled(request, fixture):
    mode, tight = request.param
    return opening.compile_constraints(fixture[1], mode=mode, tight_quotients=tight)


@pytest.fixture(scope="module")
def honest(compiled, fixture):
    data, ctx = fixture[:2]
    query = bytes.fromhex(data["queries"][0]["packet_hex"])
    transcript = oracle.replay(ctx, query)
    public = opening.public_inputs(compiled, ctx, query, transcript.packet)
    witness = opening.make_witness(compiled, ctx, query, transcript.packet, transcript=transcript)
    return query, transcript, public, witness


def assign(witness, value, number):
    """Independent literal bit encoding for corruption tests."""
    result = list(witness)
    for indices, integer in ((value.bits, number-value.lower), (value.slack, value.upper-number)):
        assert 0 <= integer < 1 << len(indices)
        for j, at in enumerate(indices):
            result[at] = (integer >> j) & 1
    return tuple(result)


@pytest.mark.parametrize("position", range(8))
def test_all_original_queries_match_full_preterminal_and_complete_wire(compiled, fixture, position):
    data, ctx = fixture[:2]
    query = bytes.fromhex(data["queries"][position]["packet_hex"])
    trace = oracle.replay(ctx, query)
    public = opening.public_inputs(compiled, ctx, query, trace.packet)
    witness = opening.make_witness(compiled, ctx, query, trace.packet, transcript=trace)
    assert opening.satisfy(compiled, public, witness)
    assert opening.check_statement(compiled, ctx, query, trace.packet, witness)
    assert opening.recover_preterminal(compiled, ctx, witness) == tuple(x for pair in trace.preterminal for poly in pair for x in poly)
    assert compiled.cut_labels[-2:] == ("group1:stage0:node0", "group1:stage1:node0")
    assert len(trace.packet) == 211


def test_satisfaction_and_complete_public_check_never_replay_or_evaluate_graph(compiled, fixture, honest, monkeypatch):
    ctx = fixture[1]
    query, trace, public, witness = honest
    def forbidden(*_args, **_kwargs):
        raise AssertionError("A verifier replayed/evaluated the graph")
    monkeypatch.setattr(oracle, "replay", forbidden)
    monkeypatch.setattr(oracle, "multiply", forbidden)
    monkeypatch.setattr(affine, "_linear_image", forbidden)
    monkeypatch.setattr(affine, "compile_residual", forbidden)
    assert opening.satisfy(compiled, public, witness)
    assert opening.check_statement(compiled, ctx, query, trace.packet, witness)


@pytest.mark.parametrize("family", ("source:", "preterminal:", "remainder:"))
def test_every_source_preterminal_and_remainder_value_and_range_mutation_is_rejected(compiled, honest, family):
    _, _, public, witness = honest
    values = tuple(x for x in compiled.ranges if x.label.startswith(family))
    expected = 80 if family == "source:" else 32
    if family == "preterminal:" and compiled.mode == "folded":
        assert not values  # C is explicitly eliminated, not an unchecked witness.
        return
    assert len(values) == expected
    for value in values:
        for at in (value.bits[0], value.slack[0]):
            changed = list(witness)
            changed[at] ^= 1
            assert not opening.satisfy(compiled, public, tuple(changed)), (value.label, at)


def test_every_modular_quotient_and_its_range_mutation_is_rejected(compiled, honest):
    _, _, public, witness = honest
    assert len(compiled.quotients) == (320 if compiled.mode == "baseline" else 256)
    for quotient in compiled.quotients:
        for at in (quotient.value.bits[0],)+quotient.value.slack[:1]:
            changed = list(witness)
            changed[at] ^= 1
            assert not opening.satisfy(compiled, public, tuple(changed)), quotient.label


def test_prime_scalar_boolean_constraints_are_indispensable_not_CRT_idempotence(compiled, honest):
    _, _, public, witness = honest
    assert 7*(7-1) % 21 == 0 and 7*(7-1) % compiled.field != 0
    assert (1 % 3, 0 % 7) != (1 % 3, 1 % 7)  # Independent limb roots need a common wire.
    # Preserve EVERY linear row while changing a common source bit to7.
    # Quotient field coordinates absorb the changed affine contributions; their
    # paired slack absorbs the changed value. Boolean gates stop this alias.
    forged = list(witness)
    source = compiled.ranges[0]
    delta = 7-forged[source.bits[0]]
    forged[source.bits[0]] = 7
    forged[source.slack[0]] = (forged[source.slack[0]]-delta) % compiled.field
    for quotient in compiled.quotients:
        difference = (opening._evaluate(quotient.numerator, public, forged)
                      -opening._evaluate(quotient.numerator, public, witness)) % compiled.field
        adjustment = difference*pow(quotient.modulus, -1, compiled.field) % compiled.field
        bit = quotient.value.bits[0]
        forged[bit] = (forged[bit]+adjustment) % compiled.field
        if quotient.value.slack:
            slack = quotient.value.slack[0]
            forged[slack] = (forged[slack]-adjustment) % compiled.field
    forged = tuple(forged)
    assert opening.satisfy(compiled, public, forged, omit_boolean=True)
    assert not opening.satisfy(compiled, public, forged)


def test_canonical_Q_range_and_centered_remainder_are_real_nonlinear_dependencies(compiled, honest):
    _, _, public, witness = honest
    # Q fits its120-bit word, but is not a canonical source or shifted remainder.
    for value in (compiled.ranges[0], next(x for x in compiled.ranges if x.label == "remainder:0")):
        changed = list(witness)
        for j, at in enumerate(value.bits):
            changed[at] = (compiled.q >> j) & 1
        for at in value.slack:
            changed[at] = 0
        range_row = next(row for row in compiled.linear_rows if row.label == value.label+":range")
        assert opening._evaluate(range_row, public, changed) == 1
        assert not opening.satisfy(compiled, public, tuple(changed))
    tiny = terminal.Context(3, 7, 11, 5)
    assert terminal.reduced_predicate(tiny, 0, 5, 21, omit=("remainder_range",))
    assert not terminal.reduced_predicate(tiny, 0, 5, 21)  # Wrong output from a noncentered r.


def test_unbounded_quotient_can_create_field_zero_without_integer_equality(compiled):
    quotient = compiled.quotients[0]
    prime, field = quotient.modulus, compiled.field
    unbounded = pow(prime, -1, field)
    assert (1-prime*unbounded) % field == 0
    assert 1-prime*unbounded != 0 and unbounded > quotient.value.upper
    assert abs(1-prime*unbounded) >= field
    # This isolated unbounded-row falsifier is outside the compiled bit ranges.
    assert all(row.residual_bound < field for row in compiled.linear_rows)


@pytest.mark.parametrize("limb", (0, 1))
def test_one_limb_errors_are_not_saved_by_the_other_limb(compiled, fixture, honest, limb):
    ctx = fixture[1]
    _, _, public, witness = honest
    family = "preterminal:0" if compiled.mode == "baseline" else "remainder:0"
    value = next(x for x in compiled.ranges if x.label == family)
    old = sum(witness[at] << j for j, at in enumerate(value.bits))
    prime, other = ctx.primes[limb], ctx.primes[1-limb]
    delta = other*pow(other, -1, prime)
    changed = assign(witness, value, (old+delta) % ctx.q)
    wrong, unaffected = [], []
    for quotient in compiled.quotients:
        if quotient.label.startswith(f"affine:{limb}:"):
            wrong.append(opening._evaluate(quotient.numerator, public, changed) % prime)
        if quotient.label.startswith(f"affine:{1-limb}:"):
            unaffected.append(opening._evaluate(quotient.numerator, public, changed) % other)
    assert any(wrong) and not any(unaffected)
    assert not opening.satisfy(compiled, public, changed)


def test_honest_output_falsecanonical_kernel_has_no_canonical_bit_encoding(compiled, fixture, honest):
    ctx = fixture[1]
    query, trace, _, _ = honest
    false_cut, _ = oracle.false_digit_cut(ctx, trace.cuts[0], ctx.relin)
    altered = replace(trace, cuts=(false_cut,)+trace.cuts[1:])
    assert oracle.replay(ctx, query, altered, canonical=False).packet == trace.packet
    with pytest.raises(ValueError, match="polynomial|range"):
        opening.make_witness(compiled, ctx, query, trace.packet, transcript=altered)


@pytest.mark.parametrize("which", ("query", "epoch", "key", "index", "ids", "unused_output", "wire"))
def test_public_original_context_and_complete_packet_binding(compiled, fixture, honest, which):
    data, ctx = fixture[:2]
    query, trace, _, witness = honest
    if which == "query":
        other = bytes.fromhex(data["queries"][7]["packet_hex"])
        assert not opening.check_statement(compiled, ctx, other, trace.packet, witness)
        return
    if which == "unused_output":
        compact = list(oracle.parse_response(ctx, trace.packet))
        pair = [list(poly) for poly in compact[-1]]
        pair[1][-1] = (pair[1][-1]+1) % ctx.p
        compact[-1] = tuple(tuple(poly) for poly in pair)
        packet = oracle.serialize(ctx, tuple(compact))
        assert not opening.check_statement(compiled, ctx, query, packet, witness)
        return
    if which == "wire":
        with pytest.raises(ValueError):
            opening.check_statement(compiled, ctx, query, trace.packet+b"\x00", witness)
        return
    changed = {"epoch": {"epoch": ctx.epoch+"x"}, "key": {"key_id": "a"*64},
               "index": {"index": ctx.index[::-1]}, "ids": {"ids": ctx.ids[::-1]}}[which]
    with pytest.raises(ValueError):
        opening.check_statement(compiled, replace(ctx, **changed), query, trace.packet, witness)


@pytest.mark.parametrize("mutation", ("omit", "duplicate", "reverse", "modulus", "noncanonical_coefficient"))
def test_every_complete_response_group_and_coefficient_encoding_is_bound(compiled, fixture, honest, mutation):
    ctx = fixture[1]
    query, trace, _, witness = honest
    fields = msgpack.unpackb(trace.packet, raw=False)
    if mutation == "omit":
        fields[1] = fields[1][:-1]
    elif mutation == "duplicate":
        fields[1] = fields[1]+fields[1][-1:]
    elif mutation == "reverse":
        fields[1] = fields[1][::-1]
    elif mutation == "modulus":
        fields[0][3] = (ctx.p+2).to_bytes(4, "little")
    else:
        # P is a valid32-bit word, but not a canonical coefficient moduloP.
        word = int.from_bytes(fields[1][-1][1], "little")
        word = (word >> 32 << 32)+ctx.p
        fields[1][-1][1] = word.to_bytes(ctx.n*4, "little")
    packet = msgpack.packb(fields, use_bin_type=True)
    if mutation == "reverse":
        assert not opening.check_statement(compiled, ctx, query, packet, witness)
    else:
        with pytest.raises(ValueError):
            opening.check_statement(compiled, ctx, query, packet, witness)


def test_strict_field_boolean_and_container_grammar(compiled, honest):
    _, _, public, witness = honest
    for malformed in (True, 1.0, "1", -1, compiled.field):
        changed = (malformed,)+witness[1:]
        with pytest.raises(ValueError, match="grammar"):
            opening.satisfy(compiled, public, changed)
    assert not opening.satisfy(compiled, public, (2,)+witness[1:])
    for bad in (list(witness), witness[:-1]):
        with pytest.raises(ValueError, match="grammar"):
            opening.satisfy(compiled, public, bad)
    with pytest.raises(ValueError, match="grammar"):
        opening.satisfy(compiled, (True,)+public[1:], witness)
    with pytest.raises(ValueError, match="omission"):
        opening.satisfy(compiled, public, witness, omit_linear=("not-a-row",))


def test_sparse_R1CS_stream_independently_satisfies_author_interface_dimensions(compiled, honest):
    _, _, public, witness = honest
    z = witness+(1,)+public
    count = compiled.variable_count+len(compiled.linear_rows)
    sums = {name: [0]*count for name in ("A", "B", "C")}
    nonzeros = dict.fromkeys(sums, 0)
    for name, row, column, coefficient in opening.r1cs_entries(compiled):
        assert 0 <= row < count and 0 <= column < len(z) and 0 < coefficient < compiled.field
        sums[name][row] = (sums[name][row]+coefficient*z[column]) % compiled.field
        nonzeros[name] += 1
    assert all((a*b-c) % compiled.field == 0 for a, b, c in zip(sums["A"], sums["B"], sums["C"], strict=True))
    counts = compiled.counts()
    assert nonzeros == {name: counts[name+"_nonzeros"] for name in nonzeros}
    assert len(opening.serialize_witness(compiled, witness)) == 32*compiled.variable_count


def test_bounded_counts_keep_baseline_and_shared_stronger_control_distinct(compiled):
    card = compiled.counts()
    if compiled.mode == "baseline":
        assert (card["base_value_slack_pairs"], card["base_boolean_constraints"], card["quotient_count"],
                card["linear_constraints"], card["public_inputs"]) == (144, 34560, 320, 784, 48)
        assert max(card["quotient_widths"]) > 100
    else:
        expected_rows = 624 if compiled.tight_quotients else 368
        assert (card["base_value_slack_pairs"], card["base_boolean_constraints"], card["quotient_count"],
                card["linear_constraints"], card["public_inputs"]) == (112, 26880, 256, expected_rows, 256)
        assert max(x.value.width for x in compiled.quotients if x.label.startswith("affine:")) <= 14
        assert max(x.value.width for x in compiled.quotients if x.label.startswith("terminal:")) <= 7
    assert card["field_no_wrap_admitted"] and card["max_integer_residual_bound"] < compiled.field
    assert card["generic_gets_identical_elimination_folding_and_public_preprocessing"]
    assert card["proof_backend_bytes_prover_verifier_lifecycle_and_runtime_unknown"]
    if not compiled.tight_quotients:
        assert all(not quotient.value.slack for quotient in compiled.quotients)
        assert all(quotient.value.upper == quotient.value.lower+(1 << quotient.value.width)-1 for quotient in compiled.quotients)


def test_static_selected_scalar_and_profile_admission(fixture):
    ctx = fixture[1]
    assert opening.SCALAR == (1 << 252)+27742317777372353535851937790883648493
    with pytest.raises(ValueError, match="field"):
        opening.compile_constraints(ctx, field=7)
    with pytest.raises(ValueError, match="mode"):
        opening.compile_constraints(ctx, mode="approximate")
    with pytest.raises(ValueError, match="context"):
        opening.compile_constraints((8, 17))
