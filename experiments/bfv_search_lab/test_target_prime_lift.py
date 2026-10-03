"""E107 exact scalar relations, omission negatives and strict admission."""

from dataclasses import replace

import pytest

from experiments.bfv_search_lab import target_prime_lift as lift


@pytest.mark.parametrize("parameters", lift.TINY_CONTEXTS)
def test_every_tiny_source_has_one_centered_remainder_and_nearest_output(parameters):
    ctx = lift.Context(*parameters).validate()
    for c in range(ctx.q):
        witness = lift.derive(ctx, c)
        # Enumerate only the per-source centered remainder support, not the
        # preregistered whole rich/reduced tuple domains owned by the runner.
        candidates = tuple(r for r in range(-(ctx.q//2), ctx.q//2+1)
                           if (ctx.t*r+ctx.p*c) % ctx.q == 0)
        assert candidates == (witness.r,)
        expected = lift.nearest_lift(ctx, c)
        assert witness.lift(ctx) == expected
        assert witness.y == expected % ctx.p and witness.k in (-1, 0, 1)
        assert (expected-c) % ctx.t == 0 and 2*abs(ctx.q*expected-ctx.p*c) < ctx.q*ctx.t
        assert lift.rich_predicate(ctx, c, witness.y, witness.k, witness.r)
        assert lift.reduced_predicate(ctx, c, witness.y, witness.r)
        assert lift.integer_predicate(ctx, c, witness.y, witness.k, witness.r)


def test_native_scalar_profile_uses_exact_integer_arithmetic_without_native_helpers():
    ctx = lift.Context(*lift.NATIVE_SCALAR_PROFILE).admit_native_scalar()
    assert ctx.q.bit_length() == 120
    for c in (0, 1, ctx.q//2, ctx.q-2, ctx.q-1):
        witness = lift.derive(ctx, c)
        assert witness.lift(ctx) == lift.nearest_lift(ctx, c)
        assert lift.reduced_predicate(ctx, c, witness.y, witness.r)
        assert lift.rich_predicate(ctx, c, witness.y, witness.k, witness.r)
    with pytest.raises(ValueError, match="frozen native"):
        lift.Context(*lift.TINY_CONTEXTS[0]).admit_native_scalar()


@pytest.mark.parametrize("gate,c,y,k,r", (
    ("limb0", 0, 9, 1, 7),       # D=385: divisible by7 and11, not3.
    ("limb1", 0, 10, 0, 9),      # D=165: divisible by3 and11, not7.
    ("target", 1, 6, 0, 2),       # D=105: divisible byQ21, notP11.
    ("modt", 0, 0, -1, 0),       # Same honest y; corrupted committed lift.
    ("wrap_range", 0, 0, 5, 0),   # l'=l+Pt; same honest y, not a reduced attack.
    ("remainder_range", 0, 0, 0, 231),
    ("source_range", 105, 0, 0, 0),
    ("output_range", 0, 11, -1, 0),
))
def test_rich_omission_falsifiers_fail_the_complete_integer_statement(gate, c, y, k, r):
    ctx = lift.Context(3, 7, 11, 5)
    assert not lift.rich_predicate(ctx, c, y, k, r)
    assert lift.rich_predicate(ctx, c, y, k, r, omit=(gate,))
    assert not lift.integer_predicate(ctx, c, y, k, r)
    if gate in ("modt", "wrap_range"):
        assert y == lift.derive(ctx, c).y  # This is a lift-only false witness.


@pytest.mark.parametrize("gate,c,y,r", (
    ("target", 0, 1, 0),
    ("limb0", 0, 9, 7),
    ("limb1", 0, 7, 3),
    ("remainder_range", 0, 5, 21),
    ("source_range", 21, 0, 0),
    ("output_range", 0, 11, 0),
))
def test_reduced_essential_obligation_omissions_have_explicit_false_witnesses(gate, c, y, r):
    ctx = lift.Context(3, 7, 11, 5)
    assert not lift.reduced_predicate(ctx, c, y, r)
    assert lift.reduced_predicate(ctx, c, y, r, omit=(gate,))
    if gate in ("target", "limb0", "limb1", "remainder_range"):
        assert y != lift.derive(ctx, c).y
    # Source/output aliases are failures of canonical encodings, not a claim
    # that congruent values denote a different compact field element.


def test_reduced_relation_does_not_commit_to_or_require_the_rich_lift():
    ctx = lift.Context(3, 7, 11, 5)
    witness = lift.derive(ctx, 1)
    assert lift.reduced_predicate(ctx, witness.c, witness.y, witness.r)
    assert not lift.rich_predicate(ctx, witness.c, witness.y, witness.k+ctx.t, witness.r)
    assert lift.rich_predicate(ctx, witness.c, witness.y, witness.k+ctx.t, witness.r, omit=("wrap_range",))
    with pytest.raises(ValueError, match="omitted"):
        lift.reduced_predicate(ctx, witness.c, witness.y, witness.r, omit=("modt",))


def test_original_source_and_parameter_pins_are_external_statement_obligations():
    ctx = lift.Context(3, 7, 11, 5)
    original_c = 0
    alternate = lift.derive(ctx, 1)
    assert lift.reduced_predicate(ctx, alternate.c, alternate.y, alternate.r)
    assert alternate.c != original_c  # A true different statement is not a receipt for c0.
    changed = replace(ctx, p=31).validate()
    assert changed.digest() != ctx.digest()
    assert not lift.reduced_predicate(changed, alternate.c, alternate.y, alternate.r)


@pytest.mark.parametrize("parameters", (
    (3, 3, 11, 5), (9, 7, 11, 5), (3, 15, 11, 5), (2, 7, 11, 5),
    (3, 7, 12, 5), (3, 7, 21, 5), (3, 7, 7, 5), (3, 7, 5, 5),
    (3, 7, 11, 4), (3, 7, 11, 7), (3, 7, 13, 5), (True, 7, 11, 5),
    (3, 7, 11, 1 << 32), (3, 7, (1 << 64)+1, 5), (3, 7, 121, 5),
))
def test_invalid_or_changed_context_geometry_is_rejected(parameters):
    with pytest.raises(ValueError, match="scalar context"):
        lift.Context(*parameters).validate()


def test_repository_probable_prime_gate_rejects_pseudoprimes_and_oversized_values():
    for composite in (341, 2047, 3215031751, 341550071728321, 3825123056546413051):
        assert not lift._prime64(composite)
    for prime in (3, 7, 101, *lift.NATIVE_SCALAR_PROFILE[:2]):
        assert lift._prime64(prime)
    assert not lift._prime64((1 << 64)+13)
    assert not lift._prime64(True)


@pytest.mark.parametrize("position", range(4))
def test_malformed_witness_types_never_enter_diagnostic_omission_arithmetic(position):
    ctx = lift.Context(3, 7, 11, 5)
    for malformed in (True, 1.0, "0", None, 1 << 257):
        entries = [0, 0, 0, 0]
        entries[position] = malformed
        with pytest.raises(ValueError, match="integer witness"):
            lift.rich_predicate(ctx, *entries, omit=("source_range", "output_range", "wrap_range", "remainder_range"))


def test_malformed_reduced_and_omission_grammar_are_rejected():
    ctx = lift.Context(3, 7, 11, 5)
    for entries in ((True, 0, 0), (0, True, 0), (0, 0, True)):
        with pytest.raises(ValueError, match="integer witness"):
            lift.reduced_predicate(ctx, *entries)
    for omit in ("target", ("unknown",), (True,), ["target"]):
        with pytest.raises(ValueError, match="omitted"):
            lift.rich_predicate(ctx, 0, 0, 0, 0, omit=omit)
    with pytest.raises(ValueError, match="pinned scalar"):
        lift.reduced_predicate((3, 7, 11, 5), 0, 0, 0)
    for c in (-1, ctx.q):
        with pytest.raises(ValueError, match="Noncanonical"):
            lift.derive(ctx, c)
        with pytest.raises(ValueError, match="Noncanonical"):
            lift.nearest_lift(ctx, c)


def test_paid_widths_share_elimination_and_leave_all_proof_costs_unknown():
    ctx = lift.Context(*lift.NATIVE_SCALAR_PROFILE)
    card = lift.cost_card(ctx)
    assert card["q_bits"] == card["source_unsigned_bits"] == 120
    assert card["q_limb_bits"] == (60, 60)
    assert card["centered_remainder_twos_complement_bits"] == 120
    assert card["target_bits"] == card["output_unsigned_bits"] == 32
    assert card["rich_wrap_trit_fixed_width_bits"] == 2 and card["reduced_wrap_trit_bits"] == 0
    assert card["rich_modular_equations"] == card["reduced_modular_equations"] == 3
    assert card["three_field_description_conditional_on_registered_moduli_primality"]
    assert card["fresh_auxiliary_modulus_strict_lower_bound_twice"] == 4*ctx.p+ctx.t
    assert card["candidate_and_generic_receive_identical_remainder_elimination_and_existing_target"]
    assert card["range_commitment_challenges_openings_provisioning_and_lifecycle_cost_unknown"]
