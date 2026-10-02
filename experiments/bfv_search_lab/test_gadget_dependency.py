"""Independent finite laws and false-assurance regressions for E99."""

from collections import Counter
from dataclasses import replace
from fractions import Fraction
from itertools import combinations, product
from random import Random

import pytest

from experiments.bfv_search_lab import gadget_dependency as lab
from experiments.bfv_search_lab import partial_packed_switch as packed
from experiments.bfv_search_lab.test_committed_precision_epoch import make_keys
from experiments.bfv_search_lab.test_partial_packed_switch import multiply
from experiments.bfv_search_lab.target_prefix_samples import extract


def scalar_map(matrix, values, q):
    return tuple(sum(a*b for a, b in zip(row, values, strict=True)) % q for row in matrix)


def geometry_laws():
    """Whole small uniform mask/CBD law, independent of the adapter's rank test."""
    cards = []
    for q, radix, levels in product((3, 5, 9, 13), (3, 5), (3, 4)):
        all_rows = lab.adjacent(levels, radix)
        subset = lab.adjacent(levels, radix, disjoint=True)
        basis = lab.modular_basis(q, radix, levels)
        maps = [Counter() for _ in range(3)]
        for values in product(range(q), repeat=levels):
            for counts, matrix in zip(maps, (all_rows, subset, basis), strict=True):
                counts[scalar_map(matrix, values, q)] += 1
        for counts, matrix in zip(maps[:2], (all_rows, subset), strict=True):
            assert len(counts) == q**len(matrix) and set(counts.values()) == {q**(levels-len(matrix))}
            assert lab.mask_surjective(q, matrix)
        assert abs(lab.determinant(basis)) == q and not lab.mask_surjective(q, basis)
        assert len(maps[2]) == q**(levels-1) and set(maps[2].values()) == {q}
        law, denominator = lab.joint_cbd(all_rows)
        literal = Counter()
        for bits in product((0, 1), repeat=2*levels):
            values = tuple(bits[2*j]-bits[2*j+1] for j in range(levels))
            literal[tuple(sum(a*b for a, b in zip(row, values, strict=True)) for row in all_rows)] += 1
        assert literal == law and denominator == 4**levels
        covariance = tuple(tuple(Fraction(sum(xs[i]*xs[j]*mass for xs, mass in law.items()), denominator)
                                 for j in range(levels-1)) for i in range(levels-1))
        assert all(sum(xs[i]*mass for xs, mass in law.items()) == 0 for i in range(levels-1))
        expected = tuple(tuple(Fraction(radix*radix+1, 2) if i == j else
                               Fraction(-radix, 2) if abs(i-j) == 1 else Fraction(0)
                               for j in range(levels-1)) for i in range(levels-1))
        assert covariance == expected
        assert covariance == tuple(tuple(Fraction(x, 2) for x in row) for row in lab.gram(all_rows))
        cards.append({"Q": q, "radix": radix, "levels": levels, "scalar_mask_inputs": q**levels,
                      "all_adjacent_uniform_rows": levels-1, "disjoint_IID_rows": len(subset),
                      "modular_basis_joint_image": len(maps[2]), "modular_basis_not_joint_surjective": True,
                      "CBD1_literal_coin_outcomes": denominator, "joint_noise_support": len(law),
                      "covariance": [[str(x) for x in row] for row in covariance]})
    return cards


def transcript(q, radix, source_label, source, target, masks, errors, start=0):
    bodies = tuple(tuple((radix**(j+start)*s+e-a) % q for s, e, a in
                         zip(source, err, multiply(mask, target), strict=True))
                   for j, (mask, err) in enumerate(zip(masks, errors, strict=True)))
    return lab.Transcript(q, 1, tuple(lab.KeyRow(((source_label, radix**(j+start)),),
                                               f"{source_label}:a{j+start}", f"{source_label}:e{j+start}", mask, body)
                                      for j, (mask, body) in enumerate(zip(masks, bodies, strict=True))))


def phase_check(tr, target, errors, coefficients):
    equations = 0
    for c in coefficients:
        row = lab.transform(tr, c)
        phase = multiply(row.mask, target)
        for k, (b, a) in enumerate(zip(row.body, phase, strict=True)):
            assert (b+a-sum(w*e[k] for w, e in zip(c, errors, strict=True))) % tr.q == 0
            equations += 1
    return equations


def formal_axes():
    q, radix, n, levels = 3, 3, 2, 3
    rows = (*lab.adjacent(levels, radix), lab.modulus_digits(q, radix, levels, balanced=True))
    fixed_masks, fixed_errors = ((0, 1), (2, 0), (1, 2)), ((1, -1), (0, 1), (-1, 0))
    counts, equations = Counter(), 0
    for source, target in product(product((-1, 0, 1), repeat=n), repeat=2):
        for axis, alphabet in (("masks", range(q)), ("errors", (-1, 0, 1))):
            for values in product(alphabet, repeat=n*levels):
                polynomials = tuple(values[j*n:(j+1)*n] for j in range(levels))
                masks, errors = (polynomials, fixed_errors) if axis == "masks" else (fixed_masks, polynomials)
                for label, actual in (("S", source), ("S-square", multiply(source, source))):
                    tr = transcript(q, radix, label, actual, target, masks, errors)
                    equations += phase_check(tr, target, errors, rows)
                counts[axis] += 1
    assert dict(counts) == {"masks": 59049, "errors": 59049} and equations == 1417176
    return {"formal_N": n, "Q": q, "radix": radix, "levels": levels,
            "factor_cover_cases": dict(counts), "coefficient_equations": equations,
            "not_exhaustive_joint_mask_error_Cartesian_product": True}


def actual_key_contexts(n):
    contexts, equations, hidden = 0, 0, 0
    rng = Random(99001+n)
    for q in (97, 1009):
        levels = packed.context(q, 3)
        for skip in range(levels+1):
            source = tuple(rng.randrange(-1, 2) for _ in range(n))
            target = (0,)*(n-1)+(1,)
            keys, errors = make_keys(q, 3, source, target, n, skip, rng)
            for f, actual in enumerate((source, multiply(source, source))):
                start = skip if f else 0
                masks = tuple(a for a, _ in keys.values[f])
                if not masks:
                    continue
                tr = transcript(q, 3, ("S", "S-square")[f], actual, target, masks, errors[f], start)
                assert tuple((row.mask, row.body) for row in tr.rows) == keys.values[f]
                c = lab.modular_basis(q, 3, levels-start)
                equations += phase_check(tr, target, errors[f], c)
                hidden += 1
            contexts += 1
    return {"N": n, "whole_key_contexts": contexts, "coefficient_equations": equations,
            "hidden_nonprefix_source_families": hidden}


def hidden_laws():
    q, n, contexts, coins = 3, 4, 0, 0
    secrets = tuple(s for s in product((-1, 0, 1), repeat=n) if sum(x != 0 for x in s) <= 2)
    assert len(secrets) == 33
    for secret, remainders, k in product(secrets, product(range(q), repeat=n+1), range(n)):
        terms = [(1, remainders[0])]
        for i, s in enumerate(secret):
            if s:
                terms.append((s*(1 if i <= k else -1), remainders[1+(k-i) % n]))
        law = Counter(sum(sign*(q*(u < r)-r) for (sign, r), u in zip(terms, us, strict=True))
                      for us in product(range(q), repeat=len(terms)))
        denominator = q**len(terms)
        assert sum(law.values()) == denominator and sum(v*mass for v, mass in law.items()) == 0
        variance = Fraction(sum(v*v*mass for v, mass in law.items()), denominator)
        expected = sum(r*(q-r) for _, r in terms)
        assert variance == expected <= lab.hidden_variance_bound(q, remainders[0], remainders[1:], 2)
        contexts += 1
        coins += denominator
    return {"N": n, "Q": q, "hidden_ternary_targets": len(secrets), "remainder_tuples": q**(n+1),
            "coefficient_event_contexts": contexts, "uniform_coin_outcomes": coins,
            "independent_integer_moment_and_hidden_cap_checks": contexts}


def test_full_small_mask_coin_laws_match_independent_enumeration():
    assert len(geometry_laws()) == 16


@pytest.mark.parametrize("n", (2, 4, 8))
def test_actual_sources_square_omissions_and_hidden_positions(n):
    assert actual_key_contexts(n)["whole_key_contexts"] == 14


@pytest.mark.parametrize("q,matrix,expected", (
    (9, ((0, 3, 0),), False), (6, ((2, 3),), True),
    (9, ((1, 0), (0, 3)), False), (9, ((-3, 1, 0), (0, -3, 1)), True),
))
def test_composite_surjectivity_matches_complete_image(q, matrix, expected):
    values = {scalar_map(matrix, x, q) for x in product(range(q), repeat=len(matrix[0]))}
    assert lab.mask_surjective(q, matrix) == (len(values) == q**len(matrix)) == expected


def test_distinct_actual_source_labels_cannot_be_merged():
    s, t, q = (1, 1), (0, 1), 13
    first = transcript(q, 3, "S", s, t, ((2, 3),), ((0, 0),)).rows[0]
    second = transcript(q, 3, "S-square", multiply(s, s), t, ((4, 5),), ((0, 0),)).rows[0]
    with pytest.raises(ValueError, match="Every distinct source"):
        lab.transform(lab.Transcript(q, 1, (first, second)), (-1, 1))
    spoofed = replace(second, sources=(("S", 1),))
    row = lab.transform(lab.Transcript(q, 1, (first, spoofed)), (-1, 1))
    assert any((a+b) % q for a, b in zip(row.body, multiply(row.mask, t), strict=True))
    # Honest source identities are an external premise, not proved by algebra.


def test_modular_relation_retains_integer_Q_multiple_and_final_carry():
    for q, radix, levels in ((13, 3, 3), (27, 3, 3), (97, 3, 5)):
        for balanced in (False, True):
            digits = lab.modulus_digits(q, radix, levels, balanced=balanced)
            assert sum(x*radix**i for i, x in enumerate(digits)) == q
            tr = transcript(q, radix, "S", (1, -1), (1, 0), ((1, 2),)*levels, ((0, 0),)*levels)
            row = lab.transform(tr, digits)
            assert row.integer_source_form == (("S", q),)
            assert abs(lab.determinant(lab.modular_basis(q, radix, levels, balanced=balanced))) == q


def test_dividing_gcd_does_not_preserve_modular_relation():
    tr = transcript(9, 3, "S", (1, -1), (1, 0), ((1, 2),)*3, ((0, 0),)*3)
    row = lab.transform(tr, (0, 3, 0))
    assert not lab.mask_surjective(9, lab.atom_matrix((row,), "mask_atoms"))
    with pytest.raises(ValueError, match="Every distinct source"):
        lab.transform(tr, (0, 1, 0))


def test_overlap_is_not_IID_despite_uniform_masks():
    tr = transcript(13, 3, "S", (1, -1), (1, 0), ((1, 2),)*4, ((0, 0),)*4)
    rows = tuple(lab.transform(tr, c) for c in lab.adjacent(4, 3))
    assert lab.mask_surjective(13, lab.atom_matrix(rows, "mask_atoms"))
    with pytest.raises(ValueError, match="Disjoint error atoms"):
        lab.iid_subset(13, rows)
    assert lab.iid_subset(13, (rows[0], rows[2])) == (1, 3)


def test_zero_covariance_does_not_imply_independent_CBD_rows():
    matrices = ((1, 1), (1, -1))
    assert lab.gram(matrices) == ((2, 0), (0, 2))
    law, _ = lab.joint_cbd(matrices)
    assert (1, 0) not in law and any(a == 1 for a, _ in law) and any(b == 0 for _, b in law)
    rows = tuple(lab.Relation((), tuple(zip(("a0", "a1"), c, strict=True)),
                             tuple(zip(("e0", "e1"), c, strict=True)), (0, 0), (0, 0)) for c in matrices)
    assert lab.mask_surjective(13, matrices)
    with pytest.raises(ValueError, match="Disjoint error atoms"):
        lab.iid_subset(13, rows)


def test_shared_atoms_aggregate_before_Gram_and_rank():
    first = lab.KeyRow((("S", 1),), "a", "e", (1, 2), (0, 0))
    tr = lab.Transcript(13, 1, (first, first))
    row = lab.transform(tr, (-1, 1))
    assert row.mask_atoms == row.error_atoms == () and row.mask == (0, 0)
    changed = replace(first, mask=(2, 2))
    with pytest.raises(ValueError, match="inconsistent"):
        lab.transform(lab.Transcript(13, 1, (first, changed)), (-1, 1))


def test_same_modular_lattice_does_not_supply_l_uniform_samples():
    q, radix, levels = 13, 3, 3
    assert abs(lab.determinant(lab.canonical_basis(q, radix, levels))) == q
    assert not lab.mask_surjective(q, lab.canonical_basis(q, radix, levels))
    assert lab.modulus_digits(q, radix, levels, balanced=True) == (1, 1, 1)
    assert lab.gram(((1, 1, 1),))[0][0] == 3 < lab.gram(lab.adjacent(levels, radix))[0][0]


def test_noise_subset_count_pays_atoms_and_identical_law():
    assert lab.independent_inventory(13, lab.adjacent(4, 3)) == {
        "independent_disjoint_atom_indices": (0, 2), "IID_same_CBD_signature_indices": (0, 2)}
    assert lab.independent_inventory(13, ((1, 0), (0, 2))) == {
        "independent_disjoint_atom_indices": (0, 1), "IID_same_CBD_signature_indices": (0,)}


def test_hidden_nonprefix_target_invalidates_prefix_extraction():
    mask, t, q = (1, 2, 3, 4), (0, 0, 0, 1), 13
    body = tuple(-x % q for x in multiply(mask, t))
    wrong = extract(mask, body, q, 1)
    assert any((b-sum(x*s for x, s in zip(a, t[:1], strict=True))) % q for a, b in wrong)
    correct = extract(mask, body, q, 4)
    assert all((b-sum(x*s for x, s in zip(a, t, strict=True))) % q == 0 for a, b in correct)


def test_hidden_signed_sampler_counts_and_does_not_publish_positions():
    policy = lab.HiddenSupport(4, 2, 1)
    choices = {tuple(1 if i == plus else -1 if i in support else 0 for i in range(4))
               for support in combinations(range(4), 2) for plus in support}
    assert lab.support_count(policy) == len(choices) == 12
    rng = Random(99004)
    sampled = {lab.sample_hidden(policy, rng) for _ in range(1000)}
    assert sampled == choices and tuple(vars(policy)) == ("n", "weight", "positives")


def test_hidden_support_variance_is_top_h_any_positions():
    # Prefix's first remainder is0; hidden target can select the last remainder.
    assert lab.hidden_variance_bound(3, 0, (0, 0, 0, 1), 1) == 2
    assert lab.hidden_variance_bound(3, 0, (0, 0, 0, 1), 0) == 0
    assert lab.hidden_variance_bound(3, 1, (1, 1, 1, 1), 2) == 6


@pytest.mark.parametrize("policy", (lab.HiddenSupport(3, 1, 1), lab.HiddenSupport(4, 5, 1),
                                    lab.HiddenSupport(4, 2, 3), lab.HiddenSupport(4, True, 1)))
def test_invalid_support_policies_reject(policy):
    with pytest.raises(ValueError):
        lab.support_count(policy)


@pytest.mark.parametrize("rows", ((), ((True, 1),), ((1,), (1, 2))))
def test_noncanonical_matrix_inputs_reject(rows):
    with pytest.raises(ValueError):
        lab.mask_surjective(13, rows)
