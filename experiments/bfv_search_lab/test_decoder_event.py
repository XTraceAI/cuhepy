"""E111 independent interval, weighted cover, coupled graph and terminal checks."""

from collections import Counter
from dataclasses import replace
from fractions import Fraction
from itertools import product
from types import SimpleNamespace

from gmpy2 import mpz
import pytest

from experiments.bfv_search_lab import compact_bgv as compact
from experiments.bfv_search_lab import decoder_event as lab
from experiments.bfv_search_lab import trace_bgv as trace
from experiments.bfv_search_lab.test_carry_trace_noise import make_graph
from experiments.bfv_search_lab.test_finite_lifetime_noise import schoolbook

# Exact unchanged public E105 masks, so tests do not draw another setup/context.
INDEX_MASK = (1988871112820527403, 711510856191565670, 1031010871629900, 798133186135646588, 1823959156852065097, 2137114452065430446, 2223635905000960667, 1641879628814770328)
QUERY_MASK = (172833944746179678, 363450350335163846, 1470531050025747424, 1787710380253859393, 1569464594367938321, 1864400505495596177, 1942559778179068011, 1710499799073805033)


@pytest.fixture(scope="module")
def graph():
    return make_graph(INDEX_MASK, QUERY_MASK)


@pytest.fixture(scope="module")
def event(graph):
    return lab.NativeEvent(graph, (0, 1))


@pytest.mark.parametrize("modulus", (2, 3, 7, 17))
def test_all_small_interval_images_and_digit_bounds_enclose_literal_residues(modulus):
    for lo in range(-2*modulus, 2*modulus):
        for length in range(2*modulus+1):
            interval = lab.Interval(lo, lo+length)
            arcs = lab.canonical_arcs(interval, modulus)
            image = {x % modulus for x in range(interval.lower, interval.upper+1)}
            assert {x for arc in arcs for x in range(arc.lower, arc.upper+1)} == image
            for level in range(3):
                bound = lab.digit_interval(arcs, level, 2)
                assert all(bound.lower <= (x >> (2*level)) % 4 <= bound.upper for x in image)


def test_Q61_top_digit_is_public_one_bit_not_full_radix_bound():
    q = (1 << 61)-1
    arcs = lab.canonical_arcs(lab.Interval(0, q-1), q)
    assert lab.digit_interval(arcs, 15) == lab.Interval(0, 1)


@pytest.mark.parametrize("n", (1, 2, 3))
def test_weighted_cells_match_independent_literal_coin_enumeration(n):
    literal = Counter(tuple(bits[2*i]-bits[2*i+1] for i in range(n)) for bits in product((0, 1), repeat=2*n))
    assert literal == dict(lab.weighted_states(n))
    assert sum(literal.values()) == lab.Cell.root(n).mass == 4**n
    for atoms in product(((-1,), (0,), (1,), (-1, 1), (-1, 0, 1)), repeat=n):
        cell = lab.Cell(atoms)
        assert cell.mass == sum(m for e, m in literal.items() if all(x in a for x, a in zip(e, atoms, strict=True)))


@pytest.mark.parametrize("constants,matrix,radius", (
    ((0,), ((1, 1),), 0), ((0,), ((1, -1),), 1),
    ((1, -1), ((2, -1), (1, 2)), 1), ((0,), ((3, 0),), 1),
))
def test_full_abstract_cover_exact_masses_and_truncated_upper_never_drop_unresolved(constants, matrix, radius):
    event = lab.AffineEvent(constants, matrix, radius)
    literal = sum(m for e, m in lab.weighted_states(2)
                  if any(abs(c+sum(a*x for a, x in zip(row, e, strict=True))) > radius
                         for c, row in zip(constants, matrix, strict=True)))
    for depth in (0, 1, 2):
        generic = lab.certify(event, max_depth=depth)
        candidate = lab.certify(event, max_depth=depth, rule="candidate-residue")
        assert generic.root == candidate.root
        counts = lab.check_certificate(event, generic)
        assert Fraction(counts["failure_lower"]) <= Fraction(literal, 16) <= Fraction(counts["failure_upper"])
        assert counts["covered_distinct_states"] == 9
        if depth == 2:
            assert counts["unresolved_mass"] == 0
            assert counts["unsafe_mass"] == literal


def test_complete_map_injectivity_does_not_prevent_coarse_event_certificate():
    event = lab.AffineEvent((0, 0), ((1, 0), (0, 1)), 1)
    assert len({e for e, _ in lab.weighted_states(2)}) == 9
    counts = lab.check_certificate(event, lab.certify(event, max_depth=2))
    assert counts["nodes"] == 1 and counts["failure_upper"] == "0"


def test_same_atom_reuse_has_different_event_mass_than_fresh_independent_atoms():
    shared = lab.AffineEvent((0,), ((2,),), 1)
    independent = lab.AffineEvent((0,), ((1, 1),), 1)
    shared_mass = lab.check_certificate(shared, lab.certify(shared, max_depth=1))
    independent_mass = lab.check_certificate(independent, lab.certify(independent, max_depth=2))
    assert Fraction(shared_mass["failure_upper"]) == Fraction(1, 2)
    assert Fraction(independent_mass["failure_upper"]) == Fraction(1, 8)


@pytest.mark.parametrize("mutation", ("digest", "status", "missing", "duplicate", "domain", "children", "rule"))
def test_checker_rejects_forged_claims_and_nonpartition_covers(mutation):
    event = lab.AffineEvent((0,), ((1, 1),), 0)
    certificate = lab.certify(event, max_depth=2)
    if mutation == "digest":
        forged = replace(certificate, event_digest="0"*64)
    elif mutation == "status":
        forged = replace(certificate, root=lab.Node(lab.Cell.root(2), "safe"))
    elif mutation == "missing":
        forged = replace(certificate, root=replace(certificate.root, children=certificate.root.children[:-1]))
    elif mutation == "duplicate":
        children = certificate.root.children
        forged = replace(certificate, root=replace(certificate.root, children=(children[0], children[0], children[2])))
    elif mutation == "domain":
        forged = replace(certificate, root=replace(certificate.root, cell=lab.Cell(((0,), (-1, 0, 1)))))
    elif mutation == "children":
        forged = replace(certificate, root=lab.Node(lab.Cell.root(2), "unresolved", certificate.root.children))
    else:
        forged = replace(certificate, rule="unregistered-cheap-marginal")
    with pytest.raises(ValueError):
        lab.check_certificate(event, forged)


@pytest.mark.parametrize("atoms", ((), ((True,),), ((2,),), ((0, -1),), ((0, 0),), ([],)))
def test_strict_atom_grammar_rejects_bool_empty_unsorted_or_duplicate_support(atoms):
    with pytest.raises(ValueError):
        lab.Cell(atoms)


@pytest.mark.parametrize("lower,upper", ((True, 1), (0, False), (2, 1), (0.0, 1)))
def test_interval_arithmetic_never_accepts_float_or_bool(lower, upper):
    with pytest.raises(ValueError):
        lab.Interval(lower, upper)


@pytest.mark.parametrize("bits", tuple(product((0, 1), repeat=2)))
def test_native_safe_root_certificate_uses_margin_only_no_graph_replay(graph, bits, monkeypatch):
    event = lab.NativeEvent(graph, bits)
    uniform = event.uniform_control()
    assert uniform["whole_trace_cap"] == 29584 and uniform["terminal_cap"] == 24
    def forbidden(*args):
        raise AssertionError("Safe cell checker must not replay the ciphertext graph")
    monkeypatch.setattr(event, "evaluate", forbidden)
    generic, candidate = lab.certify(event), lab.certify(event, rule="candidate-residue")
    assert generic.root == candidate.root
    for cert in (generic, candidate):
        counts = lab.check_certificate(event, cert)
        assert counts["nodes"] == 1 and counts["safe_mass"] == 65536
        assert counts["unsafe_mass"] == counts["unresolved_mass"] == 0
        assert counts["failure_lower"] == counts["failure_upper"] == "0"


@pytest.mark.parametrize("bits", tuple(product((0, 1), repeat=2)))
def test_same_error_phase_digits_components_and_terminal_match_actual_API(graph, bits):
    event = lab.NativeEvent(graph, bits)
    bound = event.bound(lab.Cell.root(8))
    for errors in ((-1,)*8, (0,)*8, (1,)*8, (-1, 0, 1, -1, 0, 1, -1, 0)):
        values = event.evaluate(errors)
        result = trace.search(graph.cipher(event.message, errors, graph.query_mask), [graph.index], 3, graph.pk, graph.keys)[0]
        assert tuple(tuple(map(int, p)) for p in result.components) == values.components
        actual_phase = tuple(x % event.q for x in schoolbook(values.components[1], event.secret))
        actual_phase = tuple((a+b) % event.q for a, b in zip(values.components[0], actual_phase, strict=True))
        assert actual_phase == tuple(x % event.q for x in values.final_phase)
        terminal = compact.compact(result, graph.pk, 16)
        assert tuple(tuple(map(int, p)) for p in terminal.components) == values.terminal
        assert tuple(compact.decrypt(terminal, graph.pk, graph.sk)) == values.plaintext == event.expected_plaintext
        assert tuple(trace.decode([list(values.plaintext)], 3, 2, graph.pk)) == values.distances == event.expected_distances
        assert values.ranked_ids == event.expected_rank and not values.failed
        assert all(i.lower <= x <= i.upper for x, i in zip(values.final_phase, bound.phase, strict=True))
        for j, row in enumerate(values.digits):
            assert all(i.lower <= x <= i.upper for x, i in zip(row, bound.digit_ranges[j], strict=True))


def test_wrong_fixed_gadget_error_cannot_be_given_a_legitimate_digest(graph):
    fields = vars(graph).copy()
    family = list(graph.errors[0])
    family[0] = (0,)*8
    fields["errors"] = (tuple(family), graph.errors[1])
    with pytest.raises(ValueError, match="key phase"):
        lab.NativeEvent(SimpleNamespace(**fields), (0, 1))


def test_wrong_automorphism_schedule_is_not_a_registered_native_event(graph):
    fields = vars(graph).copy()
    fields["keys"] = replace(graph.keys, rotations=((3, graph.keys.rotations[0][1]),))
    with pytest.raises(ValueError, match="Registered E105"):
        lab.NativeEvent(SimpleNamespace(**fields), (0, 1))


def test_terminal_rounding_has_exact_residue_and_nearest_lattice_error_not_floating_estimate():
    # Abstract scalar rounding unit test, not a native parameter substitute.
    for c in range(97):
        rounded = lab.round_coefficient(c, 97, 31, 3)
        assert rounded % 3 == c % 3
        assert 2*abs(97*rounded-31*c) <= 97*3
        assert rounded == int(compact._round_coefficient(mpz(c), mpz(97), mpz(31), 3))
