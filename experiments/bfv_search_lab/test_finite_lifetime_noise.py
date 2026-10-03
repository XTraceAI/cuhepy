"""E102 independent literal-coin laws and false-independence regressions."""

from collections import Counter
from fractions import Fraction
from itertools import product

from gmpy2 import mpz
import pytest

from experiments.bfv_search_lab import finite_lifetime_noise as lab
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace


def schoolbook(left, right):
    """Independent literal polynomial multiplication; retains integer lift."""
    n, out = len(left), [0]*len(left)
    for power in range(2*n-1):
        value = sum(left[i]*right[power-i] for i in range(max(0, power-n+1), min(n, power+1)))
        out[power % n] += value if power < n else -value
    return tuple(out)


def literal_errors(n, eta=1):
    for bits in product((0, 1), repeat=2*eta*n):
        yield tuple(sum(bits[2*eta*i:2*eta*i+eta])-sum(bits[2*eta*i+eta:2*eta*(i+1)]) for i in range(n))


def literal_law(weights, eta):
    return Counter(sum(w*e for w, e in zip(weights, errors, strict=True))
                   for errors in literal_errors(len(weights), eta))


def phase(parts, secret, q):
    out = tuple(parts[-1])
    for part in reversed(parts[:-1]):
        out = tuple((x+y) % q for x, y in zip(part, schoolbook(out, secret), strict=True))
    return out


def integer_cipher(message, errors, mask, secret, q, t):
    body = tuple((m+t*e-v) % q for m, e, v in zip(message, errors, schoolbook(mask, secret), strict=True))
    return body, mask


def tensor(left, right, q):
    return (tuple(x % q for x in schoolbook(left[0], right[0])),
            tuple((a+b) % q for a, b in zip(schoolbook(left[0], right[1]), schoolbook(left[1], right[0]), strict=True)),
            tuple(x % q for x in schoolbook(left[1], right[1])))


def small_laws():
    """All six supported setups, nine messages and sixteen query coin strings."""
    n, q, t, radix = 2, 97, 3, 4
    contexts = identities = tail_checks = outcomes = 0
    cards = []
    specs = (((1, 0), (0, 0)), ((1, -1), (0, 0)), ((1, 0), (1, -1)),
             ((1, 0), (-1, 1)), ((0, 0), (0, 0)), ((1, 1), (1, 1)))
    for index, (message, enrollment_error) in enumerate(specs):
        secret = ((-1, 0), (1, 1), (0, -1))[index % 3]
        index_mask, query_mask = (3+index, 2+2*index), (7+index, 1+index)
        source = integer_cipher(message, enrollment_error, index_mask, secret, q, t)
        fixed_phase = tuple(m+t*e for m, e in zip(message, enrollment_error, strict=True))
        canonical = tensor(source, integer_cipher((0, 0), (0, 0), query_mask, secret, q, t), q)[2]
        columns = lab.digits(canonical, q, radix)
        errors = tuple(tuple((j+i+index) % 3-1 for i in range(n)) for j in range(len(columns)))
        residual = lab.switch_residual(canonical, errors, q, radix, t)
        independently_decomposed = tuple(tuple(c//radix**j % radix for c in canonical) for j in range(len(columns)))
        assert columns == independently_decomposed
        reference_residual = tuple(t*sum(schoolbook(d, e)[k] for d, e in zip(columns, errors, strict=True)) for k in range(n))
        assert residual == reference_residual
        assert max(map(abs, residual)) <= lab.uniform_switch_cap(errors, radix, t)
        bodies = []
        for j, error in enumerate(errors):
            a = (j+3, 2*j+1)
            b = tuple((radix**j*v+t*e-z) % q for v, e, z in zip(schoolbook(secret, secret), error, schoolbook(a, secret), strict=True))
            bodies.append((b, a))
        for u in product((-1, 0, 1), repeat=n):
            counters = [Counter(), Counter()]
            mean = schoolbook(fixed_phase, u)
            for fresh in literal_errors(n):
                query = integer_cipher(u, fresh, query_mask, secret, q, t)
                parts = tensor(source, query, q)
                assert parts[2] == canonical  # Seeded relin weights precede E.
                switch = tuple(tuple(sum(schoolbook(d, key[k])[i] for d, key in zip(columns, bodies, strict=True)) % q for i in range(n)) for k in range(2))
                reduced = tuple(tuple((a+b) % q for a, b in zip(parts[k], switch[k], strict=True)) for k in range(2))
                expected = tuple(x+y for x, y in zip(schoolbook(fixed_phase, tuple(m+t*e for m, e in zip(u, fresh, strict=True))), residual, strict=True))
                assert phase(parts, secret, q) == tuple(x % q for x in schoolbook(fixed_phase, tuple(m+t*e for m, e in zip(u, fresh, strict=True))))
                assert phase(reduced, secret, q) == tuple(x % q for x in expected)
                for k in range(n):
                    counters[k][expected[k]-mean[k]-residual[k]] += 1
                    identities += 2
                outcomes += 1
            for k, counter in enumerate(counters):
                weights = lab.coefficient_weights(fixed_phase, k, t)
                law = lab.affine_cbd(tuple((f"E{i}", w) for i, w in enumerate(weights)))
                assert {x: Fraction(m, law.denominator) for x, m in law.counts} == {
                    x: Fraction(m, 16) for x, m in counter.items()}
                assert sum(counter.values()) == 16
                for a in range(1, max(map(abs, counter))+2):
                    literal_tail = Fraction(sum(m for x, m in counter.items() if abs(x) >= a), 16)
                    assert literal_tail == lab.tail(law, a) <= lab.chernoff(law, a)
                    tail_checks += 1
            contexts += 1
        cards.append({"fixture": index, "fixed_integer_index_phase": fixed_phase,
                      "same_key_relinearization_error": residual,
                      "uniform_switch_cap": lab.uniform_switch_cap(errors, radix, t)})
    assert contexts == 54 and outcomes == 864 and identities == 3456
    return {"setups": 6, "N": n, "Q": q, "t": t, "radix": radix,
            "message_contexts": contexts, "literal_CBD_coin_outcomes": outcomes,
            "integer_phase_coefficient_equalities": identities,
            "exact_tail_and_rational_Chernoff_checks": tail_checks, "cards": cards}


def synthetic_context(n, dimension):
    """Supported deterministic diagnostics, never purported honest key sampling."""
    q, t, eta, bits = (1 << 61)-1, 2*dimension+1, 1, 4
    secret = tuple((-1, 0, 1)[i % 3] for i in range(n))
    public_a = tuple((13*i+3) % q for i in range(n))
    public_e = tuple((i+1) % 3-1 for i in range(n))
    public_b = tuple((t*e-v) % q for e, v in zip(public_e, schoolbook(public_a, secret), strict=True))
    key_id = f"{n:064x}"
    pk = bgv.PublicKey(n, t, mpz(q), eta, tuple(map(mpz, public_a)), tuple(map(mpz, public_b)), key_id)
    sk = bgv.SecretKey(tuple(mpz(s % q) for s in secret), key_id)
    padded = 1 << (dimension-1).bit_length()
    levels = (q.bit_length()+bits-1)//bits
    family_errors = []

    def key(target, family):
        errors = tuple(tuple((i+j+family) % 3-1 for i in range(n)) for j in range(levels))
        family_errors.append(errors)
        columns = []
        for j, error in enumerate(errors):
            a = tuple((17*i+11*j+family+5) % q for i in range(n))
            b = tuple(((1 << (j*bits))*v+t*e-z) % q for v, e, z in zip(target, error, schoolbook(a, secret), strict=True))
            columns.append((tuple(map(mpz, b)), tuple(map(mpz, a))))
        return tuple(columns)

    relin = key(schoolbook(secret, secret), 0)
    rotations = []
    for j in range(padded.bit_length()-1):
        exponent = pow(1+2*n//padded, 1 << j, 2*n)
        target = [0]*n
        for i, s in enumerate(secret):
            position = i*exponent % (2*n)
            target[position % n] += s if position < n else -s
        rotations.append((exponent, key(tuple(target), j+1)))
    keys = trace.EvaluationKeys(key_id, padded, bits, relin, tuple(rotations), t*eta*n*((1 << bits)-1)*levels)
    return pk, sk, keys, tuple(family_errors), secret


def api_cipher(message, error, salt, pk, secret):
    centered = tuple(((int(x)+pk.t//2) % pk.t)-pk.t//2 for x in message)
    mask = tuple((7*i+salt) % int(pk.q) for i in range(pk.n))
    values = integer_cipher(centered, error, mask, secret, int(pk.q), pk.t)
    return bgv.Ciphertext(tuple(tuple(map(mpz, part)) for part in values), pk.key_id, pk.t//2+pk.t*pk.eta)


def actual_api_cases():
    pk, sk, keys, errors, secret = synthetic_context(16, 8)
    queries = tuple(product((0, 1), repeat=8))
    rows = [[0]*8, [1]*8, [i % 2 for i in range(8)], [1-i % 2 for i in range(8)]]
    cases = 0
    for query in queries:
        message, tiles = bgv.coefficient_inputs(list(query), rows, pk.n)
        fresh = tuple((i+sum(query)) % 3-1 for i in range(pk.n))
        query_cipher = api_cipher(message, fresh, 41, pk, secret)
        index = [api_cipher(tile, tuple((i+j) % 3-1 for i in range(pk.n)), 17+j, pk, secret) for j, tile in enumerate(tiles)]
        responses = trace.search(query_cipher, index, len(rows), pk, keys)
        decoded = trace.decode([bgv.decrypt(c, pk, sk) for c in responses], len(rows), 8, pk)
        expected = [sum(a != b for a, b in zip(query, row, strict=True)) for row in rows]
        assert decoded == expected
        cases += 1
    assert cases == 256
    return {"N": pk.n, "dimension": 8, "queries": cases, "rows": len(rows),
            "all_exact_scores": cases*len(rows), "same_key_reused": True,
            "synthetic_supported_masks_and_errors_not_honest_sampling": True}


def rotation_dependency():
    pk, sk, keys, errors, secret = synthetic_context(8, 2)
    message, tiles = bgv.coefficient_inputs([0, 1], [[0, 0], [0, 1], [1, 0]], pk.n)
    index = api_cipher(tiles[0], tuple((i+1) % 3-1 for i in range(pk.n)), 13, pk, secret)
    first_digits, later_digits, decoded, residual_checks = set(), set(), 0, 0
    for selected in literal_errors(2):
        fresh = selected+(0,)*(pk.n-2)
        query = api_cipher(message, fresh, 19, pk, secret)
        tensor_cipher = bgv.multiply(query, index, pk)
        canonical = tuple(map(int, tensor_cipher.components[2]))
        first_digits.add(lab.digits(canonical, int(pk.q), 1 << keys.digit_bits))
        relin = trace._switch(tensor_cipher.components[2], keys.relin, pk, keys.digit_bits)
        reduced = bgv.Ciphertext(tuple(tuple((a+b) % pk.q for a, b in zip(p, q, strict=True))
                                      for p, q in zip(tensor_cipher.components[:2], relin, strict=True)),
                                pk.key_id, tensor_cipher.phase_bound+keys.switch_error_bound)
        shifted = trace._monomial(reduced, -(keys.padded-1), pk)
        exponent, _ = keys.rotations[0]
        transformed = [0]*pk.n
        for i, c in enumerate(shifted.components[1]):
            pos = i*exponent % (2*pk.n)
            transformed[pos % pk.n] = int(c if pos < pk.n else -c) % int(pk.q)
        later_digits.add(lab.digits(tuple(transformed), int(pk.q), 1 << keys.digit_bits))
        for source, family in ((canonical, errors[0]), (tuple(transformed), errors[1])):
            residue = lab.switch_residual(source, family, int(pk.q), 1 << keys.digit_bits, pk.t)
            assert max(map(abs, residue)) <= lab.uniform_switch_cap(family, 1 << keys.digit_bits, pk.t)
            residual_checks += pk.n
        response = trace.search(query, [index], 3, pk, keys)
        assert trace.decode([bgv.decrypt(c, pk, sk) for c in response], 3, 2, pk) == [1, 0, 2]
        decoded += 1
    assert len(first_digits) == 1 and len(later_digits) > 1 and decoded == 16
    return {"N": pk.n, "dimension": 2, "conditional_two_atom_literal_coin_outcomes": decoded,
            "not_whole_N8_error_distribution": True, "first_relin_distinct_digit_tensors": len(first_digits),
            "later_rotation_distinct_digit_tensors": len(later_digits),
            "uniform_residual_coefficient_checks": residual_checks,
            "fresh_error_dependent_rotation_digits": True}


def falsifiers():
    shared = lab.affine_cbd((("E", 1), ("E", 1)))
    wrong_independent = lab.affine_cbd((("E0", 1), ("E1", 1)))
    assert lab.tail(shared, 2) == Fraction(1, 2)
    assert lab.tail(wrong_independent, 2) == Fraction(1, 8)
    single = Counter(literal_errors(1))
    dependent = Counter()
    independent_product = Counter()
    for (e,), mass in single.items():
        dependent[e*e] += mass
        for (fresh,), other_mass in single.items():
            independent_product[e*fresh] += mass*other_mass
    true_law = lab.Law(tuple(sorted(dependent.items())), 4)
    false_law = lab.Law(tuple(sorted(independent_product.items())), 16)
    assert lab.tail(true_law, 1, two_sided=False) == Fraction(1, 2)
    assert lab.tail(false_law, 1, two_sided=False) == Fraction(1, 8)
    assert lab.power_mgf(true_law, Fraction(2)) == Fraction(3, 2)
    assert lab.power_mgf(false_law, Fraction(2)) == Fraction(17, 16)
    # Four evaluations contain the same setup atom; P(all |E|=1) is 1/2,
    # not (1/2)^4. An unconditional prior does not remain a posterior law.
    shared_setup_all_fail, false_resampled_all_fail = Fraction(1, 2), Fraction(1, 16)
    return {"aliased_fresh_atom_exact_tail": "1/2", "false_independent_atom_tail": "1/8",
            "same_coin_coefficient_true_positive_tail": "1/2", "false_product_independence_tail": "1/8",
            "same_coin_true_power_MGF_at_base2": "3/2", "false_independent_power_MGF_at_base2": "17/16",
            "one_reused_setup_atom_four_queries_all_fail": str(shared_setup_all_fail),
            "false_fresh_setup_per_query_all_fail": str(false_resampled_all_fail),
            "premise_falsifiers_not_deployed_attacks": True}


def exact_distribution_cases():
    cases = literal_outcomes = certified_tail_checks = absolute_checks = 0
    for eta, weights in product((1, 2, 3), ((1,), (1, -2), (2, 2), (1, -1, 3))):
        counts = literal_law(weights, eta)
        law = lab.affine_cbd(tuple((str(i), w) for i, w in enumerate(weights)), eta)
        assert dict(law.counts) == counts and law.denominator == 4**(eta*len(weights))
        for threshold in range(1, max(map(abs, counts))+2):
            assert lab.tail(law, threshold) <= lab.chernoff(law, threshold)
            certified_tail_checks += 1
        cases += 1
        literal_outcomes += 4**(eta*len(weights))
    # A separate polynomial-power oracle starts from literal one-atom coins.
    def convolution(left, right):
        out = [0]*(len(left)+len(right)-1)
        for i, a in enumerate(left):
            for j, b in enumerate(right):
                out[i+j] += a*b
        return out
    for eta, atoms in product((1, 2, 3), (0, 1, 2, 4, 8)):
        single = Counter(abs(e[0]) for e in literal_errors(1, eta))
        base, exponent, coefficients = [single[i] for i in range(eta+1)], atoms, [1]
        while exponent:
            if exponent % 2:
                coefficients = convolution(coefficients, base)
            exponent //= 2
            if exponent:
                base = convolution(base, base)
        law = lab.absolute_cbd_sum(eta, atoms)
        assert dict(law.counts) == {i: c for i, c in enumerate(coefficients) if c}
        assert sum(coefficients) == law.denominator
        for threshold in range(1, eta*atoms+2):
            assert lab.tail(law, threshold, two_sided=False) <= lab.chernoff(law, threshold, two_sided=False)
            certified_tail_checks += 1
        if atoms:
            for target in (Fraction(1, 4), Fraction(1, 16), Fraction(1, 256)):
                cap, bound = lab.l1_setup_cap(eta, atoms, target)
                assert lab.tail(law, cap+1, two_sided=False) <= bound <= target
                absolute_checks += 1
    return {"weighted_literal_laws": cases, "weighted_literal_coin_outcomes": literal_outcomes,
            "absolute_CBD_generating_polynomial_laws": 15,
            "exact_tail_vs_rational_Chernoff_checks": certified_tail_checks,
            "good_setup_cap_vs_independent_exact_tail_checks": absolute_checks}


def test_complete_small_same_key_degree_two_laws_and_decoder_phase():
    assert small_laws()["integer_phase_coefficient_equalities"] == 3456


def test_actual_trace_search_API_and_full_exact_scores_with_supported_fixtures():
    assert actual_api_cases()["all_exact_scores"] == 1024


def test_first_relin_digits_are_fresh_error_free_but_trace_digits_are_not():
    assert rotation_dependency()["fresh_error_dependent_rotation_digits"]


def test_full_literal_CBD_and_absolute_noise_oracles():
    assert exact_distribution_cases()["good_setup_cap_vs_independent_exact_tail_checks"] == 36


def test_false_freshness_same_coin_weights_and_once_sampled_setup_regressions():
    assert falsifiers()["same_coin_true_power_MGF_at_base2"] == "3/2"


def test_aliases_cancel_before_squaring_and_produce_zero_law():
    assert lab.affine_cbd((("E", 3), ("E", -3))) == lab.Law(((0, 1),), 1)
    assert lab.affine_cbd((("E", 2), ("E", 1))) == lab.affine_cbd((("E", 3),))


@pytest.mark.parametrize("eta,atoms,budget", product((1, 2, 3), (1, 8, 32), (Fraction(1, 16), Fraction(1, 256))))
def test_setup_Chernoff_caps_conservative_in_exact_small_law(eta, atoms, budget):
    law = lab.absolute_cbd_sum(eta, atoms)
    cap, bound = lab.l1_setup_cap(eta, atoms, budget)
    assert lab.tail(law, cap+1, two_sided=False) <= bound <= budget


def test_conservative_lifetime_sums_distinct_failure_terms_and_abandoned_queries():
    assert lab.lifetime_failure(Fraction(1, 64), Fraction(1, 512), 8) == Fraction(1, 32)
    assert lab.lifetime_failure(Fraction(1, 64), Fraction(1, 512), 64) == Fraction(9, 64)
    assert lab.lifetime_failure(Fraction(1, 2), Fraction(1, 2), 8) == 1


@pytest.mark.parametrize("kappa,events", product((8, 16, 32), (1, 8, 64)))
def test_integer_concentration_never_rounds_square_root_down(kappa, events):
    rad = lab.concentration_radius(71, kappa, events)
    square = 71*(kappa+(2*events-1).bit_length())
    assert rad*rad >= square and (rad-1)**2 < square


@pytest.mark.parametrize("n,eta,levels,trace_factor,lifetime,kappa,mode", (
    (8, 1, 2, 2, 1, 8, "seeded-owner"), (32, 2, 4, 4, 8, 16, "seeded-owner"),
    (128, 3, 4, 4, 64, 32, "seeded-owner"), (128, 3, 4, 4, 64, 32, "public-key"),
))
def test_full_paid_model_is_contained_by_identical_known_adapter(n, eta, levels, trace_factor, lifetime, kappa, mode):
    card = lab.model_card(n, eta, levels, trace_factor, lifetime, kappa, mode)
    assert card["complete_uniform_setup_phase"] == card["strongest_known_adapter_phase"]
    assert not card["parameters_approved"] and not card["originality_resource_gate_passed"]
    assert Fraction(card["combined_correctness_failure_upper"]) <= Fraction(2, 2**kappa)


@pytest.mark.parametrize("call", (
    lambda: lab.cbd_counts(True), lambda: lab.affine_cbd((("E", 1.5),)),
    lambda: lab.Law(((0, 1), (0, 1)), 2), lambda: lab.Law(((0, -1),), -1),
    lambda: lab.power_mgf(lab.Law(((0, 1),), 1), 1.25),
    lambda: lab.power_mgf(lab.Law(((0, 1),), 1), Fraction(1)),
    lambda: lab.l1_setup_cap(1, 8, Fraction(0)),
    lambda: lab.digits((-1, 0), 97, 4), lambda: lab.digits((97, 0), 97, 4),
    lambda: lab.multiply((1, 2), (1, 2, 3, 4)),
    lambda: lab.concentration_radius(1, 8, 0), lambda: lab.lifetime_failure(Fraction(0), Fraction(0), 0),
))
def test_refuses_false_or_malformed_probability_and_ring_metadata(call):
    with pytest.raises(ValueError):
        call()
