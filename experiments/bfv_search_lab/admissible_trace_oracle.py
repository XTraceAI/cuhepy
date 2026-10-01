"""E81 bounded noncanonical BGV trace correctness, not a succinct proof.

An exact global digit box/recomposition relation admits aliases without extra
worst-case noise relative to canonical unsigned digits at the SAME gadget base.
All approved root/key/noise bounds remain necessary. This is a known-method
exactness control, no parameter/feedback/private-timing or novelty assurance.
"""

from dataclasses import replace
import itertools

from experiments.bfv_search_lab import packed_query_expansion as packed
from experiments.bfv_search_lab import seed_composition_relation as canonical


def admissible_recomposition(p, split, bits, q):
    B, ell = 1 << bits, (q.bit_length() + bits - 1) // bits
    return (type(split) is tuple and len(split) == ell
            and all(type(row) is tuple and len(row) == len(p)
                    and all(type(x) is int and 0 <= x < B for x in row) for row in split)
            and all(type(x) is int and 0 <= x < q for x in p)
            and all(sum(split[j][i] * B**j for j in range(ell)) % q == x for i, x in enumerate(p)))


def alias_digits(p, bits, q, policy):
    B, ell = 1 << bits, (q.bit_length() + bits - 1) // bits
    capacity = B**ell
    if policy not in ("canonical", "max_representative", "alternating", "max_digit_sum"):
        raise ValueError("Unknown public alias policy")
    selected = []
    for i, x in enumerate(p):
        k = (capacity - 1 - x) // q
        if policy == "canonical" or (policy == "alternating" and i % 2 == 0):
            k = 0
        elif policy == "max_digit_sum":
            if k > 64:
                raise ValueError("Alias enumeration exceeds bounded oracle")
            k = max(range(k + 1), key=lambda j: sum((int(x) + j * q >> (h * bits)) & (B - 1) for h in range(ell)))
        selected.append(int(x) + k * q)
    return tuple(tuple((x >> (j * bits)) & (B - 1) for x in selected) for j in range(ell))


def _expand(request, pk, keys, *, policy="canonical", supplied=None):
    q = int(pk.q)
    work = (tuple(tuple(map(int, p)) for p in request.ciphertext.components),)
    switches, cursor = [], 0
    for level, (exponent, key) in enumerate(keys.rotations):
        even, odd = [], []
        for branch, pair in enumerate(work):
            rot = tuple(canonical.automorphism(p, exponent, q) for p in pair)
            split = alias_digits(rot[1], keys.digit_bits, q, policy)
            if supplied is not None:
                if cursor >= len(supplied):
                    raise ValueError("Missing admitted branch")
                candidate = supplied[cursor]
                if (type(candidate) is not canonical.Switch or type(candidate.level) is not int
                        or type(candidate.branch) is not int or (candidate.level, candidate.branch) != (level, branch)
                        or not canonical._integer_tree((candidate.input_c1, candidate.rotated_c1, candidate.switched))
                        or candidate.input_c1 != pair[1] or candidate.rotated_c1 != rot[1]
                        or not admissible_recomposition(rot[1], candidate.gadget, keys.digit_bits, q)):
                    raise ValueError("Invalid global bounded digit/branch relation")
                split = candidate.gadget
            terms = tuple(tuple(canonical.product(d, col[k], q) for d, col in zip(split, key, strict=True)) for k in range(2))
            switched = tuple(tuple(sum(p[i] for p in terms_) % q for i in range(pk.n)) for terms_ in terms)
            saved = canonical.Switch(level, branch, pair[1], rot[1], split, switched)
            if supplied is not None and candidate != saved:
                raise ValueError("Incorrect admitted switch output")
            switches.append(saved)
            cursor += 1
            rotated = (tuple((x + y) % q for x, y in zip(rot[0], switched[0], strict=True)), switched[1])
            even.append(tuple(tuple((x + y) % q for x, y in zip(p, r, strict=True)) for p, r in zip(pair, rotated, strict=True)))
            odd.append(tuple(canonical.monomial(tuple((x - y) % q for x, y in zip(p, r, strict=True)), -(1 << level), q)
                             for p, r in zip(pair, rotated, strict=True)))
        work = tuple(even + odd)
    if supplied is not None and cursor != len(supplied):
        raise ValueError("Extraneous admitted branch")
    return work, tuple(switches)


def make_trace(index, request, pk, keys, *, policy):
    canonical._check_inputs(index, request, pk, keys)
    work, switches = _expand(request, pk, keys, policy=policy)
    expanded = work[:index.space.columns]
    output = canonical._evaluate(index, expanded, pk)
    certificate = canonical.support.certify(index.space.layout)
    return canonical.Trace("E81-bounded-unsigned-global-v1:" + canonical.context(index, request, pk, keys), switches,
                           expanded, output, canonical._project(output, certificate))


def check_trace(index, request, pk, keys, trace):
    """Public full recomputation and uniform no-wrap gate; no secret input."""
    try:
        canonical._check_inputs(index, request, pk, keys)
        if (type(trace) is not canonical.Trace
                or trace.public_context != "E81-bounded-unsigned-global-v1:" + canonical.context(index, request, pk, keys)
                or not canonical._integer_tree((trace.expanded, trace.full_output, trace.projected_output))):
            return False
        # _check_inputs includes the complete pinned public output bound. This
        # remains the SAME bound: admitted digits have canonical magnitude.
        work, _ = _expand(request, pk, keys, supplied=trace.switches)
        expanded = work[:index.space.columns]
        output = canonical._evaluate(index, expanded, pk)
        return (trace.expanded == expanded and trace.full_output == output
                and trace.projected_output == canonical._project(output, canonical.support.certify(index.space.layout)))
    except (ValueError, TypeError, IndexError, AttributeError):
        return False


def canonical_view(index, request, pk, keys, trace):
    return replace(trace, public_context=canonical.context(index, request, pk, keys))


def exhaustive_scalar():
    """All 3 secrets, 81 bounded key-error tuples, 256 digit vectors at Q97.

    Public encryption dimension1 is deliberately only a scalar algebra oracle.
    It is not an RLWE security parameter or a real encrypted-search benchmark.
    """
    q, t, B, ell, message = 97, 3, 4, 4, 1
    checked, aliases = 0, 0
    for s in (-1, 0, 1):
        A = (13, 71, 6, 33)
        for errors in itertools.product((-1, 0, 1), repeat=ell):
            key_B = tuple((B**j * s + t * errors[j] - A[j] * s) % q for j in range(ell))
            for d in itertools.product(range(B), repeat=ell):
                representative = sum(x * B**j for j, x in enumerate(d))
                c1 = representative % q
                c0 = (message - c1 * s) % q
                out0, out1 = (c0 + sum(x * b for x, b in zip(d, key_B, strict=True))) % q, sum(x * a for x, a in zip(d, A, strict=True)) % q
                phase = (out0 + out1 * s) % q
                phase = phase if phase <= q // 2 else phase - q
                expected = message + t * sum(x * e for x, e in zip(d, errors, strict=True))
                assert abs(expected) <= message + t * ell * (B - 1) < q / 2
                assert phase == expected and phase % t == message
                checked += 1
                aliases += representative >= q
    return {"q": q, "t": t, "base": B, "digits": ell, "secret_choices": 3,
            "all_bounded_error_tuples": 81, "all_digit_vectors": 256,
            "cases": checked, "noncanonical_alias_cases": aliases,
            "every_integer_phase_and_exact_decode_matches": True}


def negative_controls():
    # Exact integer recomposition alone does NOT control switching noise.
    q, t, message, B = 97, 3, 1, 4
    canonical_digits, unbounded = (2, 3, 1, 0), (34, -5, 1, 0)
    assert sum(d * B**j for j, d in enumerate(canonical_digits)) == sum(d * B**j for j, d in enumerate(unbounded)) == 30
    def decoded(d):
        phase = (message + t * d[0]) % q  # e0=1; every other switching error=0.
        return (phase if phase <= q // 2 else phase - q) % t
    assert decoded(canonical_digits) == message and decoded(unbounded) != message
    # Two small RNS limbs each accept their own bounded gadget. They are NOT
    # one globally shared integer gadget witness over Q=13*17.
    d13, d17 = (1, 3, 0, 0), (1, 0, 1, 0)
    assert sum(d * B**j for j, d in enumerate(d13)) % 13 == 0
    assert sum(d * B**j for j, d in enumerate(d17)) % 17 == 0
    r13, r17 = t * sum(d13) % 13, t * sum(d17) % 17
    phase = (r13 + 13 * ((r17 - r13) * pow(13, -1, 17) % 17)) % 221
    centered = phase if phase <= 221 // 2 else phase - 221
    assert centered % t != 0
    return {"unbounded_integer_recomposition_equal": True, "unbounded_decoded": decoded(unbounded),
            "expected": message, "RNS_limb_digit_vectors": (d13, d17),
            "RNS_each_limb_recomposition_valid": True, "RNS_global_centered_phase": centered,
            "RNS_decoded": centered % t, "RNS_expected": 0,
            "scope": "Counterexamples to omitted digit bounds and independently chosen limb digits, not to globally linked bounded gadgets."}


def count_delta(n, columns, replies, q_bits, digit_bits):
    base = canonical.count_designs(n, columns, replies, q_bits, digit_bits)
    ks, ell = base["factor"] - 1, base["gadget_digits"]
    return {"n": n, "columns": columns, "replies": replies, "q_bits": q_bits, "digit_bits": digit_bits,
            "same_digit_box_coefficients": ks * ell * n,
            "same_digit_box_bit_constraints_upper": ks * ell * n * digit_bits,
            "same_global_modQ_recomposition_equations": ks * n,
            "canonical_less_than_Q_comparisons_potentially_removed": ks * n,
            "same_conservative_switch_and_output_bound": True,
            "Q_or_key_or_wire_increase_relative_same_base_canonical_control": 0,
            "integer_RNS_digits_must_be_globally_shared": True,
            "proof_constraint_time_bytes_gain_measured": False,
            "scope": "Known bounded decomposition adapter; specialized controls may already omit/share comparisons. Dominant digit-box work remains; no new primitive or proof-speed claim."}
