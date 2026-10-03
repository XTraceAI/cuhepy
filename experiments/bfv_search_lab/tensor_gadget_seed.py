"""Q69 known homomorphic-gadget tensor seed, no encrypted/protected service.

Use every radix cross term and the public scalar digits of B**(a+b) mod Q.
The resulting C1 lift is common and bounded, unlike arbitrary RNS-limb digits.
This may avoid a first rotation source cut even in full groups. Public matrix
compilation is a mandatory known control with substantial state/work cost.
"""

from __future__ import annotations

from experiments.bfv_search_lab import propagated_gadget_bgv as gadget


def power_digits(q, bits):
    ell, base = (q.bit_length() + bits - 1) // bits, 1 << bits
    return tuple(
        tuple(
            tuple(
                row[0]
                for row in gadget.canonical_digits((pow(base, a + b, q),), q, bits)
            )
            for b in range(ell)
        )
        for a in range(ell)
    )


def c1_seed(query, indexed, relin_digits, relin_a, q, bits):
    """Exact small integer reference; no secret key or independent limb input."""
    n, ell = len(query[0]), (q.bit_length() + bits - 1) // bits
    dq = tuple(gadget.canonical_digits(p, q, bits) for p in query)
    di = tuple(gadget.canonical_digits(p, q, bits) for p in indexed)
    gamma = power_digits(q, bits)
    out = [[0] * n for _ in range(ell)]
    for component in range(2):
        for a in range(ell):
            for b in range(ell):
                product = gadget.integer_product(dq[component][a], di[1 - component][b])
                for j in range(ell):
                    scalar = gamma[a][b][j]
                    if scalar:
                        out[j] = [
                            x + scalar * y for x, y in zip(out[j], product, strict=True)
                        ]
    for d, public_a in zip(relin_digits, relin_a, strict=True):
        digits = gadget.canonical_digits(public_a, q, bits)
        for j in range(ell):
            product = gadget.integer_product(d, digits[j])
            out[j] = [x + y for x, y in zip(out[j], product, strict=True)]
    return tuple(tuple(row) for row in out)


def seed_bound(n, q, bits, relin_bits=30):
    ell, limit = (q.bit_length() + bits - 1) // bits, (1 << bits) - 1
    gamma = power_digits(q, bits)
    sums = [
        sum(gamma[a][b][j] for a in range(ell) for b in range(ell)) for j in range(ell)
    ]
    relin_ell = (q.bit_length() + relin_bits - 1) // relin_bits
    return (
        2 * n * limit**2 * max(sums) + n * relin_ell * ((1 << relin_bits) - 1) * limit
    )


def source_models(geometry, bits):
    """Fixed Q/P complete-body/key/producer models, not native instructions."""
    g = geometry
    n, q, t, eta, d = g["N"], int(g["Q_hex"], 16), g["t"], g["eta"], g["D"]
    bq, bi = t // 2 + t * eta, t // 2 + t * eta * (2 * n + 1)
    ell, ell30, poly = (q.bit_length() + bits - 1) // bits, 4, n * 15
    canonical_error = t * eta * n * ell30 * ((1 << 30) - 1)
    lseed = seed_bound(n, q, bits)
    out = []
    for vectors in g["vectors"]:
        tiles = (vectors + n // d - 1) // (n // d)
        for rule in ("mixed_unary_two_propagations", "tensor_seed_first_rotation"):
            bounds, removed, source_bytes, canonical_bytes, first_nodes = [], 0, 0, 0, 0
            for start in range(0, tiles, d):
                size = min(d, tiles - start)
                canonical = gadget.model(
                    n,
                    q,
                    t,
                    eta,
                    d,
                    size,
                    30,
                    bq,
                    bi,
                    propagated_stages=0,
                    terminal=g["P"],
                )
                canonical_bytes += canonical["full_source_and_terminal_Q_body_bytes"]
                if rule == "mixed_unary_two_propagations" and size <= d // 2:
                    small = gadget.model(
                        n, q, t, eta, d, size, bits, bq, bi, propagated_stages=2
                    )
                    stage_error = sum(
                        r["suffix_support_weight"]
                        * (
                            r["switch_error_bound"]
                            if r["level"] < 3
                            else canonical_error
                        )
                        for r in small["stages"]
                    )
                    bound = d * (n * bq * bi + canonical_error) + stage_error
                    eliminated = small["removed_source_cuts"]
                elif rule == "tensor_seed_first_rotation":
                    # C1 state is fixed by public tensor/relinearization inputs;
                    # both plus and minus exist before the first binary merge.
                    source = lseed * (2 if size > d // 2 else 1)
                    bound = (
                        d * (n * bq * bi + canonical_error)
                        + (d // 2) * t * eta * n * ell * source
                        + (d // 2 - 1) * canonical_error
                    )
                    eliminated = min(size, d // 2)
                    first_nodes += eliminated
                else:
                    bound, eliminated = canonical["full_phase_bound"], 0
                terminal_bound = (g["P"] * bound + q - 1) // q + ((n + 1) * t + 1) // 2
                bounds.append(
                    {
                        "tiles": size,
                        "full_phase_bound": bound,
                        "phase_bound_bits": bound.bit_length(),
                        "terminal_bound": terminal_bound,
                        "guard": 2 * bound < q and 2 * terminal_bound < g["P"],
                    }
                )
                removed += eliminated
                source_bytes += (
                    canonical["full_source_and_terminal_Q_body_bytes"]
                    - eliminated * poly
                )
            changed_rotation_keys = 3 if rule.startswith("mixed") else 1
            extra_key_polys = changed_rotation_keys * 2 * (ell - ell30)
            out.append(
                {
                    "vectors": vectors,
                    "rule": rule,
                    "digit_bits": bits,
                    "digits": ell,
                    "group_guards": bounds,
                    "all_guards_pass": all(v["guard"] for v in bounds),
                    "removed_source_cuts": removed,
                    "full_source_and_terminal_Q_body_bytes": source_bytes,
                    "canonical_body_bytes": canonical_bytes,
                    "saving_fraction": 1 - source_bytes / canonical_bytes,
                    "additional_evaluation_key_polynomials": extra_key_polys,
                    "additional_evaluation_key_Q_body_bytes": extra_key_polys * poly,
                    "tensor_seed_state_bound": lseed
                    if rule.startswith("tensor")
                    else None,
                    "direct_tensor_seed_query_index_ring_products": 2 * ell**2 * tiles
                    if rule.startswith("tensor")
                    else None,
                    "direct_tensor_seed_relin_A_ring_products": ell * ell30 * tiles
                    if rule.startswith("tensor")
                    else None,
                    "compiled_query_matrix_polynomials": 4 * ell * first_nodes
                    if rule.startswith("tensor")
                    else None,
                    "compiled_query_matrix_Q_body_bytes": 4 * ell * first_nodes * poly
                    if rule.startswith("tensor")
                    else None,
                    "compiled_query_matrix_RNS_word_bytes": 4
                    * ell
                    * first_nodes
                    * n
                    * 2
                    * 8
                    if rule.startswith("tensor")
                    else None,
                    "compiled_query_matrix_online_ring_products": 4 * ell * first_nodes
                    if rule.startswith("tensor")
                    else None,
                    "compiled_relin_matrix_online_ring_products": 2
                    * ell30
                    * first_nodes
                    if rule.startswith("tensor")
                    else None,
                    "compiled_matrix_setup_work_measured": False,
                    "full_native_admission_implemented": False,
                    "scope": "Public feasibility/body/sufficient matrix models only; no security approval or latency/usefulness result. Strong known-method controls receive the same public matrices. Mixed early keys are charged even when full groups use canonical fallback.",
                }
            )
    return out
