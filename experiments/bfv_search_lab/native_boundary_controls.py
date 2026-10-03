"""E106 complete native affine control, conditional on external integer gates.

The graph starts with the two expanded original-query polynomials. Canonical
switch digits and terminal preimages are features; their ranges, global-Q
lifts, original packet binding and exact terminal rounding are NOT proved by
this affine map. Uniform rows are owner-protected known adjoint controls, not
a release protocol, low-state construction or HE security estimate.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import product
import secrets

import gmpy2

from experiments.bfv_search_lab import native_boundary_oracle as oracle


def _shape(ctx):
    ctx.validate()
    labels, group_sizes, per_stage = [], [], [0]*len(ctx.rotations)
    for start in range(0, len(ctx.index), ctx.padded):
        count = min(ctx.padded, len(ctx.index)-start)
        group_sizes.append(count)
        labels.extend(f"tile{tile}:relin" for tile in range(start, start+count))
        shift, size = ctx.padded//2, count
        for stage in range(len(ctx.rotations)):
            size = min(shift, size)
            labels.extend(f"group{start//ctx.padded}:stage{stage}:node{i}" for i in range(size))
            per_stage[stage] += size
            shift //= 2
    return tuple(labels), tuple(group_sizes), tuple(per_stage)


def _linear_image(ctx, features):
    """Own actual schedule; replace each nonlinear decomposition by features."""
    n, q = ctx.n, ctx.q
    labels, groups, _ = _shape(ctx)
    expected = (2+len(labels)*ctx.levels)*n
    if type(features) is not tuple or len(features) != expected or any(type(x) is not int for x in features):
        raise ValueError("Wrong complete affine feature vector")
    query = (features[:n], features[n:2*n])
    cursor, sources, seen = 2*n, [], []

    def switch(source, key, label):
        nonlocal cursor
        digits = tuple(features[cursor+j*n:cursor+(j+1)*n] for j in range(ctx.levels))
        cursor += ctx.levels*n
        reconstruction = tuple(sum(row[i] << (ctx.digit_bits*j) for j, row in enumerate(digits)) % q
                               for i in range(n))
        sources.extend((a-b) % q for a, b in zip(reconstruction, source, strict=True))
        seen.append(label)
        result = ((0,)*n, (0,)*n)
        for row, pair in zip(digits, key, strict=True):
            result = tuple(oracle.add(a, oracle.multiply(row, b, q), q)
                           for a, b in zip(result, pair, strict=True))
        return result

    responses = []
    for group, count in enumerate(groups):
        start, work = group*ctx.padded, []
        for tile in range(start, start+count):
            a0, a1 = ctx.index[tile]
            b0, b1 = query
            c0 = oracle.multiply(a0, b0, q)
            c1 = oracle.add(oracle.multiply(a0, b1, q), oracle.multiply(a1, b0, q), q)
            c2 = oracle.multiply(a1, b1, q)
            k0, k1 = switch(c2, ctx.relin, f"tile{tile}:relin")
            work.append((oracle.monomial(oracle.add(c0, k0, q), 1-ctx.padded, q),
                         oracle.monomial(oracle.add(c1, k1, q), 1-ctx.padded, q)))
        shift = ctx.padded//2
        for stage, (exponent, key) in enumerate(ctx.rotations):
            merged = []
            for i in range(min(shift, len(work))):
                plus, minus = work[i], work[i]
                if i+shift < len(work):
                    right = tuple(oracle.monomial(poly, shift, q) for poly in work[i+shift])
                    plus = tuple(oracle.add(a, b, q) for a, b in zip(work[i], right, strict=True))
                    minus = tuple(oracle.add(a, b, q, -1) for a, b in zip(work[i], right, strict=True))
                rotated = tuple(oracle.automorphism(poly, exponent, q) for poly in minus)
                k0, k1 = switch(rotated[1], key, f"group{group}:stage{stage}:node{i}")
                result = (oracle.add(rotated[0], k0, q), k1)
                merged.append(tuple(oracle.add(a, b, q) for a, b in zip(plus, result, strict=True)))
            work, shift = merged, shift//2
        responses.append(work[0])
    assert cursor == expected and tuple(seen) == labels
    return tuple(sources), tuple(x for cipher in responses for poly in cipher for x in poly)


@dataclass(frozen=True)
class Compiled:
    context_digest: str
    q: int
    primes: tuple[int, int]
    n: int
    cut_labels: tuple[str, ...]
    feature_count: int
    output_count: int
    matrix: tuple[tuple[int, ...], ...]

    @property
    def residual_count(self):
        return len(self.matrix)


def compile_residual(ctx):
    """Bounded public column probing, including all actual partial-tail cuts.

    Dense materialization is a tiny oracle, not the claimed registration cost
    of a native compiler. Source/RNS/terminal canonical checks stay external.
    """
    labels, groups, _ = _shape(ctx)
    f, o = (2+len(labels)*ctx.levels)*ctx.n, 2*len(groups)*ctx.n
    m = len(labels)*ctx.n+o
    if ctx.n != 8 or f > 1024 or m*(f+o) > 300000:
        raise ValueError("Only bounded N8 affine compilation is in scope")
    zero = (0,)*f
    assert _linear_image(ctx, zero) == ((0,)*(len(labels)*ctx.n), (0,)*o)
    columns = []
    for position in range(f):
        unit = tuple(int(i == position) for i in range(f))
        sources, outputs = _linear_image(ctx, unit)
        columns.append(sources+outputs)
    matrix = tuple(tuple(column[row] for column in columns)+tuple(
        -int(row == len(labels)*ctx.n+j) % ctx.q for j in range(o)) for row in range(m))
    return Compiled(ctx.digest(), ctx.q, ctx.primes, ctx.n, labels, f, o, matrix)


def features(ctx, query_cipher, cuts, preterminal):
    """Structural features, intentionally without the external digit gate.

    A forged digit trace can satisfy every affine relation. The caller must
    still validate global-Q canonical digits and exact terminal/wire relations.
    These values do not themselves authorize private decryption.
    """
    labels, groups, _ = _shape(ctx)
    if (type(query_cipher) is not tuple or len(query_cipher) != 2
            or type(cuts) is not tuple or len(cuts) != len(labels)
            or type(preterminal) is not tuple or len(preterminal) != len(groups)):
        raise ValueError("Wrong complete feature grammar")
    def plain(poly, modulus=None):
        if (type(poly) is not tuple or any(type(x) is not int and type(x) is not gmpy2.mpz for x in poly)):
            raise ValueError("Wrong integer/GMP polynomial grammar")
        return oracle.polynomial(tuple(int(x) for x in poly), ctx.n, modulus)

    out = [x for poly in query_cipher for x in plain(poly, ctx.q)]
    for label, cut in zip(labels, cuts, strict=True):
        if (type(cut) is not oracle.Switch or cut.label != label or type(cut.digits) is not tuple
                or len(cut.digits) != ctx.levels):
            raise ValueError("Wrong complete digit cut order/shape")
        for poly in cut.digits:
            out.extend(plain(poly))
    for cipher in preterminal:
        if type(cipher) is not tuple or len(cipher) != 2:
            raise ValueError("Wrong terminal preimage shape")
        for poly in cipher:
            out.extend(plain(poly, ctx.q))
    return tuple(out)


def _values(compiled, values):
    if (type(compiled) is not Compiled or type(values) is not tuple
            or len(values) != compiled.feature_count+compiled.output_count
            or any(type(x) is not int for x in values)):
        raise ValueError("Wrong compiled affine vector")


def residuals(compiled, values):
    _values(compiled, values)
    return tuple(sum(a*b for a, b in zip(row, values, strict=True)) % compiled.q for row in compiled.matrix)


def _prime(prime):
    # The statistical statement is conditional on primality; this is the same
    # probable-prime arithmetic gate used for the repository's selected primes.
    if type(prime) is not int or not 3 <= prime < 1 << 64 or not gmpy2.is_prime(prime, 32):
        raise ValueError("A named prime field is required")


@dataclass(frozen=True)
class ProtectedRow:
    context_digest: str
    prime: int
    hints: tuple[int, ...]
    output_weights: tuple[int, ...]


def compile_adjoint(compiled, prime, weights):
    """Known A^T alpha control; discard zero-RHS cut weights after compiling."""
    _prime(prime)
    if (type(compiled) is not Compiled or prime not in compiled.primes
            or type(weights) is not tuple or len(weights) != compiled.residual_count
            or any(type(x) is not int or not 0 <= x < prime for x in weights)):
        raise ValueError("Wrong independent full-residual field weights")
    hints = tuple(sum(weight*row[j] for weight, row in zip(weights, compiled.matrix, strict=True)) % prime
                  for j in range(compiled.feature_count))
    cut_coordinates = compiled.residual_count-compiled.output_count
    # The final rows are predicted preterminal output minus supplied Y. All
    # earlier rows have zero RHS, so their weights need not remain protected.
    return ProtectedRow(compiled.context_digest, prime, hints, weights[cut_coordinates:])


def compile_private_rows(compiled, k=4, *, randbelow=secrets.randbelow):
    """Independent ideal-uniform registration rows for EACH named prime.

    Protected registration/rows are trusted; this helper supplies no attestation,
    rollback persistence, side-channel guarantee or private-key release gate.
    The injected sampler is solely a deterministic test seam, never a PRG claim.
    """
    if type(compiled) is not Compiled or type(k) is not int or not 1 <= k <= 16:
        raise ValueError("Wrong bounded protected-row registration")
    result = []
    for prime in compiled.primes:
        _prime(prime)
        rows = []
        for _ in range(k):
            weights = tuple(randbelow(prime) for _ in range(compiled.residual_count))
            rows.append(compile_adjoint(compiled, prime, weights))
        result.append(tuple(rows))
    return tuple(result)


def check_adjoint(row, values):
    """Affine arithmetic only; caller-pinned context and integer gates required."""
    if (type(row) is not ProtectedRow or type(values) is not tuple
            or len(values) != len(row.hints)+len(row.output_weights) or any(type(x) is not int for x in values)):
        raise ValueError("Wrong protected affine arithmetic input")
    f = len(row.hints)
    lhs = sum(a*b for a, b in zip(row.hints, values[:f], strict=True))
    rhs = sum(a*b for a, b in zip(row.output_weights, values[f:], strict=True))
    return (lhs-rhs) % row.prime == 0


def check_rows(compiled, rows, values):
    _values(compiled, values)
    if (type(rows) is not tuple or len(rows) != len(compiled.primes)
            or any(type(family) is not tuple or not family for family in rows)):
        raise ValueError("Both field families are required")
    accepted = True
    for prime, family in zip(compiled.primes, rows, strict=True):
        for row in family:
            if (type(row) is not ProtectedRow or row.prime != prime
                    or row.context_digest != compiled.context_digest or len(row.hints) != compiled.feature_count
                    or len(row.output_weights) != compiled.output_count):
                raise ValueError("Wrong protected prime/context/shape")
            # Complete every arithmetic row after a mismatch. This Python code
            # still provides no constant-time or lifecycle assurance.
            accepted &= check_adjoint(row, values)
    return bool(accepted)


def rank_mod(matrix, prime):
    """Exact modular elimination, conditional on the selected field modulus."""
    _prime(prime)
    if (type(matrix) is not tuple or not matrix or type(matrix[0]) is not tuple or not matrix[0]
            or len(matrix)*len(matrix[0]) > 300000
            or any(type(row) is not tuple or len(row) != len(matrix[0]) or any(type(x) is not int for x in row) for row in matrix)):
        raise ValueError("Wrong bounded field matrix")
    rows, rank = [[x % prime for x in row] for row in matrix], 0
    for j in range(len(rows[0])):
        pivot = next((i for i in range(rank, len(rows)) if rows[i][j]), None)
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        inv = pow(rows[rank][j], -1, prime)
        rows[rank] = [x*inv % prime for x in rows[rank]]
        for i in range(rank+1, len(rows)):
            factor = rows[i][j]
            if factor:
                rows[i] = [(a-factor*b) % prime for a, b in zip(rows[i], rows[rank], strict=True)]
        rank += 1
        if rank == len(rows):
            break
    return rank


def rank_inventory(compiled):
    return {str(prime): {"complete_residual_map_rank": rank_mod(compiled.matrix, prime),
                         "feature_only_map_rank": rank_mod(tuple(row[:compiled.feature_count] for row in compiled.matrix), prime),
                         "residual_rows": compiled.residual_count, "feature_columns": compiled.feature_count,
                         "including_terminal_preimage_columns": compiled.feature_count+compiled.output_count}
            for prime in compiled.primes}


def uniform_residual_exhaustion(prime=5, dimension=3):
    """Every nonzero ideal residual/row; not a general nonlinear trace proof."""
    _prime(prime)
    if type(dimension) is not int or not 1 <= dimension <= 4 or prime**(2*dimension) > 100000:
        raise ValueError("Only a bounded exact uniform field control is permitted")
    rows, errors, maximum = tuple(product(range(prime), repeat=dimension)), 0, 0
    for error in rows:
        if not any(error):
            continue
        accepted = sum(sum(a*b for a, b in zip(row, error, strict=True)) % prime == 0 for row in rows)
        assert accepted*prime == len(rows)
        errors += 1
        maximum = max(maximum, accepted)
    return {"prime": prime, "residual_coordinates": dimension, "nonzero_residuals": errors,
            "uniform_rows": len(rows), "checks": errors*len(rows), "maximum_accept_count": maximum,
            "one_row_exact_miss_probability": [1, prime], "nonlinear_and_release_prerequisites_not_proved": True}


def cost_card(*, n, padded, records, q_bits, digit_bits, terminal_bits, k=4, limbs=2):
    """Source-derived Q120/two-limb count card, not timing or a lower bound."""
    if (any(type(x) is not int for x in (n, padded, records, q_bits, digit_bits, terminal_bits, k, limbs))
            or n < 8 or n > 32768 or n & (n-1) or padded < 1 or padded > n//2 or padded & (padded-1)
            or not 1 <= records <= 64*n or q_bits != 120 or not 4 <= digit_bits <= 60
            or not 16 <= terminal_bits <= 60 or terminal_bits >= q_bits or not 1 <= k <= 16 or limbs != 2):
        raise ValueError("Wrong bounded native count geometry")
    capacity, ell = n//padded, (q_bits+digit_bits-1)//digit_bits
    tiles = (records+capacity-1)//capacity
    groups = tuple(min(padded, tiles-start) for start in range(0, tiles, padded))
    rotations = sum(sum(min(m, padded//(1 << j)) for j in range(1, padded.bit_length())) for m in groups)
    cuts, replies = tiles+rotations, len(groups)
    f, o, m = (2+cuts*ell)*n, 2*replies*n, (cuts+2*replies)*n

    def packed(count, bits):
        return (count*bits+7)//8

    return {"n": n, "padded": padded, "records": records, "tile_capacity": capacity,
            "tiles": tiles, "active_group_sizes": groups, "replies": replies,
            "gadget_levels": ell, "homomorphic_query_expansion_cuts": 0,
            "product_relinearization_cuts": tiles, "butterfly_cuts": rotations,
            "total_canonical_switch_cuts": cuts, "canonical_source_coefficients": cuts*n,
            "canonical_digit_coefficients_derived_or_supplied": cuts*ell*n,
            "terminal_coordinate_relations": o, "affine_feature_count": f, "affine_residual_count": m,
            "source_witness_packed_bytes": packed(cuts*n, q_bits),
            "source_witness_two_uint64_RNS_bytes": cuts*n*limbs*8,
            "terminal_preimage_packed_bytes": packed(o, q_bits),
            "terminal_preimage_two_uint64_RNS_bytes": o*limbs*8,
            "source_and_terminal_witness_packed_bytes": packed((cuts*n)+o, q_bits),
            "source_and_terminal_witness_two_uint64_RNS_bytes": ((cuts*n)+o)*limbs*8,
            "compact_response_coefficient_body_bytes": 2*replies*packed(n, terminal_bits),
            "dense_compiled_hint_packed_bytes": packed(k*f, q_bits),
            "retained_private_output_weights_packed_bytes": packed(k*o, q_bits),
            "dense_hint_and_retained_weights_packed_bytes": packed(k*(f+o), q_bits),
            "dense_hint_and_retained_weights_two_uint64_RNS_bytes": k*(f+o)*limbs*8,
            "discardable_zero_RHS_source_weights_per_prime": k*cuts*n,
            "sampled_uniform_weights_per_prime_at_registration": k*m,
            "online_dense_field_products_both_primes": limbs*k*(f+o),
            "unfused_reverse_adjoint_ring_products_both_primes_registration_upper_bound": limbs*k*(4*tiles+2*ell*cuts),
            "native_pointwise_ring_products_per_prime": 4*tiles+2*ell*cuts,
            "native_online_forward_NTTs_per_prime": 2+ell*cuts,
            "native_online_inverse_NTTs_per_prime": 3*tiles+2*cuts,
            "native_index_forward_NTTs_per_prime_registration": 2*tiles,
            "native_key_forward_NTTs_per_prime_registration": 2*ell*padded.bit_length(),
            "native_constructor_auxiliary_transforms_CRT_bases_and_allocations_additional_unpriced": True,
            "native_switch_and_final_CRT_coefficients": cuts*n+o,
            "literal_dense_matrix_Q_coefficients_if_materialized": m*(f+o),
            "query_codec_SHAKE_original_packet_binding_and_local_bounds_additional": True,
            "range_global_CRT_digit_derivation_terminal_quotient_checks_additional": True,
            "source_witness_may_be_derived_locally_at_paid_public_work": True,
            "all_controls_receive_same_grouping_fusion_and_derived_digits": True,
            "terminal_quotient_range_proof_bytes_or_prover_cost_unknown": True,
            "specialized_ring_double_CRT_complete_adapter_cost_unknown": True,
            "TEE_attestation_provisioning_links_durable_lifecycle_cost_unknown": True,
            "word_counts_are_not_RSS_hardware_cycles_or_witness_lower_bounds": True,
            "rank_seed_entropy_compression_or_approved_parameters_not_claimed": True,
            "rounds_count_choice_not_an_HE_or_protocol_security_target": True}


def paidcost_cards(ctx, k=4):
    ctx.validate()
    return cost_card(n=ctx.n, padded=ctx.padded, records=len(ctx.ids), q_bits=ctx.q.bit_length(),
                     digit_bits=ctx.digit_bits, terminal_bits=ctx.p.bit_length(), k=k)
