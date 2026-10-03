"""E105 exact conditioned trace law and matched representation/count controls.

This finite N8/D2 diagnostic fixes all setup/masks and enumerates fresh CBD1
atoms. Exact carries preserve source/maintenance dependence. Cache operation
counts are not HE performance, parameter approval or a general reuse theorem.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from fractions import Fraction
from itertools import product
from math import gcd

from gmpy2 import mpz

from experiments.bfv_search_lab import finite_lifetime_noise as noise
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace


def monomial(poly, shift):
    n, out = len(poly), [0]*len(poly)
    for i, value in enumerate(poly):
        position = (i+shift) % (2*n)
        out[position % n] = value if position < n else -value
    return tuple(out)


def automorphism(poly, exponent):
    n, out = len(poly), [0]*len(poly)
    if exponent % 2 != 1:
        raise ValueError("Odd negacyclic automorphism exponent required")
    for i, value in enumerate(poly):
        position = i*exponent % (2*n)
        out[position % n] = value if position < n else -value
    return tuple(out)


def projection(poly):
    shifted = monomial(poly, -1)
    return noise.add(shifted, automorphism(shifted, 1+len(poly)))


def cbd_states():
    """Whole eight-atom support; literal bit multiplicity is 2**zero_count."""
    for errors in product((-1, 0, 1), repeat=8):
        yield errors, 1 << errors.count(0)


def unit_inverse(matrix, modulus):
    """Exact sufficient invertibility certificate, checked over Z/modulus Z.

    A failure to find a unit pivot is not a general noninvertibility theorem
    over composite moduli. A returned inverse is independently multiplied back.
    """
    n = len(matrix)
    if (type(matrix) is not tuple or not 1 <= n <= 8
            or any(type(row) is not tuple or len(row) != n or any(type(x) is not int for x in row) for row in matrix)
            or type(modulus) is not int or modulus < 3):
        raise ValueError("Bounded exact square modular matrix required")
    rows = [[x % modulus for x in row]+[int(i == j) for j in range(n)] for i, row in enumerate(matrix)]
    for column in range(n):
        pivot = next((i for i in range(column, n) if gcd(rows[i][column], modulus) == 1), None)
        if pivot is None:
            return None
        rows[column], rows[pivot] = rows[pivot], rows[column]
        inverse = pow(rows[column][column], -1, modulus)
        rows[column] = [x*inverse % modulus for x in rows[column]]
        for i in range(n):
            if i != column:
                factor = rows[i][column]
                rows[i] = [(a-factor*b) % modulus for a, b in zip(rows[i], rows[column], strict=True)]
    result = tuple(tuple(row[n:]) for row in rows)
    for left, right in ((matrix, result), (result, matrix)):
        assert tuple(tuple(sum(left[i][k]*right[k][j] for k in range(n)) % modulus for j in range(n)) for i in range(n)) == tuple(tuple(int(i == j) for j in range(n)) for i in range(n))
    return result


def digit_columns(poly, levels=16):
    return tuple(tuple((value >> (4*j)) & 15 for value in poly) for j in range(levels))


@dataclass(frozen=True)
class State:
    errors: tuple[int, ...]
    mass: int
    delta: tuple[int, ...]
    delta_digits: tuple[tuple[int, ...], ...]
    original_noise: tuple[int, ...]


@dataclass(frozen=True)
class Query:
    bits: tuple[int, int]
    message: tuple[int, ...]
    beta: tuple[int, ...]
    beta_digits: tuple[tuple[int, ...], ...]
    original_mean: tuple[int, ...]


class Graph:
    """Fixed supported actual graph; no key draw/approval or secret-release gate."""

    def __init__(self, pk, sk, keys, family_errors, integer_secret, index_message,
                 index_error, index_mask, query_mask):
        if (pk.n != 8 or pk.t != 5 or pk.q != (1 << 61)-1 or pk.eta != 1
                or keys.padded != 2 or keys.digit_bits != 4 or len(keys.rotations) != 1
                or len(family_errors) != 2 or any(len(f) != 16 for f in family_errors)
                or sk.key_id != pk.key_id or keys.key_id != pk.key_id):
            raise ValueError("Registered N8/D2/t5/Q61, two-family fixture required")
        for poly in (integer_secret, index_message, index_error, index_mask, query_mask):
            if len(noise.polynomial(poly)) != 8:
                raise ValueError("Whole full-N integer fixture required")
        if (any(x not in (-1, 0, 1) for x in integer_secret+index_error)
                or any(not -2 <= x <= 2 for x in index_message)
                or any(not 0 <= x < pk.q for x in index_mask+query_mask)
                or tuple(int(x) for x in sk.s) != tuple(x % int(pk.q) for x in integer_secret)):
            raise ValueError("Supported secret/error/message or canonical mask required")
        self.pk, self.sk, self.keys = pk, sk, keys
        self.errors, self.secret = family_errors, integer_secret
        self.index_message, self.index_error = index_message, index_error
        self.index_mask, self.query_mask = index_mask, query_mask
        self.q, self.t, self.n = int(pk.q), pk.t, pk.n
        self.q_digits = tuple((self.q >> (4*j)) & 15 for j in range(16))
        self.counts = Counter()
        self.index_phase = tuple(m+pk.t*e for m, e in zip(index_message, index_error, strict=True))
        self.index = self.cipher(index_message, index_error, index_mask)
        self.c2 = tuple(x % self.q for x in noise.multiply(index_mask, query_mask))
        self.relin_switch = trace._switch(tuple(map(mpz, self.c2)), keys.relin, pk, 4)
        self.relin_residual = noise.switch_residual(self.c2, family_errors[0], self.q, 16, pk.t)
        self.fixed_maintenance = projection(self.relin_residual)
        self._check_registered_key_phases()
        units = tuple(tuple(int(i == j) for i in range(8)) for j in range(8))
        self.mask_columns = tuple(automorphism(monomial(tuple(pk.t*x for x in noise.multiply(index_mask, u)), -1), 9)
                                  for u in units)
        self.source_columns = tuple(projection(tuple(pk.t*x for x in noise.multiply(self.index_phase, u))) for u in units)
        self.counts["common_affine_matrix_entries"] = 2*8*8
        self.states = tuple(self._state(e, mass) for e, mass in cbd_states())
        assert len(self.states) == 6561 and sum(s.mass for s in self.states) == 65536

    def _check_registered_key_phases(self):
        targets = (noise.multiply(self.secret, self.secret), automorphism(self.secret, 9))
        for key, errors, target in zip((self.keys.relin, self.keys.rotations[0][1]), self.errors, targets, strict=True):
            for j, ((body, mask), error) in enumerate(zip(key, errors, strict=True)):
                if len(noise.polynomial(error)) != 8 or any(e not in (-1, 0, 1) for e in error):
                    raise ValueError("Full supported fixed key-error polynomial required")
                phase = noise.add(tuple(map(int, body)), noise.multiply(tuple(map(int, mask)), self.secret))
                assert tuple(x % self.q for x in phase) == tuple(((1 << (4*j))*s+self.t*e) % self.q for s, e in zip(target, error, strict=True))

    def cipher(self, message, errors, mask):
        product = noise.multiply(mask, self.secret)
        body = tuple((m+self.t*e-x) % self.q for m, e, x in zip(message, errors, product, strict=True))
        return bgv.Ciphertext((tuple(map(mpz, body)), tuple(map(mpz, mask))), self.pk.key_id, 7)

    def _state(self, errors, mass):
        delta = tuple(sum(e*column[k] for e, column in zip(errors, self.mask_columns, strict=True)) % self.q for k in range(8))
        original = tuple(sum(e*column[k] for e, column in zip(errors, self.source_columns, strict=True)) for k in range(8))
        self.counts["common_affine_state_integer_products"] += 2*8*8
        self.counts["common_affine_state_integer_adds"] += 2*8*8
        self.counts["common_delta_mod_Q"] += 8
        self.counts["carry_only_prepared_delta_digit_extracts"] += 16*8
        return State(errors, mass, delta, digit_columns(delta), original)

    def query(self, bits):
        if type(bits) is not tuple or len(bits) != 2 or any(type(x) is not int or x not in (0, 1) for x in bits):
            raise ValueError("One of four registered legal binary queries required")
        message = (1-2*bits[1], 1-2*bits[0])+(0,)*6
        query = self.cipher(message, (0,)*8, self.query_mask)
        tensor = bgv.multiply(query, self.index, self.pk)
        assert tuple(map(int, tensor.components[2])) == self.c2
        mask = tuple(int((x+y) % self.pk.q) for x, y in zip(tensor.components[1], self.relin_switch[1], strict=True))
        beta = tuple(x % self.q for x in automorphism(monomial(mask, -1), 9))
        self.counts["common_query_beta_mod_Q"] += 8
        self.counts["carry_only_prepared_beta_digit_extracts"] += 16*8
        return Query(bits, message, beta, digit_columns(beta), projection(noise.multiply(self.index_phase, message)))

    def canonical(self, query, state):
        canonical = tuple((a+b) % self.q for a, b in zip(query.beta, state.delta, strict=True))
        self.counts["common_rotation_input_adds"] += 8
        self.counts["common_rotation_input_mod_Q"] += 8
        self.counts["common_rotation_digit_extracts"] += 16*8
        return canonical, digit_columns(canonical)

    def actual(self, query, state):
        cipher = self.cipher(query.message, state.errors, self.query_mask)
        result = trace.search(cipher, [self.index], 3, self.pk, self.keys)[0]
        phase = tuple(map(int, result.components[1]))
        phase = tuple((a+b) % self.q for a, b in zip(result.components[0], noise.multiply(phase, self.secret), strict=True))
        plaintext = bgv.decrypt(result, self.pk, self.sk)
        return phase, tuple(trace.decode([plaintext], 3, 2, self.pk))


def carries(beta, delta, q, beta_digits, delta_digits, expected_digits):
    """Exact radix addition/borrow states, including canonical Q wrap."""
    wrap = tuple(int(a+b >= q) for a, b in zip(beta, delta, strict=True))
    q_digits = tuple((q >> (4*j)) & 15 for j in range(16))
    incoming, rows = (0,)*8, [(0,)*8]
    for j in range(16):
        raw = tuple(a+b-w*q_digits[j]+c for a, b, w, c in zip(beta_digits[j], delta_digits[j], wrap, incoming, strict=True))
        assert tuple(x % 16 for x in raw) == expected_digits[j]
        incoming = tuple(x//16 for x in raw)
        assert all(x in (-1, 0, 1) for x in incoming)
        rows.append(incoming)
    assert incoming == (0,)*8
    return wrap, tuple(rows)


class Memo:
    """Matched signed/orbit-normalized four-coefficient kernel lookup control.

    Logical operations, entries and stored integer coefficients are counted.
    Python object memory, vector ISA and wall-clock costs are not inferred.
    """

    def __init__(self):
        self.compiled, self.cache = {}, {}
        self.counts = Counter()

    def compile(self, kernel):
        if kernel not in self.compiled:
            factor = 0
            for x in kernel:
                factor = gcd(factor, abs(x))
            if not factor:
                value = ((0,)*8, 0, 0)
            else:
                primitive = tuple(x//factor for x in kernel)
                orbit = tuple(monomial(primitive, shift) for shift in range(16))
                canonical, shift = min((poly, shift) for shift, poly in enumerate(orbit))
                value = canonical, shift, factor
                self.counts["compile_orbit_coefficient_visits"] += 16*8
                self.counts["compile_gcd_visits"] += 8
            self.compiled[kernel] = value
        return self.compiled[kernel]

    def apply(self, kernel, poly):
        canonical, shift, factor = self.compile(kernel)
        self.counts["kernel_apply_calls"] += 1
        if not factor or not any(poly):
            self.counts["zero_kernel_or_input_calls"] += 1
            return (0,)*8
        result = [0]*8
        for start in (0, 4):
            chunk = poly[start:start+4]
            if not any(chunk):
                self.counts["zero_chunk_skips"] += 1
                continue
            # Chunk position is a public monomial output shift, so both halves
            # share one pool; storing start-specific copies weakens the control.
            key = canonical, chunk
            self.counts["cache_probes"] += 1
            if key not in self.cache:
                out = [0]*8
                for i, value in enumerate(chunk):
                    if value:
                        for j, coefficient in enumerate(canonical):
                            if coefficient:
                                at = i+j
                                term = value if coefficient == 1 else -value if coefficient == -1 else value*coefficient
                                out[at % 8] += term if at < 8 else -term
                                if abs(coefficient) == 1:
                                    self.counts["miss_unit_sign_coefficient_uses"] += 1
                                else:
                                    self.counts["miss_nonzero_integer_products"] += 1
                                self.counts["miss_nonzero_integer_adds"] += 1
                self.cache[key] = tuple(out)
                self.counts["cache_misses"] += 1
                self.counts["stored_input_integer_coefficients"] += 4
                self.counts["stored_output_integer_coefficients"] += 8
            else:
                self.counts["cache_hits"] += 1
            shifted_chunk = monomial(self.cache[key], start)
            self.counts["chunk_position_orbit_coefficient_visits"] += 8
            for k, value in enumerate(shifted_chunk):
                result[k] += value
                self.counts["chunk_merge_integer_adds"] += 1
        restored = monomial(tuple(result), -shift)
        self.counts["restore_orbit_coefficient_visits"] += 8
        if factor != 1:
            self.counts["restore_scale_integer_products"] += 8
        return tuple(factor*x for x in restored)

    def snapshot(self):
        return {**dict(self.counts), "compiled_original_kernels": len(self.compiled),
                "compiled_distinct_primitive_orbits": len({value[0] for value in self.compiled.values()}),
                "cache_entries": len(self.cache),
                "stored_integer_coefficients_excluding_kernel_and_key_object_overhead": 12*len(self.cache),
                "resident_memory_and_elapsed_time_measured": False}


def span_coefficients(basis, target, counts):
    """Small exact linear-relation compiler; no heuristic kernel rank claim."""
    if not basis:
        return () if not any(target) else None
    width = len(basis)
    rows = [[Fraction(kernel[i]) for kernel in basis]+[Fraction(target[i])] for i in range(8)]
    pivots, position = [], 0
    for column in range(width):
        pivot = next((i for i in range(position, 8) if rows[i][column]), None)
        assert pivot is not None  # The selected basis is independent over Q.
        rows[position], rows[pivot] = rows[pivot], rows[position]
        factor = rows[position][column]
        rows[position] = [x/factor for x in rows[position]]
        counts["kernel_span_compile_rational_operations"] += width+1
        for i in range(8):
            if i != position:
                factor = rows[i][column]
                rows[i] = [a-factor*b for a, b in zip(rows[i], rows[position], strict=True)]
                counts["kernel_span_compile_rational_operations"] += 2*(width+1)
        pivots.append(position)
        position += 1
    if any(not any(row[:-1]) and row[-1] for row in rows):
        return None
    return tuple(rows[pivot][-1] for pivot in pivots)


class Direct:
    def __init__(self, errors, *, caps=None, signed_inputs=False, coherent=False):
        self.errors, self.memo, self.counts = errors, Memo(), Counter()
        self.caps = (15,)*15+(1,) if caps is None else caps
        assert len(self.caps) == len(errors)
        unique, basis = tuple(dict.fromkeys(errors)), []
        for error in unique:
            if span_coefficients(tuple(basis), error, self.counts) is None:
                basis.append(error)
        mapping = {e: span_coefficients(tuple(basis), e, self.counts) for e in unique}
        # This registered diagnostic has integer relations. Do not pretend a
        # rational fractional input is an integer gadget under another setup.
        assert all(all(c.denominator == 1 for c in row) for row in mapping.values())
        self.basis = tuple(basis)
        self.coefficients = tuple(tuple(int(c) for c in mapping[e]) for e in errors)
        self.group_bounds = []
        for j in range(len(basis)):
            positive = sum(max(c[j], 0)*cap for c, cap in zip(self.coefficients, self.caps, strict=True))
            negative = sum(max(-c[j], 0)*cap for c, cap in zip(self.coefficients, self.caps, strict=True))
            self.group_bounds.append(positive+negative if signed_inputs and not coherent else max(positive, negative))

    def grouped(self, columns):
        out = [[0]*8 for _ in self.basis]
        for coefficients, digit in zip(self.coefficients, columns, strict=True):
            for j, weight in enumerate(coefficients):
                if weight:
                    for k, x in enumerate(digit):
                        out[j][k] += weight*x
                        self.counts["group_input_integer_adds"] += 1
                        if abs(weight) != 1:
                            self.counts["group_input_integer_products"] += 1
        result = tuple(tuple(poly) for poly in out)
        assert all(max(map(abs, row), default=0) <= bound for row, bound in zip(result, self.group_bounds, strict=True))
        return result

    def functional(self, columns):
        out = [0]*8
        for error, digit in zip(self.basis, self.grouped(columns), strict=True):
            value = self.memo.apply(error, digit)
            for k, x in enumerate(value):
                out[k] += x
                self.counts["functional_output_integer_adds"] += 1
        return tuple(out)

    def snapshot(self):
        return {"functional": dict(self.counts), "memo": self.memo.snapshot(),
                "registered_rows": len(self.errors), "distinct_error_polynomials": len(set(self.errors)),
                "exact_rational_kernel_span_rank": len(self.basis),
                "integer_row_relation_coefficients": self.coefficients,
                "group_input_absolute_bounds": self.group_bounds}


class Binary(Direct):
    """Strong standard bit-plane control; all planes share kernel/chunk pool."""

    def functional(self, columns):
        out = [0]*8
        for error, digit, bound in zip(self.basis, self.grouped(columns), self.group_bounds, strict=True):
            # Ordinary row grouping receives all diagnostic aliases. Public
            # top-digit clipping is already reflected in the grouped bounds.
            for bit in range(bound.bit_length()):
                plane = tuple((1 if x >= 0 else -1)*((abs(x) >> bit) & 1) for x in digit)
                self.counts["binary_plane_coefficient_extracts"] += 8
                value = self.memo.apply(error, plane)
                for k, x in enumerate(value):
                    out[k] += (1 << bit)*x
                    self.counts["functional_output_integer_adds"] += 1
                    if bit:
                        self.counts["functional_scale_integer_products"] += 1
        return tuple(out)


class Carry:
    """Known carry factorization; extra representation work is paid explicitly."""

    def __init__(self, errors, q):
        if type(q) is not int or q != (1 << 61)-1:
            raise ValueError("Registered Q61 carry-coherence diagnostic required")
        self.errors, self.q = errors, q
        self.binary, self.counts = Binary(errors), Counter()
        self.delta_cache, self.beta_cache = {}, {}
        digits_q = tuple((q >> (4*j)) & 15 for j in range(16))
        self.q_kernel = tuple(sum(d*e[k] for d, e in zip(digits_q, errors, strict=True)) for k in range(8))
        self.carry_kernels = tuple(tuple(errors[j][k]-16*errors[j-1][k] for k in range(8)) for j in range(1, 16))
        # Registered Q61 has15 low radix digits equal15. ONLY under that
        # precondition are carries all0/1 or all0/-1 according to Q wrap.
        # Give the carry route the same row-span and bit-plane optimization.
        self.correction = Binary(self.carry_kernels, caps=(1,)*15, signed_inputs=True, coherent=True)
        self.counts["compile_Q_kernel_integer_products"] = 16*8
        self.counts["compile_Q_kernel_integer_adds"] = 16*8
        self.counts["compile_carry_kernel_integer_products"] = 15*8
        self.counts["compile_carry_kernel_integer_adds"] = 15*8

    def functional(self, query, state, canonical_digits):
        if query.beta not in self.beta_cache:
            self.beta_cache[query.beta] = self.binary.functional(query.beta_digits)
            self.counts["carry_only_beta_digit_extracts"] += 16*8
        if state.delta not in self.delta_cache:
            self.delta_cache[state.delta] = self.binary.functional(state.delta_digits)
            self.counts["carry_only_delta_digit_extracts"] += 16*8
        self.counts["beta_delta_whole_state_cache_probes"] += 2
        wrap, rows = carries(query.beta, state.delta, self.q, query.beta_digits, state.delta_digits, canonical_digits)
        self.counts["carry_wrap_comparisons"] += 8
        self.counts["carry_coefficient_integer_adds"] += 16*8*3
        self.counts["carry_Q_digit_integer_products"] += 16*8
        self.counts["carry_coefficient_mod_radix"] += 16*8
        self.counts["carry_coefficient_floor_div_radix"] += 16*8
        wrap_value = self.binary.memo.apply(self.q_kernel, wrap)
        out = [a+b-c for a, b, c in zip(self.beta_cache[query.beta], self.delta_cache[state.delta], wrap_value, strict=True)]
        self.counts["factor_output_integer_adds"] += 2*8
        value = self.correction.functional(rows[1:-1])
        for k, x in enumerate(value):
            out[k] += x
            self.counts["factor_output_integer_adds"] += 1
        return tuple(out)

    def snapshot(self):
        return {"factor": dict(self.counts), "grouped_carry_binary_control": self.correction.snapshot(),
                "base_delta_binary_control": self.binary.snapshot(),
                "beta_state_entries": len(self.beta_cache), "delta_state_entries": len(self.delta_cache),
                "additional_beta_delta_output_integer_coefficients": 8*(len(self.beta_cache)+len(self.delta_cache)),
                "cross_query_reuse_is_finite_law_computation_not_online_HE_protocol": True}
