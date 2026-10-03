"""E108 complete transparent scalar constraints, not a cryptographic proof.

Original query expansion and canonical response parsing are paid public work.
Only witness generation may replay the HE graph. Satisfaction checks common
Boolean wires and compiled sparse linear rows over the Spartan scalar field.
The folded compiler is an equally shared ordinary known control.
"""

from __future__ import annotations

from dataclasses import dataclass

from experiments.bfv_search_lab import native_boundary_controls as affine
from experiments.bfv_search_lab import native_boundary_oracle as oracle
from experiments.bfv_search_lab import target_prime_lift as terminal

SCALAR = (1 << 252)+27742317777372353535851937790883648493


@dataclass(frozen=True)
class Linear:
    label: str
    witness: tuple[tuple[int, int], ...]
    public: tuple[tuple[int, int], ...]
    constant: int
    residual_bound: int


@dataclass(frozen=True)
class Range:
    label: str
    lower: int
    upper: int
    width: int
    bits: tuple[int, ...]
    slack: tuple[int, ...]


@dataclass(frozen=True)
class Quotient:
    label: str
    modulus: int
    numerator: Linear
    value: Range


@dataclass(frozen=True)
class Compiled:
    """Trusted owner-local static instance, never accepted from the server.

    Context-digest equality alone does not authenticate deserialized row data.
    A real proof backend must bind its actual instance and public inputs.
    """
    field: int
    context_digest: str
    mode: str
    tight_quotients: bool
    n: int
    q: int
    p: int
    t: int
    cut_labels: tuple[str, ...]
    affine_matrix: tuple[tuple[int, ...], ...]
    primes: tuple[int, int]
    public_bounds: tuple[int, ...]
    public_rhs_maps: tuple[tuple[int, tuple[tuple[int, int], ...], int], ...]
    ranges: tuple[Range, ...]
    quotients: tuple[Quotient, ...]
    linear_rows: tuple[Linear, ...]
    variable_count: int

    @property
    def public_count(self):
        return len(self.public_bounds)

    @property
    def boolean_indices(self):
        return range(self.variable_count)

    def counts(self):
        # Boolean: A=w_i, B=w_i-1, C=0. Linear: A=row, B=1, C=0.
        linear_a = sum(len(row.witness)+len(row.public)+bool(row.constant) for row in self.linear_rows)
        base = len(self.ranges)-len(self.quotients)
        return {"mode": self.mode, "field": self.field, "public_inputs": self.public_count,
                "tight_quotient_slack": self.tight_quotients,
                "witness_variables": self.variable_count, "boolean_constraints": self.variable_count,
                "base_value_slack_pairs": base, "base_boolean_constraints": 2*base*self.q.bit_length(),
                "quotient_count": len(self.quotients), "quotient_widths": tuple(x.value.width for x in self.quotients),
                "linear_constraints": len(self.linear_rows),
                "total_R1CS_constraints": self.variable_count+len(self.linear_rows),
                "A_nonzeros": self.variable_count+linear_a,
                "B_nonzeros": 2*self.variable_count+len(self.linear_rows), "C_nonzeros": 0,
                "paid_query_dependent_RHS_field_products": sum(len(row) for _, row, _ in self.public_rhs_maps),
                "paid_terminal_RHS_field_products": 32 if self.mode == "folded" else 0,
                "materialized_public_affine_Q_coefficients": sum(len(row) for row in self.affine_matrix),
                "paid_online_context_validation_and_full_index_key_digest_additional": True,
                "static_instance_and_original_public_inputs_require_owner_pins": True,
                "max_integer_residual_bound": max(x.residual_bound for x in self.linear_rows),
                "field_no_wrap_admitted": all(x.residual_bound < self.field for x in self.linear_rows),
                "generic_gets_identical_elimination_folding_and_public_preprocessing": True,
                "proof_backend_bytes_prover_verifier_lifecycle_and_runtime_unknown": True}


def _linear(label, witness, public=(), constant=0, bound=0):
    return Linear(label, tuple(sorted((i, a) for i, a in witness.items() if a)),
                  tuple(sorted((i, a) for i, a in dict(public).items() if a)), constant, bound)


def _accumulate(out, coefficients, scale=1):
    for i, a in coefficients:
        out[i] = out.get(i, 0)+scale*a


def _expression(value):
    return tuple((at, 1 << i) for i, at in enumerate(value.bits))


def _evaluate(row, public, witness):
    return (row.constant+sum(a*witness[i] for i, a in row.witness)
            +sum(a*public[i] for i, a in row.public))


def _admit(ctx):
    if type(ctx) is not oracle.Context:
        raise ValueError("Expected the pinned native context")
    ctx.admit_native_fixture()
    terminal.Context(*ctx.primes, ctx.p, ctx.t).admit_native_scalar()


def compile_constraints(ctx, *, mode="baseline", field=SCALAR, tight_quotients=True):
    """Static sparse arithmetic instance; no PCS or proof setup is generated."""
    _admit(ctx)
    if (type(mode) is not str or mode not in ("baseline", "folded") or type(field) is not int or field != SCALAR
            or type(tight_quotients) is not bool):
        raise ValueError("Wrong registered scalar constraint mode or field")
    compiled_affine = affine.compile_residual(ctx)
    matrix = compiled_affine.matrix
    cuts = len(compiled_affine.cut_labels)*ctx.n
    outputs, width = compiled_affine.output_count, ctx.q.bit_length()
    rows, ranges, quotients, cursor = [], [], [], 0

    def ranged(label, lower, upper, *, tight=True):
        nonlocal cursor
        if lower > upper:
            raise ValueError("Empty quotient range")
        bits = (upper-lower).bit_length()
        admitted_upper = upper if tight else lower+(1 << bits)-1
        value = Range(label, lower, admitted_upper, bits, tuple(range(cursor, cursor+bits)),
                      tuple(range(cursor+bits, cursor+2*bits)) if tight else ())
        cursor += (2 if tight else 1)*bits
        ranges.append(value)
        if not tight:
            return value
        terms = dict(_expression(value))
        _accumulate(terms, tuple((at, 1 << j) for j, at in enumerate(value.slack)))
        bound = max(upper-lower, 2*((1 << bits)-1)-(upper-lower))
        rows.append(_linear(label+":range", terms, constant=-(upper-lower), bound=bound))
        return value

    source = tuple(ranged(f"source:{i}", 0, ctx.q-1) for i in range(cuts))
    preterminal = tuple(ranged(f"preterminal:{i}", 0, ctx.q-1) for i in range(outputs)) if mode == "baseline" else ()
    shifted = tuple(ranged(f"remainder:{i}", 0, ctx.q-1) for i in range(outputs))
    assert all(x.width == width for x in ranges)

    def quotient(label, modulus, numerator, minimum, maximum):
        lower, upper = -((-minimum)//modulus), maximum//modulus
        value = ranged(label, lower, upper, tight=tight_quotients)
        terms = dict(numerator.witness)
        _accumulate(terms, _expression(value), -modulus)
        constant = numerator.constant-modulus*lower
        # Width-only admission must use its LOOSER bit upper bound here.
        # Integer equality then pins the genuine quotient without a slack gate.
        bound = max(abs(minimum-modulus*value.upper), abs(maximum-modulus*lower))
        if bound >= field:
            raise ValueError("Integer field relation can wrap")
        rows.append(_linear(label+":equation", terms, numerator.public, constant, bound))
        quotients.append(Quotient(label, modulus, numerator, value))

    feature_expressions = []
    # Digits are slices of one shared scalar string, never independent limb bits.
    for cut in range(len(compiled_affine.cut_labels)):
        for digit in range(ctx.levels):
            for coordinate in range(ctx.n):
                value = source[cut*ctx.n+coordinate]
                start = digit*ctx.digit_bits
                feature_expressions.append(tuple((value.bits[start+j], 1 << j) for j in range(ctx.digit_bits)))
    half = (ctx.q-1)//2
    limb_rows = []
    for limb, prime in enumerate(ctx.primes):
        for i, row in enumerate(matrix):
            terms, public, constant = {}, {}, 0
            if mode == "baseline":
                for j, coefficient in enumerate(row[:2*ctx.n]):
                    if coefficient % prime:
                        public[j] = coefficient % prime
                maximum = sum(coefficient*(ctx.q-1) for coefficient in public.values())
                for expression, coefficient in zip(feature_expressions, row[2*ctx.n:compiled_affine.feature_count], strict=True):
                    coefficient %= prime
                    _accumulate(terms, expression, coefficient)
                    maximum += coefficient*((1 << ctx.digit_bits)-1)
                for value, coefficient in zip(preterminal, row[compiled_affine.feature_count:], strict=True):
                    coefficient %= prime
                    _accumulate(terms, _expression(value), coefficient)
                    maximum += coefficient*(ctx.q-1)
                numerator = _linear(f"affine:{limb}:{i}", terms, public)
                quotient(numerator.label, prime, numerator, 0, maximum)
            else:
                # Substitute C=-t*P^-1*(u-H) modulo this named prime, then
                # fold every bit power BEFORE forming the integer row bounds.
                gamma = -ctx.t*pow(ctx.p, -1, prime) % prime
                for expression, coefficient in zip(feature_expressions, row[2*ctx.n:compiled_affine.feature_count], strict=True):
                    _accumulate(terms, expression, coefficient % prime)
                for value, coefficient in zip(shifted, row[compiled_affine.feature_count:], strict=True):
                    _accumulate(terms, _expression(value), coefficient*gamma)
                    constant -= coefficient*gamma*half
                terms = {j: a % prime for j, a in terms.items() if a % prime}
                rhs_at = len(limb_rows)
                limb_rows.append((prime, tuple((j, a % prime) for j, a in enumerate(row[:2*ctx.n]) if a % prime), constant % prime))
                numerator = _linear(f"affine:{limb}:{i}", terms, {rhs_at: -1}, prime)
                quotient(numerator.label, prime, numerator, 1, prime+sum(terms.values()))

    if mode == "baseline":
        public_bounds = (ctx.q,)*(2*ctx.n)+(ctx.p,)*outputs
        for i, (value, u) in enumerate(zip(preterminal, shifted, strict=True)):
            for limb, prime in enumerate(ctx.primes):
                terms = {}
                _accumulate(terms, _expression(value), ctx.p)
                _accumulate(terms, _expression(u), ctx.t)
                numerator = _linear(f"terminal:{i}:limb{limb}", terms, constant=-ctx.t*half)
                quotient(numerator.label, prime, numerator, -ctx.t*half, ctx.p*(ctx.q-1)+ctx.t*half)
            terms = {}
            _accumulate(terms, _expression(u), -ctx.t)
            numerator = _linear(f"terminal:{i}:target", terms, {2*ctx.n+i: ctx.q}, ctx.t*half)
            quotient(numerator.label, ctx.p, numerator, -ctx.t*half, ctx.q*(ctx.p-1)+ctx.t*half)
    else:
        public_bounds = tuple(prime for prime, _, _ in limb_rows)+(ctx.p,)*outputs
        for i, u in enumerate(shifted):
            terms = {at: (ctx.t*(1 << j)) % ctx.p for j, at in enumerate(u.bits)}
            numerator = _linear(f"terminal:{i}:target", terms, {len(limb_rows)+i: -1}, ctx.p)
            quotient(numerator.label, ctx.p, numerator, 1, ctx.p+sum(terms.values()))
    if any(x.residual_bound >= field for x in rows):
        raise ValueError("A range relation can wrap in the selected field")
    return Compiled(field, ctx.digest(), mode, tight_quotients, ctx.n, ctx.q, ctx.p, ctx.t, compiled_affine.cut_labels,
                    matrix, ctx.primes, public_bounds, tuple(limb_rows), tuple(ranges), tuple(quotients), tuple(rows), cursor)


def _pin(compiled, ctx):
    _admit(ctx)
    if type(compiled) is not Compiled or compiled.context_digest != ctx.digest():
        raise ValueError("Wrong compiled owner context")


def public_inputs(compiled, ctx, original_query, response_packet):
    """Paid host preprocessing of ORIGINAL pinned bytes and complete wire."""
    _pin(compiled, ctx)
    query = tuple(x for poly in oracle.expand_query(ctx, original_query) for x in poly)
    compact = oracle.parse_response(ctx, response_packet)
    if oracle.serialize(ctx, compact) != response_packet:
        raise ValueError("Noncanonical complete response serialization")
    output = tuple(x for cipher in compact for poly in cipher for x in poly)
    if compiled.mode == "baseline":
        return query+output
    half, rhs = (ctx.q-1)//2, []
    for prime, coefficients, constant in compiled.public_rhs_maps:
        rhs.append(-(constant+sum(a*query[i] for i, a in coefficients)) % prime)
    rhs.extend((ctx.q*y+ctx.t*half) % ctx.p for y in output)
    return tuple(rhs)


def _vectors(compiled, public, witness):
    if (type(compiled) is not Compiled or type(public) is not tuple or len(public) != compiled.public_count
            or any(type(x) is not int or not 0 <= x < bound for x, bound in zip(public, compiled.public_bounds, strict=True))
            or type(witness) is not tuple or len(witness) != compiled.variable_count
            or any(type(x) is not int or not 0 <= x < compiled.field for x in witness)):
        raise ValueError("Wrong canonical public/field witness grammar")


def satisfy(compiled, public, witness, *, omit_boolean=False, omit_linear=()):
    """Transparent field equations ONLY; omission seams are diagnostic."""
    _vectors(compiled, public, witness)
    if (type(omit_boolean) is not bool or type(omit_linear) not in (tuple, frozenset)
            or any(type(x) is not str for x in omit_linear)
            or not set(omit_linear) <= {row.label for row in compiled.linear_rows}):
        raise ValueError("Unknown diagnostic constraint omission")
    # Canonical field grammar makes membership exactly the prime-field
    # equation x(x-1)=0. This avoids multiplying every known literal bit.
    if not omit_boolean and any(x not in (0, 1) for x in witness):
        return False
    return all(_evaluate(row, public, witness) % compiled.field == 0
               for row in compiled.linear_rows if row.label not in omit_linear)


def _set_range(witness, value, number):
    if type(number) is not int or not value.lower <= number <= value.upper:
        raise ValueError("Value outside the registered integer range")
    shifted, slack = number-value.lower, value.upper-number
    for j, at in enumerate(value.bits):
        witness[at] = (shifted >> j) & 1
    for j, at in enumerate(value.slack):
        witness[at] = (slack >> j) & 1


def make_witness(compiled, ctx, original_query, response_packet, *, transcript=None):
    """Public prover preparation may replay; satisfaction never does."""
    public = public_inputs(compiled, ctx, original_query, response_packet)
    if transcript is None:
        transcript = oracle.replay(ctx, original_query)
    if (type(transcript) is not oracle.Transcript or transcript.query != original_query
            or transcript.binding != oracle.binding(ctx, original_query)
            or tuple(cut.label for cut in transcript.cuts) != compiled.cut_labels):
        raise ValueError("Wrong prover transcript/source order")
    sources = []
    for cut in transcript.cuts:
        if type(cut.digits) is not tuple or len(cut.digits) != ctx.levels:
            raise ValueError("Wrong prover digit slices")
        for row in cut.digits:
            oracle.polynomial(row, ctx.n, 1 << ctx.digit_bits)
        sources.extend(sum(row[i] << (ctx.digit_bits*j) for j, row in enumerate(cut.digits)) for i in range(ctx.n))
    values = tuple(x for cipher in transcript.preterminal for poly in cipher for x in poly)
    if len(values) != 32:
        raise ValueError("Wrong complete prover terminal shape")
    half, scalar = (ctx.q-1)//2, terminal.Context(*ctx.primes, ctx.p, ctx.t)
    shifted = tuple(terminal.derive(scalar, c).r+half for c in values)
    base_values = tuple(sources)+(values if compiled.mode == "baseline" else ())+shifted
    base = compiled.ranges[:len(base_values)]
    if len(base) != len(compiled.ranges)-len(compiled.quotients):
        raise ValueError("Wrong complete prover source shape")
    witness = [0]*compiled.variable_count
    for value, number in zip(base, base_values, strict=True):
        _set_range(witness, value, number)
    for quotient in compiled.quotients:
        numerator = _evaluate(quotient.numerator, public, witness)
        if numerator % quotient.modulus:
            raise ValueError("Prover values do not satisfy the modular relation")
        _set_range(witness, quotient.value, numerator//quotient.modulus)
    return tuple(witness)


def recover_preterminal(compiled, ctx, witness):
    """Materialize C AFTER satisfaction for diagnostics, without the graph."""
    _pin(compiled, ctx)
    if type(witness) is not tuple or len(witness) != compiled.variable_count or any(type(x) is not int for x in witness):
        raise ValueError("Wrong field witness")
    def number(value):
        return value.lower+sum(witness[at] << j for j, at in enumerate(value.bits))
    if compiled.mode == "baseline":
        return tuple(number(value) for value in compiled.ranges if value.label.startswith("preterminal:"))
    half, inverse = (ctx.q-1)//2, pow(ctx.p, -1, ctx.q)
    return tuple(-ctx.t*(number(value)-half)*inverse % ctx.q for value in compiled.ranges if value.label.startswith("remainder:"))


def check_statement(compiled, ctx, original_query, response_packet, witness):
    """Complete local pinned-input arithmetic check; no private callback/proof."""
    return satisfy(compiled, public_inputs(compiled, ctx, original_query, response_packet), witness)


def r1cs_entries(compiled):
    """Sparse (matrix,row,column,value) stream; z=(witness,1,public).

    Logical dimensions are unpadded. A backend's row/witness padding, PCS and
    commitment setup must be added; this stream does not instantiate Spartan.
    """
    constant = compiled.variable_count
    for i in compiled.boolean_indices:
        yield "A", i, i, 1
        yield "B", i, i, 1
        yield "B", i, constant, compiled.field-1
    for at, row in enumerate(compiled.linear_rows, compiled.variable_count):
        for i, a in row.witness:
            yield "A", at, i, a % compiled.field
        for i, a in row.public:
            yield "A", at, constant+1+i, a % compiled.field
        if row.constant % compiled.field:
            yield "A", at, constant, row.constant % compiled.field
        yield "B", at, constant, 1


def serialize_witness(compiled, witness):
    """Literal canonical field-word tape; these bytes are not a proof size."""
    if (type(compiled) is not Compiled or type(witness) is not tuple or len(witness) != compiled.variable_count
            or any(type(x) is not int or not 0 <= x < compiled.field for x in witness)):
        raise ValueError("Wrong canonical field witness tape")
    width = (compiled.field.bit_length()+7)//8
    return b"".join(x.to_bytes(width, "little") for x in witness)
