"""E68 H=D A / Z=C D and projected registration algebra, not a vLHE.

The operator has INNER-Q centered entries; registration has a DISTINCT prime
outer q. Challenges/hints remain ideal trusted local objects. No encryption,
SIS extraction, packing, privacy protocol or reusable receiver is implemented.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json

from gmpy2 import is_prime

from experiments.bfv_search_lab import structured_operator_oracle as operator


@dataclass(frozen=True)
class Registration:
    outer_q: int
    binding: str
    crs: tuple[tuple[int, ...], ...]  # W x d
    hint: tuple[tuple[int, ...], ...]  # selected L x d
    challenge: tuple[tuple[int, ...], ...]  # kappa x selected L, binary
    fingerprints: tuple[tuple[int, ...], ...]  # kappa x W, signed integers
    honest_norm_bound: int


def _multiply(left, right, q):
    return tuple(tuple(sum(a*b for a, b in zip(row, column, strict=True)) % q
                       for column in zip(*right, strict=True)) for row in left)


def registration(op, crs, challenge, outer_q, epoch, *, selected_rows=None):
    operator.validate(op)
    if (type(outer_q) is not int or not op.q < outer_q < 1 << 60 or not is_prime(outer_q)
            or type(epoch) is not bytes or len(epoch) != 32
            or type(crs) is not tuple or len(crs) != op.width
            or not crs or type(crs[0]) is not tuple or not 1 <= len(crs[0]) <= 8
            or any(type(row) is not tuple or len(row) != len(crs[0])
                   or any(type(x) is not int or not 0 <= x < outer_q for x in row) for row in crs)):
        raise ValueError("Invalid bounded OUTER registration inputs")
    rows = tuple(range(op.rows)) if selected_rows is None else selected_rows
    operator.project((0,) * op.rows, rows)
    if (not rows or type(challenge) is not tuple or not 1 <= len(challenge) <= 8
            or any(type(row) is not tuple or len(row) != len(rows)
                   or any(type(x) is not int or x not in (0, 1) for x in row) for row in challenge)
            or op.rows * op.width * len(crs[0]) > 1000000):
        raise ValueError("Invalid bounded binary challenge/geometry")
    bound = len(rows) * max(abs(x) for column in op.generators for p in column for x in p)
    if 2 * bound >= outer_q:
        raise ValueError("Toy outer field cannot distinguish the signed honest norm")
    # Preserve the centered INNER-Q integers; do not reuse their Q residues
    # as the entries of a different outer field.
    lifted = replace(op, q=outer_q)
    columns = tuple(operator.project(operator.forward(lifted, tuple(c)), rows)
                    for c in zip(*crs, strict=True))
    hint = tuple(zip(*columns, strict=True))
    fingerprints = []
    for c in challenge:
        residue = operator.adjoint(lifted, operator.projection_adjoint(c, rows, op.rows))
        fingerprints.append(tuple(x if x <= outer_q // 2 else x - outer_q for x in residue))
    body = {"n": op.n, "inner_q": op.q, "outer_q": outer_q, "replies": op.replies,
            "degrees": op.degrees, "generators": op.generators, "selected_rows": rows,
            "epoch": epoch.hex(), "crs": crs}
    binding = hashlib.sha256(json.dumps(body, separators=(",", ":"), sort_keys=True).encode()).hexdigest()
    return Registration(outer_q, binding, crs, hint, challenge, tuple(fingerprints), bound)


def check_registration(state, candidate_fingerprints, approved_binding):
    """Ideal norm/equality diagnostic; neither extraction nor secure setup."""
    if state.binding != approved_binding:
        return False
    if (type(candidate_fingerprints) is not tuple or len(candidate_fingerprints) != len(state.challenge)
            or any(type(row) is not tuple or len(row) != len(state.crs)
                   or any(type(x) is not int or abs(x) > state.honest_norm_bound for x in row)
                   for row in candidate_fingerprints)):
        return False
    return _multiply(candidate_fingerprints, state.crs, state.outer_q) == _multiply(state.challenge, state.hint, state.outer_q)


def check_online_identity(state, public_query, output):
    """Only Z u = C x algebra, with ideal private trusted state, no decrypt."""
    if (type(public_query) is not tuple or len(public_query) != len(state.crs)
            or type(output) is not tuple or len(output) != len(state.hint)
            or any(type(x) is not int or not 0 <= x < state.outer_q for x in (*public_query, *output))):
        raise ValueError("Wrong ideal online identity geometry")
    return _multiply(state.fingerprints, tuple((x,) for x in public_query), state.outer_q) == _multiply(state.challenge, tuple((x,) for x in output), state.outer_q)


def digit_factorization_counterexample(base, prime):
    """No universal scalar T with low_digit(D*A)=D*T, even when A=1.

    This rejects only commuting a gadget limb through arbitrary D. Full digit
    recomposition remains exact and a different packing algorithm is possible.
    """
    operator.balanced_digits(1, base)
    if type(prime) is not int or not is_prime(prime) or prime <= 2 * base:
        raise ValueError("Prime must retain the signed toy inputs")
    one = operator.balanced_digits(1, base)[0]
    limb = operator.balanced_digits(base, base)[0]
    assert one == 1 and limb == 0 and base * one % prime != limb
    return {"A": 1, "D_values": [1, base], "T_forced_by_D_one": one,
            "limb_of_D_base_A": limb, "D_base_times_T": base % prime,
            "factorization_fails": True,
            "scope": "Single gadget limb is not a field-linear function of D. Not a counterexample to full ReinsPIRe packing/proof."}


def count_screen(*, rows, width, columns, inner_q, outer_q, d, ell=3, kappa=128):
    """Literal objects only; parameter tuple/admissibility/packing unresolved."""
    if (any(type(x) is not int or x < 1 for x in (rows, width, columns, inner_q, outer_q, d, ell, kappa))
            or columns > width or d & (d - 1) or not is_prime(outer_q) or outer_q <= inner_q):
        raise ValueError("Invalid count geometry")
    entry_bits, outer_bits = inner_q.bit_length(), outer_q.bit_length()
    bound = rows * (inner_q // 2)
    signed_bits = (2 * bound).bit_length()
    gamma = 1
    while outer_q**gamma < 1 << kappa:
        gamma += 1
    log_digit = (outer_bits + ell - 1)//ell
    # Also price the known coefficient-norm storage bound from ReinsPIRe
    # Lemma 5, rather than treating full outer residues as mandatory storage.
    compiled_bits = min(outer_bits, d.bit_length() - 1 + log_digit + 1)
    return {"literal_D_body_bytes": (rows*width*entry_bits + 7)//8,
            "generator_body_bytes": (rows*columns*entry_bits + 7)//8,
            "literal_D_to_generator_ratio": width/columns,
            "CRS_body_if_materialized_bytes": (width*d*outer_bits + 7)//8,
            "H_body_if_materialized_bytes": (rows*d*outer_bits + 7)//8,
            "Hprime_body_if_materialized_bytes": (rows*ell*d*outer_bits + 7)//8,
            "example_packing_log_digit": log_digit,
            "Hprime_known_compilation_norm_bits": compiled_bits,
            "Hprime_known_norm_bitpacked_body_bytes": (rows*ell*d*compiled_bits + 7)//8,
            "binary_C_plus_signed_Z_body_bytes": (kappa*rows + kappa*width*signed_bits + 7)//8,
            "compressed_Cprime_Zprime_body_bytes": (gamma*(rows+width)*outer_bits + 7)//8,
            "gamma_known_prime_field_mix_count": gamma,
            "honest_Z_integer_bound": bound, "admissible_extracted_D_bound_formula": "2*L*b",
            "outer_parameter_choice_or_correctness_assured": False,
            "packing_or_extraction_implemented": False,
            "scope": "Object count for generic literal outer construction. H/Hprime are NOT universal storage lower bounds; streaming/representation may change them. No auxiliary-LHE keys/messages/work included."}
