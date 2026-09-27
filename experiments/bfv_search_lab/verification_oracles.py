"""E13/E14 tiny arithmetic oracles, NOT a verification or authentication protocol.

No cryptographic challenge generator, transcript, commitment, token lifecycle,
attestation or receipt is implemented here. Field checks use explicit toy
matrices/primes for exhaustive tests. Integer relations specify obligations a
future trusted core or proof backend must enforce on committed intermediate
values. Passing a relation must never authorize private decryption.
"""

from dataclasses import dataclass
import math


def _field(p):
    # Deliberately tiny: exact primality and exhaustive challenge experiments.
    if type(p) is not int or not 2 <= p <= 65521 or any(p % d == 0 for d in range(2, math.isqrt(p)+1)):
        raise ValueError("Expected a toy prime field (p <= 65521)")


def _vector(values, length, p):
    if len(values) != length or any(type(v) is not int or not 0 <= v < p for v in values):
        raise ValueError("Expected a canonical field vector of the declared length")


def _matrix(a, p):
    _field(p)
    if not 1 <= len(a) <= 64 or not 1 <= len(a[0]) <= 64:
        raise ValueError("Expected a nonempty toy matrix with dimensions <= 64")
    for row in a:
        _vector(row, len(a[0]), p)


def matvec(a, x, p):
    _matrix(a, p)
    _vector(x, len(a[0]), p)
    return [sum(v*w for v, w in zip(row, x, strict=True)) % p for row in a]


def linear_check(a, x, y, challenge, p):
    """Trusted recomputation of A^T*r; deliberately includes preprocessing work.

    A caller-supplied challenge is solely an algebra fixture, not a safe protocol.
    Any real one-use preprocessing must be hidden and bound to a fixed output.
    """
    _matrix(a, p)
    _vector(x, len(a[0]), p)
    _vector(y, len(a), p)
    _vector(challenge, len(a), p)
    projection = [sum(a[i][j]*challenge[i] for i in range(len(a))) % p for j in range(len(x))]
    return (sum(r*v for r, v in zip(challenge, y, strict=True))
            - sum(u*v for u, v in zip(projection, x, strict=True))) % p == 0


def negacyclic_ntt_matrix(n, psi, p):
    """Independent natural-order Vandermonde oracle for f(psi^(2*j+1))."""
    _field(p)
    if (type(n) is not int or not 2 <= n <= 32 or n & (n-1)
        or (p-1) % (2*n) or type(psi) is not int or not 0 < psi < p or pow(psi, n, p) != p-1):
        raise ValueError("Expected a power-of-two toy ring and primitive 2N-th root")
    return [[pow(psi, (2*j+1)*i, p) for i in range(n)] for j in range(n)]


def batch_error_vanishes(errors, weights, p):
    """Toy whole-vector batch check; one hidden weight per row, not a checksum."""
    _matrix(errors, p)
    _vector(weights, len(errors), p)
    return all(sum(weights[b]*errors[b][i] for b in range(len(errors))) % p == 0
               for i in range(len(errors[0])))


@dataclass(frozen=True)
class TerminalWitness:
    residue: int
    quotient: int
    output: int


def _terminal_parameters(q, p, t):
    if (any(type(v) is not int for v in (q, p, t)) or not 1 < t < p < q
        or (q-p) % t or q % t == 0):
        raise ValueError("Expected Q>P>t, Q=P mod t and nonzero Q mod t")


def terminal_witness(c, q, p, t):
    """Construct the exact floor witness; permits the necessary negative quotient."""
    _terminal_parameters(q, p, t)
    if type(c) is not int or not 0 <= c < q:
        raise ValueError("Expected a canonical coefficient")
    r = c % t
    k = (2*p*c - 2*q*r + q*t) // (2*q*t)
    return TerminalWitness(r, k, (k*t+r) % p)


def terminal_relation(c, witness, q, p, t):
    """Check integer ranges/inequalities, not just equations in a proof field."""
    _terminal_parameters(q, p, t)
    r, k, out = witness.residue, witness.quotient, witness.output
    if (any(type(v) is not int for v in (c, r, k, out))
        or not 0 <= c < q or not 0 <= r < t or not 0 <= out < p or (c-r) % t):
        return False
    numerator, denominator = 2*p*c - 2*q*r + q*t, 2*q*t
    return denominator*k <= numerator < denominator*(k+1) and (k*t+r-out) % p == 0


def gadget_relation(c, digits, q, digit_bits):
    """Canonical base-2^b decomposition; exact number, range and integer sum."""
    if type(q) is not int or q <= 1 or type(digit_bits) is not int or not 1 <= digit_bits <= 60:
        raise ValueError("Invalid gadget context")
    base, count = 1 << digit_bits, (q.bit_length()+digit_bits-1)//digit_bits
    return (type(c) is int and 0 <= c < q and len(digits) == count
            and all(type(d) is int and 0 <= d < base for d in digits)
            and c == sum(d << (i*digit_bits) for i, d in enumerate(digits)))


def crt_relation(c, residues, moduli):
    """Canonical CRT integer; valid for pairwise coprime moduli, including RNS primes."""
    if (not 1 <= len(moduli) <= 8 or any(type(p) is not int or p < 2 for p in moduli)
        or any(math.gcd(p, q) != 1 for i, p in enumerate(moduli) for q in moduli[:i])):
        raise ValueError("Expected distinct pairwise coprime CRT moduli")
    return (type(c) is int and 0 <= c < math.prod(moduli) and len(residues) == len(moduli)
            and all(type(r) is int and 0 <= r < p and c % p == r
                    for r, p in zip(residues, moduli, strict=True)))


def digit_boundary_counts(n, padded, count):
    """Modeled internal traffic for Q120/two-limb/four-digit CUDA; no runtime claim."""
    if (any(type(v) is not int for v in (n, padded, count)) or not 8 <= n <= 32768 or n & (n-1)
        or not 1 <= padded <= min(n//2, 512) or padded & (padded-1) or not 1 <= count <= 1 << 20):
        raise ValueError("Invalid joint CUDA layout")
    tiles = (count + n//padded - 1)//(n//padded)
    rotations = 0
    for start in range(0, tiles, padded):
        active, shift = min(padded, tiles-start), padded//2
        while shift:
            active = min(active, shift)
            rotations += active
            shift //= 2
    coefficients = (tiles+rotations)*n
    return dict(index_tiles=tiles, butterfly_switches=rotations,
                switch_input_coefficients=coefficients,
                native_layout_roundtrip_bytes=coefficients*(2*8+4*2*8),
                shared_uint64_digits_roundtrip_bytes=coefficients*(2*8+4*8),
                aligned_words_roundtrip_bytes=coefficients*(2*8+2*8),
                ideally_packed_roundtrip_bytes=coefficients*(15+15),
                terminal_coefficients=((count+n-1)//n)*2*n)
