"""Native, leveled BFV over Z_q[X]/(X^N + 1), using GMP integer arithmetic.

The default uses a single prime ciphertext modulus. An opt-in product of 60-bit
primes also supports the residue server backend. GMP Kronecker substitution handles polynomial products; a small-modulus NTT handles
plaintext batching. No SEAL/TenSEAL code is called. This is an experimental,
variable-time implementation for learning and optimization, not audited crypto.
"""

import hashlib
import json
import secrets
from collections.abc import Sequence
from dataclasses import asdict
from functools import lru_cache
from numbers import Integral
from typing import Any

import gmpy2
from gmpy2 import mpz

from xtrace_sdk.x_vec.crypto.encryption.homomorphic_base import HomomorphicBase
from xtrace_sdk.x_vec.utils.xtrace_types import (
    BFVCiphertext,
    BFVKeyPair,
    BFVParameters,
    BFVPolynomial,
    BFVPublicKey,
    BFVSecretKey,
    BFVSwitchKey,
    EncryptedVector,
)


def _round_div(value: mpz, divisor: mpz) -> mpz:
    """Nearest integer, with ties toward +infinity; works for negative inputs."""
    return (2 * value + divisor) // (2 * divisor)


def _poly_product(lhs: BFVPolynomial, rhs: BFVPolynomial) -> BFVPolynomial:
    """Exact negacyclic integer product of two nonnegative coefficient arrays.

    Choose base 2^width larger than every ordinary convolution coefficient.
    Packing then multiplying with GMP computes that convolution without carries
    crossing coefficient boundaries. Fold X^N = -1 *after* unpacking. In BFV
    multiplication these signed integers must survive until scale-and-round.
    This function is the main seam for a future RNS/NTT or CUDA backend.
    """
    n = len(lhs)
    width = max(c.bit_length() for c in lhs) + max(c.bit_length() for c in rhs)
    width += n.bit_length()
    packed_lhs = gmpy2.pack(list(lhs), width)
    packed_rhs = packed_lhs if lhs is rhs else gmpy2.pack(list(rhs), width)
    product = packed_lhs * packed_rhs
    coefficients = gmpy2.unpack(product, width)
    coefficients.extend([mpz(0)] * (2 * n - len(coefficients)))
    return tuple(coefficients[i] - coefficients[i + n] for i in range(n))


def _ring_product(lhs: BFVPolynomial, rhs: BFVPolynomial, q: mpz) -> BFVPolynomial:
    return tuple(c % q for c in _poly_product(lhs, rhs))


def _automorphism(poly: BFVPolynomial, exponent: int, q: mpz) -> BFVPolynomial:
    """Substitute X -> X^exponent, where exponent is odd, using X^N = -1."""
    n = len(poly)
    result = [mpz(0)] * n
    for i, value in enumerate(poly):
        position = (i * exponent) % (2 * n)
        result[position % n] = (value if position < n else -value) % q
    return tuple(result)


def _ntt(values: Sequence[int], root: int, modulus: int) -> list[int]:
    """Radix-2 finite-field transform; inverse uses root^-1 and an external 1/N."""
    result = list(values)
    n = len(result)
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if i < j:
            result[i], result[j] = result[j], result[i]
    length = 2
    while length <= n:
        stride_root = pow(root, n // length, modulus)
        for start in range(0, n, length):
            twiddle = 1
            for offset in range(length // 2):
                i = start + offset
                u = result[i]
                v = result[i + length // 2] * twiddle % modulus
                result[i] = (u + v) % modulus
                result[i + length // 2] = (u - v) % modulus
                twiddle = twiddle * stride_root % modulus
        length *= 2
    return result


@lru_cache(maxsize=8)
def _batch_plan(n: int, t: int) -> tuple[int, tuple[int, ...], tuple[int, ...]]:
    # t = 1 mod 2N ensures a primitive 2N-th root psi exists in F_t.
    candidate = 2
    while True:
        psi = pow(candidate, (t - 1) // (2 * n), t)
        if pow(psi, n, t) == t - 1:
            break
        candidate += 1
    twists = tuple(pow(psi, i, t) for i in range(n))
    # Two rows: psi^(3^i) and psi^(-3^i). Substitution X -> X^3 rotates
    # each row one slot to the left; it does not rotate across the rows.
    exponents = [pow(3, i, 2 * n) for i in range(n // 2)]
    order = tuple((e - 1) // 2 for e in exponents)
    order += tuple(((-e) % (2 * n) - 1) // 2 for e in exponents)
    return psi * psi % t, twists, order


@lru_cache(maxsize=16)
def _coefficient_modulus(bits: int) -> mpz:
    # No ciphertext NTT is used, so q need not be 1 modulo 2N.
    # Avoid prev_prime(), which is unavailable on older supported GMP builds.
    candidate = (mpz(1) << bits) - 1
    while not gmpy2.is_prime(candidate):
        candidate -= 2
    return candidate


@lru_cache(maxsize=16)
def _rns_coefficient_primes(n: int, bits: int) -> tuple[int, ...]:
    """Deterministic 60-bit NTT primes, in the native Ring's auxiliary-base order.

    This first residue layout supports 60, 120, ..., 480 modulus bits. It does
    not change the gadget, error distribution, encryption or rounding rules.
    """
    if bits < 60 or bits > 480 or bits % 60:
        raise ValueError(
            "rns_modulus requires coeff_modulus_bits to be a multiple of 60 in [60, 480]"
        )
    result = []
    candidate = (1 << 60) - 2 * n + 1
    for _ in range(bits // 60):
        while not gmpy2.is_prime(candidate):
            candidate -= 2 * n
        if candidate <= 1 << 59:
            raise ValueError("No suitable 60-bit RNS prime")
        result.append(candidate)
        candidate -= 2 * n
    return tuple(result)


def _parameter_dict(params: BFVParameters) -> dict[str, Any]:
    # Preserve the original v1 key fingerprints and JSON when the option is off.
    result = asdict(params)
    if not params.rns_modulus:
        del result["rns_modulus"]
    return result


def _parameter_modulus(params: BFVParameters) -> mpz:
    if params.rns_modulus:
        q = mpz(1)
        for prime in _rns_coefficient_primes(params.poly_modulus_degree, params.coeff_modulus_bits):
            q *= prime
        return q
    return _coefficient_modulus(params.coeff_modulus_bits)


def _small_poly(n: int, eta: int, q: mpz) -> BFVPolynomial:
    # Centered binomial: sum of eta independent bits minus another eta bits.
    # Each sample uses OS-backed randomness; never use benchmark PRNGs here.
    return tuple(
        mpz(secrets.randbits(eta).bit_count() - secrets.randbits(eta).bit_count()) % q
        for _ in range(n)
    )


def _ternary_poly(n: int, q: mpz) -> BFVPolynomial:
    return tuple(mpz(secrets.randbelow(3) - 1) % q for _ in range(n))


def _key_id(params: BFVParameters, b: BFVPolynomial, a: BFVPolynomial) -> str:
    digest = hashlib.sha256(json.dumps(_parameter_dict(params), sort_keys=True).encode())
    width = (params.coeff_modulus_bits + 7) // 8
    for poly in (b, a):
        for c in poly:
            digest.update(int(c).to_bytes(width, "little"))
    return digest.hexdigest()


class BFV(HomomorphicBase[BFVCiphertext, BFVPolynomial, BFVKeyPair, BFVPublicKey]):
    """Self-implemented BFV with batching, relinearization and row rotations.

    Arithmetic is exact modulo the plaintext modulus while noise permits.
    There is no bootstrapping, automatic parameter selection or security-level
    claim. Tiny rings are accepted for algebra tests and are insecure.
    """

    def __init__(self, keys: BFVKeyPair) -> None:
        self.keys = keys

    @staticmethod
    def validate_parameters(params: BFVParameters) -> None:
        """Check algebraic constraints, independently of a security assessment."""
        integer_params = asdict(params)
        rns_modulus = integer_params.pop("rns_modulus")
        if type(rns_modulus) is not bool:
            raise ValueError("rns_modulus must be a boolean")
        if any(not isinstance(v, int) or isinstance(v, bool) for v in integer_params.values()):
            raise ValueError("BFV parameters must be integers")
        n, t = params.poly_modulus_degree, params.plain_modulus
        if n < 8 or n > 32768 or n & (n - 1):
            raise ValueError("poly_modulus_degree must be a power of two in [8, 32768]")
        if t < 3 or t.bit_length() > 60 or not gmpy2.is_prime(t) or t % (2 * n) != 1:
            raise ValueError("plain_modulus must be prime, <= 60 bits, and 1 modulo 2N")
        if not t.bit_length() + 8 <= params.coeff_modulus_bits <= 512:
            raise ValueError("coeff_modulus_bits must be between plain_modulus bits + 8 and 512")
        if not 1 <= params.decomposition_bits <= params.coeff_modulus_bits:
            raise ValueError("decomposition_bits must be in [1, coeff_modulus_bits]")
        if not 1 <= params.error_eta <= 64:
            raise ValueError("error_eta must be in [1, 64]")
        if rns_modulus:
            _rns_coefficient_primes(n, params.coeff_modulus_bits)

    @staticmethod
    def key_gen(
        poly_modulus_degree: int = 8192,
        plain_modulus: int = 65537,
        coeff_modulus_bits: int = 180,
        decomposition_bits: int = 30,
        error_eta: int = 21,
        rotation_steps: Sequence[int] = (),
        relinearization: bool = True,
        rns_modulus: bool = False,
    ) -> BFVKeyPair:
        """Generate public/secret keys and requested public evaluation keys.

        :param rotation_steps: Left rotations within each of the two N/2-slot rows.
            Negative steps rotate right. Only requested rotations get keys.
        :param relinearization: Generate the key needed to reduce products to two polynomials.
        :param rns_modulus: Use a product of 60-bit NTT primes; requires fresh keys and ciphertexts.
        :return: PK/SK pair; only the PK (including evaluation keys) goes to the server.
        :rtype: BFVKeyPair
        """
        params = BFVParameters(
            poly_modulus_degree,
            plain_modulus,
            coeff_modulus_bits,
            decomposition_bits,
            error_eta,
            rns_modulus,
        )
        BFV.validate_parameters(params)
        n, q = poly_modulus_degree, _parameter_modulus(params)
        s = _ternary_poly(n, q)
        a = tuple(mpz(secrets.randbelow(int(q))) for _ in range(n))
        error = _small_poly(n, error_eta, q)
        a_s = _ring_product(a, s, q)
        b = tuple((e - v) % q for e, v in zip(error, a_s, strict=True))

        def switch_key(source: BFVPolynomial) -> BFVSwitchKey:
            result = []
            for shift in range(0, coeff_modulus_bits, decomposition_bits):
                a_i = tuple(mpz(secrets.randbelow(int(q))) for _ in range(n))
                e_i = _small_poly(n, error_eta, q)
                product = _ring_product(a_i, s, q)
                b_i = tuple(
                    ((v << shift) - a_v + e) % q
                    for v, a_v, e in zip(source, product, e_i, strict=True)
                )
                result.append((b_i, a_i))
            return tuple(result)

        relin_key = switch_key(_ring_product(s, s, q)) if relinearization else ()
        galois_keys = {}
        for steps in rotation_steps:
            if not isinstance(steps, int):
                raise ValueError("rotation_steps must contain integers")
            exponent = pow(3, steps % (n // 2), 2 * n)
            if exponent != 1 and exponent not in galois_keys:
                galois_keys[exponent] = switch_key(_automorphism(s, exponent, q))
        identity = _key_id(params, b, a)
        return {
            "pk": {
                "params": params,
                "q": q,
                "key_id": identity,
                "b": b,
                "a": a,
                "relin_key": relin_key,
                "galois_keys": galois_keys,
            },
            "sk": {"s": tuple(v if v <= q // 2 else v - q for v in s), "key_id": identity},
        }

    @staticmethod
    def _plaintext(plaintext: Sequence[int], params: BFVParameters) -> BFVPolynomial:
        if len(plaintext) != params.poly_modulus_degree:
            raise ValueError("Plaintext must contain exactly N coefficients")
        if any(not isinstance(c, Integral) or not 0 <= c < params.plain_modulus for c in plaintext):
            raise ValueError("Plaintext coefficients must be integers in [0, t)")
        return tuple(mpz(c) for c in plaintext)

    @staticmethod
    def batch_encode(slots: Sequence[int], params: BFVParameters) -> BFVPolynomial:
        """CRT encode up to N integers into a polynomial, zero-padding empty slots.

        :param slots: Values in [0, t), ordered as two rows of N/2 slots.
        :return: N polynomial coefficients in [0, t).
        :rtype: BFVPolynomial
        """
        BFV.validate_parameters(params)
        n, t = params.poly_modulus_degree, params.plain_modulus
        if len(slots) > n:
            raise ValueError("At most N batch slots can be encoded")
        if any(not isinstance(c, Integral) or not 0 <= c < t for c in slots):
            raise ValueError("Batch slots must be integers in [0, t)")
        root, twists, order = _batch_plan(n, t)
        evaluations = [0] * n
        for position, value in zip(order, slots, strict=False):
            evaluations[position] = int(value)
        coefficients = _ntt(evaluations, pow(root, -1, t), t)
        inv_n = pow(n, -1, t)
        return tuple(
            mpz(c * inv_n * pow(twist, -1, t) % t)
            for c, twist in zip(coefficients, twists, strict=True)
        )

    @staticmethod
    def batch_decode(plaintext: BFVPolynomial, params: BFVParameters) -> list[int]:
        """Decode a polynomial into the two rows of exact integer slots."""
        BFV.validate_parameters(params)
        plaintext = BFV._plaintext(plaintext, params)
        t = params.plain_modulus
        root, twists, order = _batch_plan(params.poly_modulus_degree, t)
        evaluations = _ntt(
            [int(c) * twist % t for c, twist in zip(plaintext, twists, strict=True)], root, t
        )
        return [evaluations[i] for i in order]

    @staticmethod
    def validate_ciphertext(ciphertext: BFVCiphertext, pk: BFVPublicKey) -> None:
        """Reject mixed keys, incompatible shapes, and noncanonical coefficients."""
        n, q = pk["params"].poly_modulus_degree, ciphertext.modulus
        if ciphertext.key_id != pk["key_id"]:
            raise ValueError("Ciphertext belongs to a different BFV key")
        if not pk["params"].plain_modulus < q <= pk["q"]:
            raise ValueError("Invalid ciphertext modulus")
        if len(ciphertext.components) not in (2, 3):
            raise ValueError("BFV ciphertext must have two or three components")
        for poly in ciphertext.components:
            if len(poly) != n or any(
                not isinstance(c, Integral) or not 0 <= int(c) < q for c in poly
            ):
                raise ValueError("Invalid ciphertext polynomial")

    @staticmethod
    def encrypt(plaintext: BFVPolynomial, pk: BFVPublicKey) -> BFVCiphertext:
        """Encrypt polynomial m: (b*u + e0 + floor(q/t)*m, a*u + e1).

        :param plaintext: Polynomial produced by ``batch_encode`` or N coefficients.
        :param pk: Public key; the secret key is not used for encryption.
        :return: A randomized two-component BFV ciphertext.
        :rtype: BFVCiphertext
        """
        params, q = pk["params"], pk["q"]
        plaintext = BFV._plaintext(plaintext, params)
        n = params.poly_modulus_degree
        u = _ternary_poly(n, q)
        e0, e1 = _small_poly(n, params.error_eta, q), _small_poly(n, params.error_eta, q)
        bu, au = _ring_product(pk["b"], u, q), _ring_product(pk["a"], u, q)
        delta = q // params.plain_modulus
        c0 = tuple((v + e + delta * m) % q for v, e, m in zip(bu, e0, plaintext, strict=True))
        c1 = tuple((v + e) % q for v, e in zip(au, e1, strict=True))
        return BFVCiphertext((c0, c1), q, pk["key_id"])

    @staticmethod
    def _phase(ciphertext: BFVCiphertext, keys: BFVKeyPair) -> BFVPolynomial:
        BFV.validate_ciphertext(ciphertext, keys["pk"])
        if keys["sk"]["key_id"] != keys["pk"]["key_id"]:
            raise ValueError("Secret and public keys do not match")
        q = ciphertext.modulus
        s = tuple(c % q for c in keys["sk"]["s"])
        # Horner evaluation handles both relinearized and quadratic ciphertexts.
        phase = ciphertext.components[-1]
        for poly in reversed(ciphertext.components[:-1]):
            phase = tuple(
                (a + b) % q for a, b in zip(_ring_product(phase, s, q), poly, strict=True)
            )
        return phase

    @staticmethod
    def decrypt(ciphertext: BFVCiphertext, keys: BFVKeyPair) -> BFVPolynomial:
        """Recover round(t * (c0 + c1*s + ...) / q) modulo t.

        Decryption does not authenticate ciphertexts or detect every noise failure.
        """
        t = keys["pk"]["params"].plain_modulus
        return tuple(
            _round_div(t * c, ciphertext.modulus) % t for c in BFV._phase(ciphertext, keys)
        )

    @staticmethod
    def _pair(lhs: BFVCiphertext, rhs: BFVCiphertext, pk: BFVPublicKey) -> None:
        BFV.validate_ciphertext(lhs, pk)
        BFV.validate_ciphertext(rhs, pk)
        if lhs.modulus != rhs.modulus or len(lhs.components) != len(rhs.components):
            raise ValueError("Ciphertexts must have the same modulus and component count")

    @staticmethod
    def add(
        ciphertext1: BFVCiphertext, ciphertext2: BFVCiphertext, pk: BFVPublicKey
    ) -> BFVCiphertext:
        """Homomorphic polynomial addition modulo t."""
        BFV._pair(ciphertext1, ciphertext2, pk)
        q = ciphertext1.modulus
        components = tuple(
            tuple((a + b) % q for a, b in zip(p1, p2, strict=True))
            for p1, p2 in zip(ciphertext1.components, ciphertext2.components, strict=True)
        )
        return BFVCiphertext(components, q, pk["key_id"])

    @staticmethod
    def subtract(
        ciphertext1: BFVCiphertext, ciphertext2: BFVCiphertext, pk: BFVPublicKey
    ) -> BFVCiphertext:
        """Homomorphic polynomial subtraction modulo t."""
        BFV._pair(ciphertext1, ciphertext2, pk)
        q = ciphertext1.modulus
        components = tuple(
            tuple((a - b) % q for a, b in zip(p1, p2, strict=True))
            for p1, p2 in zip(ciphertext1.components, ciphertext2.components, strict=True)
        )
        return BFVCiphertext(components, q, pk["key_id"])

    @staticmethod
    def add_plain(
        ciphertext: BFVCiphertext, plaintext: BFVPolynomial, pk: BFVPublicKey
    ) -> BFVCiphertext:
        """Add a plaintext polynomial at the ciphertext's current modulus."""
        BFV.validate_ciphertext(ciphertext, pk)
        plaintext = BFV._plaintext(plaintext, pk["params"])
        q = ciphertext.modulus
        delta = q // pk["params"].plain_modulus
        c0 = tuple(
            (c + delta * m) % q for c, m in zip(ciphertext.components[0], plaintext, strict=True)
        )
        return BFVCiphertext((c0, *ciphertext.components[1:]), q, pk["key_id"])

    @staticmethod
    def multiply_plain(
        ciphertext: BFVCiphertext, plaintext: BFVPolynomial, pk: BFVPublicKey
    ) -> BFVCiphertext:
        """Multiply by an unscaled plaintext polynomial (e.g. a batch slot mask)."""
        BFV.validate_ciphertext(ciphertext, pk)
        plaintext = BFV._plaintext(plaintext, pk["params"])
        return BFVCiphertext(
            tuple(_ring_product(c, plaintext, ciphertext.modulus) for c in ciphertext.components),
            ciphertext.modulus,
            pk["key_id"],
        )

    @staticmethod
    def _switch(
        poly: BFVPolynomial, switch_key: BFVSwitchKey, pk: BFVPublicKey
    ) -> tuple[BFVPolynomial, BFVPolynomial]:
        q, params = pk["q"], pk["params"]
        n, bits = params.poly_modulus_degree, params.decomposition_bits
        mask = (mpz(1) << bits) - 1
        result = [[mpz(0)] * n for _ in range(2)]
        for i, pair in enumerate(switch_key):
            digits = tuple((c >> (i * bits)) & mask for c in poly)
            for k in range(2):
                product = _ring_product(digits, pair[k], q)
                result[k] = [(a + b) % q for a, b in zip(result[k], product, strict=True)]
        return tuple(result[0]), tuple(result[1])

    @staticmethod
    def relinearize(ciphertext: BFVCiphertext, pk: BFVPublicKey) -> BFVCiphertext:
        """Replace the s^2 component with a gadget key encryption under s."""
        BFV.validate_ciphertext(ciphertext, pk)
        if len(ciphertext.components) == 2:
            return ciphertext
        if ciphertext.modulus != pk["q"]:
            raise ValueError("Relinearization requires the original ciphertext modulus")
        if not pk["relin_key"]:
            raise ValueError("Public key has no relinearization key")
        c0, c1, c2 = ciphertext.components
        k0, k1 = BFV._switch(c2, pk["relin_key"], pk)
        return BFVCiphertext(
            (
                tuple((a + b) % pk["q"] for a, b in zip(c0, k0, strict=True)),
                tuple((a + b) % pk["q"] for a, b in zip(c1, k1, strict=True)),
            ),
            pk["q"],
            pk["key_id"],
        )

    @staticmethod
    def multiply(
        ciphertext1: BFVCiphertext,
        ciphertext2: BFVCiphertext,
        pk: BFVPublicKey,
        *,
        relinearize: bool = True,
    ) -> BFVCiphertext:
        """BFV multiply, scale-and-round, then optionally relinearize.

        The tensor products are computed over Z[X]/(X^N+1), not R_q. Reducing
        them modulo q before rounding t*product/q would destroy the message.
        """
        BFV._pair(ciphertext1, ciphertext2, pk)
        if ciphertext1.modulus != pk["q"] or len(ciphertext1.components) != 2:
            raise ValueError("Multiplication requires two components at the original modulus")
        a0, a1 = ciphertext1.components
        b0, b1 = ciphertext2.components
        d0, d2 = _poly_product(a0, b0), _poly_product(a1, b1)
        cross1 = _poly_product(a0, b1)
        # Hamming uses squares: the two cross products are then identical.
        cross2 = cross1 if ciphertext1 is ciphertext2 else _poly_product(a1, b0)
        d1 = tuple(a + b for a, b in zip(cross1, cross2, strict=True))
        q, t = pk["q"], pk["params"].plain_modulus
        result = BFVCiphertext(
            tuple(tuple(_round_div(t * c, q) % q for c in poly) for poly in (d0, d1, d2)),
            q,
            pk["key_id"],
        )
        return BFV.relinearize(result, pk) if relinearize else result

    @staticmethod
    def xor(
        ciphertext1: BFVCiphertext, ciphertext2: BFVCiphertext, pk: BFVPublicKey
    ) -> BFVCiphertext:
        """Slotwise XOR for batched *binary* inputs: (a-b)^2. No bit validation is possible here."""
        difference = BFV.subtract(ciphertext1, ciphertext2, pk)
        return BFV.multiply(difference, difference, pk)

    @staticmethod
    def rotate_rows(ciphertext: BFVCiphertext, steps: int, pk: BFVPublicKey) -> BFVCiphertext:
        """Rotate both N/2-slot rows left by steps; negative steps rotate right."""
        BFV.validate_ciphertext(ciphertext, pk)
        if ciphertext.modulus != pk["q"] or len(ciphertext.components) != 2:
            raise ValueError("Rotation requires two components at the original modulus")
        n, q = pk["params"].poly_modulus_degree, pk["q"]
        exponent = pow(3, steps % (n // 2), 2 * n)
        if exponent == 1:
            return ciphertext
        if exponent not in pk["galois_keys"]:
            raise ValueError(f"Public key has no rotation key for steps={steps}")
        c0, c1 = (_automorphism(c, exponent, q) for c in ciphertext.components)
        k0, k1 = BFV._switch(c1, pk["galois_keys"][exponent], pk)
        return BFVCiphertext(
            (tuple((a + b) % q for a, b in zip(c0, k0, strict=True)), k1), q, pk["key_id"]
        )

    @staticmethod
    def modulus_switch(
        ciphertext: BFVCiphertext, modulus_bits: int, pk: BFVPublicKey
    ) -> BFVCiphertext:
        """Round each component from q to q' to compact a completed result.

        Further key switching/multiplication at q' is not implemented. Reducing
        too far can make decryption fail; callers must validate their circuit.
        """
        BFV.validate_ciphertext(ciphertext, pk)
        if (
            not isinstance(modulus_bits, int)
            or not pk["params"].plain_modulus.bit_length() + 8
            <= modulus_bits
            <= ciphertext.modulus.bit_length()
        ):
            raise ValueError("Invalid target modulus bit length")
        target = min(_coefficient_modulus(modulus_bits), ciphertext.modulus)
        # With a product modulus, the same-bit prime can be larger than Q.
        # An equal-bit request is a no-op; it must never raise the modulus.
        components = tuple(
            tuple(_round_div(c * target, ciphertext.modulus) % target for c in poly)
            for poly in ciphertext.components
        )
        return BFVCiphertext(components, target, pk["key_id"])

    @staticmethod
    def noise_budget(ciphertext: BFVCiphertext, keys: BFVKeyPair) -> int:
        """Local diagnostic: floor(log2(q / (2*||center(t*phase)||_inf))).

        Like decryption this needs the secret key. Do not expose it as a server
        oracle. A positive result does not authenticate a ciphertext or prove
        that an earlier operation did not wrap its noise.
        """
        q, t = ciphertext.modulus, keys["pk"]["params"].plain_modulus
        values = [(t * c) % q for c in BFV._phase(ciphertext, keys)]
        largest = max(min(c, q - c) for c in values)
        return (
            q.bit_length() - 1 if largest == 0 else max(0, int(q // (2 * largest)).bit_length() - 1)
        )

    @staticmethod
    def ciphertext_to_ints(ciphertext: BFVCiphertext, pk: BFVPublicKey) -> EncryptedVector:
        """Native wire v1: magic, version, N, q, key id, size, packed polynomials.

        Preserves the clients' list[int] interface. This is a BFV-specific format,
        not compatible with the existing Paillier HTTP endpoint or SEAL bytes.
        """
        BFV.validate_ciphertext(ciphertext, pk)
        return [
            0x58424656,
            1,
            pk["params"].poly_modulus_degree,
            int(ciphertext.modulus),
            int(ciphertext.key_id, 16),
            len(ciphertext.components),
            *(
                int(gmpy2.pack(list(c), ciphertext.modulus.bit_length()))
                for c in ciphertext.components
            ),
        ]

    @staticmethod
    def ciphertext_from_ints(values: Sequence[int | bytes], pk: BFVPublicKey) -> BFVCiphertext:
        """Load native wire v1; byte entries use the same little endian convention as Paillier."""
        if len(values) not in (8, 9):
            raise ValueError("Invalid BFV ciphertext framing")
        if any(not isinstance(v, (Integral, bytes)) for v in values):
            raise ValueError("Ciphertext entries must be nonnegative integers or bytes")
        data = [int.from_bytes(v, "little") if isinstance(v, bytes) else int(v) for v in values]
        if any(v < 0 for v in data):
            raise ValueError("Ciphertext entries must be nonnegative")
        n, q = pk["params"].poly_modulus_degree, mpz(data[3])
        if (
            data[:3] != [0x58424656, 1, n]
            or data[4] != int(pk["key_id"], 16)
            or data[5] != len(data) - 6
        ):
            raise ValueError("Incompatible BFV ciphertext header or key")
        if not pk["params"].plain_modulus < q <= pk["q"]:
            raise ValueError("Invalid ciphertext modulus")
        components = []
        for packed in data[6:]:
            if packed.bit_length() > n * q.bit_length():
                raise ValueError("Packed polynomial exceeds N coefficients")
            coefficients = gmpy2.unpack(mpz(packed), q.bit_length())
            coefficients.extend([mpz(0)] * (n - len(coefficients)))
            components.append(tuple(coefficients))
        result = BFVCiphertext(tuple(components), q, pk["key_id"])
        BFV.validate_ciphertext(result, pk)
        return result

    @staticmethod
    def serialize_public_key(pk: BFVPublicKey) -> str:
        """Export public encryption, relinearization and rotation keys as JSON."""

        def poly(values: BFVPolynomial) -> list[str]:
            return [format(c, "x") for c in values]

        def switch(values: BFVSwitchKey) -> list[list[list[str]]]:
            return [[poly(b), poly(a)] for b, a in values]

        return json.dumps(
            {
                "version": 1,
                "params": _parameter_dict(pk["params"]),
                "key_id": pk["key_id"],
                "b": poly(pk["b"]),
                "a": poly(pk["a"]),
                "relin_key": switch(pk["relin_key"]),
                "galois_keys": {str(g): switch(key) for g, key in pk["galois_keys"].items()},
            },
            separators=(",", ":"),
        )

    @staticmethod
    def deserialize_public_key(value: str) -> BFVPublicKey:
        """Load public JSON, checking parameters, polynomial shapes and key identity.

        Serialization is intended for trusted local storage/experiments. Its
        fingerprint detects mixups, not malicious modification or resource abuse.
        """
        try:
            data = json.loads(value)
            if data["version"] != 1:
                raise ValueError("Unsupported public key version")
            params = BFVParameters(**data["params"])
            BFV.validate_parameters(params)
            n, q = params.poly_modulus_degree, _parameter_modulus(params)
            digits = (
                params.coeff_modulus_bits + params.decomposition_bits - 1
            ) // params.decomposition_bits

            def poly(values: Any) -> BFVPolynomial:
                if (
                    not isinstance(values, list)
                    or len(values) != n
                    or any(not isinstance(v, str) for v in values)
                ):
                    raise ValueError("Invalid key polynomial")
                result = tuple(mpz(c, 16) for c in values)
                if any(not 0 <= c < q for c in result):
                    raise ValueError("Noncanonical key coefficient")
                return result

            def switch(values: Any) -> BFVSwitchKey:
                if not isinstance(values, list) or len(values) != digits:
                    raise ValueError("Invalid gadget key length")
                if any(not isinstance(pair, list) or len(pair) != 2 for pair in values):
                    raise ValueError("Invalid gadget key pair")
                return tuple((poly(pair[0]), poly(pair[1])) for pair in values)

            b, a = poly(data["b"]), poly(data["a"])
            identity = _key_id(params, b, a)
            if data["key_id"] != identity:
                raise ValueError("Public key fingerprint does not match")
            galois_keys = {int(g): switch(key) for g, key in data["galois_keys"].items()}
            if any(not 1 < g < 2 * n or g % 2 == 0 for g in galois_keys):
                raise ValueError("Invalid Galois exponent")
            return {
                "params": params,
                "q": q,
                "key_id": identity,
                "b": b,
                "a": a,
                "relin_key": switch(data["relin_key"]) if data["relin_key"] else (),
                "galois_keys": galois_keys,
            }
        except (KeyError, TypeError, AttributeError, OverflowError) as exc:
            raise ValueError("Malformed BFV public key") from exc

    @staticmethod
    def serialize_secret_key(sk: BFVSecretKey) -> str:
        """Export the secret separately; never include this in server setup."""
        return json.dumps(
            {"version": 1, "key_id": sk["key_id"], "s": [int(c) for c in sk["s"]]},
            separators=(",", ":"),
        )

    @staticmethod
    def deserialize_secret_key(value: str, pk: BFVPublicKey) -> BFVSecretKey:
        """Load and check a ternary secret against its public RLWE sample."""
        try:
            data = json.loads(value)
            if data["version"] != 1 or data["key_id"] != pk["key_id"]:
                raise ValueError("Secret key version or identity mismatch")
            values = data["s"]
            if not isinstance(values, list) or len(values) != pk["params"].poly_modulus_degree:
                raise ValueError("Invalid secret key polynomial")
            if any(type(c) is not int or c not in (-1, 0, 1) for c in values):
                raise ValueError("Secret key coefficients must be ternary integers")
            s = tuple(mpz(c) for c in values)
            q = pk["q"]
            product = _ring_product(pk["a"], tuple(c % q for c in s), q)
            error = [(a + b) % q for a, b in zip(product, pk["b"], strict=True)]
            if any(min(e, q - e) > pk["params"].error_eta for e in error):
                raise ValueError("Secret key does not match the public key")
            return {"s": s, "key_id": pk["key_id"]}
        except (KeyError, TypeError, AttributeError, OverflowError) as exc:
            raise ValueError("Malformed BFV secret key") from exc
