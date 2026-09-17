from dataclasses import dataclass
from typing import TypeAlias, TypedDict

import gmpy2


# ── Paillier (regular) ─────────────────────────────────────────────────────

class PaillierPublicKey(TypedDict):
    g: gmpy2.mpz
    n: gmpy2.mpz
    n_squared: gmpy2.mpz


class PaillierSecretKey(TypedDict):
    phi: gmpy2.mpz
    inv: gmpy2.mpz


class PaillierKeyPair(TypedDict):
    pk: PaillierPublicKey
    sk: PaillierSecretKey


# ── Paillier Lookup ────────────────────────────────────────────────────────

class PaillierLookupPublicKey(TypedDict):
    g: gmpy2.mpz
    n: gmpy2.mpz
    n_squared: gmpy2.mpz
    g_n: gmpy2.mpz


class PaillierLookupSecretKey(TypedDict):
    phi: gmpy2.mpz
    a: gmpy2.mpz
    g_a_inv: gmpy2.mpz


class PaillierLookupKeyPair(TypedDict):
    pk: PaillierLookupPublicKey
    sk: PaillierLookupSecretKey
    g_table: dict[int, list[int]]
    noise_table: list[int]
    key_len: int
    message_chunks: int


# ── BFV ───────────────────────────────────────────────────────────────────

BFVPolynomial: TypeAlias = tuple[gmpy2.mpz, ...]
BFVSwitchKey: TypeAlias = tuple[tuple[BFVPolynomial, BFVPolynomial], ...]


@dataclass(frozen=True)
class BFVParameters:
    """Native BFV arithmetic parameters; these are not a security certification."""

    poly_modulus_degree: int = 8192
    plain_modulus: int = 65537
    coeff_modulus_bits: int = 180
    decomposition_bits: int = 30
    error_eta: int = 21
    rns_modulus: bool = False


@dataclass(frozen=True)
class BFVCiphertext:
    """Polynomials modulo ``modulus`` in Z[X]/(X^N + 1), tied to one public key."""

    components: tuple[BFVPolynomial, ...]
    modulus: gmpy2.mpz
    key_id: str


class BFVPublicKey(TypedDict):
    params: BFVParameters
    q: gmpy2.mpz
    key_id: str
    b: BFVPolynomial
    a: BFVPolynomial
    relin_key: BFVSwitchKey
    galois_keys: dict[int, BFVSwitchKey]


class BFVSecretKey(TypedDict):
    s: BFVPolynomial
    key_id: str


class BFVKeyPair(TypedDict):
    pk: BFVPublicKey
    sk: BFVSecretKey


# ── Encrypted vector type ──────────────────────────────────────────────────

EncryptedVector: TypeAlias = list[int]
"""Scheme-agnostic encrypted embedding vector (list of ciphertext ints)."""

# Backward-compatible alias for Paillier-specific code.
PaillierEncryptedNumber: TypeAlias = EncryptedVector

EncryptedIndex: TypeAlias = list[EncryptedVector]
"""Per-document encrypted embedding index — one ``EncryptedVector`` per chunk."""
