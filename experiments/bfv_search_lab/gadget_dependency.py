"""E99 exact public key-row adapter and hidden-support controls, not security.

Source/atom identities describe trusted honest generation. Public algebra does
not establish those premises, authenticate a query, or authorize decryption.
Integer arithmetic and exact CBD masses are homemade; no HE library is imported.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from fractions import Fraction
from itertools import combinations, product
from math import comb, gcd


def _matrix(rows):
    if (type(rows) is not tuple or not rows or type(rows[0]) is not tuple
            or not 1 <= len(rows) <= 128 or not 1 <= len(rows[0]) <= 128
            or any(type(row) is not tuple or len(row) != len(rows[0])
                   or any(type(x) is not int or abs(x) >= 1 << 256 for x in row) for row in rows)):
        raise ValueError("Bounded rectangular integer matrix required")
    return len(rows), len(rows[0])


def determinant(rows):
    """Exact rational elimination; tiny public basis/minor control only."""
    m, n = _matrix(rows)
    if m != n:
        raise ValueError("Square determinant required")
    a, result = [list(map(Fraction, row)) for row in rows], Fraction(1)
    for j in range(n):
        pivot = next((i for i in range(j, n) if a[i][j]), None)
        if pivot is None:
            return 0
        if pivot != j:
            a[j], a[pivot] = a[pivot], a[j]
            result = -result
        d = a[j][j]
        result *= d
        for i in range(j+1, n):
            ratio = a[i][j]/d
            for k in range(j+1, n):
                a[i][k] -= ratio*a[j][k]
    assert result.denominator == 1
    return int(result)


def mask_surjective(q, rows):
    """Primitive rectangular map over Z_Q, including composite Q.

    Smith normal form gives this maximal-minor criterion. It certifies the map,
    conditional on truly independent uniform original mask atoms; not the RNG.
    """
    if type(q) is not int or not 2 <= q < 1 << 64:
        raise ValueError("Bounded modulus required")
    m, n = _matrix(rows)
    if m > n:
        return False
    if comb(n, m) > 10000:
        raise ValueError("Minor enumeration exceeds diagnostic budget")
    divisor = q
    for indices in combinations(range(n), m):
        divisor = gcd(divisor, determinant(tuple(tuple(row[i] for i in indices) for row in rows)))
        if divisor == 1:
            return True
    return False


def adjacent(levels, radix, *, disjoint=False):
    if (type(levels) is not int or not 1 <= levels <= 64
            or type(radix) is not int or not 2 <= radix <= 65535
            or type(disjoint) is not bool):
        raise ValueError("Bounded gadget shape required")
    return tuple(tuple(-radix if k == j else 1 if k == j+1 else 0 for k in range(levels))
                 for j in range(0, levels-1, 2 if disjoint else 1))


def modulus_digits(q, radix, levels, *, balanced):
    """Represent the INTEGER modulus, retaining the final carry, not residue0."""
    adjacent(levels, radix)
    if type(q) is not int or not 2 <= q < 1 << 64 or type(balanced) is not bool:
        raise ValueError("Bounded modulus/digit convention required")
    remaining, result = q, []
    for _ in range(levels-1):
        d = ((remaining+radix//2) % radix-radix//2) if balanced else remaining % radix
        result.append(d)
        remaining = (remaining-d)//radix
    result.append(remaining)
    assert sum(d*radix**j for j, d in enumerate(result)) == q
    return tuple(result)


def modular_basis(q, radix, levels, *, balanced=True):
    # Standard gadget lattice: adjacent integer-null rows plus Q digits.
    return (*adjacent(levels, radix), modulus_digits(q, radix, levels, balanced=balanced))


def canonical_basis(q, radix, levels):
    modulus_digits(q, radix, levels, balanced=False)
    return ((q, *((0,)*(levels-1))),
            *(tuple(-radix**j if k == 0 else 1 if k == j else 0 for k in range(levels))
              for j in range(1, levels)))


def aggregate(pairs):
    result = Counter()
    for label, weight in pairs:
        result[label] += weight
    return tuple(sorted((label, value) for label, value in result.items() if value))


@dataclass(frozen=True)
class KeyRow:
    sources: tuple[tuple[str, int], ...]
    mask_atom: str
    error_atom: str
    mask: tuple[int, ...]
    body: tuple[int, ...]


@dataclass(frozen=True)
class Transcript:
    q: int
    eta: int
    rows: tuple[KeyRow, ...]


def validate(transcript):
    if (type(transcript) is not Transcript or type(transcript.q) is not int
            or not 3 <= transcript.q < 1 << 64 or type(transcript.eta) is not int
            or not 1 <= transcript.eta <= 64 or type(transcript.rows) is not tuple
            or not 1 <= len(transcript.rows) <= 128 or type(transcript.rows[0]) is not KeyRow):
        raise ValueError("Canonical registered diagnostic transcript required")
    if type(transcript.rows[0].mask) is not tuple:
        raise ValueError("Canonical public mask required")
    n, masks = len(transcript.rows[0].mask), {}
    if not 2 <= n <= 16 or n & (n-1):
        raise ValueError("Bounded power-of-two ring required")
    for row in transcript.rows:
        if type(row) is not KeyRow or type(row.sources) is not tuple or not row.sources:
            raise ValueError("Registered distinct source labels required")
        for name in (row.mask_atom, row.error_atom, *(label for label, _ in row.sources)):
            if type(name) is not str or not 1 <= len(name) <= 64:
                raise ValueError("Bounded atom/source identity required")
        if (any(type(weight) is not int or abs(weight) >= 1 << 256 for _, weight in row.sources)
                or row.sources != aggregate(row.sources)):
            raise ValueError("Canonical integer source form required")
        for poly in (row.mask, row.body):
            if (type(poly) is not tuple or len(poly) != n
                    or any(type(x) is not int or not 0 <= x < transcript.q for x in poly)):
                raise ValueError("Canonical public mask/body required")
        if row.mask_atom in masks and masks[row.mask_atom] != row.mask:
            raise ValueError("Shared mask atom has inconsistent public value")
        masks[row.mask_atom] = row.mask
    return n


@dataclass(frozen=True)
class Relation:
    integer_source_form: tuple[tuple[str, int], ...]
    mask_atoms: tuple[tuple[str, int], ...]
    error_atoms: tuple[tuple[str, int], ...]
    mask: tuple[int, ...]
    body: tuple[int, ...]


def transform(transcript, coefficients):
    """Only source-null mod-Q relations; retain nonzero integer Q multiples."""
    n = validate(transcript)
    if (type(coefficients) is not tuple or len(coefficients) != len(transcript.rows)
            or not any(coefficients) or any(type(x) is not int or abs(x) >= 1 << 256 for x in coefficients)):
        raise ValueError("Canonical nonzero bounded relation required")
    rows, q = transcript.rows, transcript.q
    sources = aggregate((label, c*value) for c, row in zip(coefficients, rows, strict=True)
                        for label, value in row.sources)
    if any(value % q for _, value in sources):
        raise ValueError("Every distinct source must cancel modulo Q")
    def atoms(field):
        return aggregate((getattr(row, field), c) for c, row in zip(coefficients, rows, strict=True))

    def poly(field):
        return tuple(sum(c*getattr(row, field)[i] for c, row in zip(coefficients, rows, strict=True)) % q
                     for i in range(n))
    return Relation(sources, atoms("mask_atom"), atoms("error_atom"), poly("mask"), poly("body"))


def atom_matrix(relations, field):
    if (type(relations) is not tuple or not relations or field not in ("mask_atoms", "error_atoms")
            or any(type(row) is not Relation for row in relations)):
        raise ValueError("Declared relation atom matrix required")
    labels = tuple(sorted({label for row in relations for label, _ in getattr(row, field)}))
    return tuple(tuple(dict(getattr(row, field)).get(label, 0) for label in labels) for row in relations)


def gram(rows):
    _matrix(rows)
    return tuple(tuple(sum(a*b for a, b in zip(left, right, strict=True)) for right in rows) for left in rows)


def iid_subset(q, relations):
    """Conservative sufficient CBD IID law, not an assertion from covariance."""
    matrix = atom_matrix(relations, "mask_atoms")
    if not mask_surjective(q, matrix):
        raise ValueError("Masks are not jointly independent uniform")
    used, signature = set(), None
    for row in relations:
        atoms = {label for label, _ in row.error_atoms}
        this = tuple(sorted(abs(value) for _, value in row.error_atoms))
        if not atoms or used & atoms or (signature is not None and this != signature):
            raise ValueError("Disjoint error atoms and an identical CBD law required")
        used |= atoms
        signature = this
    return signature


def joint_cbd(rows, eta=1):
    """Exact finite weighted integer law; never a Gaussian substitution."""
    _, atoms = _matrix(rows)
    if type(eta) is not int or not 1 <= eta <= 64 or (2*eta+1)**atoms > 1000000:
        raise ValueError("Exact noise law exceeds finite diagnostic budget")
    masses = {e: comb(2*eta, eta+e) for e in range(-eta, eta+1)}
    law = Counter()
    for values in product(masses, repeat=atoms):
        mass = 1
        for value in values:
            mass *= masses[value]
        law[tuple(sum(w*e for w, e in zip(row, values, strict=True)) for row in rows)] += mass
    denominator = 2**(2*eta*atoms)
    assert sum(law.values()) == denominator
    return law, denominator


def independent_inventory(q, rows):
    """Tiny exhaustive disjoint-atom subset control; no correlated cost model."""
    m, _ = _matrix(rows)
    if m > 8:
        raise ValueError("Subset enumeration exceeds diagnostic budget")
    independent, iid = (), ()
    for size in range(1, m+1):
        for indices in combinations(range(m), size):
            used, signatures = set(), []
            for i in indices:
                atoms = {j for j, weight in enumerate(rows[i]) if weight}
                if not atoms or atoms & used:
                    break
                used |= atoms
                signatures.append(tuple(sorted(abs(x) for x in rows[i] if x)))
            else:
                selected = tuple(rows[i] for i in indices)
                if mask_surjective(q, selected):
                    if size > len(independent):
                        independent = indices
                    if len(set(signatures)) == 1 and size > len(iid):
                        iid = indices
    return {"independent_disjoint_atom_indices": independent, "IID_same_CBD_signature_indices": iid}


@dataclass(frozen=True)
class HiddenSupport:
    n: int
    weight: int
    positives: int


def support_count(policy):
    if (type(policy) is not HiddenSupport or any(type(x) is not int for x in
                                               (policy.n, policy.weight, policy.positives))
            or not 2 <= policy.n <= 32768 or policy.n & (policy.n-1)
            or not 0 <= policy.positives <= policy.weight <= policy.n):
        raise ValueError("Public N/weight/sign-count policy required; positions remain private")
    return comb(policy.n, policy.weight)*comb(policy.weight, policy.positives)


def sample_hidden(policy, rng):
    """Honest owner sampling, not attested by a public policy or this adapter.

    Production would require a reviewed CSPRNG/private implementation. Tests
    may inject a deterministic sampler. The returned polynomial is PRIVATE.
    """
    support_count(policy)
    positions = rng.sample(range(policy.n), policy.weight)
    positive = set(rng.sample(positions, policy.positives))
    secret = [0]*policy.n
    for index in positions:
        secret[index] = 1 if index in positive else -1
    return tuple(secret)


def hidden_variance_bound(q, body_remainder, mask_remainders, weight_cap):
    """Public remainder bound with hidden positions; no target witness input."""
    if (type(q) is not int or not 2 <= q < 1 << 64 or type(mask_remainders) is not tuple
            or not mask_remainders or type(weight_cap) is not int or not 0 <= weight_cap <= len(mask_remainders)
            or any(type(x) is not int or not 0 <= x < q for x in (body_remainder, *mask_remainders))):
        raise ValueError("Canonical remainders and hidden support cap required")
    values = sorted((r*(q-r) for r in mask_remainders), reverse=True)
    return body_remainder*(q-body_remainder)+sum(values[:weight_cap])
