"""E88 original-ring common-mask and block-rotation arithmetic controls.

No CM encryption, bootstrap, proof or independent-matrix-key assumption is
implemented. Secret rows are local test/reference data, never server witnesses.
"""

from __future__ import annotations

from dataclasses import dataclass

from experiments.bfv_search_lab.batched_score_bridge import context


def validate(components, q):
    context(q, 3)
    if (type(components) is not tuple or len(components) not in (2, 3)
            or type(components[0]) is not tuple):
        raise ValueError("C0/C1 and optional C2 required")
    n = len(components[0])
    if (not 2 <= n <= 16 or n & (n - 1)
            or any(type(poly) is not tuple or len(poly) != n
                   or any(type(x) is not int or not 0 <= x < q for x in poly) for poly in components)):
        raise ValueError("Invalid bounded canonical ring components")
    return n


@dataclass(frozen=True)
class CommonView:
    q: int
    n: int
    masks: tuple[tuple[int, ...], ...]
    bodies: tuple[int, ...]


def view(components, q):
    n = validate(components, q)
    return CommonView(q, n, components[1:], components[0])


def restore(common):
    if type(common) is not CommonView or type(common.masks) is not tuple:
        raise ValueError("Invalid common-mask view")
    components = (common.bodies, *common.masks)
    if validate(components, common.q) != common.n or type(common.n) is not int:
        raise ValueError("Inconsistent common-mask degree")
    return components


def orbit_rows(secret, q):
    # Column k consists of the signed row of the negacirculant secret operator.
    n = len(secret)
    if (type(secret) is not tuple or not 2 <= n <= 16 or n & (n - 1)
            or any(type(x) is not int or not -q < x < q for x in secret)):
        raise ValueError("Invalid bounded local secret reference")
    context(q, 3)
    return tuple(tuple((secret[(k - j) % n] * (1 if j <= k else -1)) % q
                       for j in range(n)) for k in range(n))


def local_phases(common, source_families):
    restore(common)
    if type(source_families) is not tuple or len(source_families) != len(common.masks):
        raise ValueError("Local source-power family mismatch")
    rows = tuple(orbit_rows(secret, common.q) for secret in source_families)
    if any(len(row) != common.n for row in rows):
        raise ValueError("Mixed local source degree")
    return tuple((common.bodies[k] + sum(sum(a * s for a, s in zip(mask, family[k], strict=True))
                                        for mask, family in zip(common.masks, rows, strict=True))) % common.q
                 for k in range(common.n))


def block(common, start, width):
    restore(common)
    if (type(start) is not int or type(width) is not int
            or not 0 <= start < common.n or not 1 <= width <= common.n - start):
        raise ValueError("Invalid complete block coverage")
    # Multiplication by X^-start, not cyclic rotation. Same canonical slot keys.
    masks = tuple(tuple((mask[(j + start) % common.n] *
                         (1 if j + start < common.n else -1)) % common.q
                        for j in range(common.n)) for mask in common.masks)
    return masks, common.bodies[start:start + width]


def public_union_support(n, prefix, width):
    if (any(type(x) is not int for x in (n, prefix, width)) or n < 2 or n & (n - 1)
            or not 1 <= prefix <= n or not 1 <= width <= n):
        raise ValueError("Invalid public prefix/orbit geometry")
    return tuple(j for j in range(n) if any((k - j) % n < prefix for k in range(width)))


def diagonal_commutes_shift(diagonal, q):
    """Full exact [D,T] test, equivalent to membership for a diagonal map."""
    context(q, 3)
    n = len(diagonal)
    if (type(diagonal) is not tuple or not 2 <= n <= 16 or n & (n - 1)
            or any(type(x) is not int or not 0 <= x < q for x in diagonal)):
        raise ValueError("Invalid public slot diagonal")
    return all(diagonal[(j + 1) % n] == diagonal[j] for j in range(n))
