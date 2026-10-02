"""E96 exact public independent-row subset for a known-prefix target secret."""

from __future__ import annotations


def positions(n, prefix):
    if (type(n) is not int or not 2 <= n <= 32768 or n & (n - 1)
            or type(prefix) is not int or not 1 <= prefix <= n):
        raise ValueError("Invalid polynomial ring or publicly known prefix")
    return tuple(range(prefix - 1, n, prefix))


def sample_count(n, prefix, published_zeros):
    if type(published_zeros) is not int or not 1 <= published_zeros <= 1 << 32:
        raise ValueError("Invalid published-zero lifetime")
    return len(positions(n, prefix)) * published_zeros


def extract(mask, body, q, prefix):
    """Public coefficients only; noise sign flips and CBD is symmetric.

    The honest uniform mask/independent-error and known-zero secret suffix are
    external prerequisites, not facts established by this framing function.
    These are disjoint windows, not all correlated ring rotations.
    """
    if (type(mask) is not tuple or type(body) is not tuple or len(mask) != len(body)
            or type(q) is not int or not 3 <= q < 1 << 64 or q % 2 != 1
            or any(type(x) is not int or not 0 <= x < q for p in (mask, body) for x in p)):
        raise ValueError("Canonical public owner zero required")
    return tuple((tuple(mask[k-j] for j in range(prefix)), -body[k] % q)
                 for k in positions(len(mask), prefix))
