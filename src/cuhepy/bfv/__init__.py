"""BFV: leveled homomorphic encryption over Z_q[X]/(X^N + 1).

Supports addition, multiplication and SIMD slot batching.

- :mod:`cuhepy.bfv.scheme` — the scheme itself (GMP integer arithmetic).
- :mod:`cuhepy.bfv.evaluator` / :mod:`~cuhepy.bfv.rns` / :mod:`~cuhepy.bfv.native`
  — evaluation backends, from a cached-GMP reference to compiled C++ RNS/NTT.
- :mod:`cuhepy.bfv.private` — the separate private decoder backend.

The encrypted-search application built on this scheme lives in
:mod:`cuhepy.hamming`.

Experimental, variable-time, and not audited. No security-level claim.
"""
