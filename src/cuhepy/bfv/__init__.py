"""BFV: leveled homomorphic encryption over Z_q[X]/(X^N + 1).

Supports addition, multiplication and SIMD slot batching, which lets the
evaluator pack many distances into a single response ciphertext.

- :mod:`cuhepy.bfv.scheme` — the scheme itself (GMP integer arithmetic).
- :mod:`cuhepy.bfv.evaluator` / :mod:`cuhepy.bfv.rns` / :mod:`cuhepy.bfv.native`
  — evaluation backends, from a cached-GMP reference to compiled C++ RNS/NTT.
- :mod:`cuhepy.bfv.client` — packed encrypted Hamming search.
- :mod:`cuhepy.bfv.guarded_client` / :mod:`cuhepy.bfv.verified_client` /
  :mod:`cuhepy.bfv.attested_client` — protocol layers that address the
  decryption-oracle attack documented in ``docs/research/native-bfv-security.md``.

Experimental, variable-time, and not audited. No security-level claim.
"""
