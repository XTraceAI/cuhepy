"""Paillier: additively homomorphic encryption over Z_{n^2}.

- :mod:`cuhepy.paillier.scheme` — the textbook scheme: ``key_gen``, ``encrypt``,
  ``decrypt`` and ``add`` over arbitrary integers in [0, n).
- :mod:`cuhepy.paillier.lookup` — alpha-subgroup variant using precomputed
  tables for faster encryption. See ``docs/research/paillier-security.md`` for
  the parameter constraints it imposes.

The encrypted-search application built on these schemes, including the CUDA
backends, lives in :mod:`cuhepy.hamming`.
"""
