"""Paillier: additively homomorphic encryption over Z_{n^2}.

- :mod:`cuhepy.paillier.scheme` — the textbook scheme (key_gen/encrypt/decrypt/add).
- :mod:`cuhepy.paillier.lookup` — alpha-subgroup variant using precomputed tables
  for faster encryption. See ``docs/research/paillier-security.md`` for the
  parameter constraints this variant imposes.
- :mod:`cuhepy.paillier.client` / :mod:`cuhepy.paillier.lookup_client` — Hamming
  clients that dispatch to CPU or the CUDA backend.
"""
