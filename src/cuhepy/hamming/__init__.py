"""Encrypted Hamming-distance search — the worked application built on the schemes.

This package is *not* a cryptographic primitive. It encodes binary vectors so
that an evaluator holding only a public key can compute Hamming distances
homomorphically, and decodes the results. The schemes it builds on live in
:mod:`cuhepy.paillier` and :mod:`cuhepy.bfv` and are usable on their own.

- :mod:`cuhepy.hamming.base` — the interface all Hamming clients implement.
- :mod:`cuhepy.hamming.paillier` / :mod:`~cuhepy.hamming.paillier_lookup` —
  one ciphertext per vector; the evaluator does one modular multiply per chunk.
- :mod:`cuhepy.hamming.bfv` — SIMD-packed: many distances per response ciphertext.
- ``bfv_guarded`` / ``bfv_verified`` / ``bfv_attested`` — protocol layers that
  address the decryption-oracle attack in ``docs/research/native-bfv-security.md``.
"""
