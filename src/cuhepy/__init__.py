"""cuhepy — GPU-accelerated homomorphic encryption in Python.

Two schemes, each with a CPU reference implementation and optional compiled
backends:

- :mod:`cuhepy.paillier` — additively homomorphic Paillier, with a CUDA backend
  and an alpha-subgroup variant that uses precomputed tables.
- :mod:`cuhepy.bfv` — leveled BFV with SIMD batching, plus C++ RNS/NTT backends.

Both expose an encrypted Hamming-distance kernel (:mod:`cuhepy.hamming`), the
worked application these backends were built for: an evaluator holding only the
public key ranks encrypted vectors without learning them.

Experimental research code. See ``docs/research/`` for the security reviews and
``attacks/`` for demonstrations of where the schemes break.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("cuhepy")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "unknown"

__all__ = ["__version__"]
