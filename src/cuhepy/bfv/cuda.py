"""Optional CUDA public server with the existing BFV wire format and parameters.

The GPU receives only ciphertexts and public evaluation keys. This backend does
not attest execution: the current Nitro signer deliberately rejects it. Import,
export and terminal response compaction run on the CPU; circuit arithmetic runs
on CUDA. There is no automatic CPU fallback after selecting CUDA.
"""

from typing import Any

from cuhepy.bfv.native import BFVNativeServer
from cuhepy.bfv.rns import BFVRNSArithmetic


def cuda_available() -> bool:
    """Probe the optional extension and driver without creating a server plan."""
    try:
        from cuhepy.bfv._gpu_ext import _bfv_cuda
    except ImportError:
        return False
    return _bfv_cuda.ABI_VERSION == 4 and _bfv_cuda.available()


class BFVCudaServer(BFVNativeServer):
    """Immutable public CUDA plan; reuse it across queries to amortize setup.

    Supports three 60-bit RNS primes, 30-bit gadget digits, plaintext modulus
    below 2**30, and padded vector dimensions up to 512. Index ciphertexts are
    imported and uploaded on every search; they are never cached by identity.
    """

    @staticmethod
    def _load_extension(arithmetic: BFVRNSArithmetic) -> Any:
        try:
            from cuhepy.bfv._gpu_ext import _bfv_cuda
        except ImportError as exc:
            raise RuntimeError(
                "Build the optional BFV CUDA extension in cuhepy/bfv/_gpu_ext first"
            ) from exc
        if _bfv_cuda.ABI_VERSION != 4:
            raise RuntimeError("Rebuild the BFV CPU and CUDA extensions together")
        if not _bfv_cuda.available():
            raise RuntimeError("No CUDA device is available for the BFV server")
        return _bfv_cuda

    def cache_bytes(self) -> int:
        """GPU plan bytes, including evaluation keys; excludes per-search scratch."""
        return super().cache_bytes()
