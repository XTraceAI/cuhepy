"""Optional CUDA public server with the existing BFV wire format and parameters.

The GPU receives only ciphertexts and public evaluation keys. This backend does
not attest execution: the current Nitro signer deliberately rejects it. Packed
coefficient import and circuit arithmetic run on CUDA; framing, output export
and terminal compaction run on CPU. There is no automatic CPU fallback.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from cuhepy.bfv.native import BFVNativeServer
from cuhepy.bfv.rns import BFVRNSArithmetic
from cuhepy.types import EncryptedVector


@dataclass(frozen=True, eq=False)
class BFVCudaIndex:
    """Validated GPU snapshot, bound to and retaining its exact public server plan.

    Replacing or mutating the original Python index has no effect on this
    snapshot. Release it by dropping references; it contains no secret key.
    """

    _owner: "BFVCudaServer" = field(repr=False)
    _handle: object = field(repr=False)
    vector_count: int
    device_bytes: int


def cuda_available() -> bool:
    """Probe the optional extension and driver without creating a server plan."""
    try:
        from cuhepy.bfv._gpu_ext import _bfv_cuda
    except ImportError:
        return False
    return _bfv_cuda.ABI_VERSION == 5 and _bfv_cuda.available()


class BFVCudaServer(BFVNativeServer):
    """Immutable public CUDA plan; reuse it across queries to amortize setup.

    Supports three 60-bit RNS primes, 30-bit gadget digits, plaintext modulus
    below 2**30, and padded vector dimensions up to 512. Raw searches upload the
    index on every call; prepare_index creates an explicit immutable snapshot.

    kernel_level controls paired experiments: 0=original CUDA, 1=shared-memory
    NTT, 2=also GPU wire import, 3=also shared evaluation-key reuse (default).
    batch_tiles bounds scratch memory independently of corpus size. Larger
    batches do not necessarily improve throughput. Profiling adds synchronization
    and must be excluded from performance samples.
    """

    def __init__(
        self,
        arithmetic: BFVRNSArithmetic,
        padded_embed_len: int,
        response_modulus_bits: int,
        *,
        kernel_level: int = 3,
        batch_tiles: int = 32,
    ) -> None:
        if type(kernel_level) is not int or kernel_level not in (0, 1, 2, 3):
            raise ValueError("CUDA kernel_level must be 0, 1, 2, or 3")
        if type(batch_tiles) is not int or not 1 <= batch_tiles <= 256:
            raise ValueError("CUDA batch_tiles must be an integer in [1, 256]")
        self._kernel_level = kernel_level
        self._batch_tiles = batch_tiles
        super().__init__(arithmetic, padded_embed_len, response_modulus_bits)

    def _create_server(self, *args: Any) -> Any:
        return self._extension.create_server(*args, self._kernel_level, self._batch_tiles)

    @staticmethod
    def _load_extension(arithmetic: BFVRNSArithmetic) -> Any:
        try:
            from cuhepy.bfv._gpu_ext import _bfv_cuda
        except ImportError as exc:
            raise RuntimeError(
                "Build the optional BFV CUDA extension in cuhepy/bfv/_gpu_ext first"
            ) from exc
        if _bfv_cuda.ABI_VERSION != 5:
            raise RuntimeError("Rebuild the BFV CPU and CUDA extensions together")
        if not _bfv_cuda.available():
            raise RuntimeError("No CUDA device is available for the BFV server")
        return _bfv_cuda

    def cache_bytes(self) -> int:
        """GPU plan bytes, including evaluation keys; excludes per-search scratch."""
        return super().cache_bytes()

    def prepare_index(
        self, index: Sequence[Sequence[int | bytes]], vector_count: int
    ) -> BFVCudaIndex:
        """Validate and upload once for repeated queries, with explicit ownership."""
        if (
            type(vector_count) is not int
            or vector_count < 0
            or len(index) != (vector_count + self._capacity - 1) // self._capacity
        ):
            raise ValueError("vector_count does not match the packed ciphertext count")
        handle = self._extension.prepare_index(
            self._server, tuple(self._wire(v) for v in index), vector_count
        )
        return BFVCudaIndex(self, handle, vector_count, self._extension.index_bytes(handle))

    def search_prepared(
        self,
        query: Sequence[int | bytes],
        index: BFVCudaIndex,
        *,
        compact: bool = True,
        profile: dict[str, Any] | None = None,
    ) -> list[EncryptedVector]:
        """Search an immutable GPU snapshot without reuploading index ciphertexts."""
        if not isinstance(index, BFVCudaIndex) or index._owner is not self:
            raise ValueError("Prepared index belongs to another CUDA server plan")
        args = (self._server, self._wire(query), index._handle, compact)
        if profile is None:
            packed = self._extension.prepared_search(*args)
        else:
            packed, timings = self._extension.profile_prepared_search(*args)
            profile.update(timings)
        return self._finish(packed, compact)
