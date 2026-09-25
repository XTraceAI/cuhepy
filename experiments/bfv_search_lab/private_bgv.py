"""Fixed-work terminal decoder, intended to run AFTER BGV receipt verification.

Only the native secret multiplication and centered plaintext reduction are in
scope. Key generation/import, query encryption, Python copies, plaintext result
handling and physical/microarchitectural attacks are not covered. This raw
arithmetic adapter does not itself authenticate a response; use BGVAttestedClient.
"""

from __future__ import annotations

import os
import struct
import threading
from typing import Any

from cuhepy.bfv.scheme import _rns_coefficient_primes
from experiments.bfv_search_lab import shallow_bgv as bgv, compact_bgv as compact


class PrivateDecoder:
    """No variable-time fallback; native buffers are locked and wiped on close."""

    def __init__(self, pk: bgv.PublicKey, sk: bgv.SecretKey, *, bits: int = 25) -> None:
        from experiments.bfv_search_lab._owner import _bgv_private

        if _bgv_private.ABI_VERSION != 1:
            raise RuntimeError("Rebuild the fixed-work BGV decoder")
        if (sk.key_id != pk.key_id or len(sk.s) != pk.n
            or any(c not in (0, 1, pk.q - 1) for c in sk.s)):
            raise ValueError("Expected the matching ternary BGV secret")
        self.pk = pk
        self.modulus = compact.terminal_modulus(pk.q, pk.t, bits)
        primes = _rns_coefficient_primes(pk.n, 120)
        # Import is explicitly outside the fixed-work scope; this Python copy
        # and the caller's SecretKey do not have a secure-erasure guarantee.
        secret = bytes(255 if c == pk.q - 1 else int(c) for c in sk.s)
        self._native = _bgv_private
        self._handle = _bgv_private.create_decoder(
            pk.n, int(self.modulus), pk.t, primes[0], primes[1], secret
        )
        self._pid = os.getpid()
        self._lock = threading.RLock()
        self._closed = False

    def _check(self) -> None:
        if os.getpid() != self._pid:
            raise RuntimeError("Create a new BGV decoder after fork")
        if self._closed:
            raise RuntimeError("BGV decoder is closed")

    def decode(self, ciphertexts: list[compact.CompactCiphertext]) -> list[list[int]]:
        self._check()
        with self._lock:
            self._check()
            if not 1 <= len(ciphertexts) <= 64:
                raise ValueError("Expected 1..64 private BGV results")
            pairs = []
            for cipher in ciphertexts:
                compact._validate(cipher, self.pk)
                if cipher.modulus != self.modulus:
                    raise ValueError("Unexpected private BGV modulus")
                components = [struct.pack(f"<{self.pk.n}Q", *(int(v) for v in poly))
                              for poly in cipher.components]
                pairs.append((components[0], components[1]))
            data = self._native.decode_many(self._handle, tuple(pairs))
            return self._plaintexts(data, len(pairs))

    def decode_packed(self, pairs: tuple[tuple[bytes, bytes], ...]) -> list[list[int]]:
        """Avoid GMP/Python coefficient round trips; authenticate the envelope first."""
        self._check()
        with self._lock:
            self._check()
            data = self._native.decode_packed_many(self._handle, pairs)
            return self._plaintexts(data, len(pairs))

    def _plaintexts(self, data: bytes, count: int) -> list[list[int]]:
        values = list(struct.unpack(f"<{count * self.pk.n}I", data))
        return [values[i:i + self.pk.n] for i in range(0, len(values), self.pk.n)]

    def close(self) -> None:
        if os.getpid() != self._pid:
            raise RuntimeError("Decoder belongs to another process")
        with self._lock:
            self._native.close_decoder(self._handle)
            self._closed = True

    def __reduce_ex__(self, protocol: Any) -> Any:
        raise TypeError("Private BGV decoders cannot be copied or serialized")

    def __enter__(self) -> PrivateDecoder:
        self._check()
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
