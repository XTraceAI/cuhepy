"""E58 permitted control: authenticated encrypted full-cache delivery.

Owner and client are in the same authorized domain. An untrusted server may
store this AES-GCM snapshot without learning its rows/IDs. The client pins an
owner-approved random manifest, authenticates before parsing/decompressing,
then searches locally. Keys/manifests are supplied through a trusted channel;
this module does not deploy that channel, persist freshness, erase data or
provide HE. Standard AEAD/compression/caching are known baseline ingredients.
Compressed packet length is additional declared leakage; raw mode avoids it.
"""

from __future__ import annotations

from dataclasses import dataclass
import heapq
import secrets
import struct
import zlib

from Crypto.Cipher import AES

from experiments.bfv_search_lab.coordinate_cache import Result

MAGIC = b"cuhepy/research/cache/v1\0"
HEADER = len(MAGIC) + 7 + 32
MAX_ROWS = 1 << 20


@dataclass(frozen=True)
class Manifest:
    count: int
    dimension: int
    compressed: bool
    epoch: bytes

    def header(self):
        if (type(self.count) is not int or not 1 <= self.count <= MAX_ROWS
                or type(self.dimension) is not int or not 1 <= self.dimension <= 512
                or type(self.compressed) is not bool or type(self.epoch) is not bytes or len(self.epoch) != 32):
            raise ValueError("Invalid owner-pinned cache manifest")
        return MAGIC + struct.pack("<IHB", self.count, self.dimension, self.compressed) + self.epoch

    @property
    def raw_bytes(self):
        self.header()
        return self.count * (8 + (self.dimension + 7) // 8)


def _key(key):
    if type(key) is not bytes or len(key) != 32:
        raise ValueError("Cache delivery requires an owner-approved 256-bit key")


def _rows(rows, ids, dimension):
    if (type(rows) is not tuple or type(ids) is not tuple or not 1 <= len(rows) <= MAX_ROWS
            or len(rows) != len(ids) or type(dimension) is not int or not 1 <= dimension <= 512
            or any(type(x) is not int or not 0 <= x < 1 << dimension for x in rows)
            or any(type(i) is not int or not 0 <= i < 1 << 64 for i in ids) or len(set(ids)) != len(ids)):
        raise ValueError("Invalid complete authorized cache rows/IDs")


def seal(rows, ids, dimension, key, *, compressed=True):
    _key(key)
    _rows(rows, ids, dimension)
    manifest = Manifest(len(rows), dimension, compressed, secrets.token_bytes(32))
    width = (dimension + 7) // 8
    body = b"".join(i.to_bytes(8, "little") for i in ids) + b"".join(x.to_bytes(width, "little") for x in rows)
    payload = zlib.compress(body, level=9) if compressed else body
    nonce = secrets.token_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update(manifest.header())
    encrypted, tag = cipher.encrypt_and_digest(payload)
    return manifest, manifest.header() + nonce + tag + encrypted


def _decode(payload, manifest):
    expected = manifest.raw_bytes
    if manifest.compressed:
        decoder = zlib.decompressobj()
        try:
            raw = decoder.decompress(payload, expected + 1)
        except zlib.error as error:
            raise ValueError("Invalid authenticated compressed cache") from error
        if len(raw) != expected or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            raise ValueError("Cache decompression exceeded pinned length or framing")
    else:
        raw = payload
        if len(raw) != expected:
            raise ValueError("Cache body differs from pinned length")
    split, width = 8 * manifest.count, (manifest.dimension + 7) // 8
    ids = tuple(x[0] for x in struct.iter_unpack("<Q", raw[:split]))
    rows = tuple(int.from_bytes(raw[i:i + width], "little") for i in range(split, len(raw), width))
    _rows(rows, ids, manifest.dimension)
    return rows, ids


class Cache:
    def __init__(self, payload, manifest, *, retained="raw"):
        if retained not in ("raw", "compressed"):
            raise ValueError("Unknown retained cache mode")
        rows, ids = _decode(payload, manifest)
        self.manifest, self.retained = manifest, retained
        self._rows, self._ids = (rows, ids) if retained == "raw" else (None, None)
        self._payload = payload if retained == "compressed" else None
        self.retained_body_bytes_model = manifest.raw_bytes if retained == "raw" else len(payload)
        self.raw_parse_scratch_bytes_model = manifest.raw_bytes

    def query(self, word):
        if type(word) is not int or not 0 <= word < 1 << self.manifest.dimension:
            raise ValueError("Invalid binary cache query")
        rows, ids = ((self._rows, self._ids) if self._payload is None else _decode(self._payload, self.manifest))
        scores = tuple((row ^ word).bit_count() for row in rows)
        return Result(scores, tuple(heapq.nsmallest(3, zip(scores, ids, strict=True))))


def open_snapshot(packet, key, manifest, *, retained="raw"):
    """Pinned trusted manifest is required; a server's header cannot authorize itself."""
    _key(key)
    header = manifest.header()
    # Loose length cap accommodates framing for a large incompressible corpus;
    # decompression itself retains the exact pinned output-length cap.
    if (type(packet) is not bytes or not HEADER + 28 < len(packet) <= HEADER + 28 + 2 * manifest.raw_bytes + 1024
            or packet[:HEADER] != header):
        raise ValueError("Stale manifest or malformed cache packet")
    nonce, tag, encrypted = packet[HEADER:HEADER + 12], packet[HEADER + 12:HEADER + 28], packet[HEADER + 28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update(header)
    # Never pass unauthenticated decrypted bytes to the parser/decompressor.
    payload = cipher.decrypt_and_verify(encrypted, tag)
    return Cache(payload, manifest, retained=retained)
