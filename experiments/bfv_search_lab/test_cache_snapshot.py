"""Full-cache delivery must authenticate, pin revisions and preserve every tie."""

from dataclasses import replace
import secrets
import zlib

import pytest

from experiments.bfv_search_lab import cache_snapshot as snapshot


@pytest.mark.parametrize("compressed", (False, True))
@pytest.mark.parametrize("retained", ("raw", "compressed"))
def test_complete_cache_round_trip_and_all_binary_queries(compressed, retained):
    rows, ids, key = (0, 1, 1, 15, 8), (99, 3, 2, 17, 100), secrets.token_bytes(32)
    manifest, packet = snapshot.seal(rows, ids, 4, key, compressed=compressed)
    cache = snapshot.open_snapshot(packet, key, manifest, retained=retained)
    for word in range(16):
        result = cache.query(word)
        expected = tuple((row ^ word).bit_count() for row in rows)
        assert result.scores == expected
        assert result.top3 == tuple(sorted(zip(expected, ids, strict=True))[:3])


def test_tampered_cache_never_reaches_decompression_and_old_epoch_rejects(monkeypatch):
    key = secrets.token_bytes(32)
    manifest, packet = snapshot.seal((0, 1), (99, 7), 4, key)
    called = []
    monkeypatch.setattr(snapshot, "_decode", lambda *args: called.append(True))
    for forged in (packet[:-1], packet[:-1] + bytes([packet[-1] ^ 1]), packet + b"x"):
        with pytest.raises(ValueError):
            snapshot.open_snapshot(forged, key, manifest)
    with pytest.raises(ValueError, match="Stale"):
        snapshot.open_snapshot(packet, key, replace(manifest, epoch=secrets.token_bytes(32)))
    with pytest.raises(ValueError):
        snapshot.open_snapshot(packet, secrets.token_bytes(32), manifest)
    assert not called


def test_authenticated_malformed_body_cannot_expand_beyond_manifest_or_reuse_ids():
    manifest = snapshot.Manifest(2, 4, True, secrets.token_bytes(32))
    with pytest.raises(ValueError, match="decompression"):
        snapshot._decode(zlib.compress(b"x" * 1000), manifest)
    raw = (7).to_bytes(8, "little") * 2 + bytes((0, 1))
    with pytest.raises(ValueError, match="rows/IDs"):
        snapshot._decode(zlib.compress(raw), manifest)
    with pytest.raises(ValueError, match="rows/IDs"):
        snapshot._decode(zlib.compress((7).to_bytes(8, "little") + (8).to_bytes(8, "little") + bytes((0, 16))), manifest)
