"""Seed expansion, bounded framing, and encrypted search with owner queries."""

from dataclasses import replace

from gmpy2 import mpz
import msgpack
import pytest

from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import butterfly_bgv as butterfly, compact_bgv as compact, seeded_bgv as seeded


@pytest.mark.parametrize("rns", [False, True])
def test_fresh_seeded_queries_with_joint_search_and_terminal_compaction(rns):
    pk, sk = bgv.key_gen(32, q_bits=120, rns_modulus=rns)
    keys = trace.evaluation_keys(pk, sk, 4)
    query, rows = [0, 1, 1], [[0, 1, 1], [1, 0, 0], [0, 0, 1]] * 13
    qp, tiles = bgv.coefficient_inputs(query, rows, pk.n)
    first, second = seeded.encrypt(qp, pk, sk), seeded.encrypt(qp, pk, sk)
    assert first != second
    cipher = seeded.expand(first, pk)
    assert bgv.decrypt(cipher, pk, sk) == [x % pk.t for x in qp]
    assert cipher.phase_bound == pk.t // 2 + pk.t * pk.eta
    assert seeded.expand(first, pk) == cipher
    index = [bgv.encrypt(poly, pk) for poly in tiles]
    responses = butterfly.search(cipher, index, len(rows), pk, keys)
    plaintexts = [compact.decrypt(compact.compact(c, pk), pk, sk) for c in responses]
    assert trace.decode(plaintexts, len(rows), len(query), pk) == [0, 3, 1] * 13
    # The public stream binds the key context, not just the seed.
    seed = msgpack.unpackb(first)[2]
    assert seeded._uniform(seed, pk) != seeded._uniform(seed, replace(pk, key_id="00" * 32))


def test_rejects_noncanonical_fields_wrong_context_and_bad_seed():
    pk, sk = bgv.key_gen(16, q_bits=96)
    packet = seeded.encrypt([0] * 16, pk, sk)
    fields = msgpack.unpackb(packet)
    malformed = [b"", packet + b"x", b"x" * 10000, msgpack.packb({"bad": 1})]
    for at, value in ((0, b"wrong"), (1, b"wrong"), (2, b"bad"), (3, pk.q.to_bytes(12, "little") * 16)):
        changed = fields.copy()
        changed[at] = value
        malformed.append(msgpack.packb(changed, use_bin_type=True))
    for value in malformed:
        with pytest.raises(ValueError):
            seeded.expand(value, pk)
    with pytest.raises(ValueError):
        seeded.encrypt([0] * 16, pk, replace(sk, key_id="bad"))
    with pytest.raises(ValueError):
        seeded.encrypt([mpz(0)] * 16, pk, sk)
