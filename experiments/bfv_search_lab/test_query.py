"""Correctness and single-use lifecycle of research query preparation."""

from concurrent.futures import ThreadPoolExecutor
import copy
import os
import pickle
import random
import subprocess
import sys
import textwrap

from Crypto.Hash import SHAKE256
import gmpy2

import msgpack
import pytest

from cuhepy.bfv.scheme import BFV
from cuhepy.hamming.bfv import BFVClient
from experiments.bfv_search_lab.query import (
    NativeBatchEncoder,
    OneUseQueryPool,
    QueryFactory,
    _TAG,
    _uniform,
    expand_query,
)


@pytest.fixture
def owner():
    return BFVClient(3, 16, 97, 180, 30, rns_modulus=True, response_modulus_bits=40)


def check_query(owner, packet, query):
    wire = expand_query(packet, owner._pk())
    plaintext = BFV.decrypt(BFV.ciphertext_from_ints(wire, owner._pk()), owner._keys())
    assert BFV.batch_decode(plaintext, owner.params) == owner._query_slots(query)
    return wire


@pytest.mark.parametrize("seeded", [False, True])
@pytest.mark.parametrize("native", [False, True])
@pytest.mark.parametrize("native_encode", [False, True])
def test_fresh_query_and_encrypted_search(owner, seeded, native, native_encode):
    if native or native_encode:
        pytest.importorskip("cuhepy.bfv._cpu_ext._bfv_rns")
    factory = QueryFactory(owner, seeded=seeded, native=native, native_encode=native_encode)
    first, second = factory.encrypt([0, 1, 0]), factory.encrypt([0, 1, 0])
    assert first != second
    wire = check_query(owner, first, [0, 1, 0])
    check_query(owner, second, [0, 1, 0])
    response = owner.encode_hamming_server_packed(
        wire, owner.encrypt_vec_packed([[1, 0, 1], [0, 1, 0]]), 2
    )
    assert owner.decode_hamming_client_packed(response, 2) == [3, 0]
    fields = msgpack.unpackb(first)
    assert bool(fields[2]) == seeded
    assert bool(fields[4]) != seeded


@pytest.mark.parametrize("seeded", [False, True])
def test_pool_single_use_concurrency_and_failures(owner, seeded):
    factory = QueryFactory(owner, seeded=seeded)
    pool = OneUseQueryPool(factory, capacity=8)
    with pytest.raises(RuntimeError, match="exhausted"):
        pool.encrypt([0, 1, 0])
    pool.refill(8)
    with pytest.raises(ValueError, match="capacity"):
        pool.refill()
    queries = [[i & 1, (i >> 1) & 1, (i >> 2) & 1] for i in range(8)]
    with ThreadPoolExecutor(max_workers=4) as executor:
        packets = list(executor.map(pool.encrypt, queries))
    assert len(set(packets)) == 8
    for packet, query in zip(packets, queries, strict=True):
        check_query(owner, packet, query)
    with pytest.raises(RuntimeError, match="exhausted"):
        pool.encrypt(queries[0])
    pool.refill()
    with pytest.raises(ValueError):
        pool.encrypt([2, 0, 0])
    with pytest.raises(RuntimeError, match="exhausted"):
        pool.encrypt(queries[0])
    for clone in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError, match="copied or serialized"):
            clone(pool)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="Fork guard requires a POSIX platform")
def test_fork_rejected_and_parent_token_preserved():
    # Isolate from CUDA/BLAS threads started by other tests. Deliberately inherit
    # a locked pool: the child must reject its PID before touching that lock.
    script = textwrap.dedent("""
        import os, signal
        from cuhepy.hamming.bfv import BFVClient
        from experiments.bfv_search_lab.query import QueryFactory, OneUseQueryPool, expand_query
        from cuhepy.bfv.scheme import BFV
        owner = BFVClient(3, 16, 97, 180, 30, response_modulus_bits=40)
        pool = OneUseQueryPool(QueryFactory(owner))
        pool.refill()
        pool._lock.acquire()
        pid = os.fork()
        if pid == 0:
            signal.alarm(5)
            try:
                pool.encrypt([0, 1, 0])
            except RuntimeError as error:
                os._exit(0 if 'fork' in str(error) else 2)
            os._exit(3)
        pool._lock.release()
        _, status = os.waitpid(pid, 0)
        assert os.waitstatus_to_exitcode(status) == 0
        wire = expand_query(pool.encrypt([0, 1, 0]), owner._pk())
        plaintext = BFV.decrypt(BFV.ciphertext_from_ints(wire, owner._pk()), owner._keys())
        assert BFV.batch_decode(plaintext, owner.params) == owner._query_slots([0, 1, 0])
    """)
    environment = os.environ | {
        "OPENBLAS_NUM_THREADS": "1",
        "OMP_NUM_THREADS": "1",
        "CUDA_VISIBLE_DEVICES": "",
    }
    subprocess.run([sys.executable, "-c", script], env=environment, check=True, timeout=20)


def test_refill_exception_and_key_change(owner, monkeypatch):
    factory = QueryFactory(owner)
    pool = OneUseQueryPool(factory, capacity=1)

    def fail():
        raise RuntimeError("synthetic sampler failure")

    with monkeypatch.context() as patch:
        patch.setattr(factory, "_zero", fail)
        with pytest.raises(RuntimeError, match="sampler"):
            pool.refill()
    pool.refill()
    check_query(owner, pool.encrypt([0, 0, 0]), [0, 0, 0])
    owner.public_key = dict(owner._pk())
    with pytest.raises(ValueError, match="key changed"):
        pool.refill()


def test_packet_rejects_context_shape_and_noncanonical_coefficients(owner):
    packet = QueryFactory(owner, seeded=True).encrypt([0, 1, 0])
    fields = msgpack.unpackb(packet)
    changes = [
        (0, b"wrong"),
        (1, b"\0" * 32),
        (2, b"short"),
        (3, fields[3][:-1]),
        (4, b"unexpected"),
    ]
    q = int(owner._pk()["q"])
    changes.append((3, q.to_bytes(len(fields[3]), "little")))
    for at, replacement in changes:
        malformed = fields.copy()
        malformed[at] = replacement
        with pytest.raises(ValueError):
            expand_query(msgpack.packb(malformed), owner._pk())
    for malformed in (b"", b"\xc1", b"x" * 10000, msgpack.packb([True] * 5)):
        with pytest.raises(ValueError):
            expand_query(malformed, owner._pk())


def test_batched_public_stream_is_the_same_rejection_sampler(owner):
    # Use a modulus with appreciable rejection probability to exercise refill.
    pk = dict(owner._pk())
    pk["q"] = gmpy2.mpz(257)
    seed = bytes(range(32))
    stream = SHAKE256.new(data=_TAG + bytes.fromhex(pk["key_id"]) + seed)
    expected, rejected = [], 0
    while len(expected) < owner.params.poly_modulus_degree:
        candidate = int.from_bytes(stream.read(2), "little") & 511
        if candidate < 257:
            expected.append(candidate)
        else:
            rejected += 1
    assert rejected > 0
    assert list(_uniform(seed, pk)) == expected


@pytest.mark.parametrize("n,t", [(16, 97), (64, 257), (16384, 65537)])
def test_native_encoding_exact_at_full_ring_and_boundaries(n, t):
    pytest.importorskip("cuhepy.bfv._cpu_ext._bfv_rns")
    # The encoder only needs public parameters; keygen is unnecessary here.
    owner = BFVClient(3, n, t, 180, 30, skip_key_gen=True)
    encoder = NativeBatchEncoder(owner)
    rng = random.Random(44)
    cases = [[], [t - 1], [0] * (n - 1) + [t - 1], [rng.randrange(t) for _ in range(n)]]
    for slots in cases:
        assert encoder.encode(slots) == BFV.batch_encode(slots, owner.params)
    for slots in ([t], [-1], [0] * (n + 1), [1.5], [True]):
        with pytest.raises(ValueError):
            encoder.encode(slots)


def test_raw_native_encoder_rejects_bad_context_and_wire(owner):
    native = pytest.importorskip("cuhepy.bfv._cpu_ext._bfv_rns")
    for n, t in ((0, 97), (True, 97), (3, 97), (65536, 97), (16, 65), (16, 67), (16, 1 << 60)):
        with pytest.raises((ValueError, OverflowError)):
            native.create_batch_encoder(n, t)
    plan = native.create_batch_encoder(16, 97)
    for wire in (b"", b"\0" * 127, b"\0" * 129, (97).to_bytes(128, "little"), [0] * 16):
        with pytest.raises(ValueError):
            native.batch_encode(plan, wire)
