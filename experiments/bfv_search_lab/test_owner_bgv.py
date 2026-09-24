"""Sampling distribution, independent algebra, stream equality and owner lifecycle."""

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import copy
from dataclasses import replace
import itertools
import math
import pickle
import random

from gmpy2 import mpz
import msgpack
import pytest

from cuhepy.bfv.scheme import _ring_product
from experiments.bfv_search_lab import shallow_bgv as bgv, seeded_bgv as seeded
from experiments.bfv_search_lab import compact_bgv as compact, owner_bgv as owner


@pytest.mark.parametrize("eta", range(1, 5))
def test_bulk_error_decoder_has_exact_centered_binomial_distribution(eta):
    width = (2 * eta + 7) // 8
    data = b"".join(value.to_bytes(width, "little") for value in range(1 << (2 * eta)))
    histogram = Counter(owner._errors_from_bytes(data, 1 << (2 * eta), eta))
    assert histogram == {k: math.comb(2 * eta, eta + k) for k in range(-eta, eta + 1)}


@pytest.mark.parametrize("eta", [1, 7, 8, 21, 32, 63, 64])
def test_error_fields_are_disjoint_and_ignore_only_padding(eta):
    width = (2 * eta + 7) // 8
    mask = (1 << eta) - 1
    words = [0, mask, mask << eta, (1 << (2 * eta)) - 1]
    data = b"".join(value.to_bytes(width, "little") for value in words)
    assert owner._errors_from_bytes(data, 4, eta) == [0, eta, -eta, 0]
    padding = ((1 << (width * 8)) - 1) ^ ((1 << (2 * eta)) - 1)
    assert owner._errors_from_bytes(b"".join((v | padding).to_bytes(width, "little") for v in words), 4, eta) == [0, eta, -eta, 0]


@pytest.mark.parametrize("bits", [93, 96, 120, 180, 240])
def test_bulk_expansion_reproduces_reference_stream(bits):
    pk, _ = bgv.key_gen(64, q_bits=bits)
    # An artificial public modulus exercises frequent rejection and non-byte widths.
    for q in (pk.q, mpz((1 << (bits - 1)) + 7)):
        context = replace(pk, q=q)
        for seed in (bytes(32), b"\xff" * 32):
            assert owner._uniform_bulk(seed, context) == seeded._uniform(seed, context)


def test_bulk_expansion_preserves_zero_tail_and_rejection_order(monkeypatch):
    pk, _ = bgv.key_gen(8, q_bits=96)
    width = 12
    values = [pk.q, 0, pk.q + 1, pk.q - 1, 1, 0, 0, 0, 17, 0]
    data = b"".join(int(v).to_bytes(width, "little") for v in values)

    class Stream:
        def __init__(self):
            self.position = 0

        def read(self, count):
            result = data[self.position:self.position + count]
            self.position += count
            assert len(result) == count
            return result

    monkeypatch.setattr(owner.SHAKE256, "new", lambda **kwargs: Stream())
    assert owner._uniform_bulk(bytes(32), pk) == seeded._uniform(bytes(32), pk)
    assert owner._uniform_bulk(bytes(32), pk) == tuple(map(mpz, [0, pk.q - 1, 1, 0, 0, 0, 17, 0]))


def naive_product(a, s, q):
    result = [0] * len(a)
    for i, x in enumerate(a):
        for j, y in enumerate(s):
            at = i + j
            result[at % len(a)] += x * y * (-1 if at >= len(a) else 1)
    return tuple(mpz(x % q) for x in result)


def test_shifted_ternary_identity_exhaustive_small_secrets_and_carry_extremes():
    q, n = mpz(17), 4
    inputs = [[0] * n, [q - 1] * n, [1, 0, 0, 0], [16, 5, 0, 13]]
    for signed in itertools.product((-1, 0, 1), repeat=n):
        plan = owner.TernaryProduct(tuple(mpz(c % q) for c in signed), q)
        for a in inputs:
            assert plan.multiply(tuple(mpz(v) for v in a), q) == naive_product(a, signed, q)


@pytest.mark.parametrize("n,bits", [(8, 96), (64, 240), (2048, 120), (16384, 120)])
def test_shifted_ternary_matches_generic_product_at_query_and_terminal_moduli(n, bits):
    pk, sk = bgv.key_gen(n, q_bits=bits)
    rng = random.Random(n)
    plan = owner.TernaryProduct(sk.s, pk.q)
    for q in (pk.q, compact.terminal_modulus(pk.q, pk.t, 25), compact.terminal_modulus(pk.q, pk.t, 32)):
        secret = tuple(mpz(q - 1) if c == pk.q - 1 else c for c in sk.s)
        poly = tuple(mpz(rng.randrange(int(q))) for _ in range(n))
        assert plan.multiply(poly, q) == _ring_product(poly, secret, q)


@pytest.mark.parametrize("ternary", [False, True])
def test_encryption_uses_independent_fresh_entropy_and_matches_controlled_reference(monkeypatch, ternary):
    pk, sk = bgv.key_gen(32, q_bits=120, rns_modulus=True)
    client = owner.OwnerClient(pk, sk, ternary=ternary)
    plain = [(-1) ** i * (i + 1) for i in range(pk.n)]
    size = pk.n * ((2 * pk.eta + 7) // 8)
    entropy = bytes(i % 256 for i in range(size))
    draws = []

    def tokens(count):
        draws.append(count)
        return b"s" * 32 if count == 32 else entropy

    monkeypatch.setattr(owner.secrets, "token_bytes", tokens)
    packet = client.encrypt(plain)
    assert draws == [32, size]
    errors = owner._errors_from_bytes(entropy, pk.n, pk.eta)
    monkeypatch.setattr(seeded, "_small_poly", lambda n, eta, q: tuple(mpz(e % q) for e in errors))
    assert packet == seeded.encrypt(plain, pk, sk)
    expanded = owner.expand(packet, pk)
    assert expanded == seeded.expand(packet, pk)
    assert bgv.decrypt(expanded, pk, sk) == [v % pk.t for v in plain]
    small = compact.compact(expanded, pk)
    assert client.decrypt_compact(small) == compact.decrypt(small, pk, sk)


def test_freshness_concurrent_owner_and_close_copy_fork_checks(monkeypatch):
    pk, sk = bgv.key_gen(64, q_bits=120, rns_modulus=True)
    client = owner.OwnerClient(pk, sk)
    with ThreadPoolExecutor(max_workers=3) as pool:
        packets = list(pool.map(lambda _: client.encrypt([0] * pk.n), range(12)))
    assert len(set(packets)) == len(packets)
    assert len({msgpack.unpackb(p)[2] for p in packets}) == len(packets)
    for packet in packets:
        cipher = compact.compact(owner.expand(packet, pk), pk)
        assert client.decrypt_compact(cipher) == [0] * pk.n
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError):
            operation(client)
    with monkeypatch.context() as patch:
        patch.setattr(owner.os, "getpid", lambda: client._pid + 1)
        with pytest.raises(RuntimeError, match="fork"):
            client.encrypt([0] * pk.n)
    client.close()
    client.close()
    for operation in (lambda: client.encrypt([0] * pk.n), lambda: client.decrypt_compact(cipher), client.prepare_terminal):
        with pytest.raises(RuntimeError, match="closed"):
            operation()


def test_owner_and_expansion_reject_bad_inputs():
    pk, sk = bgv.key_gen(16, q_bits=120)
    for context, secret in ((pk, replace(sk, key_id="bad")), (pk, replace(sk, s=(mpz(2),) * pk.n)),
                            (replace(pk, eta=10**9), sk), (replace(pk, t=2), sk)):
        with pytest.raises(ValueError):
            owner.OwnerClient(context, secret)
    client = owner.OwnerClient(pk, sk)
    with pytest.raises(ValueError, match="multiplication modulus"):
        client._product.prepare(mpz(1) << 240)
    for plain in ([0], [True] * pk.n):
        with pytest.raises(ValueError):
            client.encrypt(plain)
    packet = client.encrypt([0] * pk.n)
    fields = msgpack.unpackb(packet)
    bad_fields = fields.copy()
    bad_fields[-1] = pk.q.to_bytes(15, "little") * pk.n
    for bad in (b"", packet + b"x", msgpack.packb(bad_fields, use_bin_type=True)):
        with pytest.raises(ValueError):
            owner.expand(bad, pk)
    cipher = compact.compact(seeded.expand(packet, pk), pk)
    with pytest.raises(ValueError):
        client.decrypt_compact(replace(cipher, key_id="bad"))
