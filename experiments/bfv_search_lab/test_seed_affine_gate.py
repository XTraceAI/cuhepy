"""E77 exact affine/adjoint boundary and private seed-release lifecycle."""

from contextlib import closing
from dataclasses import replace
import random

from gmpy2 import mpz
import pytest

from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_query_space as crt
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import encrypted_query_gate as dense
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import packed_query_expansion as packed
from experiments.bfv_search_lab import seed_affine_gate as affine
from experiments.bfv_search_lab import verification_lifetime as lifetime
from experiments.bfv_search_lab.test_packed_query_expansion import independent_products
from experiments.bfv_search_lab.test_supported_decoder import CASES, inputs


@pytest.mark.parametrize("descriptor", CASES)
def test_affine_receiver_exact_against_full_canonical_circuit(descriptor):
    s, words, groups, ids, binding = inputs(*descriptor)
    pk, sk = masked.key_gen(s, q_bits=40, eta=1)
    keys = packed.key_gen(s, pk, sk)
    attempts, epoch = lifetime.AttemptBudget(16), b"e" * 32
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, groups, epoch, client)
        factory = affine.Factory(index, pk, keys, ids, binding, attempts)
        receiver = affine.Receiver(factory, attempts)
        assert not hasattr(receiver, "_dense") and not hasattr(receiver, "_hints_expanded")
        for word in range(16):
            values = tuple((1 - 2 * (word >> j & 1)) % 17 for _ in s.dimensions for j in range(4))
            original, _ = packed.make_query(s, epoch, word.to_bytes(16, "little"), values, client)
            hint = factory.prepare_seed(original)
            receiver.register_seed(hint)
            receiver.pin_query(original)
            expanded = packed.expand(original, s, pk, keys)
            offsets = affine.offset_query(original, s, pk, keys)
            for column, (actual, delta) in enumerate(zip(expanded.ciphertexts, offsets.ciphertexts, strict=True)):
                linear = affine.selection(original.ciphertext.components[0], column, keys.factor, pk.q)
                assert actual.components[0] == tuple((x + y) % pk.q for x, y in zip(linear, delta.components[0], strict=True))
                assert actual.components[1] == delta.components[1]
            output = packed.evaluate(index, expanded, pk, keys)
            assert tuple(tuple(tuple(map(int, p)) for p in c.components) for c in output) == independent_products(index, expanded, pk)
            body = dense.pack(dense.project(output, index, pk, expected_bound=packed.output_bound(index, pk, keys)), pk)
            dots = receiver.open_body_once(original.token_id, body, sk)
            assert dots == tuple(tuple(row) for row in crt.scores(s, groups, values))
            scores = tuple((x + word.bit_count()) % 17 for row in dots for x in row)
            expected = tuple((word ^ old).bit_count() for row in words for old in row)
            flat = tuple(i for group in ids for i in group)
            assert scores == expected and sorted(zip(scores, flat, strict=True))[:3] == sorted(zip(expected, flat, strict=True))[:3]
    assert attempts.used == 16


@pytest.mark.parametrize("shared", (0, 1))
def test_literal_selection_adjoint_and_affinity_for_arbitrary_c0(shared):
    s = crt.space(tree.layout(tree.context(32, ("0", "1"), 17), (4, 4) if shared else (3, 3), (6, 3)), (0, 1), shared=shared)
    pk, sk = masked.key_gen(s, q_bits=40, eta=1)
    keys, rng = packed.key_gen(s, pk, sk), random.Random(7701 + shared)
    assert keys.factor == 4 and s.columns in (3, 4)
    hints = tuple((tuple(mpz(rng.randrange(int(pk.q))) for _ in range(pk.n)), (mpz(0),) * pk.n) for _ in range(s.columns))
    vector = affine.compile_vector(hints, keys.factor, pk.q)
    # Independently assemble every basis column of the selector and apply z.
    for at in range(pk.n):
        expected = sum(keys.factor * hints[j][0][at - j]
                       for j in range(s.columns) if at >= j and (at - j) % keys.factor == 0) % pk.q
        assert vector[at] == expected
    with closing(owner.OwnerClient(pk, sk)) as client:
        original, _ = packed.make_query(s, bytes(32), bytes(16), (1,) * s.dimension, client)
    offsets = affine.offset_query(original, s, pk, keys)
    for _ in range(12):
        c0 = tuple(mpz(rng.randrange(int(pk.q))) for _ in range(pk.n))
        request = replace(original, ciphertext=replace(original.ciphertext, components=(c0, original.ciphertext.components[1])))
        expanded = packed.expand(request, s, pk, keys)  # Algebra only, arbitrary phase is not decrypted.
        for j, (actual, delta) in enumerate(zip(expanded.ciphertexts, offsets.ciphertexts, strict=True)):
            assert actual.components[0] == tuple((x + y) % pk.q for x, y in
                                                 zip(affine.selection(c0, j, keys.factor, pk.q), delta.components[0], strict=True))
            assert actual.components[1] == delta.components[1]
        assert dense._dot(vector, c0, pk.q) == sum(dense._dot(z0, affine.selection(c0, j, keys.factor, pk.q), pk.q)
                                                  for j, (z0, _z1) in enumerate(hints)) % pk.q


@pytest.mark.parametrize("mutation", ("c0", "c1", "c2", "truncate", "false_expansion"))
def test_rejection_precedes_secret_use_and_burns_shared_budget(monkeypatch, mutation):
    s, _words, groups, ids, binding = inputs(*CASES[1])
    pk, sk = masked.key_gen(s, q_bits=40, eta=1)
    keys, attempts = packed.key_gen(s, pk, sk), lifetime.AttemptBudget(2)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, groups, bytes(32), client)
        request, _ = packed.make_query(s, bytes(32), bytes(16), (1,) * s.dimension, client)
    factory = affine.Factory(index, pk, keys, ids, binding, attempts)
    receiver = affine.Receiver(factory, attempts)
    receiver.register_seed(factory.prepare_seed(request))
    receiver.pin_query(request)
    expanded = packed.expand(request, s, pk, keys)
    if mutation == "false_expansion":
        first = expanded.ciphertexts[0]
        changed = replace(first, components=(((first.components[0][0] + 1) % pk.q, *first.components[0][1:]), first.components[1]))
        expanded = replace(expanded, ciphertexts=(changed, *expanded.ciphertexts[1:]))
    output = packed.evaluate(index, expanded, pk, keys)
    reply = dense.project(output, index, pk, expected_bound=packed.output_bound(index, pk, keys))
    if mutation in ("c0", "c1", "c2"):
        field = {"c0": "c0_supported", "c1": "c1", "c2": "c2"}[mutation]
        rows = getattr(reply, field)
        reply = replace(reply, **{field: (((rows[0][0] + 1) % pk.q, *rows[0][1:]), *rows[1:])})
    body = dense.pack(reply, pk)
    if mutation == "truncate":
        body = body[:-1]

    def forbidden(*_args):
        pytest.fail("Rejected projected body reached secret arithmetic")

    monkeypatch.setattr(dense, "_decode", forbidden)
    assert receiver.open_body_once(bytes(16), body, sk) is None
    assert attempts.used == 1
    with pytest.raises(RuntimeError, match="consumed"):
        receiver.open_body_once(bytes(16), body, sk)
    assert attempts.used == 2


def test_seed_input_hint_context_binding_and_reuse():
    s, _words, groups, ids, binding = inputs(*CASES[1])
    pk, sk = masked.key_gen(s, q_bits=40, eta=1)
    keys, attempts = packed.key_gen(s, pk, sk), lifetime.AttemptBudget(3)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, groups, bytes(32), client)
        request, _ = packed.make_query(s, bytes(32), bytes(16), (1,) * s.dimension, client)
    factory = affine.Factory(index, pk, keys, ids, binding, attempts)
    receiver = affine.Receiver(factory, attempts)
    hint = factory.prepare_seed(request)
    with pytest.raises(ValueError, match="shared lifetime"):
        affine.Receiver(factory, lifetime.AttemptBudget(3))
    unrelated = affine.Factory(index, pk, keys, ids, binding, attempts)
    with pytest.raises(ValueError, match="owner-private"):
        receiver.register_seed(replace(hint, owner_binding=unrelated.owner_binding))
    for bad in (replace(hint, owner_binding="00" * 32), replace(hint, constants=()), replace(hint, c1_digest="wrong")):
        with pytest.raises(ValueError):
            receiver.register_seed(bad)
    receiver.register_seed(hint)
    with pytest.raises(RuntimeError, match="consumed"):
        receiver.register_seed(hint)
    with pytest.raises(RuntimeError, match="consumed"):
        factory.prepare_seed(replace(request, token_id=b"n" * 16))  # Reusing C1 is not fresh query encryption.
    with pytest.raises(ValueError):
        receiver.pin_query(replace(request, epoch=b"e" * 32))
    c1 = request.ciphertext.components[1]
    changed = replace(request, ciphertext=replace(request.ciphertext, components=(request.ciphertext.components[0],
                                                                                 ((c1[0] + 1) % pk.q, *c1[1:]))))
    with pytest.raises(RuntimeError, match="registered"):
        receiver.pin_query(changed)  # Seed mismatch consumes the private hint.
    with pytest.raises(RuntimeError, match="registered"):
        receiver.pin_query(request)


def test_seed_offsets_cannot_be_omitted():
    s, _words, groups, ids, binding = inputs(*CASES[1])
    pk, sk = masked.key_gen(s, q_bits=40, eta=1)
    keys, attempts = packed.key_gen(s, pk, sk), lifetime.AttemptBudget(1)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, groups, bytes(32), client)
        request, _ = packed.make_query(s, bytes(32), bytes(16), (1,) * s.dimension, client)
    factory = affine.Factory(index, pk, keys, ids, binding, attempts)
    receiver = affine.Receiver(factory, attempts)
    actual = factory.prepare_seed(request)
    assert any(actual.constants)
    # Deliberately wrong trusted setup demonstrates that S(C0) alone is insufficient.
    receiver.register_seed(replace(actual, constants=(0,) * len(actual.constants)))
    receiver.pin_query(request)
    output = packed.evaluate(index, packed.expand(request, s, pk, keys), pk, keys)
    body = dense.pack(dense.project(output, index, pk, expected_bound=packed.output_bound(index, pk, keys)), pk)
    assert receiver.open_body_once(request.token_id, body, sk) is None
