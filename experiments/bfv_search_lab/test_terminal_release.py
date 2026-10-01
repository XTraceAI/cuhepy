"""E66 exact release composition, pinned seeds and rejection before secrets."""

from contextlib import closing
from dataclasses import replace
import hashlib
import secrets

from gmpy2 import mpz
import pytest

from experiments.bfv_search_lab import component_recipe as recipe
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import supported_decoder as decoder
from experiments.bfv_search_lab import terminal_release as release
from experiments.bfv_search_lab import verification_lifetime as lifetime
from experiments.bfv_search_lab.test_supported_decoder import CASES, inputs


@pytest.mark.parametrize("descriptor", CASES)
@pytest.mark.parametrize("mode", ("cached", "streaming"))
def test_all_binary_queries_exact_across_layouts_and_recipe_modes(descriptor, mode):
    pytest.importorskip("experiments.bfv_search_lab._subring._crt_subring")
    s, words, groups, ids, binding = inputs(*descriptor)
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    epoch, attempts = secrets.token_bytes(32), lifetime.AttemptBudget(16)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, material, _ = recipe.enroll(s, groups, epoch, client)
        gate = release.Gate(index, material, pk, ids, binding, attempts, mode=mode)
        server = native.NativeIndex(index, pk)
        for word in range(16):
            ticket, answer, seeds = recipe.prepare(s, groups, epoch, word.to_bytes(16, "little"), secrets.token_bytes(32), client)
            gate.prepare_answer(answer, seeds)
            weights = tuple((1 - 2 * (word >> j & 1)) % 17 for _ in s.dimensions for j in range(4))
            request = ticket.consume(weights, epoch)
            output = server.evaluate(answer, request)
            assert output == masked.evaluate(index, answer, request, pk)
            body = release.pack(output, s, pk, epoch)
            dots = gate.open_body_once(request, body, sk)
            assert dots == tuple(tuple(row) for row in space.scores(s, groups, weights))
            scores = tuple((x + word.bit_count()) % 17 for row in dots for x in row)
            assert scores == tuple((word ^ old).bit_count() for row in words for old in row)
            assert gate._decoder.output_ids == ids
            assert len(body) == release.cost(s, pk)["combined_body_bytes"]
        assert attempts.used == 16


def test_malformed_body_and_stale_request_reject_before_private_decode_and_burn_attempt(monkeypatch):
    s, _, groups, ids, binding = inputs(*CASES[1])
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    epoch, attempts = secrets.token_bytes(32), lifetime.AttemptBudget(8)
    private_calls = []
    monkeypatch.setattr(decoder, "_field_carrier", lambda *args: private_calls.append(True))
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, material, _ = recipe.enroll(s, groups, epoch, client)
        gate, server = release.Gate(index, material, pk, ids, binding, attempts), native.NativeIndex(index, pk)
        for i, mutation in enumerate(("bit", "truncate", "extend", "epoch")):
            ticket, answer, seeds = recipe.prepare(s, groups, epoch, i.to_bytes(16, "little"), secrets.token_bytes(32), client)
            gate.prepare_answer(answer, seeds)
            request = ticket.consume((1,) * s.dimension, epoch)
            body = release.pack(server.evaluate(answer, request), s, pk, epoch)
            if mutation == "bit":
                body = bytes([body[0] ^ 1]) + body[1:]
            elif mutation == "truncate":
                body = body[:-1]
            elif mutation == "extend":
                body += b"\0"
            else:
                request = replace(request, epoch=b"x" * 32)
            assert gate.open_body_once(request, body, sk) is None
            with pytest.raises(RuntimeError, match="consumed"):
                gate.open_body_once(request, body, sk)
    assert attempts.used == 8 and not private_calls


def test_owner_pinned_index_and_answer_seed_mismatch_rejected_before_query():
    s, _, groups, ids, binding = inputs(*CASES[0])
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    epoch = secrets.token_bytes(32)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, material, _ = recipe.enroll(s, groups, epoch, client)
        bad = replace(material, columns=((bytes(32),), *material.columns[1:]))
        with pytest.raises(ValueError, match="owner-pinned"):
            release.Gate(index, bad, pk, ids, binding, lifetime.AttemptBudget(4))
        gate = release.Gate(index, material, pk, ids, binding, lifetime.AttemptBudget(4))
        _, answer, seeds = recipe.prepare(s, groups, epoch, bytes(16), secrets.token_bytes(32), client)
        with pytest.raises(ValueError, match="owner-pinned"):
            gate.prepare_answer(answer, (bytes(32),))
        gate.prepare_answer(answer, seeds)
        with pytest.raises(RuntimeError, match="Duplicate"):
            gate.prepare_answer(answer, seeds)


def test_omitted_c0_alternative_encoding_has_same_body_and_exact_scores():
    s, _, groups, ids, binding = inputs(*CASES[0])
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    epoch = hashlib.sha256(b"owner epoch").digest()
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, material, _ = recipe.enroll(s, groups, epoch, client)
        gate = release.Gate(index, material, pk, ids, binding, lifetime.AttemptBudget(4))
        ticket, answer, seeds = recipe.prepare(s, groups, epoch, bytes(16), secrets.token_bytes(32), client)
        gate.prepare_answer(answer, seeds)
        request = ticket.consume((1,) * s.dimension, epoch)
        output = native.NativeIndex(index, pk).evaluate(answer, request)
        omitted = next(i for i in range(pk.n) if i not in gate.certificate.kept_c0[0])
        c0 = list(output[0].components[0])
        c0[omitted] = mpz((c0[omitted] + 1) % pk.q)
        altered = (replace(output[0], components=(tuple(c0), output[0].components[1])), *output[1:])
        assert release.pack(altered, s, pk, epoch) == release.pack(output, s, pk, epoch)
        assert gate.open_body_once(request, release.pack(altered, s, pk, epoch), sk) == tuple(tuple(row) for row in space.scores(s, groups, (1,) * s.dimension))
