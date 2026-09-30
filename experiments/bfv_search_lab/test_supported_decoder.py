"""E64 exact native/GMP/phase decoding and rejection before private arithmetic."""

from contextlib import closing
from dataclasses import replace
import hashlib
import secrets

from gmpy2 import mpz
import pytest

from experiments.bfv_search_lab import coordinate_factory as coordinates
from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import client_buffer as buffer
from experiments.bfv_search_lab import crt_linear_check as checks
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import decryption_support as support
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import integer_phase_audit as audit
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import representation_oracle as oracle
from experiments.bfv_search_lab.representation_contract import Profile, Workload
from experiments.bfv_search_lab import score_layout
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import supported_decoder as decoder
from experiments.bfv_search_lab import verification_lifetime as lifetime


CASES = ((32, ("",), (19,), tree.layout),
         (32, ("0", "1"), (12, 4), tree.layout),
         (32, ("0", "10", "11"), (6, 3, 1), tree.layout),
         (32, ("0", "1"), (35, 9), tree.layout),
         (32, ("0", "1"), (12, 4), score_layout.layout),
         (32, ("0", "1"), (16, 16), score_layout.layout),
         (32, ("0", "1"), (0, 4), score_layout.layout))


def inputs(n, paths, counts, constructor):
    layout = constructor(tree.context(n, paths, 17), (4,) * len(paths), counts)
    s = space.space(layout, tuple(range(len(paths))))
    words = tuple(tuple((i * 3 + group) % 16 for i in range(count)) for group, count in enumerate(counts))
    groups = [[[int(word >> j & 1) for j in range(4)] for word in row] for row in words]
    ids, position = [], 0
    for count in counts:
        ids.append(tuple(1000 - position - i for i in range(count)))
        position += count
    # Owner-local identity only; this is not a public commitment scheme.
    binding = hashlib.sha256(repr((words, tuple(ids))).encode()).hexdigest()
    return s, words, groups, tuple(ids), binding


@pytest.mark.parametrize("n,paths,counts,constructor", CASES)
def test_mixed_legacy_score_layouts_full_reference_exact_ids_ties_and_integer_phase(n, paths, counts, constructor):
    pytest.importorskip("experiments.bfv_search_lab._subring._crt_subring")
    s, words, groups, ids, binding = inputs(n, paths, counts, constructor)
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    epoch, attempts = secrets.token_bytes(32), lifetime.AttemptBudget(8)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, groups, epoch, client)
        factory = coordinates.Factory(s, groups, epoch, client)
        server, reference = native.NativeIndex(index, pk), checks.EpochCheck(index, pk, budget=8)
        gate = decoder.Gate(index, pk, ids, binding, attempts)
        assert gate.certificate == support.matrix_oracle(s.layout)
        phase = audit.Audit(index, pk, sk)
        for word in range(4):
            ticket, answer, _ = factory.prepare(word.to_bytes(16, "little"))
            gate.prepare_answer(answer)
            reference.prepare_answer(answer)
            values = tuple((1 - 2 * (word >> j & 1)) % 17 for _ in paths for j in range(4))
            request = ticket.consume(values, epoch)
            output = server.evaluate(answer, request)
            assert output == masked.evaluate(index, answer, request, pk)
            assert reference.verify_once(request, output)  # Before full secret diagnostics.
            assert phase.measure(request, answer, output)["all_integer_phase_coefficients_match_ciphertext"]
            reply = decoder.project(output, s, pk, epoch)
            body = decoder.pack(reply, pk)
            assert gate.parse(body, reply.phase_bounds) == reply
            dots = gate.open_body_once(request, body, sk, reply.phase_bounds)
            assert dots == tuple(tuple(row) for row in space.scores(s, groups, values))
            assert dots == tuple(tuple(row) for row in tree.unpack(s.layout, [bgv.decrypt(c, pk, sk) for c in output]))
            scores = tuple((int(value) + word.bit_count()) % 17 for row in dots for value in row)
            expected = tuple((word ^ old).bit_count() for row in words for old in row)
            flat_ids = tuple(i for row in ids for i in row)
            assert scores == expected
            assert tuple(sorted(zip(scores, flat_ids, strict=True))[:3]) == tuple(sorted(zip(expected, flat_ids, strict=True))[:3])
            assert len(body) == gate.certificate.body_bytes_model(32)
            assert gate.output_ids == ids and gate.owner_plan_binding == binding
        assert attempts.used == 4


def test_wrong_supplied_coordinates_shape_epoch_binding_bounds_and_body_use_no_sk(monkeypatch):
    s, _, groups, ids, binding = inputs(*CASES[1])
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    epoch, attempts = secrets.token_bytes(32), lifetime.AttemptBudget(16)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, groups, epoch, client)
        factory, server = coordinates.Factory(s, groups, epoch, client), native.NativeIndex(index, pk)
        gate = decoder.Gate(index, pk, ids, binding, attempts)
        private_calls = []
        monkeypatch.setattr(decoder, "_field_carrier", lambda *args: private_calls.append(True))
        mutations = (
            lambda r: replace(r, c0_supported=((mpz((r.c0_supported[0][0] + 1) % pk.q),) + r.c0_supported[0][1:],)),
            lambda r: replace(r, c1=(r.c1[0][:-1] + ((r.c1[0][-1] + 1) % pk.q,),)),
            lambda r: replace(r, c0_supported=(r.c0_supported[0][:-1],)),
            lambda r: replace(r, epoch=secrets.token_bytes(32)),
            lambda r: replace(r, space_binding=bytes(32)),
            lambda r: replace(r, phase_bounds=(r.phase_bounds[0] + 1,)),
            lambda r: replace(r, key_id="00" * 32),
        )
        for ordinal, mutate in enumerate(mutations):
            ticket, answer, _ = factory.prepare(ordinal.to_bytes(16, "little"))
            gate.prepare_answer(answer)
            request = ticket.consume((1,) * s.dimension, epoch)
            reply = decoder.project(server.evaluate(answer, request), s, pk, epoch)
            assert gate.open_once(request, mutate(reply), sk) is None
            with pytest.raises(RuntimeError, match="consumed"):
                gate.open_once(request, reply, sk)
        ticket, answer, _ = factory.prepare((8).to_bytes(16, "little"))
        gate.prepare_answer(answer)
        request = ticket.consume((1,) * s.dimension, epoch)
        assert gate.open_body_once(request, b"not a packet", sk, (1,)) is None
        assert not private_calls and attempts.used == 15  # Seven original/replays + malformed body.


def test_old_epoch_gate_and_global_budget_cannot_be_reset_with_a_new_gate(monkeypatch):
    s, _, groups, ids, binding = inputs(*CASES[4])
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    attempts = lifetime.AttemptBudget(1)
    with closing(owner.OwnerClient(pk, sk)) as client:
        old_epoch = secrets.token_bytes(32)
        old_index, _ = masked.enroll(s, groups, old_epoch, client)
        old_gate = decoder.Gate(old_index, pk, ids, binding, attempts)
        token, answer, _ = coordinates.Factory(s, groups, old_epoch, client).prepare(bytes(16))
        old_gate.prepare_answer(answer)
        request = token.consume((1,) * s.dimension, old_epoch)
        private_calls = []
        monkeypatch.setattr(decoder, "_field_carrier", lambda *args: private_calls.append(True))
        assert old_gate.open_once(request, None, sk) is None
        epoch = secrets.token_bytes(32)
        index, _ = masked.enroll(s, groups, epoch, client)
        gate = decoder.Gate(index, pk, ids, binding, attempts)
        token, answer, _ = coordinates.Factory(s, groups, epoch, client).prepare(bytes(16))
        gate.prepare_answer(answer)
        request = token.consume((1,) * s.dimension, epoch)
        reply = decoder.project(native.NativeIndex(index, pk).evaluate(answer, request), s, pk, epoch)
        with pytest.raises(RuntimeError, match="Global"):
            gate.open_once(request, reply, sk)
        assert not private_calls and attempts.used == 1


def test_owner_binding_rejects_wrong_counts_duplicate_ids_and_public_digest_substitution():
    s, _, groups, ids, binding = inputs(*CASES[4])
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, groups, secrets.token_bytes(32), client)
        for wrong_ids, wrong_binding in ((ids[:-1], binding), ((ids[0], ids[0][:4]), binding), (ids, "public")):
            with pytest.raises(ValueError, match="owner-approved"):
                decoder.Gate(index, pk, wrong_ids, wrong_binding, lifetime.AttemptBudget(8))


def test_projected_split_base_then_private_insert_delete_edit_and_empty_current_result():
    w = Workload((0, 1, 2, 3, 8, 9, 10, 11), tuple(range(80, 88)), 4)
    pieces = tuple(oracle.Piece(str(i), tuple(range(4 * i, 4 * i + 4)),
                               affine.prepare(list(w.rows[4 * i:4 * i + 4]), 4, 17), "affine") for i in range(2))
    p = oracle.compile_choice(w, oracle.Choice(pieces), Profile(32, 17, eta=1), (1, 1))
    pk, sk = masked.key_gen(p.query_space, q_bits=32, eta=1)
    epoch = secrets.token_bytes(32)
    groups = [[list(row) for row in group] for group in p.groups]
    ids = tuple(tuple(p.ids[pos] for pos in block.positions) for block in p.candidate.blocks)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(p.query_space, groups, epoch, client)
        gate = decoder.Gate(index, pk, ids, p.binding, lifetime.AttemptBudget(8))
        factory, server = coordinates.Factory(p.query_space, groups, epoch, client), native.NativeIndex(index, pk)
        ledger = buffer.Ledger(p, epoch)
        ledger.transact(edits={80: 15}, delete_ids=(81,), inserts={90: 7})
        for ordinal in range(2):
            if ordinal:
                ledger.transact(delete_ids=tuple(i for i in (*p.ids, 90) if i != 81))
            word = 2
            ticket, answer, _ = factory.prepare(ordinal.to_bytes(16, "little"))
            gate.prepare_answer(answer)
            weights, offsets = oracle.query(p, word)
            request = ticket.consume(tuple(x % 17 for x in weights), epoch)
            dots = gate.open_once(request, decoder.project(server.evaluate(answer, request), p.query_space, pk, epoch), sk)
            scores = [None] * len(p.ids)
            for block, row, group in zip(p.candidate.blocks, dots, p.query_space.map_ids, strict=True):
                for position, value in zip(block.positions, affine.decode(p.maps[group], row, offsets[group]), strict=True):
                    scores[position] = value
            assert tuple(scores) == w.expected(word)
            result = ledger.snapshot.correct(tuple(scores), word, epoch=ledger.snapshot.epoch, verified_base_epoch=epoch)
            if ordinal:
                assert result.ids == result.scores == result.top3 == ()
            else:
                assert result.ids == (80, 82, 83, 84, 85, 86, 87, 90)
                expected = ((15 ^ word).bit_count(), *(int(w.rows[i] ^ word).bit_count() for i in range(2, 8)), (7 ^ word).bit_count())
                assert result.scores == expected
                assert result.top3 == tuple(sorted(zip(expected, result.ids, strict=True))[:3])
