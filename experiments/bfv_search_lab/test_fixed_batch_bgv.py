"""Fixed-batch schedule, exact phases and guarded private decryption."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace

import pytest

from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_noise_budget as noise
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import dyadic_crt as crt
from experiments.bfv_search_lab import fixed_batch_bgv as fixed
from experiments.bfv_search_lab import hierarchical_query_basis as hierarchy
from experiments.bfv_search_lab import reduction_oracles as reduction
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab.test_hierarchical_query_basis import fixture


def batch_fixture(count=8, repeat=3):
    words, maps, p, s, rows = fixture(repeat)
    queries = tuple(range(count))
    compiled = hierarchy.compile_bits(p)
    batch = fixed.Batch(s, rows, tuple(compiled.query(q)[0] for q in queries), eta=1,
                        correctness_bits=64, query_budget=max(count, 8))
    return words, maps, compiled, queries, batch


def phase(cipher, pk, sk):
    product = reduction.ring_product(tuple(map(int, cipher.components[1])), tuple(map(int, sk.s)))
    values = [(int(a) + b) % int(pk.q) for a, b in zip(cipher.components[0], product, strict=True)]
    return tuple(x if x <= pk.q // 2 else x - pk.q for x in values)


def test_full_binary_fixed_batch_exact_distances_native_gmp_and_integer_phase_oracle():
    pytest.importorskip("experiments.bfv_search_lab._subring._crt_subring")
    words, maps, compiled, queries, batch = batch_fixture(32)
    with closing(batch):
        batch.keygen()
        requests = batch._requests
        index, _ = batch.enroll()
        assert batch._requests is requests
        gate = batch.verifier()
        pool = batch.prepare_answers()
        for answer, _ in pool:
            gate.prepare_answer(answer)
        native = fixed.NativeIndex(batch.context, index)
        columns = space.columns(batch.profile.space, batch._rows())
        # Independently recover each fresh message/error phase; no secret
        # diagnostic is part of the public evaluator or response API.
        fresh_phases = []
        for encrypted, plain in zip(index.columns, columns, strict=True):
            col = []
            for cipher, message in zip(encrypted, plain, strict=True):
                actual = phase(cipher, batch.pk, batch.sk)
                for x, m in zip(actual, message, strict=True):
                    centered = ((m + batch.pk.t // 2) % batch.pk.t) - batch.pk.t // 2
                    assert (x - centered) % batch.pk.t == 0 and abs((x - centered) // batch.pk.t) <= 1
                col.append(actual)
            fresh_phases.append(col)
        for i, q in enumerate(queries):
            request, answer = batch.release(i)
            output = fixed.evaluate(batch.context, index, answer, request)
            assert native.evaluate(answer, request) == output
            assert not isinstance(output[0], bgv.Ciphertext) and not hasattr(output[0], "phase_bound")
            short = space.corrections(batch.profile.space, request.delta)
            polys = [tuple(space.expand(batch.profile.space, row)) for row in short]
            for reply, cipher in enumerate(output):
                expected = list(phase(answer.ciphertexts[reply], batch.pk, batch.sk))
                for column, poly in zip(fresh_phases, polys, strict=True):
                    expected = [a + b for a, b in zip(expected, reduction.ring_product(column[reply], poly), strict=True)]
                assert tuple(expected) == phase(cipher, batch.pk, batch.sk)
                assert max(map(abs, expected)) <= cipher.certificate.total
            receipt = gate.accept_once(request, output)
            assert receipt is not None
            dots = crt.unpack(batch.profile.space.layout, gate.decrypt_once(receipt, batch.sk))
            offsets = compiled.query(q)[1]
            actual = [affine.decode(m, ds, off) for m, ds, off in zip(maps, dots, offsets, strict=True)]
            assert actual == [[(x ^ q).bit_count() for x in rows] for rows in words]
            assert sorted((v, i) for i, v in enumerate(x for row in actual for x in row))[:3] == sorted(
                (v, i) for i, v in enumerate((x ^ q).bit_count() for rows in words for x in rows))[:3]


@pytest.mark.parametrize("mutation", ("tail", "certificate", "request", "profile", "negative", "truncated"))
def test_complete_gate_rejects_mutation_before_private_work(mutation, monkeypatch):
    _, _, _, _, batch = batch_fixture(1)
    with closing(batch):
        batch.keygen()
        index, _ = batch.enroll()
        gate = batch.verifier()
        batch.prepare_answers()
        request, answer = batch.release(0)
        gate.prepare_answer(answer)
        output = fixed.evaluate(batch.context, index, answer, request)
        if mutation in ("tail", "negative"):
            parts = [list(row) for row in output[-1].components]
            parts[1][-1] = -1 if mutation == "negative" else (parts[1][-1] + 1) % batch.pk.q
            output = (*output[:-1], replace(output[-1], components=tuple(tuple(row) for row in parts)))
        elif mutation == "certificate":
            output = (replace(output[0], certificate=replace(output[0].certificate, tail_bound=0)), *output[1:])
        elif mutation == "profile":
            output = (replace(output[0], certificate=replace(output[0].certificate, profile_binding=bytes(32))), *output[1:])
        elif mutation == "request":
            request = replace(request, delta=((request.delta[0] + 1) % batch.pk.t, *request.delta[1:]))
        else:
            output = output[:-1]
        monkeypatch.setattr(fixed, "_ring_product", lambda *args: pytest.fail("Private work before acceptance"))
        assert gate.accept_once(request, output) is None
        with pytest.raises(RuntimeError):
            gate.accept_once(request, output)
        with pytest.raises(ValueError):
            gate.decrypt_once(fixed.CheckedReply(request.token_id, output, object()), batch.sk)


def test_replay_receipt_substitution_and_concurrent_request_consumption():
    _, _, _, _, batch = batch_fixture(1)
    with closing(batch):
        batch.keygen()
        index, _ = batch.enroll()
        gate = batch.verifier()
        batch.prepare_answers()

        def release():
            try:
                return batch.release(0)
            except RuntimeError:
                return None

        with ThreadPoolExecutor(max_workers=4) as workers:
            released = list(workers.map(lambda _: release(), range(8)))
        pairs = [x for x in released if x is not None]
        assert len(pairs) == 1
        request, answer = pairs[0]
        gate.prepare_answer(answer)
        output = fixed.evaluate(batch.context, index, answer, request)
        receipt = gate.accept_once(request, output)
        assert receipt is not None
        with pytest.raises(ValueError):
            gate.decrypt_once(replace(receipt, ciphertexts=tuple(list(output))), batch.sk)
        assert gate.decrypt_once(receipt, batch.sk)
        with pytest.raises(ValueError):
            gate.decrypt_once(receipt, batch.sk)
        with pytest.raises(TypeError):
            gate.verify_once(request, ())


def test_lifecycle_pins_inputs_and_deterministic_gate_stays_conservative():
    _, _, _, _, batch = batch_fixture(1)
    with closing(batch):
        for operation in (batch.enroll, batch.prepare_answers, batch.verifier):
            with pytest.raises(RuntimeError):
                operation()
        batch.keygen()
        with pytest.raises(RuntimeError):
            batch.keygen()
        batch.enroll()
        with pytest.raises(RuntimeError):
            batch.enroll()
        batch.prepare_answers()
        with pytest.raises(RuntimeError):
            batch.prepare_answers()
    with pytest.raises(RuntimeError):
        batch.release(0)
    ctx = crt.context(16384, tuple(format(i, "05b") for i in range(32)), 1153)
    s = space.space(crt.layout(ctx, (32,) * 32, (1,) * 32), tuple(range(32)))
    assert 2 * noise.certificate(noise.Profile(s)).total < 4294475777
    with pytest.raises(ValueError, match="Q is too small"):
        masked.key_gen(s, q_bits=32)
