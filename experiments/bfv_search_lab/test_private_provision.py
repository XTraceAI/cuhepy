"""E79 authenticated decode ordering and restored complete gate controls."""

from contextlib import closing
from dataclasses import replace

import msgpack
import pytest

from experiments.bfv_search_lab import coordinate_factory
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import native_linear_check as checks
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import private_provision as provision
from experiments.bfv_search_lab.test_supported_decoder import CASES, inputs


@pytest.mark.parametrize("fault", ["tamper", "truncate", "context", "key"])
def test_bad_envelope_never_reaches_parser_or_private_constructor(fault, monkeypatch):
    key, context = b"k" * 32, b"c" * 32
    body, _ = provision.seal({"sample": (0, 1, 2)}, key, context, 512)
    if fault == "tamper":
        body = body[:-1] + bytes((body[-1] ^ 1,))
    elif fault == "truncate":
        body = body[:-1]
    elif fault == "context":
        context = b"z" * 32
    else:
        key = b"z" * 32
    calls = []
    monkeypatch.setattr(provision, "unpack", lambda *_: calls.append(True))
    with pytest.raises(ValueError):
        provision.open_private(body, key, context, 512)
    assert not calls


def test_fixed_padding_and_whitelisted_wide_integer_roundtrip():
    value = {"wide": (1 << 255, -(1 << 127)), "tuple": (1, b"a", True, None)}
    a, length = provision.seal(value, b"k" * 32, b"c" * 32, 1024)
    b, _ = provision.seal({"shorter": 1}, b"k" * 32, b"c" * 32, 1024)
    assert len(a) == len(b) and length < 1024
    assert provision.open_private(a, b"k" * 32, b"c" * 32, 1024) == value
    with pytest.raises(ValueError):
        provision.pack(object())
    with pytest.raises(ValueError):
        provision.unpack(msgpack.packb(["record", "os.system", ["something"]]))
    with pytest.raises(ValueError):
        provision.unpack(b"\x82\xa1x\x01\xa1x\x02")


@pytest.mark.parametrize("descriptor", (CASES[1], CASES[4]))
def test_all_private_state_is_encoded_received_and_restores_exact_gate(descriptor):
    s, _, groups, _, _ = inputs(*descriptor)
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    epoch = b"e" * 32
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, groups, epoch, client)
        source = checks.NativeVectorCheck(index, pk, rounds=4, budget=8)
        material = provision.checker_material(source)
        packet, _ = provision.seal({"space": s, "pk": pk, "sk": sk, "material": material}, b"k" * 32, b"c" * 32, 65536)
        received = provision.open_private(packet, b"k" * 32, b"c" * 32, 65536)
        assert (received["space"], received["pk"], received["sk"]) == (s, pk, sk)
        restored = provision.restore_checker(received["space"], received["pk"], epoch, received["material"])
        assert restored._fingerprints == source._fingerprints and restored._seeds == source._seeds
        factory = coordinate_factory.Factory(s, groups, epoch, client)
        ticket, answer, _ = factory.prepare(bytes(16))
        for gate in (source, restored):
            gate.prepare_answer(answer)
        request = ticket.consume((1,) * s.dimension, epoch)
        output = native.NativeIndex(index, pk).evaluate(answer, request)
        assert source.verify_once(request, output) and restored.verify_once(request, output)
        with pytest.raises(RuntimeError):
            restored.verify_once(request, output)
        bad = dict(received["material"], budget=0)
        with pytest.raises(ValueError):
            provision.restore_checker(s, pk, epoch, bad)
        tampered = dict(received["material"], fingerprints=(((-1,),),))
        with pytest.raises(ValueError):
            provision.restore_checker(s, pk, epoch, tampered)


def test_server_bootstrap_refuses_private_records_and_extra_fields():
    s, _, _, _, _ = inputs(*CASES[1])
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    value = {"mode": "he", "space": s, "pk": pk, "epoch": b"e" * 32, "budget": 8}
    assert provision.public_context(provision.pack(value)) == value
    with pytest.raises(ValueError):
        provision.public_context(provision.pack(dict(value, sk=sk)))
    with pytest.raises(ValueError):
        provision.public_context(provision.pack(dict(value, pk=replace(sk, key_id=pk.key_id))))
