"""Exact public CPU/GPU agreement for transform schedules and terminal rounding."""

from contextlib import closing
from dataclasses import replace
import os
import random

import pytest

from cuhepy.bfv.cuda import cuda_available
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import compact_bgv as compact, owner_bgv as owner
from experiments.bfv_search_lab.native_bgv import NativeServer, NTT_VARIANTS


@pytest.mark.parametrize("n,dimension,count", [(16, 3, 35), (2048, 13, 131), (16384, 512, 65)])
def test_all_ntt_schedules_and_device_terminal_match_reference(n, dimension, count):
    pytest.importorskip("experiments.bfv_search_lab._native._bgv_trace_cuda")
    if not cuda_available():
        if os.environ.get("CUHEPY_REQUIRE_BGV_CUDA") == "1":
            pytest.fail("CUDA was required but no device is available")
        pytest.skip("CUDA device required")
    pk, sk = bgv.key_gen(n, q_bits=120, rns_modulus=True)
    keys = trace.evaluation_keys(pk, sk, 1 << (dimension - 1).bit_length())
    rng = random.Random(n + 20260925)
    query = [rng.randrange(2) for _ in range(dimension)]
    rows = [[rng.randrange(2) for _ in query] for _ in range(count)]
    rows[:3] = [query[:], query[:], [1 - b for b in query]]
    plain, tiles = bgv.coefficient_inputs(query, rows, n)
    index = [bgv.encrypt(p, pk) for p in tiles]
    cpu = NativeServer(pk, keys, residue=True)
    with closing(owner.OwnerClient(pk, sk, native=True, rns=True)) as client:
        encrypted = owner.expand(client.encrypt(plain), pk)
        full = cpu.search(encrypted, cpu.prepare_index(index, count))
        for variant in NTT_VARIANTS:
            gpu = NativeServer(pk, keys, residue=True, device="cuda", cuda_level=4, ntt_variant=variant)
            resident = gpu.prepare_index(index, count)
            with gpu.prepare_workspace(resident) as workspace:
                initial_bytes = workspace.coefficient_bytes
                for bits in ([16, 25, 32, 59, 25] if n == 16 else [25, 32, 59, 25]):
                    expected = [compact.compact(c, pk, bits) for c in full]
                    host = workspace.search_compact(encrypted, bits=bits)
                    device = workspace.search_compact(encrypted, bits=bits, gpu_terminal=True)
                    assert host == expected == device  # Complete ciphertexts and public bounds.
                    assert workspace.coefficient_bytes == initial_bytes + 2 * n * 8
                    finished = client.finish(device, count, dimension)
                    distances = tuple(sum(a != b for a, b in zip(row, query, strict=True)) for row in rows)
                    assert finished.distances == distances
                    assert finished.top == tuple(sorted(enumerate(distances), key=lambda x: (x[1], x[0]))[:3])
                    expected_wire = compact.pack(expected, count, dimension, pk)
                    for terminal in (False, True):
                        packet, bounds = workspace.search_packet(encrypted, dimension, bits=bits,
                                                                  gpu_terminal=terminal)
                        assert packet == expected_wire
                        assert client.finish_packed_fixture(packet, expected_wire, count, dimension,
                                                            bits=bits, bounds=bounds) == finished
                with pytest.raises(ValueError, match="bound"):
                    workspace.search_compact(replace(encrypted, phase_bound=int(pk.q) // 4), gpu_terminal=True)
                with pytest.raises(ValueError, match="bool"):
                    workspace.search_compact(encrypted, gpu_terminal=1)
                assert workspace.search_compact(encrypted, bits=25, gpu_terminal=True) == expected
            with pytest.raises(RuntimeError, match="closed"):
                workspace.search_compact(encrypted, gpu_terminal=True)


@pytest.mark.parametrize("variant", ["unknown", 1, True, None])
def test_ntt_variant_must_be_explicit_valid_choice(variant):
    with pytest.raises(ValueError, match="NTT variant"):
        NativeServer(None, None, residue=True, device="cuda", ntt_variant=variant)


def test_cpu_factory_rejects_cuda_transform_choice():
    with pytest.raises(ValueError, match="NTT variant"):
        NativeServer(None, None, residue=True, ntt_variant="warp512")
