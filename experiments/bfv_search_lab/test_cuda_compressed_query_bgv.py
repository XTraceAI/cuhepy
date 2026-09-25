"""Rounded queries through independent native CPU and reusable CUDA evaluators."""

from contextlib import closing
import os
import random

import pytest

from cuhepy.bfv.cuda import cuda_available
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import compressed_query_bgv as codec, owner_bgv as owner
from experiments.bfv_search_lab.native_bgv import NativeServer


@pytest.mark.parametrize("n,dimension,count", [(16, 3, 35), (2048, 13, 131), (16384, 512, 65)])
@pytest.mark.parametrize("owner_index", [False, True])
def test_cpu_cuda_and_owner_finish_match_after_query_rounding(n, dimension, count, owner_index):
    pytest.importorskip("experiments.bfv_search_lab._native._bgv_trace_cuda")
    if not cuda_available():
        if os.environ.get("CUHEPY_REQUIRE_BGV_CUDA") == "1":
            pytest.fail("CUDA was required but no device is available")
        pytest.skip("CUDA device required")
    pk, sk = bgv.key_gen(n, q_bits=120, rns_modulus=True)
    keys = trace.evaluation_keys(pk, sk, 1 << (dimension - 1).bit_length())
    rng = random.Random(20260925 + n)
    query = [rng.randrange(2) for _ in range(dimension)]
    rows = [[rng.randrange(2) for _ in query] for _ in range(count)]
    rows[:3] = [query[:], query[:], [1 - b for b in query]]
    plain, tiles = bgv.coefficient_inputs(query, rows, n)
    with closing(owner.OwnerClient(pk, sk, native=True, rns=True)) as client:
        index = [
            owner.expand(client.encrypt(p), pk) if owner_index else bgv.encrypt(p, pk)
            for p in tiles
        ]
        cpu = NativeServer(pk, keys, residue=True)
        gpu = NativeServer(pk, keys, residue=True, device="cuda", cuda_level=4)
        host, resident = cpu.prepare_index(index, count), gpu.prepare_index(index, count)
        drop = 72 if owner_index else 56
        packet = codec.compress(client.encrypt(plain), pk, dropped_bits=drop)
        expanded = codec.expand(packet, pk, dropped_bits=drop)
        reference = cpu.search_compact(expanded, host, bits=25)
        with gpu.prepare_workspace(resident) as workspace:
            result = workspace.search_compact(expanded, bits=25)
            assert result == reference  # All coefficients, not just selected distances.
            assert workspace.search_compact(expanded, bits=25) == result
            finished = client.finish(result, count, dimension)
            expected = tuple(sum(a != b for a, b in zip(row, query, strict=True)) for row in rows)
            assert finished.distances == expected
            assert finished.top == tuple(
                sorted(enumerate(expected), key=lambda p: (p[1], p[0]))[:3]
            )
            unsafe = codec.expand(
                codec.compress(client.encrypt(plain), pk, dropped_bits=119), pk, dropped_bits=119
            )
            with pytest.raises(ValueError, match="bound"):
                workspace.search_compact(unsafe, bits=25)
            assert workspace.search_compact(expanded, bits=25) == result
