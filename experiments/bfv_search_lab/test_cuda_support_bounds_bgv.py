"""Independent CPU/CUDA agreement at the support policy's precision frontier."""

from contextlib import closing
import os
import random

import pytest

from cuhepy.bfv.cuda import cuda_available
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import compact_bgv as compact, owner_bgv as owner
from experiments.bfv_search_lab import compressed_query_bgv as query_codec
from experiments.bfv_search_lab import compressed_response_bgv as response_codec
from experiments.bfv_search_lab import joint_precision_bgv as planner
from experiments.bfv_search_lab.native_bgv import NativeServer
from experiments.bfv_search_lab.support_bounds_bgv import SupportBoundServer


@pytest.mark.parametrize("n,dimension,count", [(32, 1, 35), (64, 13, 131), (2048, 13, 257)])
@pytest.mark.parametrize("owner_index", [False, True])
def test_cpu_cuda_complete_packets_and_exact_frontier_results(n, dimension, count, owner_index):
    pytest.importorskip("experiments.bfv_search_lab._native._bgv_trace_cuda")
    if not cuda_available():
        if os.environ.get("CUHEPY_REQUIRE_BGV_CUDA") == "1":
            pytest.fail("CUDA was required but no device is available")
        pytest.skip("CUDA device required")
    pk, sk = bgv.key_gen(n, q_bits=120, rns_modulus=True)
    keys = trace.evaluation_keys(pk, sk, 1 << (dimension - 1).bit_length())
    rng = random.Random(915 + n)
    plain = [rng.randrange(2) for _ in range(dimension)]
    rows = [plain[:], plain[:], [1-b for b in plain]]
    rows += [[rng.randrange(2) for _ in plain] for _ in range(count - 3)]
    message, tiles = bgv.coefficient_inputs(plain, rows, n)
    expected = tuple(sum(a != b for a, b in zip(plain, row, strict=True)) for row in rows)
    with closing(owner.OwnerClient(pk, sk, native=True, rns=True)) as client:
        index = [owner.expand(client.encrypt(p), pk) if owner_index else bgv.encrypt(p, pk)
                 for p in tiles]
        old = NativeServer(pk, keys, residue=True)
        cpu = SupportBoundServer(pk, keys, residue=True)
        gpu = SupportBoundServer(pk, keys, residue=True, device="cuda", cuda_level=4,
                                 ntt_variant="indexed")
        old_index, host, resident = (s.prepare_index(index, count) for s in (old, cpu, gpu))
        old_plans = planner.enumerate_plans(old, old_index, dimension)
        plans = planner.enumerate_plans(cpu, host, dimension)
        # Every previously admissible byte representation remains available.
        def parameters(p):
            return p.query_drop, p.terminal_bits, p.response_drop

        assert set(map(parameters, old_plans)) <= set(map(parameters, plans))
        old_best, best = planner.select(old_plans, 1, 1), planner.select(plans, 1, 1)
        assert best.total_bytes <= old_best.total_bytes
        if dimension > 1:
            assert best.total_bytes < old_best.total_bytes
        fresh = client.encrypt(message)
        unrounded = owner.expand(fresh, pk)
        before, after = old.search(unrounded, old_index), cpu.search(unrounded, host)
        assert [c.components for c in before] == [c.components for c in after]
        with gpu.prepare_workspace(resident) as workspace:
            for plan in {planner.select(plans, up, down) for up, down in ((1, 1), (10, 100), (100, 10))}:
                packet = fresh if plan.query_drop is None else query_codec.compress(
                    fresh, pk, dropped_bits=plan.query_drop, backend="native")
                expanded = owner.expand(packet, pk) if plan.query_drop is None else query_codec.expand(
                    packet, pk, dropped_bits=plan.query_drop, backend="native")
                assert len(packet) == plan.query_bytes
                reference = cpu.search_compact(expanded, host, bits=plan.terminal_bits)
                known = compact.pack(reference, count, dimension, pk)
                actual, bounds = workspace.search_packet(
                    expanded, dimension, bits=plan.terminal_bits, gpu_terminal=True)
                assert actual == known
                assert bounds == list(plan.terminal_bounds)
                if plan.response_drop is not None:
                    options = dict(count=count, dimension=dimension, bits=plan.terminal_bits,
                                   bounds=bounds, dropped_bits=plan.response_drop)
                    known = response_codec.compress(known, pk, **options)
                    actual = response_codec.compress(actual, pk, backend="native", **options)
                    assert actual == known and len(actual) == plan.response_bytes
                    known, known_bounds = response_codec.expand(known, pk, **options)
                    actual, bounds = response_codec.expand(actual, pk, backend="native", **options)
                    assert actual == known and bounds == known_bounds
                else:
                    assert len(actual) == plan.response_bytes
                assert bounds == list(plan.final_bounds)
                result = client.finish_packed_fixture(actual, known, count, dimension,
                                                      bits=plan.terminal_bits, bounds=bounds)
                assert result.distances == expected
                assert result.top == tuple(sorted(enumerate(expected), key=lambda x: (x[1], x[0]))[:3])
