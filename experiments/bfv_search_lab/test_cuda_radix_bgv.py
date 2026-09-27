"""Radix plaintext moduli, wider terminals and full CPU/CUDA ciphertext agreement."""

from contextlib import closing
import os
import random

import pytest

from cuhepy.bfv.cuda import cuda_available
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import owner_bgv as owner, compact_bgv as compact
from experiments.bfv_search_lab import compressed_query_bgv as query_codec
from experiments.bfv_search_lab import compressed_response_bgv as response_codec
from experiments.bfv_search_lab import joint_precision_bgv as planner
from experiments.bfv_search_lab.radix_bgv import Layout, plans
from experiments.bfv_search_lab.radix_client_bgv import RadixClient
from experiments.bfv_search_lab.support_bounds_bgv import SupportBoundServer


@pytest.mark.parametrize("n,d,group,mode", [(64, 13, 3, "balanced"), (2048, 13, 3, "distance"),
    (16384, 512, 2, "balanced"), (16384, 512, 2, "distance"), (16384, 512, 3, "distance")])
@pytest.mark.parametrize("owner_index", [False, True])
def test_full_cpu_gpu_radix_and_wide_terminal_agreement(n, d, group, mode, owner_index):
    pytest.importorskip("experiments.bfv_search_lab._native._bgv_trace_cuda")
    if not cuda_available():
        if os.environ.get("CUHEPY_REQUIRE_BGV_CUDA") == "1":
            pytest.fail("CUDA was required but is unavailable")
        pytest.skip("CUDA required")
    layout = Layout(d, group, mode)
    pk, sk = bgv.key_gen(n, t=layout.plaintext_modulus(), q_bits=120, rns_modulus=True)
    keys = trace.evaluation_keys(pk, sk, layout.padded)
    count = group*(n+1)-1 if n == 64 else group*(n//layout.padded+1)-1
    rng = random.Random(916+n)
    query = [rng.randrange(2) for _ in range(d)]
    rows = [query[:], [1-b for b in query], query[:]]
    rows += [[rng.randrange(2) for _ in query] for _ in range(count-3)]
    qp, tiles = layout.inputs(query, rows, n)
    with closing(RadixClient(pk, sk, native=True, rns=True)) as client:
        encrypted = [owner.expand(client.encrypt(p), pk) if owner_index else bgv.encrypt(p, pk) for p in tiles]
        cpu = SupportBoundServer(pk, keys, residue=True)
        gpu = SupportBoundServer(pk, keys, residue=True, device="cuda", cuda_level=4, ntt_variant="indexed")
        host, resident = (s.prepare_index(encrypted, layout.groups(count)) for s in (cpu, gpu))
        plan = planner.select(plans(cpu, host, layout, count), 1, 1)
        packet = client.encrypt(qp)
        if plan.query_drop is not None:
            packet = query_codec.compress(packet, pk, dropped_bits=plan.query_drop, backend="native")
        ct = owner.expand(packet, pk) if plan.query_drop is None else query_codec.expand(
            packet, pk, dropped_bits=plan.query_drop, backend="native")
        reference = cpu.search_compact(ct, host, bits=plan.terminal_bits)
        expected_packet = compact.pack(reference, layout.groups(count), d, pk)
        with gpu.prepare_workspace(resident) as workspace:
            actual, bounds = workspace.search_packet(ct, d, bits=plan.terminal_bits, gpu_terminal=True)
            assert actual == expected_packet and bounds == list(plan.terminal_bounds)
        if plan.response_drop is not None:
            options = dict(count=layout.groups(count), dimension=d, bits=plan.terminal_bits,
                           bounds=bounds, dropped_bits=plan.response_drop)
            actual = response_codec.compress(actual, pk, backend="native", **options)
            expected_packet = response_codec.compress(expected_packet, pk, **options)
            assert actual == expected_packet
        result = client.finish_radix_fixture(layout.wrap(actual, count, "response"),
            layout.wrap(expected_packet, count, "response"), count, layout, plan)
        assert client.finish_radix_fixture(layout.wrap(actual, count, "response"),
            layout.wrap(expected_packet, count, "response"), count, layout, plan, packed=True) == result
        assert client.finish_radix_fixture(layout.wrap(actual, count, "response"),
            layout.wrap(expected_packet, count, "response"), count, layout, plan,
            packed=True, vectorized=True) == result
        expected = tuple(sum(a != b for a, b in zip(query, row, strict=True)) for row in rows)
        assert result.distances == expected
        assert result.top == tuple(sorted(enumerate(expected), key=lambda x: (x[1], x[0]))[:3])
