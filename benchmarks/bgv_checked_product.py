#!/usr/bin/env python3
"""Bound product/relinearization only: native recomputation, checks and CUDA.

Pinned ordered index/query; no assumed trusted tensor, HE secret in verifier,
expected-output acceptance gate, receipt, enclave or complete search claim.
All modes produce the same uncompressed product/switch output. Report setup,
real adapters, internal bytes and separately labeled ideal link projections.
"""

import argparse
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import platform
import random
import statistics
import subprocess
import sys
import time

from bfv_client_matrix import REPO_ROOT
from bgv_service_pipeline import provenance, timed

sys.path.insert(0, str(REPO_ROOT))
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab.checked_switch_bgv import Context
from experiments.bfv_search_lab.checked_product_bgv import ProductContext, TAG
from experiments.bfv_search_lab.native_check_bgv import NativeCheckArithmetic, NativeProductArithmetic
from experiments.bfv_search_lab.native_bgv import NativeServer


def check(state, native, query, witness, output, mode):
    begin_s, request = timed(state.begin, query, b'q'*32, mode=mode, native=native)
    frame_s, packet = timed(request.result_packet, output, witness if mode == 'witness' else b'')
    check_s, result = timed(request.check_once, packet)
    if not result.accepted:
        raise AssertionError('Honest product/switch rejected')
    return dict(begin_s=begin_s, fixture_frame_s=frame_s, check_s=check_s,
                verifier_s=begin_s+check_s, framed_verifier_s=begin_s+frame_s+check_s,
                **result.phase_seconds), len(packet)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ring-degree', type=int, choices=(64, 2048, 16384), default=16384)
    parser.add_argument('--batches', type=int, nargs='+', default=[1, 8, 32, 64])
    parser.add_argument('--repeats', type=int, default=10)
    parser.add_argument('--cuda', action='store_true')
    parser.add_argument('--rns-cuda', action='store_true', help='Also time the direct RNS/batched GPU stage')
    parser.add_argument('--json-out', type=Path, required=True)
    args = parser.parse_args()
    if (not 1 <= args.repeats <= 30 or any(not 1 <= b <= 64 for b in args.batches)
        or len(set(args.batches)) != len(args.batches) or (args.rns_cuda and not args.cuda)):
        parser.error('Invalid bounded workload')
    setup, n = {}, args.ring_degree
    setup['keygen_s'], (pk, sk) = timed(bgv.key_gen, n, q_bits=120, rns_modulus=True)
    setup['evaluation_key_s'], keys = timed(trace.evaluation_keys, pk, sk, 1)
    setup['context_s'], ctx = timed(Context.from_bgv, pk, keys)
    setup['native_context_s'], arithmetic = timed(NativeCheckArithmetic, ctx)
    setup['existing_cpu_prepare_s'], cpu = timed(NativeServer, pk, keys, residue=True)
    gpu = None
    if args.cuda:
        setup['existing_cuda_prepare_s'], gpu = timed(NativeServer, pk, keys, residue=True, device='cuda',
                                                    cuda_level=4, ntt_variant='indexed')
    del sk
    data_rng, order_rng = random.Random(20260930), random.Random(20261001)
    start = time.perf_counter()
    tiles = [bgv.encrypt([data_rng.randrange(2) for _ in range(n)], pk) for _ in range(max(args.batches))]
    setup['encrypt_max_index_s'] = time.perf_counter()-start
    cases, samples, warmup = {}, {}, {}
    for batch in args.batches:
        preparation = {}
        preparation['index_rns_adapter_s'], raw_index = timed(ctx.pack_full, [c.components for c in tiles[:batch]], 2)
        preparation['index_bind_s'], state = timed(ProductContext.prepare, ctx, raw_index, batch, b'i'*32)
        preparation['native_index_s'], native = timed(NativeProductArithmetic, state, arithmetic)
        preparation['existing_cpu_index_s'], cpu_index = timed(cpu.prepare_index, tiles[:batch], batch*n)
        gpu_index = None
        if gpu:
            preparation['existing_gpu_index_s'], gpu_index = timed(gpu.prepare_index, tiles[:batch], batch*n)
        entries = []
        for repeat in range(args.repeats+1):
            encryption_s, query = timed(bgv.encrypt, [data_rng.randrange(2) for _ in range(n)], pk)
            query_adapter_s, raw_query = timed(ctx.pack_full, [query.components], 2)
            fixture_s, (witness, output) = timed(native.evaluate, raw_query, witness=True)
            operations = ['recompute', 'existing_cpu', 'witness', 'local']+(['cuda_local'] if gpu else [])
            if args.rns_cuda:
                operations.append('cuda_rns_local')
            order_rng.shuffle(operations)
            row = dict(excluded_query_encryption_s=encryption_s, excluded_query_rns_adapter_s=query_adapter_s,
                       excluded_fixture_server_s=fixture_s)
            for op in operations:
                if op == 'recompute':
                    row['native_recompute_s'], direct = timed(native.evaluate, raw_query)
                    if direct != (b'', output):
                        raise AssertionError('Native recomputation differs')
                elif op == 'existing_cpu':
                    row['existing_cpu_search_s'], direct = timed(cpu.search, query, cpu_index)
                    if ctx.pack_full([c.components for c in direct], 2) != output:
                        raise AssertionError('Independent existing CPU output differs')
                elif op in ('cuda_local', 'cuda_rns_local'):
                    begin_s, request = timed(state.begin, raw_query, b'q'*32, mode='local', native=native)
                    if op == 'cuda_local':
                        server_s, actual = timed(gpu.search, query, gpu_index)
                        adapter_s, actual_raw = timed(ctx.pack_full, [c.components for c in actual], 2)
                    else:
                        server_s, actual_raw = timed(gpu.product_switch_rns, raw_query, gpu_index)
                        adapter_s = 0.0
                    frame_s, packet = timed(request.result_packet, actual_raw)
                    check_s, accepted = timed(request.check_once, packet)
                    # The checker already decided, using ONLY pinned inputs and
                    # randomized relations. Equality is an external test oracle.
                    if not accepted.accepted or actual_raw != output:
                        raise AssertionError('CUDA product/switch mismatch')
                    prefix = 'cuda_' if op == 'cuda_local' else 'cuda_rns_'
                    row.update({prefix+k: v for k, v in dict(begin_s=begin_s, existing_search_s=server_s,
                               python_rns_adapter_s=adapter_s, frame_s=frame_s, check_s=check_s,
                               checked_local_stage_s=begin_s+server_s+adapter_s+frame_s+check_s).items()})
                else:
                    values, _ = check(state, native, raw_query, witness, output, op)
                    row.update({op+'_'+k: value for k, value in values.items()})
            # A real immutable copy cost, outside all verifier timings. This is
            # ordinary host memory, not a Nitro/vsock/DMA transfer measurement.
            row['host_output_snapshot_s'], copied = timed(memoryview(output).tobytes)
            if copied != output:
                raise AssertionError('Output snapshot changed')
            (entries if repeat else warmup.setdefault(str(batch), [])).append(row)
            if not repeat:
                for mode in ('witness', 'local'):
                    request = state.begin(raw_query, b'q'*32, mode=mode, native=native)
                    bad = bytes([output[0] ^ 1])+output[1:]
                    if request.check_once(request.result_packet(bad, witness if mode == 'witness' else b'')).accepted:
                        raise AssertionError('Corrupted output accepted')
            print('Product/switch batch', batch, 'round', repeat, flush=True)
        samples[str(batch)] = entries
        medians = {k: statistics.median(row[k] for row in entries) for k in entries[0]}
        header = len(TAG)+32
        projections = {}
        for mode, size in (('witness', len(witness)+len(output)+header), ('local', len(output)+header)):
            # This is remaining budget for accelerator work/framing, not a
            # prediction of GPU speed or a measured verified service latency.
            projections[mode] = {str(mbps): dict(
                ideal_transfer_ms=1000*8*(len(raw_query)+size+8)/(mbps*1e6),
                remaining_accelerator_budget_ms=1000*(medians['native_recompute_s']-medians[mode+'_verifier_s'])
                    -1000*8*(len(raw_query)+size+8)/(mbps*1e6)) for mbps in (1000, 10000, 25000, 100000)}
        cases[str(batch)] = dict(setup=preparation, query_rns_bytes=len(raw_query), resident_index_rns_bytes=len(raw_index),
            resident_native_index_coefficient_bytes=len(raw_index), c2_witness_bytes=len(witness), output_bytes=len(output),
            witness_packet_bytes=len(witness)+len(output)+header, local_packet_bytes=len(output)+header,
            full_tensor_plus_output_coefficient_bytes=batch*10*n*8,
            analytical_link_projections=projections, medians=medians)
    hashes = provenance()
    for path in sorted((REPO_ROOT/'experiments/bfv_search_lab/_verify').glob('*')):
        if path.is_file() and (path.suffix in ('.py', '.h', '.cpp', '.so') or path.name == 'Makefile'):
            hashes[str(path.relative_to(REPO_ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    hashes[str(Path(__file__).resolve().relative_to(REPO_ROOT))] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    result = dict(kind='bgv_checked_product', scope=__doc__, command=sys.argv,
        git_head=subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
        utc=datetime.now(UTC).isoformat(), n=n, t=pk.t, q_hex=format(pk.q, 'x'), primes=ctx.primes,
        repeats=args.repeats, cuda=args.cuda, rns_cuda=args.rns_cuda, setup=setup, cases=cases, samples=samples, warmup=warmup,
        all_complete_cpu_ciphertexts_equal=True, all_complete_cuda_ciphertexts_equal=True if gpu else None,
        all_honest_checks_accepted=True, all_mutation_checks_rejected=True,
        public_plaintext_fixture_seed=20260930, measurement_order_seed=20261001,
        python=sys.version, platform=platform.platform(), source_and_binary_sha256=hashes)
    if gpu:
        result['gpu'] = subprocess.check_output(['nvidia-smi', '--query-gpu=name,driver_version,memory.total',
                                                 '--format=csv,noheader'], text=True).strip()
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2)+'\n')
    print(args.json_out)


if __name__ == '__main__':
    main()
