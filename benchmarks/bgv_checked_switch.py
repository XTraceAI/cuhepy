#!/usr/bin/env python3
"""CPU/GMP reference stage checking, not verified GPU/search performance.

Inputs are already trusted canonical synthetic tensors. Fresh CSPRNG batch
weights, full output parsing, trusted CRT/digits and all checking are timed.
Full-Q reference recomputation is a separate arithmetic baseline, not the
optimized native CPU server. No preprocessing cost is hidden: there is none.
Transport, input establishment, attestation and private decryption are absent.
"""

import argparse
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import platform
import random
import statistics
import struct
import subprocess
import sys
import time

from bfv_client_matrix import REPO_ROOT
from bgv_service_pipeline import provenance, timed

sys.path.insert(0, str(REPO_ROOT))
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab.checked_switch_bgv import Context, CHECKS


def recompute(tensors, pk, keys):
    result = []
    for tensor in tensors:
        switched = trace._switch(tensor[2], keys.relin, pk, 30)
        result.append(tuple(tuple((a+b) % pk.q for a, b in zip(tensor[k], switched[k], strict=True)) for k in range(2)))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ring-degree', type=int, default=16384, choices=(64, 2048, 16384))
    parser.add_argument('--batches', type=int, nargs='+', default=[1, 8, 32])
    parser.add_argument('--repeats', type=int, default=10)
    parser.add_argument('--json-out', type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.repeats <= 30 or any(not 1 <= b <= 64 for b in args.batches) or len(set(args.batches)) != len(args.batches):
        parser.error('Invalid bounded reference workload')
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    hashes = provenance()
    hashes[str(Path(__file__).resolve().relative_to(REPO_ROOT))] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    setup = {}
    setup['keygen_s'], (pk, sk) = timed(bgv.key_gen, args.ring_degree, q_bits=120, rns_modulus=True)
    setup['evaluation_key_s'], keys = timed(trace.evaluation_keys, pk, sk, 1)
    setup['context_s'], context = timed(Context.from_bgv, pk, keys)
    del sk
    data_rng, order_rng = random.Random(20260928), random.Random(20260929)
    samples, warmup, cases = {}, {}, {}
    for batch in args.batches:
        entries = []
        for repeat in range(args.repeats+1):
            tensors = [tuple(tuple(data_rng.randrange(int(pk.q)) for _ in range(pk.n)) for _ in range(3)) for _ in range(batch)]
            input_pack_s, raw = timed(context.pack_full, tensors, 3)
            fixture_s, output = timed(recompute, tensors, pk, keys)
            request_s, request = timed(context.begin, raw, batch, b'b'*32)
            packet_s, packet = timed(request.result_packet, output)
            # Complete immutable proposed output precedes every private weight.
            order = ['reference', 'check']
            order_rng.shuffle(order)
            for operation in order:
                if operation == 'reference':
                    reference_s, expected = timed(recompute, tensors, pk, keys)
                    if expected != output:
                        raise AssertionError('Reference recomputation changed')
                else:
                    start = time.perf_counter()
                    checked = request.check_once(packet)
                    check_s = time.perf_counter()-start
            if not checked.accepted:
                raise AssertionError('Honest stage result rejected')
            row = dict(reference_full_q_arithmetic_s=reference_s,
                       excluded_fixture_server_s=fixture_s,
                       input_pack_s=input_pack_s, begin_parse_bind_s=request_s,
                       result_pack_s=packet_s, check_s=check_s, **checked.phase_seconds)
            row['verifier_with_begin_s'] = request_s+check_s
            (entries if repeat else warmup.setdefault(str(batch), [])).append(row)
            if not repeat:
                mutation = context.begin(raw, batch, b'b'*32)
                packet = mutation.result_packet(output)
                last = struct.unpack_from('<Q', packet, len(packet)-8)[0]
                packet = packet[:-8]+struct.pack('<Q', (last+1) % context.primes[1])
                if mutation.check_once(packet).accepted:
                    raise AssertionError('Corrupted stage result accepted')
            print('Checked batch', batch, 'round', repeat, flush=True)
        samples[str(batch)] = entries
        cases[str(batch)] = dict(trusted_input_bytes=len(raw), result_bytes=len(packet),
                                uniform_field_weights_per_attempt=2*CHECKS*batch,
                                whole_polynomial_checks_per_limb=CHECKS,
                                single_attempt_statistical_bound_bits_at_least=59*CHECKS,
                                soundness_bound='For fixed invalid output: <= min(p0,p1)^(-3), conditional on trusted inputs/key and hidden fresh weights.')
    report = dict(kind='bgv_checked_switch_reference', scope=__doc__, git_head=head, utc=datetime.now(UTC).isoformat(),
                  command=sys.argv, n=pk.n, q_hex=format(pk.q, 'x'), primes=context.primes, setup=setup,
                  public_fixture_seed=20260928, measurement_order_seed=20260929,
                  repeats=args.repeats, cases=cases, samples=samples, warmup=warmup,
                  all_honest_stages_accepted=True, all_mutation_checks_rejected=True,
                  python=sys.version, platform=platform.platform(), source_and_binary_sha256=hashes,
                  medians={k: {f: statistics.median(r[f] for r in rows) for f in rows[0]} for k, rows in samples.items()})
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2)+'\n')
    print(args.json_out)


if __name__ == '__main__':
    main()
