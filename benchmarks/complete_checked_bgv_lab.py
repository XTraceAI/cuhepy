#!/usr/bin/env python3
"""One preregistered tiny public complete-admission cohort; no timing/private math."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from experiments.bfv_search_lab import complete_checked_bgv as complete  # noqa: E402
from experiments.bfv_search_lab import native_boundary_oracle as oracle  # noqa: E402

PUBLIC_SHA = 'ef2f41bf503da27fc7661732b9a692be38cf09f0f6dc83974fcf5e59c1e6c939'
OLD_RAW_SHA = '53d10253f239b80ddcf4e858df3e583f9b1441f54a04fd763d69729c14def9b8'
FIXTURE_SHA = '0a49605dd8d26d0e73e38c681013e83a64801df4c95b62fab80bf7b81beeb4a1'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def tuples(value):
    return tuple(tuples(v) for v in value) if type(value) is list else value


def json_exact(raw):
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError('Duplicate JSON key')
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=unique)


def producer(ctx, query):
    """Independent schoolbook public product/switch generator, not admission."""
    x, out = oracle.expand_query(ctx, query), []
    for tile in ctx.index:
        c0 = oracle.multiply(x[0], tile[0], ctx.q)
        c1 = oracle.add(oracle.multiply(x[0], tile[1], ctx.q),
                        oracle.multiply(x[1], tile[0], ctx.q), ctx.q)
        c2 = oracle.multiply(x[1], tile[1], ctx.q)
        correction = ((0,)*ctx.n, (0,)*ctx.n)
        for j, pair in enumerate(ctx.relin):
            digit = tuple((c >> (30*j)) & ((1 << 30)-1) for c in c2)
            correction = tuple(oracle.add(a, oracle.multiply(digit, b, ctx.q), ctx.q)
                               for a, b in zip(correction, pair, strict=True))
        out.append(tuple(oracle.add(a, b, ctx.q) for a, b in zip((c0, c1), correction, strict=True)))
    return tuple(out)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--public-inputs', type=Path, required=True)
    parser.add_argument('--archived-raw', type=Path, required=True)
    parser.add_argument('--json-out', type=Path, required=True)
    parser.add_argument('--ledger', type=Path, required=True)
    parser.add_argument('--attempt-marker', type=Path, required=True)
    args = parser.parse_args()
    if any(p.exists() for p in (args.json_out, args.ledger, args.attempt_marker)):
        raise ValueError('Never retry/overwrite this scientific cohort')
    # An attempt survives any subsequent failure or supervisor termination.
    with args.attempt_marker.open('x') as file:
        file.write(json.dumps({'kind': 'one-scientific-main-attempt', 'argv': sys.argv,
                               'max_main': 1, 'max_retry': 0})+'\n')
        file.flush()
        os.fsync(file.fileno())
    public_raw, old_raw = args.public_inputs.read_bytes(), args.archived_raw.read_bytes()
    if sha(public_raw) != PUBLIC_SHA or sha(old_raw) != OLD_RAW_SHA:
        raise ValueError('Wrong immutable public inputs/archived native evidence')
    data, old = json_exact(public_raw), json_exact(old_raw)
    if (set(data) != {'source_fixture_sha256', 'context', 'queries'}
            or data['source_fixture_sha256'] != FIXTURE_SHA
            or type(data['queries']) is not list or len(data['queries']) != 8
            or any(type(q) is not dict or set(q) != {'packet_hex'} for q in data['queries'])):
        raise ValueError('Wrong public-only frozen fixture projection')
    ctx = oracle.Context(**{k: tuples(v) for k, v in data['context'].items()})
    ctx.admit_native_fixture()
    if old['frozen_fixture']['sha256'] != FIXTURE_SHA or len(old['query_cards']) != 8:
        raise ValueError('Wrong archived original native cohort')
    enrollment = complete.Enrollment(ctx, max_requests=8)
    cards, sentinels = [], []
    with args.ledger.open('x') as ledger:
        for number, item in enumerate(data['queries']):
            query = bytes.fromhex(item['packet_hex'])
            expected_card = old['query_cards'][number]
            if sha(query) != expected_card['original_packet_sha256']:
                raise ValueError('Original query order differs from archived native cohort')
            request_id = number.to_bytes(32, 'little')
            request = enrollment.begin(query, request_id)
            values = producer(ctx, query)
            blocks = tuple(request.frame_block(i, enrollment.product_key.pack_full(values[b.start:b.end], 2))
                           for i, b in enumerate(request.blocks))
            result = request.admit_once(blocks, release_sentinel=sentinels.append)
            # External truth only; neither hash nor replay enters the controller.
            independent = oracle.replay(ctx, query)
            if (result.packet != independent.packet
                    or result.response_digest.hex() != expected_card['response_sha256']):
                raise ValueError('Complete canonical result differs from independent/native truth')
            card = {'query_number': number, 'query_sha256': sha(query),
                    'response_sha256': result.response_digest.hex(),
                    'query_packet_bytes': len(query), 'response_packet_bytes': len(result.packet),
                    'product_body_bytes': result.product_body_bytes,
                    'block_coverage': result.block_coverage, 'suffix_counts': result.suffix_counts,
                    'complete_public_oracle_equality': True, 'archived_native_hash_equality': True,
                    'release_sentinel_calls_after_query': len(sentinels),
                    'private_callbacks': 0, 'native_gpu_proofs_attestation_timing': 0}
            cards.append(card)
            ledger.write(json.dumps(card, sort_keys=True)+'\n')
            ledger.flush()
            os.fsync(ledger.fileno())
    record = {'kind': 'complete-checked-bgv-reference', 'status': 'complete',
              'base': '11e1690d4c4a90a718e5f2b8a98e79b4757a59bd',
              'public_inputs_sha256': PUBLIC_SHA, 'original_fixture_sha256': FIXTURE_SHA,
              'archived_native_raw_sha256': OLD_RAW_SHA, 'query_cards': cards,
              'summary': {'queries': 8, 'blocks_checked': 24, 'whole_polynomial_repetitions_per_limb': 3,
                          'complete_response_coefficients': 256, 'public_release_sentinel_calls': len(sentinels),
                          'private_callbacks': 0, 'native_gpu_proofs_attestation_timing': 0},
              'soundness_scope': 'Conditional ordinary J/min(p0,p1)^3 bound; no numerical deployment J, HE security or durable lifetime assurance.',
              'scope': 'Homemade tiny complete public reference admission known control. No actual GPU, native, proof, signing, attestation, private math, timing, new parameter or novelty acceptance.'}
    with args.json_out.open('x') as file:
        file.write(json.dumps(record, indent=2)+'\n')
        file.flush()
        os.fsync(file.fileno())
    print(json.dumps(record['summary'], sort_keys=True))


if __name__ == '__main__':
    main()
