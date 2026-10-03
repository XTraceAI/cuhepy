"""E106 actual native boundary differential oracle and deterministic counts.

No elapsed-time measurements. Disclosed generated keys are tiny toy fixtures.
"""
# Standalone benchmark bootstrap must precede repository imports.
# ruff: noqa: E402

from __future__ import annotations

import argparse
from dataclasses import asdict, replace
from datetime import UTC, datetime
import hashlib
from itertools import product
import json
from pathlib import Path
import platform
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from gmpy2 import mpz

from cuhepy.bfv.scheme import _rns_coefficient_primes
from experiments.bfv_search_lab import native_boundary_oracle as oracle
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import compact_bgv as compact, compressed_query_bgv as codec
from experiments.bfv_search_lab import butterfly_bgv as butterfly, transport_bgv as wire
from experiments.bfv_search_lab import results_bgv as results
from experiments.bfv_search_lab.native_bgv import NativeServer
from experiments.bfv_search_lab.owner_bgv import OwnerClient
from experiments.bfv_search_lab.private_bgv import PrivateDecoder

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def ints(value):
    if isinstance(value, (tuple, list)):
        return tuple(ints(x) for x in value)
    return int(value)


def make_fixture(path):
    """Sample exactly once, freeze before any main boundary-oracle evaluation."""
    if path.exists():
        raise ValueError("Never overwrite a frozen fixture")
    pk, sk = bgv.key_gen(8, t=17, eta=1, q_bits=120, rns_modulus=True)
    keys = trace.evaluation_keys(pk, sk, 4, digit_bits=30)
    rows = tuple(product((0, 1), repeat=3))+((0, 0, 0),)
    _, messages = bgv.coefficient_inputs([0, 0, 0], [list(row) for row in rows], 8)
    index = [bgv.encrypt(message, pk) for message in messages]
    p = compact.terminal_modulus(pk.q, pk.t, 32)
    context = oracle.Context(8, 17, int(pk.q), tuple(_rns_coefficient_primes(8, 120)),
                             4, 3, 30, 58, int(p), pk.key_id, "E106-owner-approved-toy-epoch1",
                             tuple(range(9)), tuple(ints(c.components) for c in index),
                             ints(keys.relin), tuple((g, ints(key)) for g, key in keys.rotations))
    context.validate()
    queries = []
    owner = OwnerClient(pk, sk, native=True, rns=True)
    try:
        for bits in product((0, 1), repeat=3):
            message, _ = bgv.coefficient_inputs(list(bits), [list(row) for row in rows], 8)
            seeded = owner.encrypt(message)
            packet = codec.compress(seeded, pk, dropped_bits=58, backend="native")
            queries.append({"bits": bits, "packet_hex": packet.hex()})
    finally:
        owner.close()
    fixture = {"utc_before_main_oracle": datetime.now(UTC).isoformat(),
               "kind": "disclosed_generated_N8_toy_keys_not_production_or_parameter_approval",
               "preregistration_sha256": sha(REPO / 'docs/research/native-boundary-preregistration.md'),
               "context": asdict(context), "pk_a": ints(pk.a), "pk_b": ints(pk.b),
               "secret": ints(sk.s), "eta": pk.eta, "index_bounds": [c.phase_bound for c in index],
               "switch_error_bound": keys.switch_error_bound, "rows": rows, "queries": queries,
               "sample_order": "keygen; fullrelin thenrotationkeys; publicindexencryptions; eightownerfreshseed/error draws andnativecoefficientcompression; freeze; mainoracle",
               "OS_entropy_and_honest_setup_security_assurance": False}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(fixture, indent=2)+'\n')
    return fixture


def nested_tuples(value):
    return tuple(nested_tuples(x) for x in value) if type(value) is list else value


def load_fixture(path):
    fixture = json.loads(path.read_text())
    ctx = oracle.Context(**{key: nested_tuples(value) for key, value in fixture['context'].items()})
    ctx.validate()
    ctx.admit_native_fixture()
    pk = bgv.PublicKey(ctx.n, ctx.t, mpz(ctx.q), fixture['eta'],
                       tuple(map(mpz, fixture['pk_a'])), tuple(map(mpz, fixture['pk_b'])), ctx.key_id)
    sk = bgv.SecretKey(tuple(map(mpz, fixture['secret'])), ctx.key_id)
    def key(columns):
        return tuple(tuple(tuple(map(mpz, poly)) for poly in pair) for pair in columns)
    keys = trace.EvaluationKeys(ctx.key_id, ctx.padded, ctx.digit_bits, key(ctx.relin),
                                tuple((g, key(columns)) for g, columns in ctx.rotations), fixture['switch_error_bound'])
    index = [bgv.Ciphertext(tuple(tuple(map(mpz, poly)) for poly in cipher), ctx.key_id, bound)
             for cipher, bound in zip(ctx.index, fixture['index_bounds'], strict=True)]
    return fixture, ctx, pk, sk, keys, index


def freeze_rows(fixture_path, path):
    """Freeze disclosed toy checker rows before the main differential run."""
    from experiments.bfv_search_lab import native_boundary_controls as controls

    if path.exists():
        raise ValueError("Never overwrite frozen checker rows")
    _, ctx, *_ = load_fixture(fixture_path)
    compiled = controls.compile_residual(ctx)
    rows = controls.compile_private_rows(compiled, k=4)
    record = {'utc_before_main_oracle': datetime.now(UTC).isoformat(),
              'kind': 'disclosed_toy_independent_uniform_per_prime_adjoint_rows_not_production_secrets',
              'fixture_sha256': sha(fixture_path), 'context_digest': compiled.context_digest,
              'controls_source_sha256': sha(REPO/'experiments/bfv_search_lab/native_boundary_controls.py'),
              'k_per_prime': 4, 'rows': [[asdict(row) for row in family] for family in rows],
              'frozen_before_main_fixture_evaluation': True,
              'sampler': 'secrets.randbelow per full residual coordinate independently; zero-RHS cut weights discarded after transpose',
              'ideal_uniform_lemma_not_OS_entropy_or_protocol_assurance': True}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2)+'\n')
    return record


def load_rows(path, fixture_path, compiled):
    from experiments.bfv_search_lab import native_boundary_controls as controls

    record = json.loads(path.read_text())
    if (record['fixture_sha256'] != sha(fixture_path) or record['context_digest'] != compiled.context_digest
            or record['controls_source_sha256'] != sha(REPO/'experiments/bfv_search_lab/native_boundary_controls.py')
            or record['k_per_prime'] != 4):
        raise ValueError("Wrong frozen toy row context/source")
    rows = tuple(tuple(controls.ProtectedRow(**{key: nested_tuples(value) for key, value in row.items()})
                       for row in family) for family in record['rows'])
    if len(rows) != 2 or any(len(family) != 4 for family in rows):
        raise ValueError("Wrong complete registered row family")
    controls.check_rows(compiled, rows, (0,)*(compiled.feature_count+compiled.output_count))
    return rows


def boundary_inputs(q, p, t):
    """Nearest reachable c=r+t*m around actual congruent rounding thresholds."""
    values = {0, 1, q-1, q//2, t-1, t, t+1}
    kappa = (p-q)//t
    for residue in range(t):
        for k in (0, 1, p//(2*t), p//t-1):
            lower = (q*(2*k+1)-2*kappa*residue)//(2*p)
            for m in (lower, lower+1):
                c = residue+t*m
                if 0 <= c < q:
                    values.add(c)
    return tuple(sorted(values))


def scalar_exhaustion():
    count = 0
    for q in range(13, 40, 2):
        for t in (3, 5, 7):
            for p in range(t+2, q, 2):
                if (p-q) % t or q % t == 0:
                    continue
                for c in range(q):
                    residue = c % t
                    choices = tuple(residue+t*k for k in range(-2, (p+t-1)//t+3))
                    best = min(choices, key=lambda x: (abs(q*x-p*c), -x))
                    assert oracle.round_lift(c, q, p, t) == best
                    assert 2*abs(q*best-p*c) < q*t
                    count += 1
    return count


def run(path, rows_path):
    from experiments.bfv_search_lab import native_boundary_controls as controls

    fixture, ctx, pk, sk, keys, index = load_fixture(path)
    server = NativeServer(pk, keys, residue=True)
    prepared = server.prepare_index(index, len(ctx.ids))
    generic = NativeServer(pk, keys, residue=False)
    generic_index = generic.prepare_index(index, len(ctx.ids))
    decoder = PrivateDecoder(pk, sk, bits=32)
    owner = OwnerClient(pk, sk, native=True, rns=True)
    cards = []
    compiled = controls.compile_residual(ctx)
    protected_rows = load_rows(rows_path, path, compiled)
    try:
        for item in fixture['queries']:
            packet = bytes.fromhex(item['packet_hex'])
            query = codec.expand(packet, pk, dropped_bits=58, backend="native")
            independent = oracle.replay(ctx, packet)
            assert oracle.expand_query(ctx, packet) == ints(query.components)
            actual = server.search(query, prepared, joint=True)
            assert independent.preterminal == tuple(ints(c.components) for c in actual)
            assert independent.preterminal == tuple(ints(c.components) for c in generic.search(query, generic_index))
            assert independent.preterminal == tuple(ints(c.components) for c in butterfly.search(query, index, 9, pk, keys))
            reduced = server.search_compact(query, prepared, joint=True, bits=32)
            native_packet = compact.pack(reduced, 9, 3, pk)
            assert independent.packet == native_packet
            compact_coefficients = oracle.parse_response(ctx, native_packet)
            phases, scores, top = oracle.decrypt_and_rank(ctx, compact_coefficients, tuple(fixture['secret']))
            expected_scores = tuple(sum(a != b for a, b in zip(item['bits'], row, strict=True)) for row in fixture['rows'])
            assert scores == expected_scores
            pairs = wire._unpack_fields(native_packet, pk, count=9, dimension=3, modulus=mpz(ctx.p),
                                        bounds=[c.phase_bound for c in reduced])
            plaintexts = oracle.checked_release(ctx, packet, independent, lambda _, pairs=pairs: decoder.decode_packed(pairs))
            assert tuple(tuple(c % ctx.t for c in phase) for phase in phases) == tuple(tuple(poly) for poly in plaintexts)
            selected = results.finish(plaintexts, 9, 3, pk, method="heap")
            assert selected.distances == scores and selected.top == top
            owned = owner.finish_packed_fixture(native_packet, independent.packet, 9, 3,
                                                bounds=[c.phase_bound for c in reduced], bits=32)
            assert owned == selected
            full_scores = trace.decode([bgv.decrypt(c, pk, sk) for c in actual], 9, 3, pk)
            per_tile = server.search(query, prepared, joint=False)
            assert trace.decode([bgv.decrypt(c, pk, sk) for c in per_tile], 9, 3, pk) == list(scores)
            assert full_scores == list(scores)
            fake, rank = oracle.false_digit_cut(ctx, independent.cuts[0], ctx.relin)
            altered = replace(independent, cuts=(fake,)+independent.cuts[1:])
            assert oracle.replay(ctx, packet, altered, canonical=False).packet == independent.packet
            try:
                oracle.replay(ctx, packet, altered)
            except ValueError:
                pass
            else:
                raise AssertionError("Falsecanonical trace accepted")
            flat = controls.features(ctx, query.components, independent.cuts, independent.preterminal)
            assert not any(controls.residuals(compiled, flat))
            assert controls.check_rows(compiled, protected_rows, flat)
            false_flat = controls.features(ctx, query.components, altered.cuts, altered.preterminal)
            assert not any(controls.residuals(compiled, false_flat))
            assert controls.check_rows(compiled, protected_rows, false_flat)
            cards.append({'query': item['bits'], 'original_packet_sha256': hashlib.sha256(packet).hexdigest(),
                          'query_packet_bytes': len(packet), 'response_packet_bytes': len(native_packet),
                          'response_sha256': hashlib.sha256(native_packet).hexdigest(), 'switch_cuts': len(independent.cuts),
                          'terminal_coordinates': len(independent.rounding), 'exact_distances': scores, 'stable_top3': top,
                          'all_preterminal_coefficients': 2*len(actual)*ctx.n,
                          'all_terminal_coefficients': 2*len(actual)*ctx.n,
                          'honest_output_false_digit_kernel_rank': rank, 'false_affine_trace_rejected_canonically': True,
                          'honest_and_false_canonical_traces_both_pass_all_frozen_affine_rows': True,
                          'first_per_tile_preterminal_equal': ints(per_tile[0].components) == independent.preterminal[0],
                          'per_tile_alternate_graph_scores_equal': True,
                          'complete_trace_sha256': hashlib.sha256(repr(independent).encode()).hexdigest()})
        threshold = boundary_inputs(ctx.q, ctx.p, ctx.t)
        for start in range(0, len(threshold), 2*ctx.n):
            values = threshold[start:start+2*ctx.n]+(0,)*max(0, 2*ctx.n-len(threshold[start:start+2*ctx.n]))
            cipher = bgv.Ciphertext((tuple(map(mpz, values[:ctx.n])), tuple(map(mpz, values[ctx.n:]))), pk.key_id, 0)
            actual = server.compact_result(cipher, 32)
            assert ints(actual.components) == tuple(tuple(oracle.round_lift(c, ctx.q, ctx.p, ctx.t) % ctx.p for c in poly)
                                                    for poly in (values[:ctx.n], values[ctx.n:]))
            # Public arbitrary coefficient rounding only; never decrypt this diagnostic.
    finally:
        decoder.close()
        owner.close()
    return {'query_cards': cards, 'scalar_exhaustion_cases': scalar_exhaustion(),
            'actual_congruent_threshold_coefficients': len(threshold),
            'actual_threshold_diagnostics_never_decrypted': True,
            'compiled_residual_dimensions': {'features': compiled.feature_count, 'outputs': compiled.output_count,
                                             'residuals': len(compiled.matrix)},
            'per_prime_rank_inventory': controls.rank_inventory(compiled),
            'uniform_field_control': controls.uniform_residual_exhaustion(),
            'frozen_checker_rows': {'path': str(rows_path.resolve()), 'sha256': sha(rows_path),
                                    'disclosed_toy_only': True, 'k_per_prime': 4},
            'paid_costs': controls.paidcost_cards(ctx),
            'illustrative_Q120_count_model_not_approved_parameters': controls.cost_card(
                n=8192, padded=512, records=8192, q_bits=120, digit_bits=30, terminal_bits=32, k=4),
            'summary': {'queries': 8, 'exact_record_distances': 72, 'native_preterminal_coefficients': 256,
                        'native_terminal_coefficients': 256, 'honest_output_false_witnesses': 8,
                        'original_main_mechanisms': 0, 'timing_panels': 0, 'approved_parameters': 0,
                        'BFV_adapter_implemented': False, 'CUDA_terminal_adapter_implemented': False},
            'scope': 'Exact N8 supported toy fixed sampled fixture. Publicrecomputation/affineknowncontrols; no efficientremoteproof, attestation/replay/durable lifecycle/security/privatecompleteassurance or timing claim.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--freeze', action='store_true')
    parser.add_argument('--freeze-rows', action='store_true')
    parser.add_argument('--protected-rows', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.freeze:
        make_fixture(args.fixture)
        print(json.dumps({'frozen_fixture': str(args.fixture), 'sha256': sha(args.fixture)}))
        return
    if args.output is None and not args.freeze_rows:
        parser.error('--output is required for the exact/count run')
    if args.protected_rows is None:
        parser.error('--protected-rows is required for row freezing and exact/count run')
    if args.freeze_rows:
        freeze_rows(args.fixture, args.protected_rows)
        print(json.dumps({'frozen_checker_rows': str(args.protected_rows), 'sha256': sha(args.protected_rows)}))
        return
    sources = ['experiments/bfv_search_lab/native_boundary_oracle.py', 'experiments/bfv_search_lab/native_boundary_controls.py',
               'experiments/bfv_search_lab/test_native_boundary_oracle.py', 'experiments/bfv_search_lab/test_native_boundary_controls.py',
               'benchmarks/native_boundary_lab.py', 'docs/research/native-boundary-preregistration.md']
    sources += ['experiments/bfv_search_lab/'+name for name in ('native_bgv.py','butterfly_bgv.py','trace_bgv.py','shallow_bgv.py',
                'compact_bgv.py','compressed_query_bgv.py','owner_bgv.py','private_bgv.py','results_bgv.py','transport_bgv.py',
                'seeded_bgv.py','attested_bgv.py','security_bgv.py','_native/residue_trace.h','_native/trace_server.h','_native/compact.h',
                '_native/query_codec.h','_native/word_codec.h','_native/bindings.cpp','_owner/bgv_private.h','_owner/finish.h')]
    sources += ['src/cuhepy/bfv/scheme.py','src/cuhepy/bfv/_cpu_ext/rns_ntt.h','src/cuhepy/bfv/_cpu_ext/bfv_residue.h']
    binaries = ['experiments/bfv_search_lab/_native/_bgv_trace.cpython-312-x86_64-linux-gnu.so',
                'experiments/bfv_search_lab/_owner/_bgv_owner.cpython-312-x86_64-linux-gnu.so',
                'experiments/bfv_search_lab/_owner/_bgv_private.cpython-312-x86_64-linux-gnu.so']
    record = {'kind': 'E106_exact_native_boundary_and_complete_known_controls_not_timing_or_security_approval',
              'metadata': {'utc': datetime.now(UTC).isoformat(), 'command': sys.argv,
                           'git_head': subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip(),
                           'python': platform.python_version(), 'platform': platform.platform(),
                           'source_sha256': {name: sha(REPO/name) for name in sources},
                           'binary_sha256': {name: sha(REPO/name) for name in binaries},
                           'binary_source_correspondence_rebuilt': False},
              'frozen_fixture': {'path': str(args.fixture.resolve()), 'sha256': sha(args.fixture)}}
    record.update(run(args.fixture, args.protected_rows))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2)+'\n')
    print(json.dumps(record['summary']))


if __name__ == '__main__':
    main()
