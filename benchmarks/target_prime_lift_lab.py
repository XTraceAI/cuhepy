"""E107 exact terminal lifting and equally optimized known-control counts."""
# Standalone benchmark bootstrap must precede repository imports.
# ruff: noqa: E402
from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import gmpy2

from benchmarks.native_boundary_lab import boundary_inputs, nested_tuples
from experiments.bfv_search_lab import native_boundary_oracle as boundary
from experiments.bfv_search_lab import target_prime_lift as lift


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def exhaust():
    cards = []
    for values in lift.TINY_CONTEXTS:
        ctx = lift.Context(*values).validate()
        richer, reduced, rich_accepted, reduced_accepted = 0, 0, set(), set()
        for c in range(ctx.q):
            expected = lift.derive(ctx, c)
            assert expected.lift(ctx) == lift.nearest_lift(ctx, c)
            for y in range(ctx.p):
                for r in range(-(ctx.q//2), ctx.q//2+1):
                    accepted = lift.reduced_predicate(ctx, c, y, r)
                    assert accepted == (y == expected.y and r == expected.r)
                    reduced += 1
                    if accepted:
                        reduced_accepted.add((c, y, r))
                    for k in (-1, 0, 1):
                        rich = lift.rich_predicate(ctx, c, y, k, r)
                        integer = lift.integer_predicate(ctx, c, y, k, r)
                        assert rich == integer == (y == expected.y and k == expected.k and r == expected.r)
                        richer += 1
                        if rich:
                            rich_accepted.add((c, y, k, r))
        assert len(rich_accepted) == len(reduced_accepted) == ctx.q
        assert {(c, y, r) for c, y, _, r in rich_accepted} == reduced_accepted
        cards.append({'parameters': values, 'context_digest': ctx.digest(), 'rich_tuples': richer,
                      'reduced_tuples': reduced, 'accepted_rich': len(rich_accepted),
                      'accepted_reduced': len(reduced_accepted), 'unique_nearest_for_every_source': True})
    assert sum(c['rich_tuples'] for c in cards) == 180978
    assert sum(c['reduced_tuples'] for c in cards) == 60326
    assert sum(c['accepted_rich'] for c in cards) == 146
    return cards


def omission_controls():
    ctx = lift.Context(3, 7, 11, 5)
    reduced = [('target', (0, 1, 0)), ('limb0', (0, 9, 7)), ('limb1', (0, 7, 3)),
               ('remainder_range', (0, 5, 21)), ('source_range', (21, 0, 0)),
               ('output_range', (0, 11, 0))]
    cards = []
    for gate, entries in reduced:
        assert not lift.reduced_predicate(ctx, *entries)
        assert lift.reduced_predicate(ctx, *entries, omit=(gate,))
        c, y, _ = entries
        wrong = 0 <= c < ctx.q and y % ctx.p != lift.derive(ctx, c).y
        cards.append({'relation': 'reduced', 'omitted_gate': gate, 'entries_c_y_r': entries,
                      'strict_rejection': True, 'omitted_gate_accepts': True,
                      'wrong_canonical_source_output': wrong,
                      'noncanonical_alias_not_itself_wrong_plaintext': gate in ('source_range', 'output_range')})
    for gate, entries in [('modt', (0, 0, -1, 0)), ('wrap_range', (0, 0, 5, 0)),
                          ('remainder_range', (0, 0, 0, 231))]:
        assert not lift.rich_predicate(ctx, *entries)
        assert lift.rich_predicate(ctx, *entries, omit=(gate,))
        c, y, k, r = entries
        cards.append({'relation': 'rich', 'omitted_gate': gate, 'entries_c_y_k_r': entries,
                      'strict_rejection': True, 'omitted_gate_accepts': True,
                      'integer_difference': ctx.q*(y+ctx.p*k)-ctx.p*c-ctx.t*r,
                      'honest_output_false_committed_witness_not_attack_on_reduced': y == lift.derive(ctx, c).y})
    replacement = lift.derive(ctx, 1)
    assert lift.reduced_predicate(ctx, replacement.c, replacement.y, replacement.r)
    assert replacement.y != lift.derive(ctx, 0).y
    return {'cards': cards, 'changed_original_source_requires_external_pin': True,
            'replacement_valid_for_different_source': {'c': replacement.c, 'y': replacement.y, 'r': replacement.r},
            'neither_predicate_authenticates_context_or_source_provenance': True}


def native_scalars(fixture_path, e106_path):
    frozen, old = json.loads(fixture_path.read_text()), json.loads(e106_path.read_text())
    assert old['frozen_fixture']['sha256'] == sha(fixture_path)
    for name, digest in old['metadata']['source_sha256'].items():
        assert sha(REPO/name) == digest
    for name, digest in old['metadata']['binary_sha256'].items():
        assert sha(REPO/name) == digest
    original = boundary.Context(**{name: nested_tuples(value) for name, value in frozen['context'].items()})
    original.admit_native_fixture()
    ctx = lift.Context(*original.primes, original.p, original.t).admit_native_scalar()
    coordinates = []
    for item in frozen['queries']:
        transcript = boundary.replay(original, bytes.fromhex(item['packet_hex']))
        for cut in transcript.rounding:
            w = lift.derive(ctx, cut.source)
            assert w.y == cut.output and w.lift(ctx) == cut.lift
            assert lift.rich_predicate(ctx, w.c, w.y, w.k, w.r)
            assert lift.reduced_predicate(ctx, w.c, w.y, w.r)
            coordinates.append({'query': item['bits'], 'position': cut.position,
                                'source': w.c, 'output': w.y, 'centered_remainder': w.r, 'derived_wrap': w.k})
    thresholds = boundary_inputs(ctx.q, ctx.p, ctx.t)
    for c in thresholds:
        w = lift.derive(ctx, c)
        assert w.lift(ctx) == boundary.round_lift(c, ctx.q, ctx.p, ctx.t)
        assert lift.reduced_predicate(ctx, w.c, w.y, w.r)
    assert len(coordinates) == 256 and len(thresholds) == 143
    card = lift.cost_card(ctx)
    auxiliary = int(gmpy2.next_prime((4*ctx.p+ctx.t)//2))
    assert 2*auxiliary > 4*ctx.p+ctx.t
    return {'terminal_coordinates': coordinates, 'public_threshold_coefficients': len(thresholds),
            'immutable_E106_native_agreement_reused_not_new_private_execution': True,
            'never_decrypted_malformed_scalar_diagnostics': True,
            'scalar_representation_counts': card,
            'matched_generic_reduced_counts': dict(card),
            'optional_fresh_auxiliary': {'modulus': auxiliary, 'bits': auxiliary.bit_length(),
                                        'existing_P_bits': ctx.p.bit_length(),
                                        'not_required_by_strongest_reduced_control': True,
                                        'commitment_setup_and_matched_soundness_cost_unknown': True},
            'all_source_switch_and_complete_input_binding_costs_unchanged': True,
            'matched_candidate_generic_count_difference': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--native-evidence', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    sources = ['experiments/bfv_search_lab/target_prime_lift.py',
               'experiments/bfv_search_lab/test_target_prime_lift.py', 'benchmarks/target_prime_lift_lab.py',
               'docs/research/target-prime-lift-preregistration.md', 'docs/research/target-prime-lift-control-amendment.md']
    record = {'kind': 'E107_exact_terminal_lift_known_control_not_proof_or_timing',
              'metadata': {'utc': datetime.now(UTC).isoformat(), 'command': sys.argv,
                           'git_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip(),
                           'source_sha256': {name: sha(REPO/name) for name in sources}},
              'input_sha256': {'frozen_fixture': sha(args.fixture), 'immutable_E106_raw': sha(args.native_evidence)}}
    record['exhaustive_contexts'] = exhaust()
    record['omissions'] = omission_controls()
    record['native_scalar_control'] = native_scalars(args.fixture, args.native_evidence)
    record['summary'] = {'rich_tuples': 180978, 'reduced_tuples': 60326, 'accepted_per_representation': 146,
                         'native_terminal_coordinates': 256, 'public_threshold_coefficients': 143,
                         'original_main_mechanisms': 0, 'timing_panels': 0, 'approved_parameters': 0,
                         'literal_candidate_contained_by_shared_generic_control': True,
                         'proof_system_or_complete_remote_protocol_implemented': False}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.output.exists():
        raise ValueError('Preserve immutable existing raw; choose a new output path')
    args.output.write_text(json.dumps(record, indent=2)+'\n')
    print(json.dumps(record['summary']))


if __name__ == '__main__':
    main()
