"""Tiny complete-path regressions; external schoolbook/native truth only."""

from concurrent.futures import ThreadPoolExecutor
import copy
from dataclasses import replace
import hashlib
import itertools
import json
from pathlib import Path
import pickle
import struct

import pytest

from experiments.bfv_search_lab import complete_checked_bgv as complete
from experiments.bfv_search_lab import checked_product_bgv as product
from experiments.bfv_search_lab import native_boundary_oracle as oracle

ROOT = Path(__file__).resolve().parents[2]
PUBLIC = ROOT.parent/'research-data/system-selection-20261003/gpu-admission-design/public-inputs.json'
PUBLIC_SHA = 'ef2f41bf503da27fc7661732b9a692be38cf09f0f6dc83974fcf5e59c1e6c939'


def tuples(x):
    return tuple(tuples(v) for v in x) if type(x) is list else x


@pytest.fixture(scope='module')
def public():
    raw = PUBLIC.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == PUBLIC_SHA
    data = json.loads(raw)
    assert set(data) == {'source_fixture_sha256', 'context', 'queries'}
    ctx = oracle.Context(**{k: tuples(v) for k, v in data['context'].items()})
    ctx.admit_native_fixture()
    return ctx, tuple(bytes.fromhex(q['packet_hex']) for q in data['queries'])


def outputs(ctx, query):
    """Independent schoolbook producer; no composed-checker primitives."""
    x = oracle.expand_query(ctx, query)
    result = []
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
        result.append(tuple(oracle.add(a, b, ctx.q) for a, b in zip((c0, c1), correction, strict=True)))
    return tuple(result)


def framed(enrollment, request, query, *, source_ctx=None):
    ctx = source_ctx or enrollment.context
    values = outputs(ctx, query)
    return tuple(request.frame_block(i, enrollment.product_key.pack_full(values[b.start:b.end], 2))
                 for i, b in enumerate(request.blocks))


def fresh(public, monkeypatch=None, *, ctx=None, query_number=0, request_id=b'r'*32):
    base, queries = public
    enrollment = complete.Enrollment(ctx or base)
    query = queries[query_number]
    request = enrollment.begin(query, request_id)
    if monkeypatch is not None:
        weights = itertools.count(1)
        monkeypatch.setattr(product.secrets, 'randbelow', lambda p: next(weights))
    return enrollment, request, framed(enrollment, request, query)


@pytest.mark.parametrize('query_number', range(8))
def test_complete_original_query_to_every_final_byte(public, query_number):
    ctx, queries = public
    enrollment = complete.Enrollment(ctx)
    request = enrollment.begin(queries[query_number], bytes([query_number])*32)
    calls = []
    result = request.admit_once(framed(enrollment, request, queries[query_number]), release_sentinel=calls.append)
    assert result.packet == oracle.replay(ctx, queries[query_number]).packet
    assert calls == [result.packet]
    assert result.block_coverage == ((0, 2), (2, 4), (4, 5))
    assert result.product_body_bytes == 1280
    assert result.suffix_counts == {'groups': 2, 'rotation_nodes': 5,
                                    'terminal_coordinates': 32, 'initial_shift': -3}
    assert len(result.packet) == 211


@pytest.mark.parametrize('tile,component,limb', itertools.product(range(5), range(2), range(2)))
def test_every_product_tile_component_and_limb(public, monkeypatch, tile, component, limb):
    enrollment, request, blocks = fresh(public, monkeypatch)
    block_number = tile//2
    block = blocks[block_number]
    local = tile-block.start
    at = len(product.TAG)+32+8*((local*4+component*2+limb)*8+7)
    value = struct.unpack_from('<Q', block.packet, at)[0]
    packet = block.packet[:at]+struct.pack('<Q', (value+1) % enrollment.context.primes[limb])+block.packet[at+8:]
    changed = tuple(replace(b, packet=packet) if i == block_number else b for i, b in enumerate(blocks))
    calls = []
    with pytest.raises(ValueError, match='arithmetic rejected'):
        request.admit_once(changed, release_sentinel=calls.append)
    assert calls == []
    with pytest.raises(RuntimeError, match='consumed'):
        request.admit_once(blocks, release_sentinel=calls.append)


@pytest.mark.parametrize('kind', ['omit_first', 'omit_last', 'duplicate', 'reorder', 'overlap', 'wrong_end', 'bool_start'])
def test_exact_global_block_coverage_before_any_weights(public, monkeypatch, kind):
    _, request, blocks = fresh(public)
    variants = {
        'omit_first': blocks[1:], 'omit_last': blocks[:-1],
        'duplicate': (blocks[0], blocks[0], blocks[2]),
        'reorder': tuple(reversed(blocks)),
        'overlap': (blocks[0], replace(blocks[1], start=1), blocks[2]),
        'wrong_end': (blocks[0], blocks[1], replace(blocks[2], end=6)),
        'bool_start': (replace(blocks[0], start=False), *blocks[1:]),
    }
    def unexpected(_):
        pytest.fail('Malformed coverage sampled verifier entropy')
    monkeypatch.setattr(product.secrets, 'randbelow', unexpected)
    calls = []
    with pytest.raises(ValueError):
        request.admit_once(variants[kind], release_sentinel=calls.append)
    assert not calls


@pytest.mark.parametrize('kind', ['bad_length', 'noncanonical', 'mutable_packet', 'wrong_digest', 'mutable_blocks'])
def test_full_snapshot_grammar_before_any_weights(public, monkeypatch, kind):
    enrollment, request, blocks = fresh(public)
    block = blocks[-1]
    at = len(block.packet)-8
    variants = {
        'bad_length': (*blocks[:-1], replace(block, packet=block.packet+b'x')),
        'noncanonical': (*blocks[:-1], replace(block, packet=block.packet[:at]+struct.pack('<Q', enrollment.context.primes[1]))),
        'mutable_packet': (*blocks[:-1], replace(block, packet=bytearray(block.packet))),
        'wrong_digest': (*blocks[:-1], replace(block, packet=block.packet[:len(product.TAG)]+b'x'*32+block.packet[len(product.TAG)+32:])),
        'mutable_blocks': list(blocks),
    }
    def unexpected(_):
        pytest.fail('Malformed final block sampled entropy in an earlier block')
    monkeypatch.setattr(product.secrets, 'randbelow', unexpected)
    calls = []
    with pytest.raises(ValueError):
        request.admit_once(variants[kind], release_sentinel=calls.append)
    assert not calls


@pytest.mark.parametrize('kind', ['epoch', 'request_id'])
def test_parent_source_epoch_request_binding(public, monkeypatch, kind):
    ctx, queries = public
    enrollment, old, blocks = fresh(public)
    other = complete.Enrollment(replace(ctx, epoch=ctx.epoch+'-next')) if kind == 'epoch' else enrollment
    request = other.begin(queries[0], b's'*32)
    def unexpected(_):
        pytest.fail('Foreign original-parent binding sampled entropy')
    monkeypatch.setattr(product.secrets, 'randbelow', unexpected)
    with pytest.raises(ValueError, match='binding'):
        request.admit_once(blocks)
    assert old.statement_digest != request.statement_digest


@pytest.mark.parametrize('kind', ['query', 'index', 'relin'])
def test_reframed_wrong_computation_is_rejected(public, monkeypatch, kind):
    ctx, queries = public
    altered = ctx
    if kind == 'index':
        altered = replace(ctx, index=(ctx.index[1], ctx.index[0], *ctx.index[2:]))
    elif kind == 'relin':
        poly = ((ctx.relin[0][0][0]+1) % ctx.q, *ctx.relin[0][0][1:])
        altered = replace(ctx, relin=((poly, ctx.relin[0][1]), *ctx.relin[1:]))
    enrollment = complete.Enrollment(altered)
    query = queries[1] if kind == 'query' else queries[0]
    request = enrollment.begin(query, b'r'*32)
    # Correct new headers do not authorize old query/index/key arithmetic.
    values = outputs(ctx, queries[0])
    blocks = tuple(request.frame_block(i, enrollment.product_key.pack_full(values[b.start:b.end], 2))
                   for i, b in enumerate(request.blocks))
    weights = itertools.count(1)
    monkeypatch.setattr(product.secrets, 'randbelow', lambda p: next(weights))
    with pytest.raises(ValueError, match='arithmetic rejected'):
        request.admit_once(blocks)


@pytest.mark.parametrize('group,component,position', itertools.product(range(2), range(2), range(8)))
def test_every_terminal_and_unused_coordinate_is_authoritative(public, group, component, position):
    ctx, queries = public
    _, request, blocks = fresh(public)
    expected = oracle.parse_response(ctx, oracle.replay(ctx, queries[0]).packet)
    altered = [[list(poly) for poly in pair] for pair in expected]
    altered[group][component][position] = (altered[group][component][position]+1) % ctx.p
    claimed = oracle.serialize(ctx, tuple(tuple(tuple(p) for p in pair) for pair in altered))
    calls = []
    with pytest.raises(ValueError, match='authoritative bytes'):
        request.admit_once(blocks, claimed_response=claimed, release_sentinel=calls.append)
    assert not calls


def test_admission_uses_no_expected_output_replay(public, monkeypatch):
    _, request, blocks = fresh(public)
    def forbidden(*args, **kwargs):
        pytest.fail('Full expected-output replay entered admission')
    monkeypatch.setattr(oracle, 'replay', forbidden)
    result = request.admit_once(blocks)
    assert len(result.packet) == 211


def test_entropy_failure_spends_parent_and_never_releases(public, monkeypatch):
    _, request, blocks = fresh(public)
    def failed(_):
        raise OSError('Entropy unavailable')
    monkeypatch.setattr(product.secrets, 'randbelow', failed)
    calls = []
    with pytest.raises(OSError):
        request.admit_once(blocks, release_sentinel=calls.append)
    with pytest.raises(RuntimeError, match='consumed'):
        request.admit_once(blocks, release_sentinel=calls.append)
    assert not calls


def test_concurrent_duplicate_attempt_has_one_public_release(public):
    _, request, blocks = fresh(public)
    calls = []
    def run():
        try:
            return request.admit_once(blocks, release_sentinel=calls.append)
        except RuntimeError:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: run(), range(2)))
    assert sum(x is not None for x in results) == len(calls) == 1


@pytest.mark.parametrize('operation', [copy.copy, copy.deepcopy, pickle.dumps])
def test_local_attempt_and_enrollment_cannot_be_cloned(public, operation):
    enrollment, request, _ = fresh(public)
    for state in (enrollment, request):
        with pytest.raises(TypeError):
            operation(state)


def test_process_guard_precedes_lock(public, monkeypatch):
    enrollment, request, blocks = fresh(public)
    monkeypatch.setattr(complete.os, 'getpid', lambda: -1)
    with pytest.raises(RuntimeError, match='fork'):
        enrollment.begin(public[1][0], b'q'*32)
    with pytest.raises(RuntimeError, match='fork'):
        request.admit_once(blocks)


def test_malformed_duplicate_requests_spend_local_cap(public):
    ctx, queries = public
    enrollment = complete.Enrollment(ctx, max_requests=2)
    enrollment.begin(queries[0], b'r'*32)
    with pytest.raises(ValueError, match='Repeated'):
        enrollment.begin(queries[0], b'r'*32)
    with pytest.raises(RuntimeError, match='budget'):
        enrollment.begin(queries[0], b's'*32)
    fresh_state = complete.Enrollment(ctx, max_requests=1)
    with pytest.raises(ValueError):
        fresh_state.begin(queries[0], b'bad')
    with pytest.raises(RuntimeError, match='budget'):
        fresh_state.begin(queries[0], b's'*32)


def test_enrollment_public_pins_are_read_only_properties(public):
    enrollment = complete.Enrollment(public[0])
    for name in ('context', 'digest', 'product_key', 'max_requests'):
        with pytest.raises(AttributeError):
            setattr(enrollment, name, None)


def test_other_geometry_stops_before_product_construction(public):
    ctx, _ = public
    with pytest.raises(ValueError, match='nine-row'):
        complete.Enrollment(replace(ctx, ids=tuple(range(10))))


@pytest.mark.parametrize('claimed', [b'', bytearray(b'x')])
def test_claimed_packet_grammar_stops_before_weights(public, monkeypatch, claimed):
    _, request, blocks = fresh(public)
    def unexpected(_):
        pytest.fail('Malformed claimed packet sampled verifier entropy')
    monkeypatch.setattr(product.secrets, 'randbelow', unexpected)
    with pytest.raises(ValueError):
        request.admit_once(blocks, claimed_response=claimed)
