"""Independent bounded public GMP reference; retained HE inputs, no new keys."""

from dataclasses import FrozenInstanceError
import os
from pathlib import Path

from gmpy2 import mpz
import pytest

from benchmarks import native_shared_query_lab as lab
from experiments.bfv_search_lab import native_boundary_oracle as oracle
from experiments.bfv_search_lab import native_shared_query as native
from experiments.bfv_search_lab import noise_cut_relation as relation
from experiments.bfv_search_lab import seeded_bgv as seeded
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import shared_query_bgv as shared
from experiments.bfv_search_lab import shared_query_gmp as gmp
from experiments.bfv_search_lab.shared_query_bounds import Profile
from experiments.bfv_search_lab.test_native_shared_query import CASE_IDS


@pytest.fixture(scope="module")
def retained():
    directory = os.getenv("CUHEPY_SHARED_QUERY_FIXTURES")
    if not directory:
        pytest.skip("Explicit retained public fixture directory required")
    directory = Path(directory)
    report, entries = lab.public_cases(directory)
    return directory, {row["id"]: row for row in entries}, lab.public_fixtures(directory, report)


def inputs(retained, case_id):
    directory, entries, fixtures = retained
    ctx, tape, _pk, primes, _pin = lab.load_case(directory, entries[case_id], fixtures)
    metadata = native.PublicMetadata(ctx.profile, primes, ctx.key_id, ctx.ids)
    keys = (ctx.relin, *(key for _, key in ctx.rotations))
    key_body = native.pack_common(
        tuple(row for key in keys for pair in key for row in pair), ctx.profile.n, ctx.profile.q
    )
    index_body = native.pack_common(
        tuple(row for pair in ctx.index for row in pair), ctx.profile.n, ctx.profile.q
    )
    query_body = native.pack_common(ctx.query, ctx.profile.n, ctx.profile.q)
    return metadata, key_body, index_body, query_body, ctx, tape


@pytest.fixture
def case(retained):
    return inputs(retained, CASE_IDS[-1])


def forbidden(*_args, **_kwargs):
    raise AssertionError(
        "Native/small producer or private HE work in independent public GMP reference"
    )


@pytest.mark.parametrize("case_id", CASE_IDS)
def test_retained_all_source_output_and_frame_coefficients(retained, case_id, monkeypatch):
    metadata, keys, index, query, ctx, tape = inputs(retained, case_id)
    expected = lab.body(ctx, tape)
    assert relation.holds(shared.compile_relation(ctx), tape.sources, tape.full_output)
    for name in ("produce", "compile_relation", "expected_frame"):
        monkeypatch.setattr(shared, name, forbidden)
    for name in ("produce", "check", "verifies", "expected_response", "residuals"):
        monkeypatch.setattr(native.NativeQuery, name, forbidden)
    for name in ("key_gen", "encrypt", "decrypt"):
        monkeypatch.setattr(bgv, name, forbidden)
    monkeypatch.setattr(seeded, "encrypt", forbidden)
    produced = gmp.GMPPublicContext(metadata, keys, index).produce(query)
    assert produced.body == expected
    assert produced.response == tape.response
    assert len(produced.body) == metadata.body_size


@pytest.mark.parametrize("n", (8, 16, 32))
@pytest.mark.parametrize("pattern", ("zero", "maximum", "alternating", "mixed"))
def test_kronecker_products_against_independent_schoolbook(n, pattern):
    q = (1 << 120) - 37
    if pattern == "zero":
        left, right = (0,) * n, (q - 1,) * n
    elif pattern == "maximum":
        left = right = (q - 1,) * n
    elif pattern == "alternating":
        left, right = (
            tuple((q - 1) * (i % 2) for i in range(n)),
            tuple((q - 1) * ((i + 1) % 2) for i in range(n)),
        )
    else:
        left, right = (
            tuple((i * 7123 + q - 1) % q for i in range(n)),
            tuple((i * i * 13 + 1) % q for i in range(n)),
        )
    assert tuple(
        map(int, gmp._ring_product(tuple(map(mpz, left)), tuple(map(mpz, right)), mpz(q)))
    ) == oracle.multiply(left, right, q)


@pytest.mark.parametrize("family", ("keys", "index", "query"))
@pytest.mark.parametrize("fault", ("short", "extra", "mutable", "view", "first_q", "last_q"))
def test_all_complete_input_coordinates_before_multiplication(case, family, fault, monkeypatch):
    metadata, keys, index, query, _ctx, _tape = case
    bodies = {"keys": keys, "index": index, "query": query}
    context = gmp.GMPPublicContext(metadata, keys, index)
    data = bodies[family]
    if fault == "short":
        data = data[:-1]
    elif fault == "extra":
        data += b"\x00"
    elif fault == "mutable":
        data = bytearray(data)
    elif fault == "view":
        data = memoryview(data)
    else:
        at = 0 if fault == "first_q" else len(data) - gmp.WIDTH
        data = data[:at] + metadata.profile.q.to_bytes(gmp.WIDTH, "little") + data[at + gmp.WIDTH :]
    bodies[family] = data
    monkeypatch.setattr(gmp, "_ring_product", forbidden)
    with pytest.raises(ValueError):
        if family == "query":
            context.produce(data)
        else:
            gmp.GMPPublicContext(metadata, bodies["keys"], bodies["index"])


@pytest.mark.parametrize("exponent,shift", ((1, 0), (17, 0), (9, -2), (1, -33), (3, 31)))
def test_signed_permutation_against_independent_schoolbook(exponent, shift):
    row, q = tuple(range(16)), (1 << 120) - 37
    expected = oracle.monomial(oracle.automorphism(row, exponent, q), shift, q)
    assert (
        tuple(map(int, gmp._permute(tuple(map(mpz, row)), mpz(q), exponent=exponent, shift=shift)))
        == expected
    )


def test_terminal_extremes_and_full_framing(case):
    metadata, _keys, _index, _query, ctx, _tape = case
    p = metadata.profile
    row = tuple((0, 1, p.q // 2, p.q - 1)[i % 4] for i in range(p.n))
    outputs = tuple((row, tuple(reversed(row))) for _ in range(metadata.groups))
    assert gmp.terminal_frame(metadata, outputs) == shared.expected_frame(ctx, outputs)


@pytest.mark.parametrize(
    "fault", ("missing_group", "missing_component", "short_row", "last_q", "bool")
)
def test_terminal_complete_grammar(case, fault):
    metadata, _keys, _index, _query, _ctx, tape = case
    outputs = tape.full_output
    if fault == "missing_group":
        outputs = outputs[:-1]
    elif fault == "missing_component":
        outputs = (outputs[0][:1], *outputs[1:])
    else:
        row = outputs[-1][-1]
        row = (
            row[:-1]
            if fault == "short_row"
            else (*row[:-1], metadata.profile.q if fault == "last_q" else True)
        )
        outputs = (*outputs[:-1], (outputs[-1][0], row))
    with pytest.raises(ValueError):
        gmp.terminal_frame(metadata, outputs)


def test_context_immutability_and_caps(case, monkeypatch):
    metadata, keys, index, query, _ctx, _tape = case
    context = gmp.GMPPublicContext(metadata, keys, index)
    with pytest.raises(FrozenInstanceError):
        context.index_body = b"bad"
    monkeypatch.setattr(gmp, "INPUT_CAP", 1)
    monkeypatch.setattr(gmp, "_ring_product", forbidden)
    with pytest.raises(ValueError):
        gmp.GMPPublicContext(metadata, keys, index)
    with pytest.raises(ValueError):
        context.produce(query)


def test_selected_source_profile_preflight_before_any_key_or_allocation():
    primes = (1152921504606748673, 1152921504606683137)
    p = Profile(16384, 512, primes[0] * primes[1], 33548413, 1031, 21, "owner", "canonical30")
    metadata = native.PublicMetadata(p, primes, "00" * 32, tuple(range(32768)))
    assert p.envelope()["admitted"]
    assert metadata.body_size == (511 + 6) * 16384 * 15
    with pytest.raises(ValueError, match="complete immutable"):
        gmp.GMPPublicContext(metadata, b"", b"")
