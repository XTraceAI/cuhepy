"""Unit admission/callback tests only; actual proofs are tested by E109 runner."""

from dataclasses import replace
from pathlib import Path

import pytest

from benchmarks.native_boundary_lab import load_fixture
from experiments.bfv_search_lab import native_boundary_oracle as oracle
from experiments.bfv_search_lab import native_opening_constraints as constraints
from experiments.bfv_search_lab import proof_backend_adapter as adapter

FIXTURE = Path(__file__).resolve().parents[3]/"research-data/native-boundary-20261003/frozen-fixture.json"


@pytest.fixture(scope="module")
def sample():
    if not FIXTURE.exists():
        pytest.skip("Frozen external E106 fixture is required")
    fixture, ctx, *_ = load_fixture(FIXTURE)
    compiled = constraints.compile_constraints(ctx, mode="folded", tight_quotients=False)
    query = bytes.fromhex(fixture["queries"][0]["packet_hex"])
    response = oracle.replay(ctx, query).packet
    return ctx, compiled, adapter.Pins(ctx.digest(), "0"*64, query), response


def test_backend_rejection_precedes_private_callback(sample):
    ctx, compiled, pins, response = sample
    calls = []
    with pytest.raises(ValueError, match="proof rejected"):
        adapter.release(compiled, ctx, pins, response, b"unit", lambda *args: False, calls.append)
    assert not calls


@pytest.mark.parametrize("proof", [b"", b"x"*((1 << 20)+1), bytearray(b"x"), None])
def test_proof_admission_never_calls_backend_or_private_callback(sample, proof):
    ctx, compiled, pins, response = sample
    calls = []
    with pytest.raises(ValueError):
        adapter.release(compiled, ctx, pins, response, proof, calls.append, calls.append)
    assert not calls


@pytest.mark.parametrize("response", [b"", b"bad", None, bytearray(b"bad")])
def test_response_admission_precedes_both_callbacks(sample, response):
    ctx, compiled, pins, _ = sample
    calls = []
    with pytest.raises(ValueError):
        adapter.release(compiled, ctx, pins, response, b"unit", calls.append, calls.append)
    assert not calls


@pytest.mark.parametrize("which", ["context", "instance", "query"])
def test_owner_local_pins_are_checked_or_domain_bound(sample, which):
    ctx, compiled, pins, response = sample
    public, domain = adapter.statement(compiled, ctx, pins, response)
    if which == "context":
        with pytest.raises(ValueError):
            adapter.statement(compiled, ctx, replace(pins, context_digest="0"*64), response)
    elif which == "instance":
        other, changed = adapter.statement(compiled, ctx, replace(pins, instance_sha256="1"*64), response)
        assert other == public and changed != domain
    else:
        with pytest.raises(ValueError):
            adapter.statement(compiled, ctx, replace(pins, original_query=b"bad"), response)
