"""Opt-in integration against a fresh real enclave; never satisfied by a mock.

Set XTRACE_BFV_NITRO_PINS to OWNER-TRUSTED nitro-cli measurement JSON and expose
the empty enclave's relay on localhost:9000 (or the explicit HOST/PORT variables).
Only synthetic data is used. This test registers one immutable index.
"""

import os
import secrets
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("XTRACE_BFV_NITRO_PINS"),
    reason="A fresh real Nitro enclave and trusted EIF pins are required",
)


def test_real_nitro_end_to_end():
    from experiments.bfv_nitro.client import load_measurements
    from experiments.bfv_nitro.transport import NitroRemote
    from cuhepy.hamming.bfv_assurance import bfv_review_policy
    from cuhepy.hamming.bfv_attested import BFVAttestedClient
    from cuhepy.hamming.bfv import BFVClient

    policy = bfv_review_policy()
    pins = load_measurements(Path(os.environ["XTRACE_BFV_NITRO_PINS"]))
    client = BFVAttestedClient(
        BFVClient(**policy.config()), secrets.token_bytes(32), pins, index_epoch=1, policy=policy
    )
    remote = NitroRemote(
        os.environ.get("XTRACE_BFV_NITRO_HOST", "127.0.0.1"),
        int(os.environ.get("XTRACE_BFV_NITRO_PORT", "9000")),
        policy=policy,
    )
    vectors = [[0] * 512, [1] * 512, [i % 2 for i in range(512)]]
    setup = client.prepare_index(vectors)
    remote.register(client.registration_packet(setup))
    client.accept_attestation(*remote.attest(client.begin_attestation()))
    assert client.finish_query(*remote.search(client.begin_query([0] * 512))) == [0, 512, 256]
