"""A defensive regression for naive PUBLIC zero-seed recipe composition."""

from contextlib import closing
from dataclasses import replace
import secrets

import pytest

from experiments.bfv_search_lab import ciphertext_factory as factory
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import dyadic_crt as crt
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import seed_composition_oracle as negative
from experiments.bfv_search_lab import seeded_bgv as seeded


@pytest.mark.parametrize("collapsed", (False, True))
def test_public_zero_seed_recovers_multiple_private_coordinates_without_he_secret(monkeypatch, collapsed):
    if collapsed:
        layout = crt.layout(crt.context(32, ("00", "01", "10", "11"), 17), (2,) * 4, (1,) * 4)
        s = space.space(layout, (0, 0, 1, 1), coordinate_ids=((0, 1), (2, 3)))
        assert s.column_degrees == (2, 2) and s.slots == 4
    else:
        layout = crt.layout(crt.context(32, ("0", "1"), 17), (2, 2), (1, 1))
        s = space.space(layout, (0, 1))
    groups = [[[1, 0]] for _ in layout.counts]
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, groups, secrets.token_bytes(32), client)
        producer = factory.Factory(index, client)
        original, captured = client.encrypt, []
        def spy(plain):
            packet = original(plain)
            captured.append(packet)
            return packet
        monkeypatch.setattr(client, "encrypt", spy)
        for word in range(16):
            captured.clear()
            ticket, answer, _ = producer.prepare(word.to_bytes(16, "little"))
            # Simulate the unsafe optimization: these seeds are NEVER returned
            # by the real Factory. Recovery receives only public transcript.
            exposed = tuple(seeded._parse(packet, pk)[1] for packet in captured)
            expected = tuple(1 - 2 * ((word >> j) & 1) for j in range(4))
            expected_pad = masked.mask(s, ticket._seed, index.epoch, ticket.token_id)
            request = ticket.consume(expected, index.epoch)
            pad, recovered = negative.recover(index, pk, answer, request, exposed)
            assert pad == expected_pad
            assert recovered == tuple(x % pk.t for x in expected)
        duplicate = replace(index, columns=(index.columns[0], index.columns[0]))
        with pytest.raises(ValueError, match="full column rank"):
            negative.recover(duplicate, pk, answer, request, exposed)


def test_overdetermined_field_solver_never_invents_a_mask():
    assert negative.solve(((1, 0), (0, 1), (1, 1)), (3, 4, 0), 7) == (3, 4)
    with pytest.raises(ValueError, match="inconsistent"):
        negative.solve(((1, 0), (0, 1), (1, 1)), (3, 4, 1), 7)
    with pytest.raises(ValueError, match="rank"):
        negative.solve(((1, 1), (2, 2)), (1, 2), 7)
