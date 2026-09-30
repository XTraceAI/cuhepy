"""E64 separately typed supported-C0/full-C1 relation and secret decoder.

The owner pins the exact layout/support, row IDs, private plan identity, key
and epoch. All supplied coordinates are checked before secret arithmetic.
Only supported phases are centered/reduced; zero-filled FIELD carriers go to
the CRT decoder, never to ordinary BGV decrypt. Existing full gates are intact.
Known extraction/support/fingerprints are not claimed as new cryptography.
Conditional relation: docs/research/supported-decoder-relation.md. Private
timing, parameter/seeded privacy review and durable state remain open.
"""

from __future__ import annotations

from dataclasses import dataclass

from gmpy2 import mpz

from cuhepy.bfv.scheme import _ring_product
from experiments.bfv_search_lab import coefficient_body as codec
from experiments.bfv_search_lab import crt_linear_check as checks
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_query_space as crt
from experiments.bfv_search_lab import decryption_support as support
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab.verification_lifetime import AttemptBudget


@dataclass(frozen=True)
class Reply:
    c0_supported: tuple[tuple[mpz, ...], ...]
    c1: tuple[tuple[mpz, ...], ...]
    key_id: str
    epoch: bytes
    space_binding: bytes
    phase_bounds: tuple[int, ...]


def validate(reply, space, pk, epoch, certificate):
    counts = tuple(map(len, certificate.kept_c0))
    if (type(reply) is not Reply or type(reply.c0_supported) is not tuple or type(reply.c1) is not tuple
            or type(reply.phase_bounds) is not tuple or reply.key_id != pk.key_id or reply.epoch != epoch
            or reply.space_binding != space.binding or len(reply.c0_supported) != len(counts)
            or len(reply.c1) != len(counts) or len(reply.phase_bounds) != len(counts)
            or any(type(p) is not tuple or len(p) != count for p, count in zip(reply.c0_supported, counts, strict=True))
            or any(type(p) is not tuple or len(p) != pk.n for p in reply.c1)
            or any(type(b) is not int or not 0 <= b < pk.q // 2 for b in reply.phase_bounds)
            or any(not isinstance(x, (int, mpz)) or isinstance(x, bool) or not 0 <= x < pk.q
                   for p in (*reply.c0_supported, *reply.c1) for x in p)):
        raise ValueError("Invalid owner-pinned supported-coordinate reply")


def project(output, space, pk, epoch):
    """Public evaluator packaging; row IDs and private maps are not required."""
    crt.validate(space)
    masked.binding(epoch, bytes(16))
    if (pk.n, pk.t) != (space.layout.context.n, space.layout.context.prime):
        raise ValueError("Wrong supported-decoder key context")
    certificate = support.certify(space.layout)
    masked.validate_ciphertexts(output, len(certificate.kept_c0), pk)
    reply = Reply(tuple(tuple(c.components[0][i] for i in indices)
                        for c, indices in zip(output, certificate.kept_c0, strict=True)),
                  tuple(c.components[1] for c in output), pk.key_id, epoch, space.binding,
                  tuple(c.phase_bound for c in output))
    validate(reply, space, pk, epoch, certificate)
    return reply


def pack(reply, pk):
    """Coefficient body only; pinned metadata/bounds use the caller's envelope."""
    return codec.pack(tuple(x for c0, c1 in zip(reply.c0_supported, reply.c1, strict=True)
                            for row in (c0, c1) for x in row), int(pk.q))


class _SupportedCheck(checks.EpochCheck):
    def __init__(self, index, pk, certificate, *, rounds, budget):
        self.certificate = certificate
        self._kept_sets = tuple(frozenset(indices) for indices in certificate.kept_c0)
        super().__init__(index, pk, rounds=rounds, budget=budget)

    def _challenges(self):
        for challenge in super()._challenges():
            yield tuple((tuple(value if i in indices else mpz(0) for i, value in enumerate(c0)), c1)
                        for (c0, c1), indices in zip(challenge, self._kept_sets, strict=True))


def _field_carrier(reply, pk, sk, certificate):
    """Dedicated selected-phase arithmetic after the projected relation gate."""
    if sk.key_id != pk.key_id or len(sk.s) != pk.n:
        raise ValueError("Wrong secret for owner-pinned supported decoder")
    phases = []
    for c0, c1, indices, bound in zip(reply.c0_supported, reply.c1, certificate.kept_c0,
                                    reply.phase_bounds, strict=True):
        product = _ring_product(c1, sk.s, pk.q)
        phase = [0] * pk.n
        for i, value in zip(indices, c0, strict=True):
            reduced = (value + product[i]) % pk.q
            centered = reduced if reduced <= pk.q // 2 else reduced - pk.q
            if abs(centered) > bound:
                raise AssertionError("Approved supported phase exceeded its honest bound")
            phase[i] = int(centered % pk.t)
        phases.append(phase)
    return phases


class Gate:
    """Trusted owner-local gate/decoder; no server-supplied checker or ID order.

    Reuse one AttemptBudget across epoch gates. This volatile helper is not a
    transport client, durable journal or approved malicious-security protocol.
    owner_plan_binding is a LOCAL identity, never a public private-data digest.
    """

    def __init__(self, index, pk, output_ids, owner_plan_binding, attempts: AttemptBudget, *, rounds=4):
        crt.validate(index.space)
        if type(output_ids) is not tuple or any(type(group) is not tuple for group in output_ids):
            raise ValueError("Exact owner-approved row ID groups required")
        flat = tuple(i for group in output_ids for i in group)
        if (not flat or len(output_ids) != len(index.space.layout.counts)
                or any(type(group) is not tuple or len(group) != count
                       for group, count in zip(output_ids, index.space.layout.counts, strict=True))
                or any(type(i) is not int or not 0 <= i < 1 << 64 for i in flat) or len(flat) != len(set(flat))
                or type(owner_plan_binding) is not str or len(owner_plan_binding) != 64
                or set(owner_plan_binding) - set("0123456789abcdef") or type(attempts) is not AttemptBudget):
            raise ValueError("Exact owner-approved row IDs, private identity and lifetime required")
        self.space, self.pk, self.epoch = index.space, pk, index.epoch
        self.output_ids, self.owner_plan_binding = output_ids, owner_plan_binding
        self.certificate = support.certify(self.space.layout)
        self._gate = attempts.bind(_SupportedCheck(index, pk, self.certificate, rounds=rounds, budget=attempts.limit))

    def prepare_answer(self, answer):
        self._gate.prepare_answer(answer)

    def parse(self, body, phase_bounds):
        values = codec.unpack(body, self.certificate.projected_coefficient_count, int(self.pk.q))
        c0, c1, cursor = [], [], 0
        for indices in self.certificate.kept_c0:
            count = len(indices)
            c0.append(values[cursor:cursor + count])
            cursor += count
            c1.append(values[cursor:cursor + self.pk.n])
            cursor += self.pk.n
        reply = Reply(tuple(c0), tuple(c1), self.pk.key_id, self.epoch, self.space.binding, phase_bounds)
        validate(reply, self.space, self.pk, self.epoch, self.certificate)
        return reply

    def open_once(self, request, reply, sk):
        """request is the client's pinned original, not a received replacement."""
        try:
            validate(reply, self.space, self.pk, self.epoch, self.certificate)
            carriers = []
            for c0, c1, indices, bound in zip(reply.c0_supported, reply.c1, self.certificate.kept_c0,
                                            reply.phase_bounds, strict=True):
                complete = [mpz(0)] * self.pk.n
                for i, value in zip(indices, c0, strict=True):
                    complete[i] = value
                # Fingerprint carriers only: never ordinary-decrypt these.
                carriers.append(bgv.Ciphertext((tuple(complete), c1), self.pk.key_id, bound))
        except (ValueError, TypeError):
            self._gate.verify_once(request, ())
            return None
        if not self._gate.verify_once(request, tuple(carriers)):
            return None
        return tuple(tuple(row) for row in tree.unpack(self.space.layout,
                           _field_carrier(reply, self.pk, sk, self.certificate)))

    def open_body_once(self, request, body, sk, phase_bounds):
        try:
            reply = self.parse(body, phase_bounds)
        except (ValueError, TypeError):
            self._gate.verify_once(request, ())
            return None
        return self.open_once(request, reply, sk)
