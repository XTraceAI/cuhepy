"""E43 owner-mediated repair of NEVER-EXPOSED pads in a frozen representation.

For approved row edits that stay in the old affine spaces, the owner computes
Delta M and adds fresh Enc(Phi(Delta M*r)) to each unused answer. This avoids a
whole M*r per pending token. All columns/answers receive fresh encryption even
for zero patches, so public packet counts do not depend on a private mask.

Known incremental linear algebra and HE addition are ingredients, not novelty
claims. This local prototype has no durable journal, remote authentication,
rollback protection, erasure or private-timing assurance. No consumed pad is
repaired/reused. New epochs are independent random handles: owner-local hashes
of plaintext rows/private maps are not published as commitments.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import secrets
import threading

from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import rank_partition as partition
from experiments.bfv_search_lab import representation_oracle as oracle
from experiments.bfv_search_lab import shallow_bgv as bgv


def add(left: bgv.Ciphertext, right: bgv.Ciphertext, pk: bgv.PublicKey) -> bgv.Ciphertext:
    masked.validate_ciphertexts((left, right), 2, pk)
    limit = left.phase_bound + right.phase_bound
    if 2 * limit >= pk.q:
        raise ValueError("Repair ciphertext exceeds the deterministic phase bound")
    return bgv.Ciphertext(tuple(tuple((a + b) % pk.q for a, b in zip(x, y, strict=True))
                                for x, y in zip(left.components, right.components, strict=True)), pk.key_id, limit)


@dataclass
class Pending:
    _pool: RepairPool = field(repr=False)
    token_id: bytes
    answer: masked.Answer
    _pad: tuple[int, ...] | None = field(repr=False)

    def consume(self, values: tuple[int, ...], epoch: bytes) -> masked.Request:
        with self._pool._lock:
            if self._pad is None:
                raise RuntimeError("Repairable pad already consumed")
            if epoch != self.answer.epoch or epoch != self._pool.index.epoch:
                raise ValueError("Stale owner-approved repair epoch")
            space.split(self.answer.space, values)
            pad, self._pad = self._pad, None  # Burn before a request can escape.
            t = self.answer.space.layout.context.prime
            return masked.Request(self.answer.space, epoch, self.token_id,
                                  tuple((w - r) % t for w, r in zip(values, pad, strict=True)))


class RepairPool:
    def __init__(self, plan: oracle.Compiled, client: owner.OwnerClient):
        if (client.pk.n, client.pk.t, client.pk.eta, int(client.pk.q)) != (
            plan.profile.n, plan.profile.prime, plan.profile.eta, plan.profile.q
        ):
            raise ValueError("Wrong pinned repair owner key/profile")
        self.plan, self.client = plan, client
        self._lock = threading.RLock()
        self._tokens: dict[bytes, Pending] = {}
        self._locations = {position: (block, row) for block, b in enumerate(plan.candidate.blocks)
                           for row, position in enumerate(b.positions)}
        self._id_positions = {identifier: i for i, identifier in enumerate(plan.ids)}
        self.index, self.index_upload_bytes = masked.enroll(plan.query_space, self._groups(), secrets.token_bytes(32), client)

    def _groups(self):
        return [[list(row) for row in g] for g in self.plan.groups]

    def prepare(self, token_id: bytes) -> Pending:
        with self._lock:
            masked.binding(self.index.epoch, token_id)
            if token_id in self._tokens:
                raise ValueError("Duplicate lifetime token identifier")
            if len(self._tokens) >= self.plan.profile.attempt_budget:
                raise ValueError("Declared lifetime token budget exhausted")
            s = self.plan.query_space
            pad = masked.mask(s, secrets.token_bytes(32), self.index.epoch, token_id)
            packets = [self.client.encrypt(p) for p in space.outputs(s.layout, space.scores(s, self._groups(), pad))]
            answer = masked.Answer(s, self.index.epoch, token_id, tuple(owner.expand(p, self.client.pk) for p in packets))
            token = Pending(self, token_id, answer, pad)
            self._tokens[token_id] = token
            return token

    def edit(self, edits: dict[int, int], *, method: str = "sparse_delta") -> dict:
        """Atomic local edit/repair; fixed IDs, geometry, key and private maps."""
        with self._lock:
            if (type(edits) is not dict or not edits
                    or method not in ("sparse_delta", "full_reencrypt")
                    or any(type(identifier) is not int or identifier not in self._id_positions for identifier in edits)
                    or any(type(row) is not int or not 0 <= row < 1 << self.plan.dimension for row in edits.values())):
                raise ValueError("Invalid approved fixed-ID row edits")
            s, pk = self.plan.query_space, self.client.pk
            fresh = pk.t // 2 + pk.t * pk.eta
            pending = [p for p in self._tokens.values() if p._pad is not None]
            # Gate the WHOLE circuit before any target can change. Every
            # possible centered query correction is covered, not one sample.
            maximum_answer = (max((c.phase_bound + fresh for p in pending for c in p.answer.ciphertexts), default=fresh)
                              if method == "sparse_delta" else fresh)
            universal = max(maximum_answer + sum(degree * (pk.t // 2) * (column[r].phase_bound + fresh if method == "sparse_delta" else fresh)
                                                for degree, column in zip(s.column_degrees, self.index.columns, strict=True))
                            for r in range(s.layout.cost.response_ciphertexts))
            if 2 * universal >= pk.q:
                raise ValueError("Repair exceeds universal phase budget; fresh rebase required")
            groups, rows, changes = self._groups(), list(self.plan.workload.rows), []
            for identifier, value in edits.items():
                position = self._id_positions[identifier]
                block, row = self._locations[position]
                mapping = self.plan.candidate.blocks[block].mapping
                new = affine.index_features(mapping, [value])[0]  # Reject out-of-space edits.
                difference = tuple(a - b for a, b in zip(new, groups[block][row], strict=True))
                groups[block][row] = new
                rows[position] = value
                changes.append((block, row, difference))
            # Sparse owner arithmetic, followed by the SAME padded encryption
            # schedule on every update. No plaintext-sized ciphertext shortcut.
            if method == "full_reencrypt":
                patch_columns = space.columns(s, groups)
            else:
                patch_columns = []
                for j in range(s.columns):
                    values = [[0] * count for count in s.layout.counts]
                    for block, row, difference in changes:
                        values[block][row] = difference[j] if j < len(difference) else 0
                    patch_columns.append(space.outputs(s.layout, values))
            epoch, upload = secrets.token_bytes(32), 0
            updated_columns = []
            for original, patches in zip(self.index.columns, patch_columns, strict=True):
                packets = [self.client.encrypt(p) for p in patches]
                upload += sum(map(len, packets))
                updated_columns.append(tuple(add(old, owner.expand(packet, pk), pk) if method == "sparse_delta" else owner.expand(packet, pk)
                                             for old, packet in zip(original, packets, strict=True)))
            updated_answers = []
            for token in pending:
                if method == "full_reencrypt":
                    values = space.scores(s, groups, token._pad)
                else:
                    weights = space.split(s, token._pad)
                    values = [[0] * count for count in s.layout.counts]
                    for block, row, difference in changes:
                        values[block][row] = sum(a * b for a, b in zip(difference, weights[s.map_ids[block]], strict=True)) % pk.t
                packets = [self.client.encrypt(p) for p in space.outputs(s.layout, values)]
                upload += sum(map(len, packets))
                cipher = tuple(add(old, owner.expand(packet, pk), pk) if method == "sparse_delta" else owner.expand(packet, pk)
                               for old, packet in zip(token.answer.ciphertexts, packets, strict=True))
                updated_answers.append(masked.Answer(s, epoch, token.token_id, cipher))
            workload = replace(self.plan.workload, rows=tuple(rows))
            candidate = replace(self.plan.candidate, source_digest=partition.epoch_digest(rows, workload.dimension))
            # Commit only after every ciphertext and answer has been prepared.
            # A crash during this local commit is NOT covered; P08 is separate.
            self.plan = replace(self.plan, workload=workload, candidate=candidate,
                                groups=tuple(tuple(tuple(row) for row in g) for g in groups))
            self.index = masked.Index(s, epoch, tuple(updated_columns))
            for token, answer in zip(pending, updated_answers, strict=True):
                token.answer = answer
            return {"method": method, "edited_rows": len(edits), "repaired_unused_tokens": len(pending),
                    "consumed_tokens_untouched": len(self._tokens) - len(pending),
                    "ciphertexts_freshly_encrypted": (s.columns + len(pending)) * s.layout.cost.response_ciphertexts,
                    "seeded_patch_packet_bytes": upload,
                    "universal_phase_bound_after_repair": universal,
                    "sparse_dot_products_per_token": sum(len(delta) for _, _, delta in changes),
                    "full_dot_products_per_token_control": sum(count * f for count, f in zip(s.layout.counts, s.layout.features, strict=True)),
                    "scope": "Local volatile owner prototype; checker re-preparation and durability charged separately."}
