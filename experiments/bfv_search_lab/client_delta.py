"""E54 strong control: private client corrections over a fixed encrypted base.

The owner and client share a confidentiality domain in the research contract.
For changed stable IDs the owner may retain/send two private bit masks encoding
new-minus-BASE rows. The client verifies/decrypts the complete frozen-base
answer, then adds these exact Hamming corrections. No ciphertext, unused pad,
HE phase or base-check material changes when a row is edited. This is ordinary
delta caching, not a new cryptographic mechanism.

Private correction state and owner work/traffic must be charged. In particular,
this control does not satisfy a contract that forbids these owner-to-client
corrections. Snapshots are locally trusted, immutable and randomly versioned;
there is no remote authenticated transport, deletion erasure or durable state.
Insert/delete and output-only disclosure are outside this fixed-ID prototype.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import secrets
import threading

from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import representation_oracle as oracle


@dataclass(frozen=True)
class Patch:
    position: int
    positive: int
    negative: int

    def correction(self, word):
        return (self.positive.bit_count() - self.negative.bit_count()
                - 2 * ((self.positive & word).bit_count() - (self.negative & word).bit_count()))


@dataclass(frozen=True)
class Snapshot:
    base: oracle.ClientView = field(repr=False)
    base_epoch: bytes
    epoch: bytes
    patches: tuple[Patch, ...] = field(repr=False)

    def validate(self):
        masked.binding(self.base_epoch, bytes(16))
        masked.binding(self.epoch, bytes(16))
        positions = tuple(p.position for p in self.patches)
        if (positions != tuple(sorted(set(positions)))
                or any(type(p.position) is not int or not 0 <= p.position < len(self.base.ids)
                       or type(p.positive) is not int or type(p.negative) is not int
                       or not 0 <= p.positive < 1 << self.base.dimension
                       or not 0 <= p.negative < 1 << self.base.dimension
                       or p.positive & p.negative or not p.positive | p.negative for p in self.patches)):
            raise ValueError("Invalid private stable-ID correction snapshot")

    @property
    def private_body_bytes(self):
        """Snapshot header + stable ID and two d-bit masks; excludes framing/RSS."""
        self.validate()
        return 64 + len(self.patches) * (8 + 2 * ((self.base.dimension + 7) // 8))

    def correct(self, base_scores, word, *, epoch):
        """Apply ONLY to a complete verified/decrypted pinned-base score array."""
        self.validate()
        if (epoch != self.epoch or type(word) is not int or not 0 <= word < 1 << self.base.dimension
                or type(base_scores) is not tuple or len(base_scores) != len(self.base.ids)
                or any(type(x) is not int or not 0 <= x <= self.base.dimension for x in base_scores)):
            raise ValueError("Stale snapshot or invalid complete base scores/query")
        result = list(base_scores)
        for p in self.patches:
            result[p.position] += p.correction(word)
        if any(not 0 <= x <= self.base.dimension for x in result):
            raise ValueError("Corrected score outside exact Hamming range")
        return tuple(result)


class Ledger:
    def __init__(self, plan, base_epoch):
        plan.workload.validate()
        masked.binding(base_epoch, bytes(16))
        self.plan, self.base_epoch = plan, base_epoch
        self.workload = plan.workload
        self._positions = {identifier: i for i, identifier in enumerate(plan.ids)}
        self._patches = {}
        self._lock = threading.Lock()
        self.snapshot = Snapshot(plan.client_view(), base_epoch, secrets.token_bytes(32), ())

    def edit(self, edits):
        with self._lock:
            if (type(edits) is not dict or not edits
                    or any(type(i) is not int or i not in self._positions for i in edits)
                    or any(type(row) is not int or not 0 <= row < 1 << self.plan.dimension for row in edits.values())):
                raise ValueError("Invalid owner-approved fixed-ID delta edits")
            rows, patches = list(self.workload.rows), dict(self._patches)
            for identifier, value in edits.items():
                position = self._positions[identifier]
                original = self.plan.workload.rows[position]
                mask = original ^ value
                if mask:
                    patches[position] = Patch(position, mask & value, mask & original)
                else:
                    patches.pop(position, None)
                rows[position] = value
            snapshot = Snapshot(self.snapshot.base, self.base_epoch, secrets.token_bytes(32),
                                tuple(patches[i] for i in sorted(patches)))
            snapshot.validate()
            self.workload = replace(self.workload, rows=tuple(rows))
            self._patches, self.snapshot = patches, snapshot
            width = (self.plan.dimension + 7) // 8
            return {"method": "private_client_delta", "edited_rows": len(edits),
                    "retained_changed_rows": len(patches),
                    "private_snapshot_body_bytes": snapshot.private_body_bytes,
                    "private_delta_update_body_bytes_model": 64 + len(edits) * (8 + 2 * width),
                    "server_update_body_bytes": 0, "ciphertexts_freshly_encrypted": 0,
                    "scope": "Trusted local owner/client; private update body model, no authenticated remote service."}
