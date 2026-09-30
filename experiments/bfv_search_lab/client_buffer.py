"""E59 known control: private mutable rows beside a frozen encrypted base.

The authorized owner/client may retain any of its data. A complete verified
base score array is corrected locally, then deleted base IDs are filtered and
inserted private rows are scored. The server's encrypted index, masks, phase
and complete verification relation never change. No deletion erasure, remote
authorization, crash persistence or new encryption primitive is provided.
Historical IDs cannot be reused. State and private update bodies are charged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import heapq
import secrets
import threading

from experiments.bfv_search_lab import client_delta as delta
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import representation_oracle as oracle


@dataclass(frozen=True)
class Result:
    ids: tuple[int, ...]
    scores: tuple[int, ...]
    top3: tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class Snapshot:
    base: oracle.ClientView = field(repr=False)
    base_epoch: bytes
    epoch: bytes
    deleted_positions: tuple[int, ...] = field(repr=False)
    patches: tuple[delta.Patch, ...] = field(repr=False)
    inserted: tuple[tuple[int, int], ...] = field(repr=False)

    def validate(self):
        delta.Snapshot(self.base, self.base_epoch, self.epoch, self.patches).validate()
        deleted = self.deleted_positions
        if (type(deleted) is not tuple or any(type(p) is not int or not 0 <= p < len(self.base.ids) for p in deleted)
                or deleted != tuple(sorted(set(deleted))) or set(deleted).intersection(p.position for p in self.patches)):
            raise ValueError("Invalid private base tombstones/corrections")
        if (type(self.inserted) is not tuple
                or any(type(item) is not tuple or len(item) != 2 for item in self.inserted)):
            raise ValueError("Invalid private inserted-row snapshot")
        ids = tuple(item[0] for item in self.inserted)
        if (any(type(i) is not int or not 0 <= i < 1 << 64 for i in ids)
                or ids != tuple(sorted(set(ids))) or set(ids).intersection(self.base.ids)
                or any(type(row) is not int or not 0 <= row < 1 << self.base.dimension for _, row in self.inserted)):
            raise ValueError("Invalid private inserted rows/IDs")

    @property
    def private_body_bytes_model(self):
        """Two epochs, dimension/base count/three counts, then private entries.

        The original private base map/ID table is additional existing state.
        This is a canonical-body model, not an authenticated packet or RSS.
        """
        self.validate()
        width = (self.base.dimension + 7) // 8
        return (82 + 8 * len(self.deleted_positions) + (8 + 2 * width) * len(self.patches)
                + (8 + width) * len(self.inserted))

    def correct(self, base_scores, word, *, epoch, verified_base_epoch):
        """Caller must verify the COMPLETE frozen-base ciphertext before SK use.

        Surviving base IDs retain enrollment order; live inserted IDs follow
        in ascending ID order. Returned IDs name every score explicitly.
        Local immutable snapshot/epoch approval is a trusted premise.
        """
        self.validate()
        if verified_base_epoch != self.base_epoch or epoch != self.epoch:
            raise ValueError("Stale private buffer or wrong verified encrypted base")
        corrected = delta.Snapshot(self.base, self.base_epoch, self.epoch, self.patches).correct(base_scores, word, epoch=epoch)
        deleted = set(self.deleted_positions)
        pairs = [(identifier, score) for p, (identifier, score) in enumerate(zip(self.base.ids, corrected, strict=True)) if p not in deleted]
        pairs.extend((identifier, (row ^ word).bit_count()) for identifier, row in self.inserted)
        ids, scores = tuple(i for i, _ in pairs), tuple(s for _, s in pairs)
        return Result(ids, scores, tuple(heapq.nsmallest(3, ((score, identifier) for identifier, score in pairs))))


class Ledger:
    def __init__(self, plan, base_epoch):
        plan.workload.validate()
        masked.binding(base_epoch, bytes(16))
        self.plan, self.base_epoch = plan, base_epoch
        self._original = dict(zip(plan.ids, plan.workload.rows, strict=True))
        self._positions = {identifier: p for p, identifier in enumerate(plan.ids)}
        self._rows, self._ever_ids = dict(self._original), set(plan.ids)
        self._lock = threading.Lock()
        self.snapshot = Snapshot(plan.client_view(), base_epoch, secrets.token_bytes(32), (), (), ())

    @property
    def owner_historical_id_body_bytes_model(self):
        return 8 * len(self._ever_ids)

    def transact(self, *, edits=None, inserts=None, delete_ids=()):
        """Atomic trusted owner-approved edit/insert/delete; no historical reuse."""
        edits, inserts = {} if edits is None else edits, {} if inserts is None else inserts
        with self._lock:
            if (type(edits) is not dict or type(inserts) is not dict or type(delete_ids) is not tuple
                    or not (edits or inserts or delete_ids)
                    or any(type(i) is not int or not 0 <= i < 1 << 64 for i in (*edits, *inserts, *delete_ids))
                    or len(set(delete_ids)) != len(delete_ids) or set(edits).intersection(delete_ids)
                    or any(i not in self._rows for i in (*edits, *delete_ids))
                    or any(i in self._ever_ids for i in inserts)
                    or any(type(row) is not int or not 0 <= row < 1 << self.plan.dimension for row in (*edits.values(), *inserts.values()))):
                raise ValueError("Invalid owner-approved private buffer transaction")
            removed = set(delete_ids)
            rows = {i: row for i, row in self._rows.items() if i not in removed}
            rows.update(edits)
            rows.update(inserts)
            deleted = tuple(p for p, i in enumerate(self.plan.ids) if i not in rows)
            patches = []
            for identifier, original in self._original.items():
                if identifier in rows:
                    current = rows[identifier]
                    mask = original ^ current
                    if mask:
                        patches.append(delta.Patch(self._positions[identifier], mask & current, mask & original))
            appended = tuple(sorted((i, row) for i, row in rows.items() if i not in self._original))
            snapshot = Snapshot(self.snapshot.base, self.base_epoch, secrets.token_bytes(32), deleted, tuple(patches), appended)
            snapshot.validate()
            # Commit only after every validation and immutable snapshot build.
            self._rows, self.snapshot = rows, snapshot
            self._ever_ids.update(inserts)
            width = (self.plan.dimension + 7) // 8
            return {"method": "private_mutable_buffer", "current_rows": len(rows),
                    "private_snapshot_body_bytes_model": snapshot.private_body_bytes_model,
                    "private_update_body_bytes_model": 76 + (8 + width) * (len(edits) + len(inserts)) + 8 * len(delete_ids),
                    "base_tombstones": len(deleted), "changed_live_base_rows": len(patches), "inserted_live_rows": len(appended),
                    "owner_historical_id_body_bytes_model": self.owner_historical_id_body_bytes_model,
                    "server_update_body_bytes": 0, "ciphertexts_freshly_encrypted": 0,
                    "scope": "Trusted local owner/client; private body model; no transport, erasure, durable state or HE rebase."}
