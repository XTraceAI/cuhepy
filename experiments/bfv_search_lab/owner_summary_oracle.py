"""E103 known centroid/radius coverage control; plaintext exact/count oracle.

Owner-pinned complete metadata is a trust premise. SHA-256 contents bind to
that premise; this module does not deploy authentication, PIR, HE, durability
or timing privacy. Variable-work diagnostics and public fixed-budget count
models are separate. Ordinary triangle bounds and caching are known controls.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import heapq
from math import ceil
import struct

MAX_ROWS = 1 << 20
MAGIC = b"cuhepy/research/owner-summary/v1\0"
Record = tuple[int, int]  # (stable uint64 ID, binary word)


def _dimension(dimension):
    if type(dimension) is not int or not 1 <= dimension <= 512:
        raise ValueError("Invalid binary dimension")


def _records(records, dimension):
    _dimension(dimension)
    if (type(records) is not tuple or len(records) > MAX_ROWS
            or any(type(r) is not tuple or len(r) != 2
                   or type(r[0]) is not int or not 0 <= r[0] < 1 << 64
                   or type(r[1]) is not int or not 0 <= r[1] < 1 << dimension for r in records)
            or len({r[0] for r in records}) != len(records)):
        raise ValueError("Invalid binary records or repeated stable IDs")


def _body(records, dimension):
    width = ceil(dimension / 8)
    return b"".join(i.to_bytes(8, "little") + row.to_bytes(width, "little") for i, row in records)


def _digest(records, dimension):
    return hashlib.sha256(MAGIC + struct.pack("<HI", dimension, len(records))
                          + _body(records, dimension)).digest()


def centroid(records, dimension):
    """Known coordinate-majority center with zero at ties; empty center is zero."""
    _records(records, dimension)
    return sum(1 << j for j in range(dimension)
               if 2 * sum((row >> j) & 1 for _, row in records) > len(records))


@dataclass(frozen=True)
class Summary:
    count: int
    centroid: int
    radius: int
    minimum_id: int | None
    digest: bytes


@dataclass(frozen=True)
class Manifest:
    dimension: int
    count: int
    capacity: int
    epoch: bytes
    owner_dataset_digest: bytes
    groups: tuple[Summary, ...]

    def serialize(self):
        _dimension(self.dimension)
        if (type(self.count) is not int or not 0 <= self.count <= MAX_ROWS
                or type(self.capacity) is not int or not 1 <= self.capacity <= MAX_ROWS
                or type(self.epoch) is not bytes or len(self.epoch) != 32
                or type(self.owner_dataset_digest) is not bytes or len(self.owner_dataset_digest) != 32
                or type(self.groups) is not tuple or not 1 <= len(self.groups) <= MAX_ROWS):
            raise ValueError("Invalid owner-pinned manifest")
        width = ceil(self.dimension / 8)
        body = MAGIC + struct.pack("<HIII", self.dimension, self.count, self.capacity, len(self.groups))
        body += self.epoch + self.owner_dataset_digest
        total = 0
        for group in self.groups:
            if (type(group) is not Summary or type(group.count) is not int
                    or not 0 <= group.count <= self.capacity
                    or type(group.centroid) is not int or not 0 <= group.centroid < 1 << self.dimension
                    or type(group.radius) is not int or not 0 <= group.radius <= self.dimension
                    or type(group.digest) is not bytes or len(group.digest) != 32
                    or (group.count and (type(group.minimum_id) is not int or not 0 <= group.minimum_id < 1 << 64))
                    or (not group.count and (group.minimum_id is not None or group.centroid or group.radius))):
                raise ValueError("Invalid owner-pinned group metadata")
            total += group.count
            body += struct.pack("<IHQ", group.count, group.radius, group.minimum_id or 0)
            body += group.centroid.to_bytes(width, "little") + group.digest
        if total != self.count:
            raise ValueError("Pinned group counts do not cover the dataset")
        return body

    @property
    def digest(self):
        return hashlib.sha256(self.serialize()).digest()


@dataclass(frozen=True)
class Packet:
    epoch: bytes
    index: int | None
    records: tuple[Record, ...]


@dataclass(frozen=True)
class Enrollment:
    manifest: Manifest
    blocks: tuple[tuple[Record, ...], ...]
    owner_radius_distance_evaluations: int
    owner_centroid_bit_visits: int

    def fetch(self, index, epoch):
        if epoch != self.manifest.epoch:
            raise ValueError("Stale requested owner epoch")
        if index is None:
            return Packet(epoch, None, ())
        if type(index) is not int or not 0 <= index < len(self.blocks):
            raise ValueError("Unknown owner block")
        return Packet(epoch, index, self.blocks[index])


def enroll(records, groups, dimension, epoch):
    """Only a trusted complete owner dataset can authorize a coverage manifest."""
    _records(records, dimension)
    if (type(groups) is not tuple or not 1 <= len(groups) <= MAX_ROWS
            or any(type(group) is not tuple for group in groups)):
        raise ValueError("Invalid owner partition")
    flat = tuple(record for group in groups for record in group)
    _records(flat, dimension)
    if sorted(flat) != sorted(records):
        raise ValueError("Owner partition omits or changes live coverage")
    blocks = tuple(tuple(sorted(group)) for group in groups)
    summaries = []
    for block in blocks:
        center = centroid(block, dimension)
        radius = max(((row ^ center).bit_count() for _, row in block), default=0)
        summaries.append(Summary(len(block), center, radius, block[0][0] if block else None,
                                 _digest(block, dimension)))
    manifest = Manifest(dimension, len(records), max(1, max(map(len, blocks))), epoch,
                        _digest(tuple(sorted(records)), dimension), tuple(summaries))
    manifest.serialize()
    return Enrollment(manifest, blocks, len(records), len(records) * dimension)


def pin_candidate(candidate, pinned):
    """A server's replacement manifest cannot authorize a radius or omitted group."""
    if type(candidate) is not Manifest or type(pinned) is not Manifest:
        raise ValueError("Owner manifest objects required")
    if candidate.serialize() != pinned.serialize():
        raise ValueError("Server metadata differs from the current owner pin")
    return pinned


def _open_packet(packet, manifest, index):
    if (type(packet) is not Packet or type(packet.epoch) is not bytes or packet.epoch != manifest.epoch
            or packet.index != index or type(packet.index) not in (int, type(None))):
        raise ValueError("Stale or substituted owner block")
    _records(packet.records, manifest.dimension)
    if index is None:
        if packet.records:
            raise ValueError("Dummy slot contains unauthorized records")
        return ()
    summary = manifest.groups[index]
    if (len(packet.records) != summary.count or tuple(sorted(packet.records)) != packet.records
            or _digest(packet.records, manifest.dimension) != summary.digest):
        raise ValueError("Missing, changed or noncanonical owner block")
    return packet.records


def padded_packet_bytes(manifest):
    """Plaintext fixed packet model; PIR query, crypto and proof overhead unknown."""
    manifest.serialize()
    return 32 + 4 + 4 + manifest.capacity * (8 + ceil(manifest.dimension / 8))


def lower_bound(manifest, index, query):
    group = manifest.groups[index]
    distance = (query ^ group.centroid).bit_count()
    if not group.count:
        return None
    return max(0, distance - group.radius), group.minimum_id


@dataclass(frozen=True)
class Outcome:
    top3: tuple[tuple[int, int, int], ...] | None
    certified: bool
    fetched_groups: tuple[int, ...]
    fetched_records: int
    summary_distance_evaluations: int
    record_distance_evaluations: int
    paid_slots: int
    dummy_slots: int
    downloaded_record_packet_bytes_model: int


def search(manifest, query, fetch, *, budget=None):
    """Known exact triangle-bound oracle, with separately paid fixed-budget slots.

    The callback addresses/control flow are public here. No PIR/timing hiding is
    implemented. A fixed insufficient budget returns inconclusive, without retry.
    """
    manifest.serialize()
    if type(query) is not int or not 0 <= query < 1 << manifest.dimension:
        raise ValueError("Invalid binary query")
    if budget is not None and (type(budget) is not int or not 1 <= budget <= len(manifest.groups)):
        raise ValueError("Invalid public fixed budget")
    bounds = tuple(lower_bound(manifest, j, query) for j in range(len(manifest.groups)))
    order = sorted((bound, j) for j, bound in enumerate(bounds) if bound is not None)
    scored, fetched, fetched_records, dummy_slots, paid_slots = [], [], 0, 0, 0
    limit = len(order) if budget is None else budget
    position = 0
    for _ in range(limit):
        top = heapq.nsmallest(3, scored)
        done = position == len(order) or (len(top) == 3 and order[position][0] > top[-1][:2])
        if done and budget is None:
            break
        index = None if done else order[position][1]
        records = _open_packet(fetch(index, manifest.epoch), manifest, index)
        paid_slots += 1
        if index is None:
            dummy_slots += 1
        else:
            fetched.append(index)
            position += 1
            fetched_records += len(records)
        # Dummy distance calls are executed in fixed-budget mode. Python branch
        # behavior remains query dependent; only operation and traffic counts fix.
        scored.extend(((query ^ row).bit_count(), i, row) for i, row in records)
        if budget is not None:
            for _ in range(manifest.capacity - len(records)):
                (query ^ 0).bit_count()
    top = tuple(heapq.nsmallest(3, scored))
    certified = position == len(order) or (len(top) == 3 and order[position][0] > top[-1][:2])
    return Outcome(top if certified else None, certified, tuple(fetched), fetched_records,
                   len(manifest.groups), fetched_records if budget is None else budget * manifest.capacity,
                   paid_slots, dummy_slots, paid_slots * padded_packet_bytes(manifest))


class MutableCache:
    """Permitted plain owner cache; counters describe operations, not timings."""

    def __init__(self, records, dimension):
        _records(records, dimension)
        self.dimension, self.rows = dimension, dict(records)
        self.mutations = 0

    def query(self, query):
        if type(query) is not int or not 0 <= query < 1 << self.dimension:
            raise ValueError("Invalid cache query")
        return tuple(heapq.nsmallest(3, (((query ^ row).bit_count(), i, row) for i, row in self.rows.items())))

    def put(self, stable_id, row):
        _records(((stable_id, row),), self.dimension)
        self.rows[stable_id] = row
        self.mutations += 1

    def delete(self, stable_id):
        if type(stable_id) is not int or stable_id not in self.rows:
            raise ValueError("Deletion requires a live stable ID")
        del self.rows[stable_id]
        self.mutations += 1

    @property
    def serialized_body_bytes_model(self):
        return len(self.rows) * (8 + ceil(self.dimension / 8))


def balanced_layout(records, capacity=128):
    """Known sorted contiguous layout with coordinate-majority summaries."""
    if type(capacity) is not int or not 1 <= capacity <= MAX_ROWS:
        raise ValueError("Invalid sorted block capacity")
    ordered = tuple(sorted(records, key=lambda r: (r[1], r[0])))
    return tuple(ordered[start:start + capacity] for start in range(0, len(ordered), capacity)) or ((),)


def prototype_layout(records, groups=16):
    """Known nearest seed grouping; deterministic evenly spaced unique seeds.

    Seed selection sees owner rows only. No Lloyd iterations/query tuning are
    included. Radius summaries later use the resulting coordinate-majority center.
    """
    if type(groups) is not int or not 1 <= groups <= MAX_ROWS:
        raise ValueError("Invalid prototype group count")
    words = sorted({row for _, row in records})
    if not words:
        return tuple(() for _ in range(groups)), 0
    count = min(groups, len(words))
    seeds = tuple(words[j * len(words) // count] for j in range(count))
    blocks = [[] for _ in range(groups)]
    for record in records:
        index = min(range(count), key=lambda j: ((record[1] ^ seeds[j]).bit_count(), j))
        blocks[index].append(record)
    return tuple(tuple(block) for block in blocks), len(records) * count
