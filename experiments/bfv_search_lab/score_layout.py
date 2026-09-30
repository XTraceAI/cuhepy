"""E51: output-only CRT layout for transposed encrypted columns.

E27 packs a row's features before multiplication, so its padded feature width
must fit in each leaf. E29 encrypts separate columns ALREADY in score positions:
that input-packing restriction does not apply. Each leaf can hold degree-many
scores regardless of the number of columns. This module separates those two
interfaces; it is ordinary linear/CRT algebra, not a new encryption primitive.

Full encryption N and Q still require independent security/correctness review.
More columns cost more state, work and noise. Feature width is never a free
capacity gain or a reason to shrink the secret-key dimension without review.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from experiments.bfv_search_lab import dyadic_crt as crt
from experiments.bfv_search_lab import linear_packing as packing


@dataclass(frozen=True)
class Layout:
    context: crt.Context
    features: tuple[int, ...]
    counts: tuple[int, ...]
    kind: str = field(default="score_only_v1", init=False)
    padded: int = field(default=1, init=False)

    @property
    def virtual_count(self):
        return max(count * (self.context.n // leaf.degree)
                   for count, leaf in zip(self.counts, self.context.leaves, strict=True))

    @property
    def cost(self):
        replies = (self.virtual_count + self.context.n - 1) // self.context.n
        # No legacy row multiplication/butterfly occurs. Only transposed
        # encrypted-column evaluation may consume this schedule.
        return packing.PackingCost(1, 1, self.virtual_count, replies, 0, replies)


def layout(ctx, features, counts):
    crt.validate(ctx)
    if (type(features) is not tuple or type(counts) is not tuple
            or len(features) != len(ctx.leaves) or len(counts) != len(ctx.leaves)
            or any(type(f) is not int or not 1 <= f <= 512 for f in features)
            or any(type(c) is not int or not 0 <= c <= 32768 for c in counts)):
        raise ValueError("Invalid output-only CRT feature/count schedule")
    return Layout(ctx, features, counts)


def validate(plan):
    if type(plan) is not Layout or plan != layout(plan.context, plan.features, plan.counts):
        raise ValueError("Inconsistent output-only CRT schedule")


def allocate(groups, rows, slots, *, n=None):
    """Fixed private-map control: minimize replies with degree-many row slots.

    Map discovery is unchanged/charged separately. Ordinary integer allocation
    and coalescing are reused; the sole change is that input feature padding no
    longer determines output capacity. This is not a joint-planner theorem.
    """
    from experiments.bfv_search_lab import field_frontier as fields
    from experiments.bfv_search_lab import rank_partition as partition
    fields.validate(groups, rows)
    n = groups.n if n is None else n
    if (type(slots) is not int or not 1 <= slots <= fields.max_slots(groups.prime)
            or slots & (slots - 1)):
        raise ValueError("Output CRT slots need roots in the selected plaintext field")
    depth = slots.bit_length() - 1
    paths = tuple(format(i, f"0{depth}b") for i in range(slots)) if depth else ("",)
    crt.context(n, paths, groups.prime)
    grouped = {}
    for block in groups.blocks:
        grouped.setdefault(block.mapping, []).extend(block.positions)
    maps = tuple(grouped)
    positions = tuple(tuple(grouped[p]) for p in maps)
    replies, allocation = partition.allocate_slots(tuple(map(len, positions)), slots, n // slots)
    labels = [i for i, count in enumerate(allocation) for _ in range(count)]
    leaves = []
    def cover(path, start, stop):
        if stop - start == 1 or all(label == labels[start] for label in labels[start:stop]):
            leaves.append((path, labels[start]))
        else:
            middle = (start + stop) // 2
            cover(path + "0", start, middle)
            cover(path + "1", middle, stop)
    cover("", 0, slots)
    offsets, blocks = [0] * len(maps), []
    for path, group in leaves:
        count = min(len(positions[group]) - offsets[group], replies * (n >> len(path)))
        piece = positions[group][offsets[group]:offsets[group] + count]
        offsets[group] += count
        blocks.append(partition.Block(path, piece, maps[group]))
    if offsets != list(map(len, positions)):
        raise AssertionError("Output allocation omitted a record")
    ctx = crt.context(n, tuple(b.path for b in blocks), groups.prime)
    output = layout(ctx, tuple(b.mapping.features for b in blocks), tuple(len(b.positions) for b in blocks))
    candidate = partition.Candidate(output, tuple(blocks), groups.cuts, groups.source_digest,
                                    groups.dimension, partition.map_body_bytes(tuple(blocks)), groups.target)
    partition.validate_epoch(candidate, rows)
    if output.cost.response_ciphertexts != replies:
        raise AssertionError("Output allocation and actual CRT capacity disagree")
    return candidate
