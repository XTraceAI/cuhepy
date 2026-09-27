"""E25: exact sparse residuals on the owner, folded templates on the evaluator.

For x != z at coordinate j, H(q,x)-H(q,z) = (1-2*q_j)*(2*x_j-1).
Store just these positions and original bits with the owner. Two masks per row
make each online correction two AND/popcounts. No refinement query or radius
threshold is needed. This changes client state/privacy, not the BGV scheme.

Hints disclose data-dependent positions AND values to their holder. They belong
only to the index owner and must be pinned with map/index/epoch. Python private
correction is variable-time. Neither a hint nor a plausible corrected distance
authenticates a server response; existing authentication remains mandatory.
"""

from __future__ import annotations

from dataclasses import dataclass
import struct
import sys

from experiments.bfv_search_lab import folded_filter as folded


@dataclass(frozen=True)
class Hint:
    dimension: int
    count: int
    offsets: bytes  # count+1 little-endian uint32 entry offsets.
    entries: bytes  # Sorted (position << 1 | original_bit), fixed-width per dimension.

    @property
    def body_bytes(self) -> int:
        """Canonical array bodies only; context/framing/epoch binding excluded."""
        return len(self.offsets) + len(self.entries)


@dataclass(frozen=True)
class Prepared:
    dimension: int
    positive: tuple[int, ...]
    negative: tuple[int, ...]
    bias: tuple[int, ...]

    @property
    def python_mask_bytes(self) -> int:
        """Conservative shallow object sum; shared small integers counted again."""
        return (sys.getsizeof(self) + sys.getsizeof(self.__dict__)
                + sum(sys.getsizeof(xs) + sum(sys.getsizeof(x) for x in xs)
                      for xs in (self.positive, self.negative, self.bias)))


def prepare(plan: folded.FoldPlan, rows: list[int]) -> Hint:
    folded.validate(plan)
    folded._words(0, rows, plan.dimension)
    if len(rows) > 32768:
        raise ValueError("Residual hint exceeds bounded research workload")
    width = ((plan.dimension - 1).bit_length() + 1 + 7) // 8
    offsets, entries, count = [0], bytearray(), 0
    for row in rows:
        changed = row ^ folded._template(plan, row)
        if changed.bit_count() > plan.max_error:
            raise ValueError("Residual outside pinned dictionary epoch")
        while changed:
            bit = changed & -changed
            position = bit.bit_length() - 1
            entries.extend(((position << 1) | ((row >> position) & 1)).to_bytes(width, "little"))
            count += 1
            changed ^= bit
        offsets.append(count)
    return Hint(plan.dimension, len(rows), struct.pack(f"<{len(offsets)}I", *offsets), bytes(entries))


def compile_hint(hint: Hint) -> Prepared:
    """Validate once on trusted enrollment, then build owner-only popcount masks."""
    if (type(hint.dimension) is not int or not 1 <= hint.dimension <= 4096
            or type(hint.count) is not int or not 0 <= hint.count <= 32768
            or type(hint.offsets) is not bytes or type(hint.entries) is not bytes
            or len(hint.offsets) != 4 * (hint.count + 1)):
        raise ValueError("Invalid residual hint shape")
    width = ((hint.dimension - 1).bit_length() + 8) // 8
    offsets = struct.unpack(f"<{hint.count + 1}I", hint.offsets)
    if (len(hint.entries) % width or offsets[0] or offsets[-1] * width != len(hint.entries)
            or any(not 0 <= b - a <= hint.dimension for a, b in zip(offsets[:-1], offsets[1:], strict=True))):
        raise ValueError("Invalid residual entry offsets")
    positive, negative, biases = [], [], []
    for start, stop in zip(offsets[:-1], offsets[1:], strict=True):
        pos = neg = 0
        previous = -1
        for i in range(start, stop):
            code = int.from_bytes(hint.entries[i * width:(i + 1) * width], "little")
            j, bit = code >> 1, code & 1
            if not previous < j < hint.dimension:
                raise ValueError("Noncanonical residual position order or range")
            if bit:
                pos |= 1 << j
            else:
                neg |= 1 << j
            previous = j
        positive.append(pos)
        negative.append(neg)
        biases.append(pos.bit_count() - neg.bit_count())
    return Prepared(hint.dimension, tuple(positive), tuple(negative), tuple(biases))


def correct(prepared: Prepared, query: int, template_scores: list[int]) -> list[int]:
    """Exact local distances from an honestly evaluated template response."""
    folded._words(query, [], prepared.dimension)
    if (len(template_scores) != len(prepared.positive)
            or any(type(x) is not int or not 0 <= x <= prepared.dimension for x in template_scores)):
        raise ValueError("Invalid local template scores")
    distances = [score + bias - 2 * (query & pos).bit_count() + 2 * (query & neg).bit_count()
                 for score, pos, neg, bias in zip(template_scores, prepared.positive, prepared.negative, prepared.bias, strict=True)]
    if any(not 0 <= x <= prepared.dimension for x in distances):
        raise ValueError("Corrected distance outside local range")
    return distances
