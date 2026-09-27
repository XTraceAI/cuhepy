"""Plaintext layout checks and operation counts, not an encrypted benchmark.

Run from the repository root with Python 3.11+; no third-party packages are
needed. Small exhaustive/random fixtures check the algebra independently of
the BFV implementation. The large-workload table is an analytical model only.
"""

from __future__ import annotations

import argparse
import itertools
import json
import random
from pathlib import Path


def _power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def layout_model(count: int, dimension: int, n: int, partials: int, bits: int) -> dict[str, int]:
    """Count tile operations for a dimension-major partial-sum layout."""
    if count < 0 or not _power_of_two(n) or not 1 <= dimension <= n // 2 or bits < 1:
        raise ValueError("Require count >= 0, power-of-two N, 1 <= dimension <= N/2, bits > 0")
    padded = 1 << (dimension - 1).bit_length()
    if not _power_of_two(partials) or partials > padded:
        raise ValueError("partials must be a power of two no larger than the padded dimension")
    capacity = n // padded
    tiles = (count + capacity - 1) // capacity
    tiles_per_response = padded // partials
    responses = (tiles + tiles_per_response - 1) // tiles_per_response
    reduction_rotations = tiles * (tiles_per_response.bit_length() - 1)
    packing_rotations = tiles - responses
    return {
        "partials_per_vector": partials,
        "input_tiles": tiles,
        "reduction_rotations": reduction_rotations,
        "packing_rotations": packing_rotations,
        "rotations": reduction_rotations + packing_rotations,
        "relinearizations": tiles,
        "key_switches": reduction_rotations + packing_rotations + tiles,
        "response_ciphertexts": responses,
        "response_coefficient_bytes": responses * ((2 * n * bits + 7) // 8),
    }


def partial_distances(
    query: list[int], vectors: list[list[int]], n: int, partials: int
) -> list[int]:
    """Simulate rotations, masks, packing, and client summation in plaintext slots."""
    dimension = len(query)
    model = layout_model(len(vectors), dimension, n, partials, 50)
    padded = 1 << (dimension - 1).bit_length()
    lanes = n // (2 * padded)
    capacity = 2 * lanes
    group_size = padded // partials
    row_size = n // 2
    outputs = [[0] * n for _ in range(model["response_ciphertexts"])]

    for tile, start in enumerate(range(0, len(vectors), capacity)):
        items = vectors[start : start + capacity]
        slots = [0] * n
        for lane, vector in enumerate(items):
            row, column = divmod(lane, lanes)
            for j, (x, q) in enumerate(zip(vector, query, strict=True)):
                slots[row * row_size + j * lanes + column] = (x - q) ** 2

        for step in range(group_size.bit_length() - 1):
            shift = lanes * (1 << step)
            previous = slots
            slots = [
                previous[i] + previous[(i // row_size) * row_size + (i + shift) % row_size]
                for i in range(n)
            ]

        response, offset = divmod(tile, group_size)
        # Masks keep disjoint sums of group_size dimensions. Packing shifts
        # each tile into a separate column interval in every partial-sum band.
        for lane in range(len(items)):
            row, column = divmod(lane, lanes)
            for part in range(partials):
                source = row * row_size + part * group_size * lanes + column
                outputs[response][source + offset * lanes] += slots[source]

    distances = []
    per_response = capacity * group_size
    for position in range(len(vectors)):
        response, local = divmod(position, per_response)
        tile, lane = divmod(local, capacity)
        row, column = divmod(lane, lanes)
        distances.append(
            sum(
                outputs[response][
                    row * row_size + part * group_size * lanes + tile * lanes + column
                ]
                for part in range(partials)
            )
        )
    return distances


def coefficient_distances(query: list[int], vectors: list[list[int]], n: int) -> list[int]:
    """Check signed-bit dot products at selected negacyclic product coefficients.

    This deliberately returns every tile separately: no encrypted repacking or
    communication saving is implemented here. Other coefficients contain extra
    correlations and are not a distance-only output representation.
    """
    dimension = len(query)
    layout_model(len(vectors), dimension, n, 1, 50)
    padded = 1 << (dimension - 1).bit_length()
    capacity = n // padded
    # No SIMD batching is assumed here. This toy plaintext ring modulus needs
    # only to distinguish every signed dot product in [-dimension, dimension].
    # It is not a reviewed BFV parameter (and need not even be prime).
    t = 2 * dimension + 1
    backward = [(padded - 1 - j, 1 - 2 * bit) for j, bit in enumerate(query)]
    distances = []
    for start in range(0, len(vectors), capacity):
        items = vectors[start : start + capacity]
        product = [0] * n
        for lane, vector in enumerate(items):
            for j, bit in enumerate(vector):
                for degree, coefficient in backward:
                    exponent = lane * padded + j + degree
                    value = (1 - 2 * bit) * coefficient
                    # X^N = -1. In particular, the last vector can wrap into
                    # low coefficients; the selected dot-product terms survive.
                    product[exponent % n] += value if exponent < n else -value
        for lane in range(len(items)):
            signed_dot = product[lane * padded + padded - 1] % t
            if signed_dot > t // 2:
                signed_dot -= t
            if (dimension - signed_dot) % 2:
                raise AssertionError("Signed-bit dot product has incorrect parity")
            distances.append((dimension - signed_dot) // 2)
    return distances


def verify_layouts() -> dict[str, int | str]:
    """Exercise all small bit pairs, tails, zero padding, and negacyclic wrap."""
    checks = {"partial_layout_cases": 0, "coefficient_layout_cases": 0}

    def check(query: list[int], vectors: list[list[int]], n: int) -> None:
        expected = [sum(x != q for x, q in zip(vector, query, strict=True)) for vector in vectors]
        padded = 1 << (len(query) - 1).bit_length()
        for exponent in range(padded.bit_length()):
            if partial_distances(query, vectors, n, 1 << exponent) != expected:
                raise AssertionError(("partial layout", n, query, exponent))
            checks["partial_layout_cases"] += 1
        if coefficient_distances(query, vectors, n) != expected:
            raise AssertionError(("coefficient layout", n, query))
        checks["coefficient_layout_cases"] += 1

    for dimension in range(1, 5):
        binary = list(itertools.product((0, 1), repeat=dimension))
        n = 2 * (1 << (dimension - 1).bit_length())
        for query_bits, other in itertools.product(binary, repeat=2):
            check(list(query_bits), [list(other), [1 - bit for bit in other], list(query_bits)], n)

    rng = random.Random(1337)  # Plaintext fixtures only; never encryption randomness.
    for n, dimension in ((32, 5), (64, 16), (128, 31)):
        padded = 1 << (dimension - 1).bit_length()
        capacity = n // padded
        for count in (0, 1, capacity - 1, capacity, capacity + 1, n - 1, n, n + 1, 2 * n + 1):
            query = [rng.randrange(2) for _ in range(dimension)]
            vectors = [[rng.randrange(2) for _ in range(dimension)] for _ in range(count)]
            check(query, vectors, n)

    return {
        "scope": "plaintext algebra only; no encrypted execution or security estimate",
        **checks,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--num-vectors", type=int, default=8192)
    parser.add_argument("--embed-len", type=int, default=512)
    parser.add_argument("--ring-degree", type=int, default=16384)
    parser.add_argument("--response-bits", type=int, default=50)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    try:
        layout_model(args.num_vectors, args.embed_len, args.ring_degree, 1, args.response_bits)
    except ValueError as error:
        parser.error(str(error))
    verification = verify_layouts()
    padded = 1 << (args.embed_len - 1).bit_length()
    rows = [
        layout_model(
            args.num_vectors, args.embed_len, args.ring_degree, 1 << exponent, args.response_bits
        )
        for exponent in range(padded.bit_length())
    ]
    report = {
        "kind": "analytical_operation_counts_not_performance_measurements",
        "verification": verification,
        "parameters": {
            "num_vectors": args.num_vectors,
            "embed_len": args.embed_len,
            "ring_degree": args.ring_degree,
            "response_bits": args.response_bits,
        },
        "notes": "Bytes count only two-component ciphertext coefficients; framing is excluded. "
        "Key-switch counts include one relinearization per input tile. "
        "Partial sums disclose more to the decrypting client than final distances.",
        "partial_reduction": rows,
    }
    print(json.dumps(verification, indent=2))
    print("partials  rotations  key-switches  responses  coefficient-bytes")
    for row in rows:
        print(
            f"{row['partials_per_vector']:8}  {row['rotations']:9}  {row['key_switches']:12}  "
            f"{row['response_ciphertexts']:9}  {row['response_coefficient_bytes']:17}"
        )
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
