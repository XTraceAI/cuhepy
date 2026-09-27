#!/usr/bin/env python3
"""CPU reference experiment: exact coefficient-packed BFV versus shallow BGV.

No rotations, relinearization or result repacking. Both operands are encrypted;
all response coefficients reach the owner. This exposes extra correlations and
is only suitable for local fixtures or an owner authorized for the full data.
The two BGV parameter sets have no reviewed security-equivalence claim.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import platform
import random
import statistics
import subprocess
import sys
import time

import gmpy2
from gmpy2 import mpz
import msgpack

from bfv_client_matrix import REPO_ROOT, make_data

sys.path.insert(0, str(REPO_ROOT))
from cuhepy.bfv.scheme import BFV
from cuhepy.types import BFVCiphertext
from experiments.bfv_search_lab import shallow_bgv as bgv


def timed(fn, *args, **kwargs):
    start = time.perf_counter()
    result = fn(*args, **kwargs)
    return time.perf_counter() - start, result


class Case:
    def __init__(self, mode, n, t, q_bits, compact=False, karatsuba=False, rns_modulus=False):
        self.mode, self.n, self.t = mode, n, t
        self.compact, self.karatsuba = compact, karatsuba
        if mode == "bfv":
            self.keys = BFV.key_gen(n, t, q_bits, relinearization=False)
            self.pk, self.sk = self.keys["pk"], self.keys["sk"]
            self.q, self.key_id = self.pk["q"], self.pk["key_id"]
        else:
            self.pk, self.sk = bgv.key_gen(n, t, q_bits, rns_modulus=rns_modulus)
            self.q, self.key_id = self.pk.q, self.pk.key_id
        self.name = f"{mode}-t{t}-q{q_bits}"
        if compact:
            self.name += "-terminal50"
        if karatsuba:
            self.name += "-three-products"

    def encrypt(self, poly):
        if self.mode == "bfv":
            return BFV.encrypt(tuple(mpz(x % self.t) for x in poly), self.pk)
        return bgv.encrypt(poly, self.pk)

    def evaluate(self, query, index):
        if self.mode == "bfv":
            result = [BFV.multiply(query, tile, self.pk, relinearize=False) for tile in index]
            if self.compact:
                result = [BFV.modulus_switch(ct, 50, self.pk) for ct in result]
            return result
        return [bgv.multiply(query, tile, self.pk, karatsuba=self.karatsuba) for tile in index]

    def decrypt(self, ciphertext):
        if self.mode == "bfv":
            return [int(x) for x in BFV.decrypt(ciphertext, self.keys)]
        return bgv.decrypt(ciphertext, self.pk, self.sk)

    def pack(self, ciphertexts, count):
        q = ciphertexts[0].modulus if self.mode == "bfv" else self.q
        bits = q.bit_length()
        # Fixed-bit polynomial bytes plus explicit public context, same framing
        # for both references. No decryption data or secret keys enter the wire.
        header = [
            "cuhepy-lab-coeff-v1",
            self.mode,
            self.n,
            self.t,
            int(q).to_bytes((bits + 7) // 8, "little"),
            bytes.fromhex(self.key_id),
            count,
        ]
        body = [
            [
                int(gmpy2.pack(list(poly), bits)).to_bytes((self.n * bits + 7) // 8, "little")
                for poly in ct.components
            ]
            for ct in ciphertexts
        ]
        return msgpack.packb([header, body], use_bin_type=True)

    def unpack(self, packet, count, components):
        # This harness handles its own bounded local fixtures, not network input.
        header, body = msgpack.unpackb(packet)
        if header[:4] != ["cuhepy-lab-coeff-v1", self.mode, self.n, self.t] or header[5:] != [
            bytes.fromhex(self.key_id),
            count,
        ]:
            raise ValueError("Incorrect reference packet context")
        q = mpz.from_bytes(header[4], "little")
        bits = q.bit_length()
        result = []
        for item in body:
            if len(item) != components:
                raise ValueError("Incorrect reference component count")
            polys = []
            for packed in item:
                if len(packed) != (self.n * bits + 7) // 8:
                    raise ValueError("Incorrect reference polynomial size")
                values = gmpy2.unpack(mpz.from_bytes(packed, "little"), bits)
                if len(values) > self.n or any(x >= q for x in values):
                    raise ValueError("Noncanonical reference polynomial")
                values.extend([mpz(0)] * (self.n - len(values)))
                polys.append(tuple(values))
            if self.mode == "bfv":
                result.append(BFVCiphertext(tuple(polys), q, self.key_id))
            else:
                if q != self.q:
                    raise ValueError("Unsupported BGV modulus")
                bound = self.pk.fresh_bound if components == 2 else self.n * self.pk.fresh_bound**2
                result.append(bgv.Ciphertext(tuple(polys), self.key_id, bound))
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--num-vectors", type=int, default=128)
    parser.add_argument("--embed-len", type=int, default=512)
    parser.add_argument("--ring-degree", type=int, default=16384)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--seed", type=int, default=1441)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.embed_len <= 512 or args.num_vectors < 1 or args.repeats < 1:
        parser.error("positive sizes/repeats and dimension <= 512 required")
    rows, initial_query, _ = make_data(args.num_vectors, args.embed_len, args.seed)
    _, tiles = bgv.coefficient_inputs(initial_query, rows, args.ring_degree)
    cases, setup = [], {}
    for mode, t, bits, compact, karatsuba in (
        ("bfv", 65537, 180, False, False),
        ("bfv", 65537, 180, True, False),
        ("bgv", 65537, 180, False, False),
        ("bgv", 65537, 180, False, True),
        ("bgv", 1031, 90, False, True),
    ):
        seconds, case = timed(Case, mode, args.ring_degree, t, bits, compact, karatsuba)
        print(f"Preparing {case.name}", file=sys.stderr, flush=True)
        index_s, case.index = timed(lambda encrypt=case.encrypt: [encrypt(tile) for tile in tiles])
        setup[case.name] = {
            "keygen_s": seconds,
            "index_encrypt_s": index_s,
            "index_bytes": len(case.pack(case.index, len(rows))),
            "input_tiles": len(tiles),
        }
        if mode == "bgv":
            setup[case.name]["public_phase_bound_bits_after_product"] = (
                case.n * case.pk.fresh_bound**2
            ).bit_length()
            setup[case.name]["conservative_no_wrap_bound_holds"] = (
                2 * case.n * case.pk.fresh_bound**2 < case.q
            )
        cases.append(case)

    def run(case, query):
        sample = {}
        start = time.perf_counter()

        def prepare():
            qp, _ = bgv.coefficient_inputs(query, [], case.n)
            return case.pack([case.encrypt(qp)], 1)

        sample["client_prepare_s"], query_bytes = timed(prepare)
        sample["server_unpack_s"], received = timed(lambda: case.unpack(query_bytes, 1, 2)[0])
        sample["server_evaluate_s"], response = timed(lambda: case.evaluate(received, case.index))
        sample["response_pack_s"], response_bytes = timed(lambda: case.pack(response, len(rows)))
        sample["client_unpack_s"], received = timed(
            lambda: case.unpack(response_bytes, len(rows), 3)
        )

        def decode():
            plaintexts = [case.decrypt(ct) for ct in received]
            return bgv.decode_coefficients(plaintexts, len(rows), args.embed_len, case.n, case.t)

        sample["client_decode_s"], distances = timed(decode)
        sample["client_top3_s"], top = timed(
            lambda: sorted(range(len(rows)), key=lambda i: (distances[i], i))[:3]
        )
        sample["online_total_s"] = time.perf_counter() - start
        expected = [sum(a != b for a, b in zip(query, row, strict=True)) for row in rows]
        if (
            distances != expected
            or top != sorted(range(len(rows)), key=lambda i: (expected[i], i))[:3]
        ):
            raise AssertionError(f"Incorrect coefficient search: {case.name}")
        sample["query_bytes"], sample["response_bytes"] = len(query_bytes), len(response_bytes)
        sample["query_plus_response_bytes"] = len(query_bytes) + len(response_bytes)
        return sample

    warmup = {case.name: run(case, initial_query) for case in cases}
    samples = {case.name: [] for case in cases}
    rng = random.Random(args.seed + 1)
    for repeat in range(args.repeats):
        query = initial_query.copy()
        query[repeat % len(query)] ^= 1
        order = cases.copy()
        rng.shuffle(order)
        for case in order:
            samples[case.name].append(run(case, query))
        print(
            f"Completed coefficient round {repeat + 1}/{args.repeats}", file=sys.stderr, flush=True
        )
    sources = [
        Path(__file__).resolve(),
        REPO_ROOT / "experiments/bfv_search_lab/shallow_bgv.py",
        REPO_ROOT / "src/cuhepy/bfv/scheme.py",
    ]
    report = {
        "kind": "cpu_reference_coefficient_layout_no_repacking_or_attestation",
        "utc": datetime.now(UTC).isoformat(),
        "command": sys.argv,
        "git_head": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True
        ).strip(),
        "python": sys.version,
        "platform": platform.platform(),
        "gmp": gmpy2.mp_version(),
        "num_vectors": len(rows),
        "dimension": args.embed_len,
        "ring_degree": args.ring_degree,
        "notes": "CPU Python/GMP reference algorithms only. Same coefficient packing and signed binary task. "
        "Fresh keys per case, independent encryption randomness, paired shuffled query rounds. "
        "No security equivalence claimed: BGV is depth-one RLWE with a conservative correctness bound, "
        "not full BGV. No relinearization, rotations or result repacking. Unmasked outputs expose "
        "additional correlations to the authorized owner. No network or attestation. "
        "Terminal BFV correctness is measured, not a general parameter assurance proof.",
        "sha256": {
            str(p.relative_to(REPO_ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sources
        },
        "setup": setup,
        "warmup": warmup,
        "results": [
            {
                "variant": case.name,
                "samples": samples[case.name],
                "medians": {
                    key: statistics.median(row[key] for row in samples[case.name])
                    for key in samples[case.name][0]
                },
            }
            for case in cases
        ],
        "all_distances_and_top3_correct": True,
    }
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2) + "\n")
    for row in report["results"]:
        med = row["medians"]
        print(
            f"{row['variant']:42} server={med['server_evaluate_s']:.6f}s "
            f"complete={med['online_total_s']:.6f}s response={med['response_bytes']}B"
        )


if __name__ == "__main__":
    main()
