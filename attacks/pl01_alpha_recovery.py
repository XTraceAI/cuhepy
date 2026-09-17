"""PL-01 — recover the PaillierLookup secret key from the PUBLIC KEY alone.

The α-subgroup Paillier variant publishes ``g_n = g^n mod n^2`` in the public
key. Its multiplicative order is exactly ``a = lcm(q1, q2)``, an ``alpha_len``-bit
integer, and decryption uses only ``a`` (never ``phi``). Baby-step/giant-step
recovers ``a`` in ~2**(alpha_len/2) group operations, after which any ciphertext
decrypts with the public key only.

Run:
    uv run python attacks/pl01_alpha_recovery.py            # alpha_len=40, ~3s
    uv run python attacks/pl01_alpha_recovery.py 1024 50    # CPU default, ~3.5min

Mitigation: set alpha_len >= 2*lambda (>=256).
See docs/research/paillier-security.md (PL-01).
"""
from __future__ import annotations

import sys
import time

import gmpy2
import numpy as np
from gmpy2 import mpz

from cuhepy.paillier.lookup import PaillierLookup

_MASK = 0xFFFFFFFFFFFFFFFF


def recover_order_from_pk(g_n: mpz, n_sq: mpz, alpha_len: int) -> int | None:
    """BSGS for the order of ``g_n`` in Z_{n^2}*, bounded by 2**alpha_len."""
    m = int(gmpy2.isqrt(mpz(1) << alpha_len)) + 1
    baby = np.empty(m, dtype=np.uint64)
    cur = mpz(1)
    for j in range(m):
        baby[j] = int(cur) & _MASK
        cur = (cur * g_n) % n_sq
    order = np.argsort(baby, kind="stable")
    sorted_keys = baby[order]

    stride_inv = gmpy2.powmod(gmpy2.invert(g_n, n_sq), m, n_sq)
    giant = mpz(1)
    for i in range(m + 1):
        pos = int(np.searchsorted(sorted_keys, np.uint64(int(giant) & _MASK)))
        if pos < m and int(sorted_keys[pos]) == (int(giant) & _MASK):
            x = i * m + int(order[pos])
            if x > 0 and gmpy2.powmod(g_n, x, n_sq) == 1:
                return x
        giant = (giant * stride_inv) % n_sq
    return None


def main() -> int:
    key_len = int(sys.argv[1]) if len(sys.argv) > 1 else 512
    alpha_len = int(sys.argv[2]) if len(sys.argv) > 2 else 40

    t0 = time.perf_counter()
    keys = PaillierLookup.key_gen(key_len, alpha_len)
    pk, sk = keys["pk"], keys["sk"]
    print(f"[keygen] key_len={key_len} alpha_len={alpha_len} "
          f"({time.perf_counter()-t0:.1f}s); true a is {int(sk['a']).bit_length()} bits")

    # Attacker sees only pk.
    t0 = time.perf_counter()
    a = recover_order_from_pk(pk["g_n"], pk["n_squared"], alpha_len)
    print(f"[bsgs]   recovered a in {time.perf_counter()-t0:.1f}s")
    if a is None:
        print("FAILED")
        return 1
    print(f"[check]  recovered == true secret a: {a == int(sk['a'])}")

    # Decrypt a fresh ciphertext with pk + recovered a only (no sk).
    L, n, n_sq, g = PaillierLookup.L, pk["n"], pk["n_squared"], pk["g"]
    g_a_inv = gmpy2.powmod(L(gmpy2.powmod(g, a, n_sq), n), -1, n)
    msg = mpz(123456789)
    ct = PaillierLookup.encrypt(msg, pk, keys["g_table"], keys["noise_table"], keys["message_chunks"])
    pt = (L(gmpy2.powmod(ct, a, n_sq), n) * g_a_inv) % n
    print(f"[break]  decrypted with pk only: {pt == msg} (got {pt})")
    return 0 if a == int(sk["a"]) and pt == msg else 1


if __name__ == "__main__":
    raise SystemExit(main())
