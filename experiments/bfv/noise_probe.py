"""Check one tile's noise budget without weakening SEAL's TC128 security setting.

This diagnostic deliberately permits the 4096-slot configuration excluded by
the main prototype. It stops on exhaustion, rather than accepting wrong distances.
All keys/data stay local. Run separately from timing benchmarks.
"""

import argparse
import json
import random
from typing import Any

from tenseal import sealapi as seal


def probe(degree: int, dimension: int, seed: int) -> dict[str, Any]:
    if dimension < 1 or dimension > degree // 2 or dimension & (dimension - 1):
        raise ValueError("dimension must be a power of two in [1, degree / 2]")
    row_size, lanes = degree // 2, degree // (2 * dimension)
    params = seal.EncryptionParameters(seal.SCHEME_TYPE.BFV)
    params.set_poly_modulus_degree(degree)
    params.set_plain_modulus(65537)
    params.set_coeff_modulus(seal.CoeffModulus.BFVDefault(degree, seal.SEC_LEVEL_TYPE.TC128))
    context = seal.SEALContext(params, True, seal.SEC_LEVEL_TYPE.TC128)
    if not context.parameters_set():
        raise ValueError(context.parameters_error_message())
    keygen = seal.KeyGenerator(context)
    pk, relin, galois = seal.PublicKey(), seal.RelinKeys(), seal.GaloisKeys()
    keygen.create_public_key(pk)
    keygen.create_relin_keys(relin)
    steps = [lanes << i for i in range(dimension.bit_length() - 1)]
    if steps:
        keygen.create_galois_keys([pow(3, step, 2 * degree) for step in steps], galois)
    encryptor, encoder = seal.Encryptor(context, pk), seal.BatchEncoder(context)
    evaluator, decryptor = seal.Evaluator(context), seal.Decryptor(context, keygen.secret_key())
    rng = random.Random(seed)
    query = [rng.randrange(2) for _ in range(dimension)]
    vectors = [[rng.randrange(2) for _ in range(dimension)] for _ in range(2 * lanes)]

    def encrypt(values: list[int]) -> Any:
        plain, encrypted = seal.Plaintext(), seal.Ciphertext()
        encoder.encode(values, plain)
        encryptor.encrypt(plain, encrypted)
        return encrypted

    q = encrypt([query[j] for _row in range(2) for j in range(dimension) for _lane in range(lanes)])
    x = encrypt([vectors[row * lanes + lane][j] for row in range(2) for j in range(dimension) for lane in range(lanes)])
    budgets = {"fresh": decryptor.invariant_noise_budget(x)}
    result = seal.Ciphertext()
    evaluator.sub(x, q, result)
    evaluator.square_inplace(result)
    evaluator.relinearize_inplace(result, relin)
    budgets["square"] = decryptor.invariant_noise_budget(result)
    for step in steps:
        rotated = seal.Ciphertext()
        evaluator.rotate_rows(result, step, galois, rotated)
        evaluator.add_inplace(result, rotated)
    budgets["sum"] = decryptor.invariant_noise_budget(result)
    mask = seal.Plaintext()
    encoder.encode([int(i % row_size < lanes) for i in range(degree)], mask)
    evaluator.multiply_plain_inplace(result, mask)
    budgets["mask"] = decryptor.invariant_noise_budget(result)
    correct = None
    if budgets["mask"] > 0:
        decoded = seal.Plaintext()
        decryptor.decrypt(result, decoded)
        slots = encoder.decode_uint64(decoded)
        expected = [sum(x != q for x, q in zip(v, query, strict=True)) for v in vectors]
        correct = slots[:lanes] + slots[row_size:row_size + lanes] == expected
    return dict(degree=degree, dimension=dimension, seed=seed, security="TC128",
                coeff_modulus_bits=[modulus.bit_count() for modulus in params.coeff_modulus()],
                noise_budget_bits=budgets, distances_correct=correct,
                status="noise_exhausted" if budgets["mask"] <= 0 else "ok" if correct else "incorrect")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--degree", type=int, choices=[4096, 8192], default=4096)
    parser.add_argument("--dimension", type=int, default=512)
    parser.add_argument("--seed", type=int, default=1337)
    args = parser.parse_args()
    print(json.dumps(probe(args.degree, args.dimension, args.seed), indent=2))
