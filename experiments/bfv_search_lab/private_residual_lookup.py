"""E25 rejection control: encrypted residual positions need private selection.

A binary mux tree selects an encrypted query bit using encrypted address bits;
an encrypted sign in {-1,0,1} gives an exact signed residual (zero pads entries).
Everything is homemade BGV; repeated multiplication is relinearized explicitly.
This scalar, tiny reference deliberately charges d-1 mux products per entry,
plus one sign product, depth log2(d)+1 and d encrypted query constants. It is
not an efficient packed implementation or a universal lower bound on HE.

For separated bilinear encodings of lookup(q,j)=q_j over any field, the rows
q=e_i form an identity submatrix, so at least d features are necessary. Allowing
a free query-only affine offset can save one. Nonlinear/multiround protocols
and ring packing lie outside that scalar feature statement.

Private positions, signs and query constants must originate in trusted owner
enrollment. This is a local oracle; no remote authentication is provided.
"""

from __future__ import annotations

from experiments.bfv_search_lab import butterfly_bgv as butterfly
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace


def _multiply(a: bgv.Ciphertext, b: bgv.Ciphertext, pk: bgv.PublicKey, keys: trace.EvaluationKeys) -> bgv.Ciphertext:
    product = bgv.multiply(a, b, pk, karatsuba=True)
    switched = trace._switch(product.components[2], keys.relin, pk, keys.digit_bits)
    return trace._bounded(tuple(tuple((x + y) % pk.q for x, y in zip(left, right, strict=True))
                                for left, right in zip(product.components[:2], switched, strict=True)),
                          product.phase_bound + keys.switch_error_bound, pk)


def correction(
    query_bits: list[bgv.Ciphertext], address_bits: list[bgv.Ciphertext], sign: bgv.Ciphertext,
    one: bgv.Ciphertext, pk: bgv.PublicKey, keys: trace.EvaluationKeys,
) -> bgv.Ciphertext:
    """Return sign*(1-2*q[address]); signs/bitness are trusted fixture semantics."""
    d = len(query_bits)
    if not 2 <= d <= 16 or d & (d - 1) or len(address_bits) != d.bit_length() - 1:
        raise ValueError("Tiny lookup requires a power-of-two query of 2..16 bits")
    butterfly.validate_keys(pk, keys)
    for cipher in [*query_bits, *address_bits, sign, one]:
        bgv._validate(cipher, pk)
        if len(cipher.components) != 2:
            raise ValueError("Private mux requires relinearized inputs")
    work = query_bits.copy()
    for bit in address_bits:
        work = [trace._add(work[i], _multiply(bit, butterfly._subtract(work[i + 1], work[i], pk), pk, keys), pk)
                for i in range(0, len(work), 2)]
    twice = trace._add(work[0], work[0], pk)
    return _multiply(sign, butterfly._subtract(one, twice, pk), pk, keys)


def cost(dimension: int, rows: int, padded_errors: int) -> dict[str, int]:
    if (type(dimension) is not int or not 2 <= dimension <= 4096 or dimension & (dimension - 1)
            or type(rows) is not int or rows < 0 or type(padded_errors) is not int or padded_errors < 0):
        raise ValueError("Invalid scalar private-lookup count")
    return {"query_ciphertexts": dimension + 1, "index_ciphertexts": rows * padded_errors * dimension.bit_length(),
            "ciphertext_products": rows * padded_errors * dimension,
            "relinearizations": rows * padded_errors * dimension,
            "multiplicative_depth": dimension.bit_length(), "response_ciphertexts_before_packing": rows,
            "bilinear_scalar_features_without_query_offset_lower_bound": dimension}
