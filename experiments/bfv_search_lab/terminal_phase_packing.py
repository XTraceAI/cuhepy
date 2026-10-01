"""E66 honest integer-phase packing oracle and additive-HE body counts.

No additive encryption or malicious release protocol. This prices the exact,
unrescaled linear phase, including signed bias and Q centering before mod t.
ZipPIR-style rescaling/packing and rate-1 schemes are DIFFERENT candidates.
"""

from __future__ import annotations


def integer_bound(n, q, secret_bound):
    if (any(type(x) is not int for x in (n, q, secret_bound))
            or n < 2 or n & (n - 1) or q < 3 or q % 2 == 0 or secret_bound < 1):
        raise ValueError("Expected positive bounded odd-Q ring geometry")
    return (q//2) * (1 + n*secret_bound)


def pack(values, bound, capacity_bits):
    """A signed-bias INTEGER packet, not a Paillier ciphertext."""
    if (type(values) is not tuple or not values or len(values) > 65536
            or type(bound) is not int or bound < 1 or type(capacity_bits) is not int
            or not 1 <= capacity_bits <= 8192
            or any(type(x) is not int or abs(x) > bound for x in values)):
        raise ValueError("Invalid bounded integer phases")
    bits = (2*bound).bit_length()
    slots = capacity_bits//bits
    if not slots:
        raise ValueError("Modulus capacity cannot hold one phase")
    return tuple(sum((x+bound) << (bits*j) for j, x in enumerate(values[start:start+slots]))
                 for start in range(0, len(values), slots))


def unpack(packets, count, bound, capacity_bits):
    if (type(packets) is not tuple or type(count) is not int or not 1 <= count <= 65536
            or type(bound) is not int or bound < 1 or type(capacity_bits) is not int
            or not 1 <= capacity_bits <= 8192):
        raise ValueError("Invalid integer packet geometry")
    bits = (2*bound).bit_length()
    slots = capacity_bits//bits
    if not slots or len(packets) != (count+slots-1)//slots:
        raise ValueError("Incorrect integer packet count")
    result = []
    for packet in packets:
        width = min(slots, count-len(result))
        if type(packet) is not int or not 0 <= packet < 1 << (width*bits):
            raise ValueError("Noncanonical integer packet")
        for j in range(width):
            x = ((packet >> (j*bits)) & ((1 << bits)-1))-bound
            if abs(x) > bound:
                raise ValueError("Phase outside signed bias range")
            result.append(x)
    return tuple(result)


def field_decode(phases, q, t):
    if (type(phases) is not tuple or type(q) is not int or q < 3 or not q % 2
            or type(t) is not int or not 3 <= t < q
            or any(type(x) is not int for x in phases)):
        raise ValueError("Incorrect phase fields")
    return tuple(((x % q) if x % q <= q//2 else x % q-q) % t for x in phases)


def cost(*, n, q, phases, secret_bound=1, paillier_bits=2048):
    bound = integer_bound(n, q, secret_bound)
    if type(phases) is not int or phases < 1 or type(paillier_bits) is not int or not 512 <= paillier_bits <= 8192:
        raise ValueError("Invalid modeled additive-HE geometry")
    bits, capacity = (2*bound).bit_length(), paillier_bits-1
    slots = capacity//bits
    if not slots:
        raise ValueError("Additive modulus cannot pack a phase")
    packets = (phases+slots-1)//slots
    reply = packets*((2*paillier_bits+7)//8)
    original = (2*phases*q.bit_length()+7)//8
    return {"integer_phase_bound": bound, "biased_phase_limb_bits": bits,
            "conservative_modulus_capacity_bits": capacity, "packed_phases_per_packet": slots,
            "additive_ciphertext_packets": packets, "additive_reply_body_bytes": reply,
            "original_full_two_component_body_bytes": original,
            "ideal_public_C1_recipe_C0_body_bytes": (phases*q.bit_length()+7)//8,
            "additive_to_full_body_ratio": reply/original,
            "per_coefficient_encrypted_secret_key_body_bytes": n*((2*paillier_bits+7)//8),
            "straight_coefficient_method_exponentiations": n*packets,
            "additive_crypto_implemented": False,
            "rescaling_or_smaller_modulus_correctness_established": False,
            "scope": "Exact unrescaled integer-phase control; no trusted/malicious receiver, crypto timing, setup/proof/framing or noise/privacy assurance. Key/exp counts are the straight coefficient method, not universal lower bounds."}
