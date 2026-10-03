"""E113 exact public bound/count screen; no key generator or security approval.

The owner law, joint-support identity, digit caps and congruent terminal map
are existing controls. A passing integer bound does not bypass shallow key_gen
or implement a malicious-server admission protocol.
"""

from __future__ import annotations

from dataclasses import dataclass

from gmpy2 import mpz
import msgpack

from cuhepy.bfv.scheme import _rns_coefficient_primes
from experiments.bfv_search_lab import compact_bgv as compact
from experiments.bfv_search_lab import compressed_query_bgv as codec
from experiments.bfv_search_lab import seeded_bgv as seeded


@dataclass(frozen=True)
class Profile:
    n: int
    dimension: int
    count: int
    t: int = 1031
    eta: int = 21
    digit_bits: int = 15

    def validate(self):
        values = (self.n, self.dimension, self.count, self.t, self.eta, self.digit_bits)
        if any(type(x) is not int for x in values):
            raise ValueError("Expected exact integer profile")
        if (not 8 <= self.n <= 32768 or self.n & (self.n-1)
            or not 1 <= self.dimension <= self.n//2 or self.count < 1
            or not 2*self.dimension < self.t < 1 << 30 or not self.t & 1
            or not 1 <= self.eta <= 64 or not 4 <= self.digit_bits <= 60):
            raise ValueError("Invalid complete coefficient-search profile")

    @property
    def padded(self):
        return 1 << (self.dimension-1).bit_length()


def ceil_div(a, b):
    return -(-a//b)


def maximum_digit_sum(q: int, bits: int):
    """Exact maximum and attaining word below q, by first differing base digit.

    Every x<q either equals q-1, or first differs from q-1 at a nonzero
    high digit. Keep its higher prefix, decrement that digit once and fill
    all lower digits. This covers the extremum without enumerating q words.
    """
    if type(q) is not int or q < 3 or type(bits) is not int or not 1 <= bits <= 60:
        raise ValueError("Invalid digit domain")
    radix = 1 << bits
    digits = [(q-1 >> j) & (radix-1) for j in range(0, q.bit_length(), bits)]
    best, witness = sum(digits), q-1
    for j, digit in enumerate(digits):
        if digit:
            prefix = (q-1) >> ((j+1)*bits)
            word = (prefix << ((j+1)*bits)) + (digit-1)*(radix**j) + radix**j-1
            score = sum(digits[j+1:])+digit-1+j*(radix-1)
            if score > best:
                best, witness = score, word
    return best, witness


def prime_and_root(n):
    """Actual existing deterministic prime selection, plus a public NTT witness."""
    q = _rns_coefficient_primes(n, 60)[0]
    if q % (2*n) != 1 or not prime64(q):
        raise ValueError("Actual source prime failed deterministic diagnostic")
    for base in range(2, 100):
        root = pow(base, (q-1)//(2*n), q)
        if pow(root, n, q) == q-1:
            return q, root
    raise ValueError("No primitive root witness in the frozen bounded search")


def prime64(value):
    """Deterministic Miller--Rabin for unsigned64-bit public candidates."""
    if type(value) is not int or not 2 <= value < 1 << 64:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if value % p == 0:
            return value == p
    d, shifts = value-1, 0
    while not d & 1:
        d >>= 1
        shifts += 1
    for base in (2, 325, 9375, 28178, 450775, 9780504, 1795265022):
        reduced = base % value
        # A base divisible by the candidate is not a Miller--Rabin witness.
        # Other bases still test composites sharing that divisor.
        if reduced == 0:
            continue
        x = pow(reduced, d, value)
        if x in (1, value-1):
            continue
        for _ in range(shifts-1):
            x = x*x % value
            if x == value-1:
                break
        else:
            return False
    return True


def group_shapes(profile):
    capacity = profile.n//profile.padded
    tiles = ceil_div(profile.count, capacity)
    return tuple(min(profile.padded, tiles-start) for start in range(0, tiles, profile.padded))


def schedule_count(padded, tiles):
    """Literal public butterfly node cardinality, including missing tails."""
    size, shift, rotations = tiles, padded//2, 0
    while shift:
        size = min(shift, size)
        rotations += size
        shift //= 2
    return rotations


def conservative_schedule(padded, tiles, input_bound, switch):
    work, shift = [input_bound]*tiles, padded//2
    while shift:
        work = [2*(work[i]+(work[i+shift] if i+shift < len(work) else 0))+switch
                for i in range(min(shift, len(work)))]
        shift //= 2
    return work[0]


def query_radius(q, t, drop):
    if type(drop) is not int or not 0 <= drop < q.bit_length():
        raise ValueError("Invalid query drop")
    if drop == 0:
        return 0, q.bit_length()
    encoding = codec.coefficient_encoding(mpz(q), t, drop)
    return encoding.added_bound, encoding.coefficient_bits


def complete_bound(profile, *, drop=0, index_mode="owner", relaxed=False):
    """Uniform deterministic phase envelopes, not observed/private noise."""
    profile.validate()
    if index_mode not in ("owner", "public") or type(relaxed) is not bool:
        raise ValueError("Invalid admitted input/digit law")
    q, root = prime_and_root(profile.n)
    p = int(compact.terminal_modulus(mpz(q), profile.t, 32))
    radius, query_bits = query_radius(q, profile.t, drop)
    n, t, eta, d = profile.n, profile.t, profile.eta, profile.dimension
    index_error = t*eta*(1 if index_mode == "owner" else 2*n+1)
    query_error = t*eta+radius
    product = (1+index_error)*(d+n*query_error)
    levels = ceil_div(q.bit_length(), profile.digit_bits)
    cap, witness = maximum_digit_sum(q, profile.digit_bits)
    relaxed_cap = levels*((1 << profile.digit_bits)-1)
    switch = t*eta*n*(relaxed_cap if relaxed else cap)
    final = profile.padded*product+(2*profile.padded-1)*switch
    rounding = ceil_div((n+1)*t, 2)
    terminal = ceil_div(p*final, q)+rounding
    public_fresh = t//2+t*eta*(2*n+1)
    generic_product = n*(t//2+t*eta+radius)*(t//2+index_error)
    conservative = tuple(conservative_schedule(profile.padded, size,
                                               generic_product+t*eta*n*relaxed_cap,
                                               t*eta*n*relaxed_cap)
                         for size in group_shapes(profile))
    return {
        "q": q, "p": p, "q_bits": q.bit_length(), "ntt_root": root,
        "query_drop": drop, "query_bits": query_bits, "query_added_bound": radius,
        "query_error_bound": query_error, "index_error_bound": index_error,
        "index_mode": index_mode, "relaxed_common_digits": relaxed,
        "levels": levels, "canonical_digit_sum_cap": cap,
        "canonical_cap_word": witness, "relaxed_digit_sum_cap": relaxed_cap,
        "factor2_verified": relaxed_cap <= 2*cap,
        "product_bound": product, "switch_bound": switch, "final_q_phase_bound": final,
        "terminal_rounding_bound": rounding, "terminal_phase_bound": terminal,
        "raw_margin_twice": q-2*final, "terminal_margin_twice": p-2*terminal,
        "raw_admitted": 2*final < q, "terminal_admitted": 2*terminal < p,
        "owner_bound_feasible": 2*final < q and 2*terminal < p,
        "general_keygen_guard_admitted": 2*n*public_fresh**2 < q,
        "general_keygen_guard_twice_product": 2*n*public_fresh**2,
        "generic_api_final_bounds": conservative,
        "generic_api_raw_admitted": all(2*b < q for b in conservative),
        "generic_api_terminal_admitted": all(2*(ceil_div(p*b, q)+rounding) < p
                                               for b in conservative),
        "partial_group_tile_counts": group_shapes(profile),
        "source_policy": "E15 joint-support + actual signed owner law + shared exact digit cap",
        "security_approved": False, "large_native_executed": False,
    }


def greatest_drop(profile, *, index_mode="owner", relaxed=False):
    """Entire frozen drop grid; preserve rejection count and uncompressed failure."""
    results = [complete_bound(profile, drop=d, index_mode=index_mode, relaxed=relaxed)
               for d in range(60)]
    feasible = [r for r in results if r["owner_bound_feasible"]]
    return {"baseline_drop0": results[0], "greatest_feasible": feasible[-1] if feasible else None,
            "tested_drop_count": len(results), "admitted_drop_count": len(feasible),
            "rejected_drop_count": len(results)-len(feasible)}


def challenge_repetitions(q, attempts=1 << 32, target_bits=128):
    if any(type(x) is not int or x < 1 for x in (q, attempts, target_bits)):
        raise ValueError("Invalid affine challenge budget")
    repetitions = 1
    while q**repetitions <= attempts*(1 << target_bits):
        repetitions += 1
    return repetitions


def array_header(count):
    return 1 if count < 16 else 3 if count < 65536 else 5


def binary_header(count):
    return 2 if count < 256 else 3 if count < 65536 else 5


def byte_card(profile, bound):
    """Exact named coefficient bodies/envelopes; no unimplemented proof costs."""
    n, d = profile.n, profile.padded
    coefficient_poly = ceil_div(n*bound["q_bits"], 8)
    tiles = sum(group_shapes(profile))
    groups = len(group_shapes(profile))
    levels, width = bound["levels"], ceil_div(bound["q_bits"], 8)
    families = d.bit_length()  # relin plus log2D rotation families
    query_body = ceil_div(n*bound["query_bits"], 8)
    query_prefix = [seeded._TAG, bytes(32), bytes(32)] if bound["query_drop"] == 0 else [
        codec._TAG, bytes(32), bytes(32), bound["query_drop"]]
    query_packet = (array_header(len(query_prefix)+1)
                    + sum(len(msgpack.packb(x, use_bin_type=True)) for x in query_prefix)
                    + binary_header(query_body)+query_body)
    response_poly = n*4
    response_header = ["cuhepy-lab-bgv-compact-v1", n, profile.t,
                       bound["p"].to_bytes(4, "little"), bytes(32), profile.count, profile.dimension]
    response_packet = (1+len(msgpack.packb(response_header, use_bin_type=True))
                       + array_header(groups)+groups*(1+2*(binary_header(response_poly)+response_poly)))
    rotations = sum(schedule_count(d, shape) for shape in group_shapes(profile))
    cuts = tiles+rotations
    terminal_coordinates = groups*2*n
    residuals = cuts*n+terminal_coordinates
    repetitions = challenge_repetitions(bound["q"])
    return {"public_ab_bitpacked_body_bytes": 2*coefficient_poly,
            "public_ab_bytealigned_native_input_body_bytes": 2*n*width,
            "private_secret_fullQ_bitpacked_body_model_bytes": coefficient_poly,
            "index_bitpacked_coefficient_body_model_bytes": tiles*2*coefficient_poly,
            "index_bytealigned_native_input_body_bytes": tiles*2*n*width,
            "all_evaluation_key_bitpacked_body_model_bytes": families*levels*2*coefficient_poly,
            "all_evaluation_key_bytealigned_native_input_body_bytes": families*levels*2*n*width,
            "native_index_uint64_slots_bytes": tiles*2*n*8,
            "native_key_uint64_slots_bytes": families*levels*2*n*8,
            "query_coefficient_body_bytes": query_body,
            "query_complete_packet_bytes": query_packet,
            "response_coefficient_body_bytes": groups*2*response_poly,
            "response_complete_compact_v1_packet_bytes": response_packet,
            "query_plus_response_complete_packet_bytes": query_packet+response_packet,
            "owner_plaintext_binary_index_bytes": ceil_div(profile.count*profile.dimension, 8),
            "stable_ids_uint64_body_bytes": profile.count*8,
            "product_cuts": tiles, "rotation_cuts": rotations, "all_cuts": cuts,
            "canonical_source_coordinates": cuts*n,
            "digit_coefficient_coordinates": cuts*n*levels,
            "terminal_coefficient_coordinates": terminal_coordinates,
            "one_prime_affine_residual_coordinates": residuals,
            "illustrative_global_affine_challenge_repetitions": repetitions,
            "illustrative_attempts": 1 << 32,
            "illustrative_stored_full_adjoints_uint64_bytes": repetitions*residuals*8,
            "ordinary_one_limb_control_count_ratio": 1,
            "unpriced": ["NTT plans/constructor auxiliary bases", "peak buffers and Python/GMP overhead",
                         "owner setup/encryption/switch products and key ID hashing",
                         "public/index/eval-key bitpacked enrollment serialization is unimplemented",
                         "authentication/registration lifecycle and enrollment envelope",
                         "scalar coefficient digit/range proof and terminal-P cross-field conversion",
                         "PCS/preprocess/setup/openings/transcript hashing and public query expansion",
                         "proof/receipt bytes and adaptive extraction/composition", "private side channels"],
            "challenge_scope": "Only fresh uniform fully-bound global affine residual dots: U/Q^k; not whole protocol security"}
