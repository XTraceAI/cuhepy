"""Independent signed schoolbook diagnostics for E113's disclosed tiny fixture."""

from __future__ import annotations

from dataclasses import asdict
from itertools import product

from gmpy2 import mpz

from experiments.bfv_search_lab import butterfly_bgv as butterfly
from experiments.bfv_search_lab import compact_bgv as compact
from experiments.bfv_search_lab import compressed_query_bgv as codec
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import trace_bgv as trace
from experiments.bfv_search_lab.one_prime_bounds import Profile, complete_bound


def schoolbook(a, b):
    n, result = len(a), [0]*len(a)
    if len(b) != n:
        raise ValueError("Mismatched polynomial sizes")
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            turns, at = divmod(i+j, n)
            result[at] += x*y*(-1 if turns & 1 else 1)
    return result


def centered(value, modulus):
    residue = int(value) % modulus
    return residue if residue <= modulus//2 else residue-modulus


def phase(components, secret, modulus):
    signed = tuple(-1 if x == modulus-1 else x for x in secret)
    work = tuple(int(x) for x in components[-1])
    for poly in reversed(components[:-1]):
        work = tuple(a+b for a, b in zip(poly, schoolbook(work, signed), strict=True))
    return tuple(centered(x, modulus) for x in work)


def nearest_congruent(c, q, p, t):
    """Compare neighboring integers with exact numerators, not production formula."""
    residue = c % t
    below = (p*c-q*residue)//(q*t)
    candidates = (residue+t*below, residue+t*(below+1))
    return min(candidates, key=lambda y: (abs(q*y-p*c), -y))


def messages(query, rows, n):
    d, padded = len(query), 1 << (len(query)-1).bit_length()
    backward, tiles = [0]*n, []
    for j, bit in enumerate(query):
        backward[padded-1-j] = 1-2*bit
    for start in range(0, len(rows), n//padded):
        tile = [0]*n
        for lane, row in enumerate(rows[start:start+n//padded]):
            for j, bit in enumerate(row):
                tile[lane*padded+j] = 1-2*bit
        tiles.append(tile)
    return backward, tiles


def ideal_polynomials(query, rows, n, t):
    backward, tiles = messages(query, rows, n)
    padded = 1 << (len(query)-1).bit_length()
    output = []
    for start in range(0, len(tiles), padded):
        result = [0]*n
        for slot, tile in enumerate(tiles[start:start+padded]):
            source, shifted = schoolbook(backward, tile), [0]*n
            for j, value in enumerate(source):
                turns, at = divmod(j+1-padded, n)
                shifted[at] = value*(-1 if turns & 1 else 1)
            for position in range(0, n, padded):
                result[position+slot] = padded*shifted[position] % t
        output.append(tuple(result))
    return tuple(output)


def ints(value):
    if isinstance(value, (tuple, list)):
        return tuple(ints(x) for x in value)
    return int(value)


def make_fixture():
    """Honest existing setup, sampled once; caller freezes before evaluation."""
    pk, sk = bgv.key_gen(16, t=17, eta=1, q_bits=60, rns_modulus=True)
    keys = trace.evaluation_keys(pk, sk, 4, digit_bits=10)
    rows = tuple(product((0, 1), repeat=3))+((0, 0, 0),)
    ids = (40, 3, 99, 7, 2, 81, 8, 5, 1)
    _, tiles = messages((0, 0, 0), rows, pk.n)
    client = owner.OwnerClient(pk, sk)
    try:
        index = tuple(client.encrypt(tile).hex() for tile in tiles)
        queries = []
        for query in product((0, 1), repeat=3):
            message, _ = messages(query, rows, pk.n)
            original = client.encrypt(message)
            rounded = codec.compress(original, pk, dropped_bits=8)
            queries.append({"bits": query, "original_packet_hex": original.hex(),
                            "rounded_packet_hex": rounded.hex()})
    finally:
        client.close()
    return {"kind": "disclosed_honest_existing_N16_t17_eta1_Q60_setup_not_security_approval",
            "pk": {"n": pk.n, "t": pk.t, "q": int(pk.q), "eta": pk.eta,
                   "a": ints(pk.a), "b": ints(pk.b), "key_id": pk.key_id},
            "secret": ints(sk.s), "keys": {"padded": keys.padded,
                "digit_bits": keys.digit_bits, "relin": ints(keys.relin),
                "rotations": tuple((g, ints(key)) for g, key in keys.rotations),
                "switch_error_bound": keys.switch_error_bound},
            "rows": rows, "ids": ids, "index_packets_hex": index, "queries": queries}


def load_fixture(fixture):
    p, k = fixture["pk"], fixture["keys"]
    pk = bgv.PublicKey(p["n"], p["t"], mpz(p["q"]), p["eta"],
                       tuple(map(mpz, p["a"])), tuple(map(mpz, p["b"])), p["key_id"])
    sk = bgv.SecretKey(tuple(map(mpz, fixture["secret"])), pk.key_id)
    def key(columns):
        return tuple(tuple(tuple(map(mpz, poly)) for poly in pair) for pair in columns)
    keys = trace.EvaluationKeys(pk.key_id, k["padded"], k["digit_bits"], key(k["relin"]),
                                tuple((g, key(columns)) for g, columns in k["rotations"]),
                                k["switch_error_bound"])
    index = [owner.expand(bytes.fromhex(packet), pk) for packet in fixture["index_packets_hex"]]
    return pk, sk, keys, index


def evaluate_fixture(fixture):
    pk, sk, keys, index = load_fixture(fixture)
    observations = []
    profile = Profile(pk.n, 3, 9, pk.t, pk.eta, keys.digit_bits)
    bound = complete_bound(profile, drop=8)
    rows, ids = fixture["rows"], fixture["ids"]
    signed_secret = tuple(-1 if x == pk.q-1 else int(x) for x in sk.s)
    for packet in fixture["queries"]:
        query = packet["bits"]
        original_bytes = bytes.fromhex(packet["original_packet_hex"])
        rounded_bytes = bytes.fromhex(packet["rounded_packet_hex"])
        if codec.compress(original_bytes, pk, dropped_bits=8) != rounded_bytes:
            raise AssertionError("Original complete query did not bind to rounded packet")
        original, encrypted = owner.expand(original_bytes, pk), codec.expand(
            rounded_bytes, pk, dropped_bits=8)
        message, _ = messages(query, rows, pk.n)
        original_phase = phase(original.components, signed_secret, int(pk.q))
        if any((v-m) % pk.t or abs(v-m) > pk.t*pk.eta
               for v, m in zip(original_phase, message, strict=True)):
            raise AssertionError("Wrong actual owner fresh phase law")
        deltas = tuple(centered(int(a-b), int(pk.q)) for a, b in zip(
            encrypted.components[0], original.components[0], strict=True))
        if any(x % pk.t or abs(x) > bound["query_added_bound"] for x in deltas):
            raise AssertionError("Query rounding violated signed carry bound")
        expected = ideal_polynomials(query, rows, pk.n, pk.t)
        outputs = {"per_tile": trace.search(encrypted, index, 9, pk, keys),
                   "joint": butterfly.search(encrypted, index, 9, pk, keys)}
        for graph, ciphertexts in outputs.items():
            full_phases = tuple(phase(c.components, signed_secret, int(pk.q)) for c in ciphertexts)
            plaintexts = tuple(tuple(x % pk.t for x in poly) for poly in full_phases)
            if plaintexts != expected:
                raise AssertionError("Actual full original-query graph differed from schoolbook oracle")
            if graph == "joint" and max(abs(x) for poly in full_phases for x in poly) > bound["final_q_phase_bound"]:
                raise AssertionError("Complete joint phase exceeded certified public envelope")
            terminal = [compact.compact(c, pk, bits=32) for c in ciphertexts]
            p = int(terminal[0].modulus)
            for source, target in zip(ciphertexts, terminal, strict=True):
                expected_components = tuple(tuple(nearest_congruent(int(c), int(pk.q), p, pk.t) % p
                                                    for c in poly) for poly in source.components)
                if tuple(tuple(map(int, poly)) for poly in target.components) != expected_components:
                    raise AssertionError("Compact-v1 complete coefficients differed from neighbor oracle")
            compact_phases = tuple(phase(c.components, signed_secret, p) for c in terminal)
            compact_plain = tuple(tuple(x % pk.t for x in poly) for poly in compact_phases)
            if compact_plain != expected:
                raise AssertionError("Compact terminal/private centering changed complete plaintext")
            if graph == "joint" and max(abs(x) for poly in compact_phases for x in poly) > bound["terminal_phase_bound"]:
                raise AssertionError("Complete compact phase exceeded certified public envelope")
            distances = trace.decode([list(p) for p in compact_plain], 9, 3, pk)
            direct = [sum(a != b for a, b in zip(query, row, strict=True)) for row in rows]
            if distances != direct:
                raise AssertionError("Private distance positions/parity changed")
            actual_top = sorted(zip(ids, distances, strict=True), key=lambda x: (x[1], x[0]))[:3]
            expected_top = sorted(zip(ids, direct, strict=True), key=lambda x: (x[1], x[0]))[:3]
            if actual_top != expected_top:
                raise AssertionError("Owner local stable-ID finish changed")
            wire = compact.pack(terminal, 9, 3, pk)
            import hashlib
            observations.append({"query": tuple(query), "graph": graph, "distances": distances,
                                 "top3_owner_local_ids": actual_top, "full_packet_bytes": len(wire),
                                 "full_packet_sha256": hashlib.sha256(wire).hexdigest(),
                                 "full_plaintext_coefficients": compact_plain,
                                 "maximum_q_centered_phase": max(abs(x) for p in full_phases for x in p),
                                 "maximum_p_centered_phase": max(abs(x) for p in compact_phases for x in p)})
    return {"profile": asdict(profile), "bound": bound, "observations": observations,
            "observation_count": len(observations), "all_original_queries_and_full_packets_checked": True,
            "owner_local_nonpositional_ID_mapping_not_remote_protocol": True,
            "private_backend_constant_time": False, "security_approved": False}
