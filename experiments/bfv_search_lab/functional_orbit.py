"""E110 disclosed tiny raw-Q external-product and functional-orbit controls.

Pure integer diagnostics. These are known gadget identities, not secure key
generation, a succinct verifier, an optimizer, or production HE parameters.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from experiments.bfv_search_lab import native_boundary_oracle as ring

FIXTURE_SHA256 = "0a49605dd8d26d0e73e38c681013e83a64801df4c95b62fab80bf7b81beeb4a1"
MODES = ("ordinary", "product-only", "full-orbit")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def tuples(value):
    return tuple(tuples(x) for x in value) if type(value) is list else value


def load_fixture(path):
    data = Path(path).read_bytes()
    if hashlib.sha256(data).hexdigest() != FIXTURE_SHA256:
        raise ValueError("Not the frozen disclosed E106 fixture")
    fixture = json.loads(data)
    ctx = ring.Context(**{k: tuples(v) for k, v in fixture["context"].items()})
    ctx.admit_native_fixture()
    secret = tuple(-1 if x == ctx.q-1 else x for x in fixture["secret"])
    ring.polynomial(secret, ctx.n)
    return fixture, ctx, secret


def centered(poly, q):
    return tuple(x if x <= q//2 else x-q for x in poly)


def phase(cipher, secret, q):
    return ring.add(cipher[0], ring.multiply(cipher[1], secret, q), q)


def integer_product(left, right):
    """Unreduced negacyclic error convolution for the exact error ledger."""
    if len(left) != len(right):
        raise ValueError("Wrong error convolution shape")
    n, out = len(left), [0]*len(left)
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            out[(i+j) % n] += a*b if i+j < n else -a*b
    return tuple(out)


def digits(ctx, source):
    ring.polynomial(source, ctx.n, ctx.q)
    # One full-Q source, shared by both residue computations.
    lifted = tuple(ring.crt(tuple(x % p for p in ctx.primes), ctx.primes) for x in source)
    if lifted != source:
        raise ValueError("Wrong common integer source")
    return tuple(tuple((x >> (ctx.digit_bits*j)) & ((1 << ctx.digit_bits)-1) for x in source)
                 for j in range(ctx.levels))


def validate_digits(ctx, source, rows):
    if type(rows) is not tuple or rows != digits(ctx, source):
        raise ValueError("Noncanonical shared full-Q digits")
    # Equality alone would accept Python numeric aliases; require strict types.
    for row in rows:
        ring.polynomial(row, ctx.n, 1 << ctx.digit_bits)


@dataclass(frozen=True)
class RawKey:
    cipher: ring.Cipher
    error: ring.Poly


@dataclass(frozen=True)
class Orbit:
    exponent: int
    coefficient: ring.Poly
    left: tuple[RawKey, ...]
    right: tuple[RawKey, ...]


@dataclass(frozen=True)
class Enrollment:
    context_digest: str
    epoch: str
    product: tuple[tuple[RawKey, ...], ...]
    responses: tuple[tuple[Orbit, ...], ...]

    def public_digest(self):
        # Diagnostic errors are disclosed in the fixture, but are not public
        # key material required by the evaluator or its replay statement.
        return digest({"context": self.context_digest, "epoch": self.epoch,
                       "product": [[key.cipher for key in family] for family in self.product],
                       "responses": [[{"g": o.exponent, "left": [k.cipher for k in o.left],
                                         "right": [k.cipher for k in o.right]} for o in family]
                                     for family in self.responses]})


def validate_enrollment(ctx, enrollment):
    if (type(enrollment) is not Enrollment or enrollment.context_digest != ctx.digest()
            or type(enrollment.epoch) is not str or enrollment.epoch != "E110-disclosed-toy-epoch1"
            or type(enrollment.product) is not tuple or len(enrollment.product) != len(ctx.index)
            or type(enrollment.responses) is not tuple
            or len(enrollment.responses) != (len(ctx.ids)+ctx.n-1)//ctx.n):
        raise ValueError("Wrong owner-pinned toy enrollment")
    for response in enrollment.responses:
        if (type(response) is not tuple or not response
                or any(type(o) is not Orbit or type(o.exponent) is not int for o in response)
                or tuple(o.exponent for o in response) != tuple(sorted({o.exponent for o in response}))):
            raise ValueError("Wrong functional orbit grammar/order")
        for orbit in response:
            if not 0 <= orbit.exponent < 2*ctx.n or orbit.exponent % 2 != 1:
                raise ValueError("Wrong functional automorphism")
            ring.polynomial(orbit.coefficient, ctx.n, ctx.q)
    families = enrollment.product + tuple(f for response in enrollment.responses for o in response
                                         for f in (o.left, o.right))
    for family in families:
        if type(family) is not tuple or len(family) != ctx.levels:
            raise ValueError("Wrong gadget family")
        for key in family:
            if type(key) is not RawKey or type(key.cipher) is not tuple or len(key.cipher) != 2:
                raise ValueError("Wrong raw gadget key")
            for poly in key.cipher:
                ring.polynomial(poly, ctx.n, ctx.q)
            ring.polynomial(key.error, ctx.n)
            if any(x not in (-1, 0, 1) for x in key.error):
                raise ValueError("Wrong disclosed toy fresh error")


def raw_key(ctx, secret, target, label):
    """Raw-Q phase target+t*E, with biased deterministic DISCLOSED toy coins."""
    ring.polynomial(target, ctx.n, ctx.q)
    stream = hashlib.shake_256(b"E110-not-cryptographic-toy-coins-v1"+label.encode()).digest(17*ctx.n)
    mask = tuple(int.from_bytes(stream[16*i:16*(i+1)], "little") % ctx.q for i in range(ctx.n))
    error = tuple(stream[16*ctx.n+i] % 3-1 for i in range(ctx.n))
    c0 = ring.add(ring.add(target, tuple(ctx.t*x % ctx.q for x in error), ctx.q),
                  ring.multiply(mask, secret, ctx.q), ctx.q, -1)
    return RawKey((c0, mask), error)


def compile_orbits(ctx, index_phases):
    """Exact butterfly phase map, combining equal orbits BEFORE key creation."""
    q, responses = ctx.q, []

    def merge(left, right, sign=1):
        out = dict(left)
        for g, coefficient in right.items():
            out[g] = ring.add(out.get(g, (0,)*ctx.n), coefficient, q, sign)
        return {g: p for g, p in out.items() if any(p)}

    for start in range(0, len(index_phases), ctx.padded):
        work = [{1: ring.monomial(p, 1-ctx.padded, q)} for p in index_phases[start:start+ctx.padded]]
        shift = ctx.padded//2
        for exponent, _ in ctx.rotations:
            next_work = []
            for i in range(min(shift, len(work))):
                plus = minus = work[i]
                if i+shift < len(work):
                    right = {g: ring.monomial(p, shift, q) for g, p in work[i+shift].items()}
                    plus, minus = merge(work[i], right), merge(work[i], right, -1)
                rotated = {g*exponent % (2*ctx.n): ring.automorphism(p, exponent, q)
                           for g, p in minus.items()}
                next_work.append(merge(plus, rotated))
            work, shift = next_work, shift//2
        responses.append(tuple(sorted(work[0].items())))
    return tuple(responses)


def prepare(ctx, secret):
    ctx.admit_native_fixture()
    index_phases = tuple(phase(cipher, secret, ctx.q) for cipher in ctx.index)
    product = []
    for i, p in enumerate(index_phases):
        target = ring.multiply(secret, p, ctx.q)
        product.append(tuple(raw_key(ctx, secret, tuple(x*(1 << (ctx.digit_bits*j)) % ctx.q for x in target),
                                     f"product:{i}:{j}") for j in range(ctx.levels)))
    responses = []
    maps = compile_orbits(ctx, index_phases)
    secret_orbits = {g: secret if g == 1 else ring.automorphism(secret, g, ctx.q)
                     for g in {g for terms in maps for g, _ in terms}}
    for r, terms in enumerate(maps):
        family = []
        for g, coefficient in terms:
            right_target = ring.multiply(secret_orbits[g], coefficient, ctx.q)
            pair = []
            for component, target in enumerate((coefficient, right_target)):
                pair.append(tuple(raw_key(ctx, secret, tuple(x*(1 << (ctx.digit_bits*j)) % ctx.q for x in target),
                                          f"orbit:{r}:{g}:{component}:{j}") for j in range(ctx.levels)))
            family.append(Orbit(g, coefficient, *pair))
        responses.append(tuple(family))
    result = Enrollment(ctx.digest(), "E110-disclosed-toy-epoch1", tuple(product), tuple(responses))
    validate_enrollment(ctx, result)
    return result


def enrollment_from_dict(value):
    def raw(v):
        return RawKey(tuples(v["cipher"]), tuples(v["error"]))
    return Enrollment(value["context_digest"], value["epoch"],
                      tuple(tuple(raw(k) for k in family) for family in value["product"]),
                      tuple(tuple(Orbit(o["exponent"], tuples(o["coefficient"]),
                                        tuple(raw(k) for k in o["left"]), tuple(raw(k) for k in o["right"]))
                                  for o in family) for family in value["responses"]))


class Meter:
    def __init__(self, ctx):
        self.ctx = ctx
        self.counts = dict.fromkeys(("ring_products", "polynomial_additions", "automorphisms", "monomials"), 0)

    def multiply(self, left, right):
        self.counts["ring_products"] += 1
        return ring.multiply(left, right, self.ctx.q)

    def add(self, left, right, sign=1):
        self.counts["polynomial_additions"] += 1
        return ring.add(left, right, self.ctx.q, sign)

    def transform(self, poly, value, kind):
        self.counts["automorphisms" if kind == "automorphism" else "monomials"] += 1
        return getattr(ring, kind)(poly, value, self.ctx.q)


@dataclass(frozen=True)
class Evaluation:
    binding: str
    mode: str
    query: bytes
    query_sources: tuple[tuple[str, ring.Poly, tuple[ring.Poly, ...]], ...]
    rotation_cuts: tuple[ring.Switch, ...]
    preterminal: tuple[ring.Cipher, ...]
    packet: bytes
    counts: tuple[tuple[str, int], ...]


def evaluate(ctx, enrollment, original_query, mode):
    validate_enrollment(ctx, enrollment)
    if mode not in MODES:
        raise ValueError("Unknown declared evaluator graph")
    query = ring.expand_query(ctx, original_query)
    binding = digest({"enrollment": enrollment.public_digest(), "mode": mode, "query": original_query.hex()})
    meter, sources, cuts = Meter(ctx), [], []
    if mode == "ordinary":
        trace = ring.replay(ctx, original_query)
        # This known graph's product count follows its complete executed tape.
        count = len(ctx.index)*(4+2*ctx.levels)+(len(trace.cuts)-len(ctx.index))*2*ctx.levels
        return Evaluation(binding, mode, original_query, (), trace.cuts, trace.preterminal,
                          trace.packet, (("ring_products", count),))

    def source(poly, label):
        rows = digits(ctx, poly)
        sources.append((label, poly, rows))
        return rows

    def apply(rows, keys):
        out = ((0,)*ctx.n, (0,)*ctx.n)
        for row, key in zip(rows, keys, strict=True):
            pair = key.cipher if type(key) is RawKey else key
            out = tuple(meter.add(a, meter.multiply(row, b)) for a, b in zip(out, pair, strict=True))
        return out

    responses = []
    if mode == "full-orbit":
        cached = {}
        for family in enrollment.responses:
            out = ((0,)*ctx.n, (0,)*ctx.n)
            for orbit in family:
                for component, keys in enumerate((orbit.left, orbit.right)):
                    at = (orbit.exponent, component)
                    if at not in cached:
                        poly = query[component] if orbit.exponent == 1 else meter.transform(query[component], orbit.exponent, "automorphism")
                        cached[at] = source(poly, f"public-query:orbit{orbit.exponent}:component{component}")
                    pair = apply(cached[at], keys)
                    out = tuple(meter.add(a, b) for a, b in zip(out, pair, strict=True))
            responses.append(out)
    else:
        rows = source(query[1], "public-query:component1")
        for start in range(0, len(ctx.index), ctx.padded):
            work = []
            for i in range(start, min(start+ctx.padded, len(ctx.index))):
                correction = apply(rows, enrollment.product[i])
                pair = tuple(meter.add(meter.multiply(query[0], a), b)
                             for a, b in zip(ctx.index[i], correction, strict=True))
                work.append(tuple(meter.transform(p, 1-ctx.padded, "monomial") for p in pair))
            shift = ctx.padded//2
            for stage, (exponent, key) in enumerate(ctx.rotations):
                next_work = []
                for i in range(min(shift, len(work))):
                    plus = minus = work[i]
                    if i+shift < len(work):
                        right = tuple(meter.transform(p, shift, "monomial") for p in work[i+shift])
                        plus = tuple(meter.add(a, b) for a, b in zip(work[i], right, strict=True))
                        minus = tuple(meter.add(a, b, -1) for a, b in zip(work[i], right, strict=True))
                    rotated = tuple(meter.transform(p, exponent, "automorphism") for p in minus)
                    rotation_rows = digits(ctx, rotated[1])
                    correction = apply(rotation_rows, key)
                    cuts.append(ring.Switch(f"group{start//ctx.padded}:stage{stage}:node{i}", rotated[1], rotation_rows, correction))
                    result = (meter.add(rotated[0], correction[0]), correction[1])
                    next_work.append(tuple(meter.add(a, b) for a, b in zip(plus, result, strict=True)))
                work, shift = next_work, shift//2
            responses.append(work[0])
    compact = tuple(tuple(tuple(ring.round_lift(c, ctx.q, ctx.p, ctx.t) % ctx.p for c in p) for p in cipher)
                    for cipher in responses)
    packet = ring.serialize(ctx, compact)
    ring.parse_response(ctx, packet)
    return Evaluation(binding, mode, original_query, tuple(sources), tuple(cuts), tuple(responses),
                      packet, tuple(sorted(meter.counts.items())))


def checked_release(ctx, enrollment, query, candidate, decode):
    """Paid public recomputation under a locally trusted enrollment pin."""
    if (type(candidate) is not Evaluation or type(candidate.query) is not bytes or type(candidate.packet) is not bytes
            or type(candidate.binding) is not str or type(candidate.mode) is not str
            or type(candidate.query_sources) is not tuple or type(candidate.rotation_cuts) is not tuple
            or type(candidate.preterminal) is not tuple or type(candidate.counts) is not tuple):
        raise ValueError("Wrong complete evaluator statement")
    if any(type(row) is not tuple or len(row) != 2 or type(row[0]) is not str
           or type(row[1]) is not int for row in candidate.counts):
        raise ValueError("Wrong operation-count grammar")
    for entry in candidate.query_sources:
        if type(entry) is not tuple or len(entry) != 3 or type(entry[0]) is not str:
            raise ValueError("Wrong public digit-source grammar")
        _, p, rows = entry
        validate_digits(ctx, p, rows)
    for cut in candidate.rotation_cuts:
        if type(cut) is not ring.Switch:
            raise ValueError("Wrong native rotation cut")
        validate_digits(ctx, cut.source, cut.digits)
    expected = evaluate(ctx, enrollment, query, candidate.mode)
    # Exact dataclass equality also covers complete output, graph and query;
    # strict polynomial validation prevents numeric aliases passing equality.
    for cipher in candidate.preterminal:
        if type(cipher) is not tuple or len(cipher) != 2:
            raise ValueError("Wrong complete output shape")
        for p in cipher:
            ring.polynomial(p, ctx.n, ctx.q)
    if candidate != expected:
        raise ValueError("Substituted graph/enrollment/query/complete output")
    return decode(expected.packet)


def fresh_error_card(ctx, enrollment, query, secret):
    cipher = ring.expand_query(ctx, query)
    product_cards, full_cards = [], []
    rows = digits(ctx, cipher[1])
    for i, keys in enumerate(enrollment.product):
        weighted = tuple(ctx.t*sum(integer_product(row, key.error)[k] for row, key in zip(rows, keys, strict=True))
                         for k in range(ctx.n))
        output = tuple(ring.add(ring.multiply(cipher[0], a, ctx.q),
                               tuple(sum(ring.multiply(row, key.cipher[c], ctx.q)[k]
                                         for row, key in zip(rows, keys, strict=True)) % ctx.q for k in range(ctx.n)), ctx.q)
                       for c, a in enumerate(ctx.index[i]))
        target = ring.multiply(phase(cipher, secret, ctx.q), phase(ctx.index[i], secret, ctx.q), ctx.q)
        if phase(output, secret, ctx.q) != ring.add(target, tuple(x % ctx.q for x in weighted), ctx.q):
            raise AssertionError("Fresh product-key error identity fails")
        bound = ctx.t*sum(sum(row) for row in rows)
        product_cards.append({"tile": i, "actual_fresh_error_linf": max(map(abs, weighted)), "absolute_bound": bound})
    actual = evaluate(ctx, enrollment, query, "full-orbit")
    query_phase = phase(cipher, secret, ctx.q)
    for r, family in enumerate(enrollment.responses):
        target, error, bound = (0,)*ctx.n, [0]*ctx.n, 0
        for orbit in family:
            target = ring.add(target, ring.multiply(ring.automorphism(query_phase, orbit.exponent, ctx.q), orbit.coefficient, ctx.q), ctx.q)
            for component, keys in enumerate((orbit.left, orbit.right)):
                d = digits(ctx, ring.automorphism(cipher[component], orbit.exponent, ctx.q))
                bound += ctx.t*sum(sum(row) for row in d)
                for row, key in zip(d, keys, strict=True):
                    e = integer_product(row, key.error)
                    error = [a+ctx.t*b for a, b in zip(error, e, strict=True)]
        if phase(actual.preterminal[r], secret, ctx.q) != ring.add(target, tuple(x % ctx.q for x in error), ctx.q):
            raise AssertionError("Full two-component orbit error identity fails")
        full_cards.append({"response": r, "actual_fresh_error_linf": max(map(abs, error)), "absolute_bound": bound})
    return {"product_tiles": product_cards, "full_orbit_responses": full_cards}


def cost_card(ctx, enrollment):
    t, levels, n = len(ctx.index), ctx.levels, ctx.n
    # Count the exact partial-tail butterfly without fabricating a query.
    v = 0
    for start in range(0, t, ctx.padded):
        nodes, shift = min(ctx.padded, t-start), ctx.padded//2
        for _ in ctx.rotations:
            nodes = min(shift, nodes)
            v += nodes
            shift //= 2
    terms = sum(len(f) for f in enrollment.responses)
    orbit_count = len({o.exponent for f in enrollment.responses for o in f})
    original = (2*t+2*levels*(1+len(ctx.rotations)))*n
    product_keys, full_keys = 2*t*levels*n, 4*terms*levels*n
    owner_orbit_maps, owner_monomials = 0, t
    for start in range(0, t, ctx.padded):
        supports, shift = [{1} for _ in ctx.index[start:start+ctx.padded]], ctx.padded//2
        for exponent, _ in ctx.rotations:
            next_supports = []
            for i in range(min(shift, len(supports))):
                support = supports[i]
                if i+shift < len(supports):
                    owner_monomials += len(supports[i+shift])
                    support = support | supports[i+shift]
                owner_orbit_maps += len(support)
                next_supports.append(support | {g*exponent % (2*n) for g in support})
            supports, shift = next_supports, shift//2
    modes = {}
    for mode, active, fresh, products, private, public in (
            ("ordinary", original, 0, t*(4+2*levels)+v*2*levels, t+v, 0),
            ("product-only", (2*t+2*levels*len(ctx.rotations))*n+product_keys, t*levels, t*(2+2*levels)+v*2*levels, v, 1),
            ("full-orbit", full_keys, 2*terms*levels, 4*terms*levels, 0, 2*orbit_count)):
        modes[mode] = {"active_server_Q_coefficients": active, "active_server_packed_Q_bytes": active*15,
                       "active_server_two_word_RNS_bytes": active*16, "fresh_raw_key_ciphertexts": fresh,
                       "online_ring_products": products, "non_query_canonical_sources": private,
                       "public_query_digit_sources": public, "total_canonical_sources": private+public,
                       "digit_words": (private+public)*levels*n,
                       "E108_shared_source_terminal_boolean_input_model": (private*n+2*len(enrollment.responses)*n)*240,
                       "whole_epoch_new_raw_key_mask_products": fresh,
                       "owner_target_products": 0 if mode == "ordinary" else 2*t if mode == "product-only" else t+terms,
                       "owner_static_map_automorphisms": owner_orbit_maps if mode == "full-orbit" else 0,
                       "owner_static_map_monomials": owner_monomials if mode == "full-orbit" else 0,
                       "owner_shared_secret_orbit_automorphisms": orbit_count-1 if mode == "full-orbit" else 0,
                       "per_index_update_new_raw_ciphertexts_upper_bound": 0 if mode == "ordinary" else levels if mode == "product-only" else 2*ctx.padded*levels,
                       "retained_original_owner_context_Q_coefficients_additional": original}
    return {"tiles": t, "rotations": v, "response_groups": len(enrollment.responses),
            "full_compiled_terms_after_equal_orbit_aggregation": terms, "distinct_query_orbits": orbit_count,
            "product_extra_key_packed_Q_bytes": product_keys*15, "full_key_packed_Q_bytes": full_keys*15,
            "terminal_coordinates": 2*len(enrollment.responses)*n,
            "terminal_body_bytes": 2*len(enrollment.responses)*((n*ctx.p.bit_length()+7)//8),
            "actual_combined_diagnostic_enrollment_Q_coefficients": product_keys+full_keys,
            "actual_combined_enrollment_and_original_context_packed_Q_bytes": (original+product_keys+full_keys)*15,
            "residency_note": "Per-mode active-server fields are minimal logical key subsets, not RSS. The diagnostic harness retains BOTH new families plus original context; public replay hashes/traverses that full enrollment. Disclosed error/target diagnostic integers and Python-object overhead are additional.",
            "models": modes,
            "update_note": "Each mode shares one new original encrypted-index ciphertext per record/tile update, plus the listed extra raw keys. Per-index raw-key bounds are locality models; no incremental update API is implemented. prepare() builds both entire new families with shared index phases.",
            "original_enrollment_note": "The existing index/relin/rotation keys are reused identically from E106. Their original key generation/public encryption work was not reproduced; complete new-enrollment cost is not claimed.",
            "representation_note": "Full-orbit aggregates the fixed index PHASE map. Re-enrollment from exact owner plaintexts, additional sparse-support identities and their state/security costs are stronger unexecuted controls; this is not a global optimum.",
            "unimplemented_paid_costs": ["PCS commitments/openings/proof bytes", "reviewed correlated-key security", "production parameters/side channels", "immutable enrollment/rollback authentication", "incremental updates and original enrollment generation", "native NTT/CUDA work and latency"],
            "qualifier": "Executed tiny integer-operation/storage counts and explicit shared scalar-bit model; no timings or proof-cost forecast."}


def amplification_card(ctx, secret):
    # Public phase counterexamples only: never send these to a private API.
    unit = (1,)+(0,)*(ctx.n-1)
    wide = (ctx.q//2,)+(0,)*(ctx.n-1)
    error = ring.multiply(wide, tuple(ctx.t*x for x in unit), ctx.q)
    baseline = ctx.t*ctx.n*ctx.levels*((1 << ctx.digit_bits)-1)
    square = ring.multiply(secret, secret, ctx.q)
    amplified = []
    for i, cipher in enumerate(ctx.index):
        for j, pair in enumerate(ctx.relin):
            target = tuple(x*(1 << (ctx.digit_bits*j)) % ctx.q for x in square)
            key_error = centered(ring.add(phase(pair, secret, ctx.q), target, ctx.q, -1), ctx.q)
            scaled = centered(ring.multiply(cipher[1], key_error, ctx.q), ctx.q)
            amplified.append({"tile": i, "row": j, "scaled_key_error_linf": max(map(abs, scaled))})
    return {"fresh_rotated_index_wide_coefficient_error_linf": max(map(abs, centered(error, ctx.q))),
            "bounded_one_component_gadget_error_bound": baseline,
            "uniform_index_coefficient_times_ordinary_key_error": amplified,
            "scope": "Raw full-Q error amplification counterexamples; no private release, production probability or chosen-ciphertext service."}


def run_fixture(fixture, ctx, secret, enrollment):
    cards, changed = [], dict.fromkeys(MODES, 0)
    for item in fixture["queries"]:
        query = bytes.fromhex(item["packet_hex"])
        outputs = {mode: evaluate(ctx, enrollment, query, mode) for mode in MODES}
        truth = tuple(sum(a != b for a, b in zip(item["bits"], row, strict=True)) for row in fixture["rows"])
        baseline_plain = None
        for mode, result in outputs.items():
            parsed = checked_release(ctx, enrollment, query, result, lambda p: ring.parse_response(ctx, p))
            phases, scores, top = ring.decrypt_and_rank(ctx, parsed, secret)
            plaintext = tuple(tuple(x % ctx.t for x in p) for p in phases)
            if mode == "ordinary":
                baseline_plain = plaintext
            if plaintext != baseline_plain or scores != truth or top != tuple((i, truth[i]) for i in sorted(ctx.ids, key=lambda i: (truth[i], i))[:3]):
                raise AssertionError("Full coefficient/score/stable tie oracle disagreement")
            changed[mode] += result.packet != outputs["ordinary"].packet
            cards.append({"query": item["bits"], "mode": mode, "packet_sha256": hashlib.sha256(result.packet).hexdigest(),
                          "packet_bytes": len(result.packet), "all_preterminal_coefficients": 2*len(result.preterminal)*ctx.n,
                          "all_terminal_coefficients": 2*len(parsed)*ctx.n, "all_plaintext_coefficients": len(phases)*ctx.n,
                          "scores": scores, "top3": top, "counts": dict(result.counts),
                          "non_query_canonical_sources": len(result.rotation_cuts), "public_query_sources": len(result.query_sources)})
        fresh = fresh_error_card(ctx, enrollment, query, secret)
        if any(row["actual_fresh_error_linf"] > row["absolute_bound"] for rows in fresh.values() for row in rows):
            raise AssertionError("Fresh error support bound fails")
        cards.append({"query": item["bits"], "fresh_error_identity": fresh})
    return {"cards": cards, "different_complete_packets_vs_ordinary": changed,
            "costs": cost_card(ctx, enrollment), "amplification": amplification_card(ctx, secret),
            "prior_return": "Contained known control; no original main mechanism, no A3 optimizer/backend advancement."}
