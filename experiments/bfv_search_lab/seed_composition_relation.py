"""E78 typed composed relation and independent full trace, NOT a proof system.

Homemade integer convolution/permutations/decomposition. Verification here
recomputes public work; no commitment, extraction, succinct verification, HE
security or production release assurance is implemented. Canonical residues
and integer recomposition are explicit; a field identity alone is insufficient.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib

from experiments.bfv_search_lab import decryption_support as support
from experiments.bfv_search_lab import packed_query_expansion as packed
from experiments.bfv_search_lab import reduction_oracles as integer


def product(a, b, q):
    return tuple(x % q for x in integer.ring_product(tuple(map(int, a)), tuple(map(int, b))))


def automorphism(p, exponent, q):
    n, result = len(p), [0] * len(p)
    for i, x in enumerate(p):
        position = i * exponent
        result[position % n] = int(x) * (1 if (position // n) % 2 == 0 else -1) % q
    return tuple(result)


def monomial(p, shift, q):
    n, result = len(p), [0] * len(p)
    for i, x in enumerate(p):
        position = i + shift
        result[position % n] = int(x) * (1 if (position // n) % 2 == 0 else -1) % q
    return tuple(result)


def digits(p, bits, q):
    B, ell = 1 << bits, (q.bit_length() + bits - 1) // bits
    if any(type(x) is not int or not 0 <= x < q for x in p):
        raise ValueError("Canonical full-Q residues required")
    return tuple(tuple((x >> (j * bits)) & (B - 1) for x in p) for j in range(ell))


def canonical_recomposition(p, split, bits, q):
    """Integer equality and global [0,Q), not equality modulo each RNS limb."""
    n, ell, B = len(p), (q.bit_length() + bits - 1) // bits, 1 << bits
    if (type(split) is not tuple or len(split) != ell
            or any(type(row) is not tuple or len(row) != n
                   or any(type(x) is not int or not 0 <= x < B for x in row) for row in split)
            or any(type(x) is not int or not 0 <= x < q for x in p)):
        return False
    return all(sum(split[j][i] * B**j for j in range(ell)) == x for i, x in enumerate(p))


def _integer_tree(value):
    return all(_integer_tree(x) for x in value) if type(value) is tuple else type(value) is int


@dataclass(frozen=True)
class Switch:
    level: int
    branch: int
    input_c1: tuple
    rotated_c1: tuple
    gadget: tuple
    switched: tuple


@dataclass(frozen=True)
class Trace:
    public_context: str
    switches: tuple[Switch, ...]
    expanded: tuple
    full_output: tuple
    projected_output: tuple


def context(index, request, pk, keys):
    # Public encrypted objects only. No plaintext digest/private challenge hash.
    return hashlib.sha256(repr(("E78-full-relation-v1", index, request, keys, pk,
                                support.certify(index.space.layout))).encode()).hexdigest()


def _check_inputs(index, request, pk, keys):
    packed._keys(keys, index.space, pk)
    if (request.space_binding != index.space.binding or request.epoch != index.epoch
            or request.ciphertext.key_id != pk.key_id
            or len(request.ciphertext.components) != 2):
        raise ValueError("Wrong owner-pinned original query/index context")
    # Existing validation pins fresh bound and all key/space/epoch shapes.
    # The actual oracle below never calls packed.expand or packed.evaluate.
    from experiments.bfv_search_lab import crt_masked_bgv as masked
    masked.binding(request.epoch, request.token_id)
    masked.validate_ciphertexts((request.ciphertext,), 1, pk)
    if request.ciphertext.phase_bound != pk.t // 2 + pk.t * pk.eta:
        raise ValueError("Wrong original query bound")
    if len(index.columns) != index.space.columns:
        raise ValueError("Wrong owner-approved index column count")
    for column in index.columns:
        masked.validate_ciphertexts(column, index.space.layout.cost.response_ciphertexts, pk)
    packed.output_bound(index, pk, keys)


def _expand(request, pk, keys, supplied=None):
    q = int(pk.q)
    work = (tuple(tuple(map(int, p)) for p in request.ciphertext.components),)
    switches, cursor = [], 0
    for level, (exponent, key) in enumerate(keys.rotations):
        even, odd = [], []
        for branch, pair in enumerate(work):
            rot = tuple(automorphism(p, exponent, q) for p in pair)
            split = digits(rot[1], keys.digit_bits, q)
            if supplied is not None:
                if cursor >= len(supplied):
                    raise ValueError("Missing expansion branch")
                candidate = supplied[cursor]
                if (type(candidate) is not Switch or (candidate.level, candidate.branch) != (level, branch)
                        or type(candidate.level) is not int or type(candidate.branch) is not int
                        or not _integer_tree((candidate.input_c1, candidate.rotated_c1, candidate.switched))
                        or candidate.input_c1 != pair[1] or candidate.rotated_c1 != rot[1]
                        or not canonical_recomposition(rot[1], candidate.gadget, keys.digit_bits, q)):
                    raise ValueError("Original seed/branch/canonical digit mismatch")
                split = candidate.gadget
            terms = tuple(tuple(product(d, column[k], q) for d, column in zip(split, key, strict=True))
                          for k in range(2))
            switched = tuple(tuple(sum(p[i] for p in polys) % q for i in range(pk.n)) for polys in terms)
            saved = Switch(level, branch, pair[1], rot[1], split, switched)
            if supplied is not None and supplied[cursor] != saved:
                raise ValueError("Incorrect key-switch output")
            switches.append(saved)
            cursor += 1
            rotated = (tuple((x + y) % q for x, y in zip(rot[0], switched[0], strict=True)), switched[1])
            plus = tuple(tuple((x + y) % q for x, y in zip(p, r, strict=True)) for p, r in zip(pair, rotated, strict=True))
            minus = tuple(monomial(tuple((x - y) % q for x, y in zip(p, r, strict=True)), -(1 << level), q)
                          for p, r in zip(pair, rotated, strict=True))
            even.append(plus)
            odd.append(minus)
        work = tuple(even + odd)
    if supplied is not None and cursor != len(supplied):
        raise ValueError("Extraneous branch witness")
    return work, tuple(switches)


def _evaluate(index, expanded, pk):
    q, output = int(pk.q), []
    for reply in range(index.space.layout.cost.response_ciphertexts):
        values = [[0] * pk.n for _ in range(3)]
        for column, query in zip(index.columns, expanded, strict=True):
            a, b = column[reply].components, query
            products = ((product(a[0], b[0], q),),
                        (product(a[0], b[1], q), product(a[1], b[0], q)),
                        (product(a[1], b[1], q),))
            for k, terms in enumerate(products):
                values[k] = [(x + sum(p[i] for p in terms)) % q for i, x in enumerate(values[k])]
        output.append(tuple(tuple(p) for p in values))
    return tuple(output)


def _project(output, certificate):
    return tuple((tuple(reply[0][i] for i in keep), reply[1], reply[2])
                 for reply, keep in zip(output, certificate.kept_c0, strict=True))


def make_trace(index, request, pk, keys):
    _check_inputs(index, request, pk, keys)
    work, switches = _expand(request, pk, keys)
    expanded = work[:index.space.columns]
    output = _evaluate(index, expanded, pk)
    return Trace(context(index, request, pk, keys), switches, expanded, output,
                 _project(output, support.certify(index.space.layout)))


def check_trace(index, request, pk, keys, trace):
    """Expensive full recomputation, not a cheap/cryptographic verifier."""
    try:
        _check_inputs(index, request, pk, keys)
        if type(trace) is not Trace or trace.public_context != context(index, request, pk, keys):
            return False
        if not _integer_tree((trace.expanded, trace.full_output, trace.projected_output)):
            return False
        work, _ = _expand(request, pk, keys, trace.switches)
        expanded = work[:index.space.columns]
        output = _evaluate(index, expanded, pk)
        return (trace.expanded == expanded and trace.full_output == output
                and trace.projected_output == _project(output, support.certify(index.space.layout)))
    except (ValueError, TypeError, IndexError, AttributeError):
        return False


@dataclass(frozen=True)
class Node:
    name: str
    operation: str
    inputs: tuple[str, ...]
    phase: str
    polynomials: int
    coefficient_type: str
    degree: int


def relation_dag(n, columns, replies, q_bits, digit_bits):
    """Typed interface counts, no mock PCS/commitment objects."""
    if (any(type(v) is not int or v < 1 for v in (n, columns, replies, q_bits, digit_bits))
            or columns > n or n & (n - 1)):
        raise ValueError("Invalid DAG geometry")
    h, ell = 1 << (columns - 1).bit_length(), (q_bits + digit_bits - 1) // digit_bits
    nodes = [Node("context", "owner-approved epoch/IDs/projection/full-Q and RNS map", (), "setup", 0, "binding", n),
             Node("index", "bound encrypted index", ("context",), "setup", 2 * columns * replies, "residue", n),
             Node("keys", "bound related-secret switch keys", ("context",), "setup", 2 * ell * (h.bit_length() - 1), "residue", n),
             Node("c0", "original request component", ("context",), "query", 1, "residue", n),
             Node("c1", "original fresh seed component", ("context",), "seed", 1, "residue", n)]
    parents = ("c1",)
    for level in range(h.bit_length() - 1):
        even, odd = [], []
        for branch, parent in enumerate(parents):
            name = f"g{level}_{branch}"
            nodes.append(Node(name, "canonical integer gadget/range", (parent, "context"), "seed", ell, "digit", n))
            switched = f"k{level}_{branch}"
            nodes.append(Node(switched, "key-A product sum", (name, "keys"), "seed", 1, "residue", n))
            left, right = f"c1_{level + 1}_{branch}", f"c1_{level + 1}_{branch + (1 << level)}"
            nodes.append(Node(left, "C1 plus branch", (parent, switched), "seed", 1, "residue", n))
            nodes.append(Node(right, "C1 minus monomial branch", (parent, switched), "seed", 1, "residue", n))
            even.append(left)
            odd.append(right)
        parents = tuple(even + odd)
    nodes.append(Node("offset", "all key-B branches folded through index/projection", tuple(n.name for n in nodes if n.coefficient_type == "digit") + ("index", "keys", "c1"), "seed", 3 * replies, "residue", n))
    nodes.append(Node("answer", "A_D*c0+b_D(c1), every full output component", ("offset", "index", "c0", "context"), "query", 3 * replies, "residue", n))
    seen = set()
    for node in nodes:
        if node.name in seen or any(parent not in seen for parent in node.inputs):
            raise AssertionError("Malformed/cyclic relation DAG")
        seen.add(node.name)
    return tuple(nodes)


def count_designs(n, columns, replies, q_bits, digit_bits=4, rounds=4, kept_c0=None):
    nodes = relation_dag(n, columns, replies, q_bits, digit_bits)
    h, ell = 1 << (columns - 1).bit_length(), (q_bits + digit_bits - 1) // digit_bits
    ks = h - 1

    def body(entries):
        return (entries * q_bits + 7) // 8
    L = 3 * n * replies if kept_c0 is None else kept_c0 + 2 * n * replies
    gadget_coeffs = ks * ell * n
    common = {"original_query_coefficients": 2 * n, "full_output_coefficients": 3 * n * replies,
              "accepted_projected_output_coefficients": L, "canonical_gadget_coefficients": gadget_coeffs,
              "canonical_digit_range_bit_constraints_upper": gadget_coeffs * digit_bits,
              "input_residue_global_range_bit_constraints_upper": ks * n * q_bits,
              "integer_recomposition_equalities": ks * n,
              "necessary_seed_C1_keyA_ring_products": ks * ell,
              "fixed_index_coefficients": 2 * columns * replies * n,
              "fixed_evaluation_key_coefficients": 2 * ell * (h.bit_length() - 1) * n,
              "seed_keyB_products_foldable_but_not_free": ks * ell,
              "index_products_naive": 4 * columns * replies,
              "index_products_karatsuba_control": 3 * columns * replies,
              "modular_product_equations_before_linear_folding": 2 * ks * ell + 3 * columns * replies,
              "gadget_key_product_integer_quotient_bound_upper": n * ((1 << digit_bits) - 1) + 1,
              "index_product_integer_quotient_bound_upper": n * ((1 << q_bits) - 1) + 1,
              "modular_and_RNS_relation_interface": "single full-Q modulus in oracle; proof must use matching native ring equations or linked integer/RNS quotients/carries and ranges; backend cost unknown",
              "unseeded_original_query_body_bytes": body(2 * n),
              "seeded_original_query_body_bytes": body(n) + 32,
              "seeded_original_query_assumption": "same explicitly conditional seeded-HE/RO premise as E73; not ordinary secret-seed PRG security",
              "full_accepted_output_body_bytes": body(L),
              "proof_bytes_and_PCS_commit_open_work": "unknown without specified reviewed backend",
              "binding_interface": "index/keys/epoch/IDs/projection roots AND original C0/C1 AND accepted output; no output-only proof",
              "parameter_approval_and_adaptive_feedback": False}
    old_private = rounds * 2 * columns * n
    # The offset circuit is linear in C1 and ALL independent gadget vectors,
    # once input/index/keys are fixed. Transposition relocates, not deletes them.
    transposed_private = rounds * n * (1 + ks * ell)
    designs = [
        {"design": "canonical_expansion_plus_multiplication_strong_control", **common,
         "linear_folding_and_batching_allowed": True,
         "material_expanded_query_coefficients_if_boundary_consumed": 2 * columns * n,
         "seed_range_constraints_can_already_be_shared": True,
         "online_private_beta_required": False},
        {"design": "composed_original_query_to_answer", **common,
         "linear_folding_and_batching_allowed": True,
         "material_expanded_query_coefficients_if_boundary_consumed": 0,
         "same_canonical_seed_digit_constraints": True,
         "online_private_beta_required": False,
         "extra_index_key_folded_constants": "unspecified unless an actual representation/PCS is chosen"},
        {"design": "seed_offset_certificate_plus_affine_gate", **common,
         "online_private_beta_required": True,
         "E77_factory_expanded_fingerprint_body_bytes": body(old_private),
         "compiled_query_vector_body_bytes": body(rounds * n),
         "transposed_seed_and_independent_digit_fingerprint_coefficients": transposed_private,
         "transposed_seed_fingerprint_body_bytes": body(transposed_private),
         "transposed_seed_state_ratio_to_E77_expanded_fingerprints": transposed_private / old_private,
         "fresh_private_beta_body_bytes": body(rounds),
         "if_full_certified_offset_delivered_extra_body_bytes": body(L),
         "committed_offset_private_beta_opening": "not supplied by public certificate; secret-query opening or paid full offset/factory required"},
    ]
    return {"n": n, "columns": columns, "replies": replies, "q_bits": q_bits,
            "factor": h, "digit_bits": digit_bits, "gadget_digits": ell,
            "DAG_nodes": len(nodes), "designs": designs,
            "decision": "Generic fusion removes an intermediate interface but not canonical seed constraints; paid beta variants keep/grow state or a reply-sized object. No novel complete saving selected."}
