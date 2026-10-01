"""E80 polyphase/module oracle and paid owner-built outer-LHE fixture.

Known algebra/composition control, not a reviewed cryptographic construction.
All private arithmetic is variable-time. Secrets/errors are explicit bounded
fixture inputs: no approved sampler, module-LWE parameters, remote enrollment,
feedback theorem or production API. No imported HE/proof implementation.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import secrets
import threading

import gmpy2

from experiments.bfv_search_lab import reduction_oracles as integer
from experiments.bfv_search_lab import structured_operator_oracle as scalar


def _poly(values, m, *, bound=None):
    if (type(values) is not tuple or len(values) != m
            or any(type(x) is not int or (bound is not None and abs(x) > bound) for x in values)):
        raise ValueError("Incorrect bounded module polynomial")


def _vector(values, count, m, *, bound=None):
    if type(values) is not tuple or len(values) != count:
        raise ValueError("Incorrect module vector")
    for p in values:
        _poly(p, m, bound=bound)


def _matrix(values, rows, columns, m):
    if type(values) is not tuple or len(values) != rows:
        raise ValueError("Incorrect module matrix")
    for row in values:
        _vector(row, columns, m)


def _product(a, b):
    return tuple(integer.ring_product(a, b))


def _sum(values, m, q=None):
    result = tuple(sum(v[i] for v in values) for i in range(m))
    return result if q is None else tuple(x % q for x in result)


def _inverse(p):
    # Involution Y -> Y^-1 implements the coefficient-dot adjoint.
    return (p[0], *tuple(-x for x in reversed(p[1:])))


@dataclass(frozen=True)
class Module:
    original: scalar.Operator
    m: int
    # [output coset][input coset][Y coefficient]; prescribed INTEGER lifts.
    matrix: tuple[tuple[tuple[int, ...], ...], ...]

    @property
    def a(self):
        return self.original.rows // self.m

    @property
    def b(self):
        return self.original.width // self.m


def module(op, m):
    scalar.validate(op)
    if type(m) is not int or m < 1 or any(d % m for d in op.degrees):
        raise ValueError("Common module degree must divide every query degree")
    stride = op.n // m
    columns = []
    for degree, generators in zip(op.degrees, op.generators, strict=True):
        for residue in range(degree // m):
            shift = residue * (op.n // degree)
            column = []
            for g in generators:
                shifted = tuple(g[(i - shift) % op.n] * (1 if i >= shift else -1)
                                for i in range(op.n))
                column.extend(tuple(shifted[r + h * stride] for h in range(m)) for r in range(stride))
            columns.append(tuple(column))
    matrix = tuple(tuple(column[i] for column in columns) for i in range(op.rows // m))
    return Module(op, m, matrix)


def pack_inputs(mod, values):
    scalar._vector(values, mod.original.width)
    result, offset = [], 0
    for degree in mod.original.degrees:
        cosets = degree // mod.m
        result.extend(tuple(values[offset + r + h * cosets] for h in range(mod.m)) for r in range(cosets))
        offset += degree
    return tuple(result)


def unpack_inputs(mod, values):
    _vector(values, mod.b, mod.m)
    result, offset = [], 0
    for degree in mod.original.degrees:
        cosets = degree // mod.m
        result.extend(values[offset + k % cosets][k // cosets] for k in range(degree))
        offset += cosets
    return tuple(result)


def pack_outputs(mod, values):
    scalar._vector(values, mod.original.rows)
    n, stride = mod.original.n, mod.original.n // mod.m
    return tuple(tuple(values[block * n + r + h * stride] for h in range(mod.m))
                 for block in range(2 * mod.original.replies) for r in range(stride))


def unpack_outputs(mod, values):
    _vector(values, mod.a, mod.m)
    n, stride = mod.original.n, mod.original.n // mod.m
    return tuple(values[block * stride + i % stride][i // stride]
                 for block in range(2 * mod.original.replies) for i in range(n))


def compatible_projection(mod, rows):
    scalar.project((0,) * mod.original.rows, rows)
    kept = set(rows)
    n, stride = mod.original.n, mod.original.n // mod.m
    for block in range(2 * mod.original.replies):
        for r in range(stride):
            group = {block * n + r + h * stride for h in range(mod.m)}
            if kept & group and not group <= kept:
                return False
    return True


def matvec(matrix, vector, m, q=None):
    _vector(vector, len(vector), m)
    _matrix(matrix, len(matrix), len(vector), m)
    return tuple(_sum(tuple(_product(a, x) for a, x in zip(row, vector, strict=True)), m, q)
                 for row in matrix)


def forward(mod, vector, q=None):
    _vector(vector, mod.b, mod.m)
    return matvec(mod.matrix, vector, mod.m, q)


def adjoint(mod, vector, q=None):
    _vector(vector, mod.a, mod.m)
    transposed = tuple(tuple(_inverse(mod.matrix[i][j]) for i in range(mod.a)) for j in range(mod.b))
    return matvec(transposed, vector, mod.m, q)


def _binary(values, a):
    if (type(values) is not tuple or not values or len(values) > 16
            or any(type(row) is not tuple or len(row) != a
                   or any(type(x) is not int or x not in (0, 1) for x in row) for row in values)):
        raise ValueError("Incorrect bounded constant-binary challenge")


def _challenge(c, y, m, q):
    return tuple(tuple(sum(w * p[i] for w, p in zip(row, y, strict=True)) % q for i in range(m)) for row in c)


def correctness(*, rows, width, inner_q, query_bound, eta, outer_q):
    """Conservative exact bound INCLUDING q - floor(q/p)*p.

    Integer D*x=p*k+r with centered r; residual is D*e-(q mod p)*k.
    Width includes every scalar coefficient, including polynomial convolution.
    """
    if (any(type(v) is not int or v < 1 for v in (rows, width, inner_q, query_bound, eta, outer_q))
            or inner_q % 2 != 1 or outer_q <= inner_q or outer_q.bit_length() > 512):
        raise ValueError("Invalid outer correctness dimensions")
    delta, remainder = divmod(outer_q, inner_q)
    product_bound = width * (inner_q // 2) * query_bound
    quotient_bound = (product_bound + inner_q // 2) // inner_q
    noise_bound = width * (inner_q // 2) * eta
    residual = noise_bound + remainder * quotient_bound
    return {"plaintext_modulus": inner_q, "outer_q": outer_q, "delta": delta,
            "q_mod_plaintext": remainder, "query_bound": query_bound, "error_bound": eta,
            "integer_product_bound": product_bound, "quotient_bound": quotient_bound,
            "integer_error_bound": noise_bound, "rounding_residual_bound": residual,
            "strict_rounding_safe": 2 * residual < delta,
            "parameter_security_assured": False}


def candidate_modulus(*, width, inner_q, query_bound, eta=1):
    product = width * (inner_q // 2) * query_bound
    quotient = (product + inner_q // 2) // inner_q
    noise = width * (inner_q // 2) * eta
    # Bound the remainder by p-1 before selecting a prime. Not an LWE estimate.
    return int(gmpy2.next_prime(2 * inner_q * (noise + (inner_q - 1) * quotient + 1) + inner_q))


@dataclass(frozen=True)
class Registration:
    m: int
    a: int
    b: int
    rank: int
    inner_q: int
    outer_q: int
    query_bound: int
    eta: int
    epoch: bytes
    binding: str
    ids_binding_owner_local: str
    crs: tuple
    hint: tuple
    challenges: tuple
    fingerprints: tuple
    norm_bound: int


def register(mod, crs, challenges, outer_q, epoch, ids_binding, *, query_bound, eta=1):
    """Trusted owner-local constructor. Binding is NOT remote authentication."""
    if (type(outer_q) is not int or not gmpy2.is_prime(outer_q) or outer_q.bit_length() > 512
            or type(epoch) is not bytes or len(epoch) != 32
            or type(ids_binding) is not str or len(ids_binding) != 64
            or set(ids_binding) - set("0123456789abcdef")
            or type(crs) is not tuple or not crs or not crs[0] or len(crs[0]) > 8):
        raise ValueError("Incorrect owner registration context")
    rank = len(crs[0])
    _matrix(crs, mod.b, rank, mod.m)
    if any(not 0 <= x < outer_q for row in crs for p in row for x in p):
        raise ValueError("CRS residues out of range")
    _binary(challenges, mod.a)
    bounds = correctness(rows=mod.original.rows, width=mod.original.width, inner_q=mod.original.q,
                         query_bound=query_bound, eta=eta, outer_q=outer_q)
    if not bounds["strict_rounding_safe"]:
        raise ValueError("Outer modulus fails the complete rounding bound")
    # Integer lifts are fixed by module(op), not arbitrary congruent entries.
    columns = tuple(forward(mod, tuple(row[j] for row in crs), outer_q) for j in range(rank))
    hint = tuple(tuple(col[i] for col in columns) for i in range(mod.a))
    z = tuple(tuple(tuple(sum(w * row[j][h] for w, row in zip(c, mod.matrix, strict=True))
                           for h in range(mod.m)) for j in range(mod.b)) for c in challenges)
    norm = mod.a * (mod.original.q // 2)
    assert all(abs(x) <= norm for row in z for p in row for x in p)
    # Public context never hashes plaintext IDs or private checker material.
    # A new random registration identity also distinguishes checker refreshes.
    context = ("E80-public-context-v1", mod.original, mod.m, epoch.hex(), outer_q,
               query_bound, eta, crs, hint, secrets.token_bytes(32).hex())
    binding = hashlib.sha256(repr(context).encode()).hexdigest()
    return Registration(mod.m, mod.a, mod.b, rank, mod.original.q, outer_q, query_bound, eta,
                        epoch, binding, ids_binding, crs, hint, challenges, z, norm)


@dataclass(frozen=True)
class Packet:
    binding: str
    epoch: bytes
    token_id: bytes
    values: tuple


def server_reply(mod, query, outer_q):
    # No private registration/checker/outer or inner secret is a server input.
    return Packet(query.binding, query.epoch, query.token_id, forward(mod, query.values, outer_q))


class FixtureSession:
    """One receiver; no operator/index/inner secret retained. Reject retires C/Z.

    Calling recover removes the fresh outer mask only after checking the full
    original request. Success is not a proof permitting arbitrary adaptive reuse.
    """

    def __init__(self, state):
        if type(state) is not Registration:
            raise ValueError("Owner-built fixture registration required")
        self.state, self.retired = state, False
        self._pending, self._seen, self._lock = {}, set(), threading.Lock()

    def issue(self, forms, secret, error, token_id):
        st = self.state
        _vector(forms, st.b, st.m, bound=st.query_bound)
        _vector(secret, st.rank, st.m, bound=1)
        _vector(error, st.b, st.m, bound=st.eta)
        if type(token_id) is not bytes or len(token_id) != 16:
            raise ValueError("Incorrect one-shot query identifier")
        with self._lock:
            if self.retired or token_id in self._seen:
                raise RuntimeError("Registration retired or identifier consumed")
            delta = st.outer_q // st.inner_q
            mask = matvec(st.crs, secret, st.m, st.outer_q)
            values = tuple(tuple((a + e + delta * x) % st.outer_q
                                 for a, e, x in zip(p, ep, xp, strict=True))
                           for p, ep, xp in zip(mask, error, forms, strict=True))
            query = Packet(st.binding, st.epoch, token_id, values)
            self._seen.add(token_id)
            self._pending[token_id] = (query, secret)
            return query

    def _remove_mask(self, reply, secret):
        st = self.state
        mask = matvec(st.hint, secret, st.m, st.outer_q)
        delta = st.outer_q // st.inner_q

        def recover(value):
            residue = value % st.outer_q
            centered = residue if residue <= st.outer_q // 2 else residue - st.outer_q
            nearest = (abs(centered) + delta // 2) // delta
            return (nearest if centered >= 0 else -nearest) % st.inner_q

        return tuple(tuple(recover(x - a) for x, a in zip(p, hp, strict=True))
                     for p, hp in zip(reply.values, mask, strict=True))

    def recover_once(self, token_id, reply):
        st = self.state
        with self._lock:
            if self.retired:
                raise RuntimeError("Registration retired")
            pending = self._pending.pop(token_id, None) if type(token_id) is bytes else None
            if pending is None:
                self.retired, self._pending = True, {}
                return None
            query, secret = pending
            valid = (type(reply) is Packet and reply.binding == st.binding and reply.epoch == st.epoch
                     and reply.token_id == token_id)
            try:
                _vector(reply.values, st.a, st.m)
                valid &= all(0 <= x < st.outer_q for p in reply.values for x in p)
            except (ValueError, TypeError, AttributeError):
                valid = False
            if valid:
                left = matvec(st.fingerprints, query.values, st.m, st.outer_q)
                valid = left == _challenge(st.challenges, reply.values, st.m, st.outer_q)
            if not valid:
                self.retired, self._pending = True, {}
                return None
            return self._remove_mask(reply, secret)


def count_screen(*, n, replies, degrees, inner_q, query_bound, m, d=2048, kappa=128, eta=1):
    """Object/operation counts, not benchmarks or approved security parameters."""
    if (any(type(x) is not int or x < 1 for x in (n, replies, m, d, kappa))
            or any(type(v) is not int or v < 1 or n % v or v % m for v in degrees) or d % m):
        raise ValueError("Invalid module count geometry")
    L, W, a, b, rank = 2 * n * replies, sum(degrees), 2 * n * replies // m, sum(degrees) // m, d // m
    q = candidate_modulus(width=W, inner_q=inner_q, query_bound=query_bound, eta=eta)
    limits = correctness(rows=L, width=W, inner_q=inner_q, query_bound=query_bound, eta=eta, outer_q=q)
    bits, inner_bits = q.bit_length(), inner_q.bit_length()
    norm = a * (inner_q // 2)
    zbits = (2 * norm).bit_length()
    def body(entries, width):
        return (entries * width + 7) // 8
    A, H = W * rank, L * rank
    C, Z = kappa * a, kappa * W
    result = {"n": n, "replies": replies, "degrees": degrees, "L": L, "W": W, "m": m,
              "a": a, "b": b, "rank": rank, "outer_dimension_count_only": d,
              "inner_q": inner_q, "outer_q": q, "outer_bits": bits, "correctness": limits,
              "outer_crs_coefficients": A, "outer_hint_coefficients": H,
              "implicit_generator_coefficients": L * len(degrees),
              "material_module_operator_coefficients": L * W // m,
              "operator_inner_bitpacked_bytes": body(L * W // m, inner_bits),
              "implicit_index_inner_bitpacked_bytes": body(L * len(degrees), inner_bits),
              "A_body_bytes": body(A, bits), "H_body_bytes": body(H, bits),
              "C_body_bytes": body(C, 1), "Z_signed_body_bytes": body(Z, zbits),
              "honest_Z_integer_bound": norm, "Z_signed_bits": zbits,
              "inner_public_key_body_bytes": body(2 * n, inner_bits),
              "inner_secret_ternary_body_bytes": body(n, 2),
              "outer_ephemeral_secret_ternary_body_bytes": body(d, 2),
              "outer_upload_body_bytes": body(W, bits), "outer_reply_body_bytes": body(L, bits),
              "recovered_inner_reply_body_bytes": body(L, inner_bits),
              "setup_H_degree_m_products": a * b * rank,
              "setup_Z_integer_coefficient_additions_upper": kappa * a * W,
              "online_server_degree_m_products": a * b,
              "online_server_schoolbook_coefficient_products": L * W,
              "online_encode_degree_m_products": b * rank,
              "online_release_degree_m_products": a * rank,
              "online_check_degree_m_products": kappa * b,
              "online_check_schoolbook_coefficient_products": kappa * W * m,
              "online_check_output_coefficient_additions_upper": kappa * L,
              "check_soundness_exponent_fixed_error_only": kappa,
              "reject_refresh_C_Z_body_bytes": body(C, 1) + body(Z, zbits),
              "Hprime_for_compressed_release": "unspecified; retained H is paid instead",
              "remote_authentication_metadata_private_map_ID_bytes": "not measured; required in complete service",
              "modulus_sampler_parameter_feedback_assurance": False,
              "scope": "Exact algebra counts for paid retained-H control, no HE/privacy theorem or timing claim."}
    result["client_registration_body_bytes"] = sum(result[k] for k in (
        "A_body_bytes", "H_body_bytes", "C_body_bytes", "Z_signed_body_bytes", "inner_public_key_body_bytes", "inner_secret_ternary_body_bytes"))
    result["outer_roundtrip_body_bytes"] = result["outer_upload_body_bytes"] + result["outer_reply_body_bytes"]
    # Keep this function's output JSON-safe and stable for immutable receipts.
    json.dumps(result)
    return result
