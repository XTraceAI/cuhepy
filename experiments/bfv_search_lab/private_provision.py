"""E79 bounded owner-private fixture provisioning; not deployed enrollment.

AES-GCM and a fixed local whitelist authenticate before decoding. The 64-byte
owner key/context root comes from trusted local IPC. No remote pickle, dynamic
imports, private cache export or durable rollback protection is provided.
"""

from dataclasses import fields
import secrets
import threading

from Crypto.Cipher import AES
import gmpy2
from gmpy2 import mpz
import msgpack

from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import cache_snapshot as snapshot
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_query_space as crt
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import native_linear_check as checks
from experiments.bfv_search_lab import score_layout
from experiments.bfv_search_lab import shallow_bgv as bgv

MAX_BODY = 16 << 20
MAGIC = b"cuhepy/research/private-provision/v1\0"
TYPES = {"Plan": affine.Plan, "Context": tree.Context, "Leaf": tree.Leaf,
         "Split": tree.Split, "Layout": tree.Layout, "Space": crt.Space,
         "PublicKey": bgv.PublicKey, "SecretKey": bgv.SecretKey, "Manifest": snapshot.Manifest,
         "ScoreLayout": score_layout.Layout}
NAMES = {value: name for name, value in TYPES.items()}


def _encode(value, depth=0):
    if depth > 24:
        raise ValueError("Provisioning nesting exceeds bound")
    if type(value) in NAMES:
        return ["record", NAMES[type(value)], [_encode(getattr(value, f.name), depth + 1) for f in fields(value) if f.init]]
    if type(value) is tuple:
        return ["tuple", [_encode(x, depth + 1) for x in value]]
    if type(value) is dict:
        if any(type(k) is not str for k in value):
            raise ValueError("Provisioning keys must be strings")
        return {k: _encode(v, depth + 1) for k, v in value.items()}
    if type(value) is mpz:
        value = int(value)
    if type(value) is int and not -(1 << 63) <= value < 1 << 64:
        width = max(1, (abs(value).bit_length() + 7) // 8)
        if width > 64:
            raise ValueError("Provisioning integer exceeds bound")
        return ["integer", int(value < 0), abs(value).to_bytes(width, "little")]
    if value is None or type(value) in (bool, int, bytes, str):
        return value
    raise ValueError("Non-whitelisted provisioning value")


def pack(value):
    result = msgpack.packb(_encode(value), use_bin_type=True)
    if not 1 <= len(result) <= MAX_BODY - 8:
        raise ValueError("Provisioning body exceeds bound")
    return result


def _decode(value, budget, depth=0, public=False):
    budget[0] -= 1
    if depth > 24 or budget[0] < 0:
        raise ValueError("Provisioning structure exceeds bound")
    if type(value) is dict:
        if any(type(k) is not str for k in value):
            raise ValueError("Provisioning keys must be strings")
        return {k: _decode(v, budget, depth + 1, public) for k, v in value.items()}
    if type(value) is list:
        if len(value) == 2 and value[0] == "tuple" and type(value[1]) is list:
            return tuple(_decode(x, budget, depth + 1, public) for x in value[1])
        if (len(value) == 3 and value[0] == "integer" and type(value[1]) is int and value[1] in (0, 1)
                and type(value[2]) is bytes and 1 <= len(value[2]) <= 64):
            if len(value[2]) > 1 and value[2][-1] == 0:
                raise ValueError("Noncanonical provisioning integer")
            x = int.from_bytes(value[2], "little")
            if value[1] and not x:
                raise ValueError("Negative zero provisioning integer")
            return -x if value[1] else x
        if (len(value) == 3 and value[0] == "record" and type(value[1]) is str and value[1] in TYPES
                and type(value[2]) is list and len(value[2]) == sum(f.init for f in fields(TYPES[value[1]]))):
            if public and value[1] in ("Plan", "SecretKey", "Manifest"):
                raise ValueError("Private record refused by compute-server decoder")
            cls = TYPES[value[1]]
            arguments = [_decode(x, budget, depth + 1, public) for x in value[2]]
            if cls is bgv.PublicKey:
                arguments[2] = mpz(arguments[2])
                arguments[4:6] = [tuple(mpz(x) for x in p) for p in arguments[4:6]]
            elif cls is bgv.SecretKey:
                arguments[0] = tuple(mpz(x) for x in arguments[0])
            return cls(*arguments)
        raise ValueError("Non-whitelisted provisioning record")
    if value is None or type(value) in (bool, int, bytes, str):
        return value
    raise ValueError("Non-whitelisted provisioning scalar")


def _unique_map(pairs):
    result = {}
    for k, v in pairs:
        if type(k) is not str or k in result:
            raise ValueError("Duplicate/non-string provisioning key")
        result[k] = v
    return result


def unpack(body, *, public=False):
    if type(body) is not bytes or not 1 <= len(body) <= MAX_BODY - 8:
        raise ValueError("Bounded provisioning body required")
    try:
        encoded = msgpack.unpackb(body, raw=False, strict_map_key=True, max_array_len=1 << 20,
                                 max_map_len=256, max_str_len=4096, max_bin_len=MAX_BODY, object_pairs_hook=_unique_map)
        return _decode(encoded, [1 << 20], public=public)
    except (msgpack.UnpackException, OverflowError, TypeError) as error:
        raise ValueError("Invalid bounded provisioning encoding") from error


def seal(value, key, context_id, padded_size):
    if (type(key) is not bytes or len(key) != 32 or type(context_id) is not bytes or len(context_id) != 32
            or type(padded_size) is not int or not 16 <= padded_size <= MAX_BODY):
        raise ValueError("Owner root and public padding bound required")
    encoded = pack(value)
    if 8 + len(encoded) > padded_size:
        raise ValueError("Public bootstrap padding bound too small")
    payload = len(encoded).to_bytes(8, "little") + encoded + bytes(padded_size - 8 - len(encoded))
    header, nonce = MAGIC + context_id, secrets.token_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update(header)
    encrypted, tag = cipher.encrypt_and_digest(payload)
    return header + nonce + tag + encrypted, len(encoded)


def open_private(packet, key, context_id, padded_size):
    if (type(key) is not bytes or len(key) != 32 or type(context_id) is not bytes or len(context_id) != 32
            or type(padded_size) is not int or not 16 <= padded_size <= MAX_BODY):
        raise ValueError("Pinned owner root/padding bound required")
    header = MAGIC + context_id
    if type(packet) is not bytes or len(packet) != len(header) + 28 + padded_size or packet[:len(header)] != header:
        raise ValueError("Stale/truncated private provisioning envelope")
    nonce, tag = packet[len(header):len(header) + 12], packet[len(header) + 12:len(header) + 28]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update(header)
    payload = cipher.decrypt_and_verify(packet[len(header) + 28:], tag)
    # No parser/decompressor/private-key constructor receives unauthenticated bytes.
    length = int.from_bytes(payload[:8], "little")
    if not 1 <= length <= padded_size - 8 or any(payload[8 + length:]):
        raise ValueError("Noncanonical private provisioning padding")
    return unpack(payload[8:8 + length])


def public_context(body):
    value = unpack(body, public=True)
    if type(value) is not dict or set(value) != {"mode", "space", "pk", "epoch", "budget"}:
        raise ValueError("Compute-server bootstrap accepts only public context")
    if value["mode"] == "he":
        if type(value["space"]) is not crt.Space or type(value["pk"]) is not bgv.PublicKey:
            raise ValueError("Public HE context required")
        masked._context(value["space"], value["pk"])
        masked.binding(value["epoch"], bytes(16))
    elif value["mode"] != "cache" or value["space"] is not None or value["pk"] is not None or value["epoch"] is not None:
        raise ValueError("Unknown public bootstrap mode")
    if type(value["budget"]) is not int or not 1 <= value["budget"] <= 65536:
        raise ValueError("Invalid bootstrap budget")
    return value


def checker_material(checker):
    if type(checker) is not checks.NativeVectorCheck or checker._pending or checker._spent or checker._attempts or checker._registered:
        raise ValueError("Only fresh trusted checker enrollment can be provisioned")
    return {"seeds": checker._seeds, "fingerprints": checker._fingerprints,
            "column_bounds": checker._column_bounds, "budget": checker._budget}


def restore_checker(s, pk, epoch, material):
    """Owner-authenticated values only; no index/private key needed to restore."""
    masked._context(s, pk)
    masked.binding(epoch, bytes(16))
    if (type(material) is not dict or set(material) != {"seeds", "fingerprints", "column_bounds", "budget"}
            or type(material["budget"]) is not int or not 1 <= material["budget"] <= 65536
            or type(material["seeds"]) is not tuple or not 1 <= len(material["seeds"]) <= 8
            or any(type(seed) is not bytes or len(seed) != 32 for seed in material["seeds"])
            or not gmpy2.is_prime(pk.q)):
        raise ValueError("Invalid trusted checker material")
    fp, bounds = material["fingerprints"], material["column_bounds"]
    if (type(fp) is not tuple or len(fp) != len(material["seeds"])
            or any(type(row) is not tuple or len(row) != s.columns
                   or any(type(p) is not tuple or len(p) != d
                          or any(type(x) is not int or not 0 <= x < pk.q for x in p)
                          for p, d in zip(row, s.column_degrees, strict=True)) for row in fp)
            or type(bounds) is not tuple or len(bounds) != s.columns
            or any(type(row) is not tuple or len(row) != s.layout.cost.response_ciphertexts
                   or any(type(x) is not int or not 0 <= x < pk.q // 2 for x in row) for row in bounds)):
        raise ValueError("Invalid trusted checker shape/ranges")
    obj = checks.NativeVectorCheck.__new__(checks.NativeVectorCheck)
    obj.space, obj.pk, obj.epoch = s, pk, epoch
    obj._native = checks.backend()
    obj._seeds, obj._fingerprints, obj._column_bounds = material["seeds"], fp, bounds
    obj._budget, obj._attempts, obj._registered = material["budget"], 0, 0
    obj._pending, obj._spent, obj._lock = {}, set(), threading.Lock()
    return obj
