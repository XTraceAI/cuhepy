"""E48: omit C1 on the wire, reconstruct it from authenticated public seeds.

The existing masked linear request has PUBLIC delta. Each fresh index/answer
C1 is generated from its public encryption seed, so the client can compute the
prescribed response C1. The complete old fingerprint is still checked before
secret decryption. This trades public client work/state for response bytes;
it is not a new encryption/compression primitive or production wire protocol.

Only fresh fixed-index/answer seeds are supported here. Dynamic additive seed
DAGs, authenticated network setup and private timing remain separate work.
Neither an OTP mask seed nor a secret checking challenge is exported.
"""

from __future__ import annotations

from dataclasses import dataclass
import importlib
import struct

from gmpy2 import is_prime, mpz

from experiments.bfv_search_lab import coefficient_body as codec
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import seeded_bgv as seeded
from experiments.bfv_search_lab import shallow_bgv as bgv


@dataclass(frozen=True)
class PublicSeeds:
    space: space.Space
    epoch: bytes
    columns: tuple[tuple[bytes, ...], ...]


def enroll(s, groups, epoch, client):
    masked._context(s, client.pk)
    masked.binding(epoch, bytes(16))
    columns, seeds, upload = [], [], 0
    for polynomials in space.columns(s, groups):
        packets = [client.encrypt(p) for p in polynomials]
        upload += sum(map(len, packets))
        columns.append(tuple(owner.expand(p, client.pk) for p in packets))
        seeds.append(tuple(seeded._parse(p, client.pk)[1] for p in packets))
    return masked.Index(s, epoch, tuple(columns)), PublicSeeds(s, epoch, tuple(seeds)), upload


def prepare(s, groups, epoch, token_id, mask_seed, client):
    values = masked.mask(s, mask_seed, epoch, token_id)
    packets = [client.encrypt(p) for p in space.outputs(s.layout, space.scores(s, groups, values))]
    answer = masked.Answer(s, epoch, token_id, tuple(owner.expand(p, client.pk) for p in packets))
    public_seeds = tuple(seeded._parse(p, client.pk)[1] for p in packets)
    return masked.MaskTicket(s, mask_seed, epoch, token_id), answer, public_seeds


def c0_body(result, pk):
    masked.validate_ciphertexts(result, len(result), pk)
    return codec.pack(tuple(int(x) for c in result for x in c.components[0]), int(pk.q))


class Reconstructor:
    def __init__(self, material: PublicSeeds, pk: bgv.PublicKey, *, mode: str = "cached"):
        masked._context(material.space, pk)
        masked.binding(material.epoch, bytes(16))
        count = material.space.layout.cost.response_ciphertexts
        if (mode not in ("cached", "streaming") or len(material.columns) != material.space.columns
                or any(len(row) != count or any(type(s) is not bytes or len(s) != 32 for s in row)
                       for row in material.columns)):
            raise ValueError("Incorrect public component seed manifest")
        self.material, self.pk, self.mode = material, pk, mode
        self._fresh = pk.t // 2 + pk.t * pk.eta
        self._backend = importlib.import_module("experiments.bfv_search_lab._subring._crt_subring")
        if (self._backend.ABI_VERSION != 1 or not is_prime(pk.q) or not 3 <= pk.q < 1 << 60
                or (pk.q - 1) % (2 * material.space.slots)):
            raise ValueError("Invalid public coefficient reconstruction backend/context")
        self._roots = {}
        q = int(pk.q)
        for degree in dict.fromkeys(material.space.column_degrees):
            psi = next((pow(a, (q - 1) // (2 * degree), q) for a in range(2, 1000)
                        if pow(pow(a, (q - 1) // (2 * degree), q), degree, q) == q - 1), None)
            if psi is None:
                raise ValueError("Missing public coefficient subring root")
            self._roots[degree] = psi
        self._prepared = None
        if mode == "cached":
            zero = (mpz(0),) * pk.n
            columns = tuple(tuple(bgv.Ciphertext((zero, owner._uniform_bulk(seed, pk)), pk.key_id, self._fresh)
                                  for seed in seeds) for seeds in material.columns)
            self._prepared = native.NativeIndex(masked.Index(material.space, material.epoch, columns), pk)

    def restore(self, request: masked.Request, body: bytes, answer_seeds: tuple[bytes, ...]):
        masked.validate_request(request)
        s, pk = self.material.space, self.pk
        count = s.layout.cost.response_ciphertexts
        if (request.space != s or request.epoch != self.material.epoch
                or type(answer_seeds) is not tuple or len(answer_seeds) != count
                or any(type(seed) is not bytes or len(seed) != 32 for seed in answer_seeds)):
            raise ValueError("Stale or invalid prescribed public component recipe")
        c0 = codec.unpack(body, count * pk.n, int(pk.q))
        zero = (mpz(0),) * pk.n
        fake = masked.Answer(s, request.epoch, request.token_id, tuple(
            bgv.Ciphertext((zero, owner._uniform_bulk(seed, pk)), pk.key_id, self._fresh) for seed in answer_seeds))
        if self._prepared is not None:
            evaluated = self._prepared.evaluate(fake, request)
            c1 = tuple(c.components[1] for c in evaluated)
            bounds = tuple(c.phase_bound for c in evaluated)
        else:
            short = space.corrections(s, request.delta)
            data = native.pack(fake.ciphertexts)
            for seeds, degree, weights in zip(self.material.columns, s.column_degrees, short, strict=True):
                columns = tuple(bgv.Ciphertext((zero, owner._uniform_bulk(seed, pk)), pk.key_id, self._fresh)
                                for seed in seeds)
                handle = self._backend.prepare(pk.n, degree, 1, count, int(pk.q), self._roots[degree], native.pack(columns))
                data = self._backend.evaluate(handle, struct.pack(f"<{len(weights)}q", *weights), data)
                # The next iteration holds only one index column. Public
                # native arrays/PRG buffers are scratch, not a free state claim.
                del handle, columns
            words = tuple(mpz(x) for x in struct.unpack(f"<{len(data) // 8}Q", data))
            c1 = tuple(words[(2 * r + 1) * pk.n:(2 * r + 2) * pk.n] for r in range(count))
            limit = self._fresh * (1 + sum(sum(map(abs, row)) for row in short))
            if 2 * limit >= pk.q:
                raise ValueError("Prescribed response exceeds the phase budget")
            bounds = (limit,) * count
        return tuple(bgv.Ciphertext((tuple(mpz(x) for x in c0[r * pk.n:(r + 1) * pk.n]), c1[r]),
                                    pk.key_id, bounds[r]) for r in range(count))

    def verify_and_restore(self, gate, request, body, answer_seeds):
        try:
            result = self.restore(request, body, answer_seeds)
        except (ValueError, TypeError):
            # Malformed attempts still burn the original gate's lifetime budget.
            gate.verify_once(request, ())
            raise ValueError("Invalid response component recipe") from None
        if not gate.verify_once(request, result):
            raise ValueError("Reconstructed complete ciphertext was rejected")
        return result
