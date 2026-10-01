"""E66 known supported-C0 + public-C1-recipe control with a separate gate.

Only selected full-Q C0 coefficients travel. Public arithmetic reconstructs
the complete C1 from owner-pinned fresh seeds; the existing supported relation
is checked before its dedicated secret decoder. No new crypto/proof/wire API.
Fresh fixed-index/answer recipes only. Local state is volatile and side-channel
and whole-protocol/parameter assurance remain the same open research tasks.
"""

from __future__ import annotations

import threading

from experiments.bfv_search_lab import coefficient_body as codec
from experiments.bfv_search_lab import component_recipe as recipe
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import decryption_support as support
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import supported_decoder as decoder


def pack(output, space, pk, epoch):
    projected = decoder.project(output, space, pk, epoch)
    return codec.pack(tuple(x for row in projected.c0_supported for x in row), int(pk.q))


def _fresh_seeds(ciphertexts, seeds, pk):
    fresh_bound = pk.t // 2 + pk.t * pk.eta
    if (type(seeds) is not tuple or len(seeds) != len(ciphertexts)
            or any(type(seed) is not bytes or len(seed) != 32 for seed in seeds)
            or any(c.phase_bound != fresh_bound or c.components[1] != owner._uniform_bulk(seed, pk)
                   for c, seed in zip(ciphertexts, seeds, strict=True))):
        raise ValueError("Recipe must match owner-pinned fresh ciphertexts")


class Gate:
    """Owner-local fresh-material adapter; no server-provided recipe/metadata.

    answer_seeds enter via prepare_answer in the trusted owner domain. Malformed
    attempts consume the same underlying global/one-use budget as valid ones.
    The online method receives a pinned ORIGINAL request and body only.
    """

    def __init__(self, index, material, pk, ids, binding, attempts, *, rounds=4, mode="cached"):
        masked._context(index.space, pk)
        if material.space != index.space or material.epoch != index.epoch or len(material.columns) != len(index.columns):
            raise ValueError("Wrong owner-pinned public seed manifest")
        replies = index.space.layout.cost.response_ciphertexts
        for column, seeds in zip(index.columns, material.columns, strict=True):
            masked.validate_ciphertexts(column, replies, pk)
            _fresh_seeds(column, seeds, pk)
        self._restore = recipe.Reconstructor(material, pk, mode=mode)
        self._decoder = decoder.Gate(index, pk, ids, binding, attempts, rounds=rounds)
        self.pk, self.space, self.epoch = pk, index.space, index.epoch
        self.certificate = support.certify(index.space.layout)
        self._answers = {}
        self._lock = threading.Lock()

    def prepare_answer(self, answer, answer_seeds):
        masked.validate_ciphertexts(answer.ciphertexts, len(self.certificate.kept_c0), self.pk)
        _fresh_seeds(answer.ciphertexts, answer_seeds, self.pk)
        with self._lock:
            self._decoder.prepare_answer(answer)
            self._answers[answer.token_id] = answer_seeds

    def open_body_once(self, request, body, sk):
        # The caller supplies its immutable original request; malformed public
        # bodies never choose a seed, key, phase bound, ID order or decoder.
        with self._lock:
            seeds = self._answers.pop(request.token_id, None)
        if seeds is None:
            return self._decoder.open_once(request, None, sk)
        try:
            values = codec.unpack(body, sum(map(len, self.certificate.kept_c0)), int(self.pk.q))
            full_c0, selected, cursor = [], [], 0
            for indices in self.certificate.kept_c0:
                row = values[cursor:cursor + len(indices)]
                selected.append(row)
                cursor += len(indices)
                poly = [0] * self.pk.n
                for i, value in zip(indices, row, strict=True):
                    poly[i] = value
                full_c0.extend(poly)
            # Omitted C0 is a PUBLIC carrier for reconstruction, never ordinary
            # secret BGV decryption. Only selected phases will be decoded.
            carrier = self._restore.restore(request, codec.pack(tuple(full_c0), int(self.pk.q)), seeds)
            reply = decoder.Reply(tuple(selected), tuple(c.components[1] for c in carrier), self.pk.key_id,
                                  self.epoch, self.space.binding, tuple(c.phase_bound for c in carrier))
        except (ValueError, TypeError):
            return self._decoder.open_once(request, None, sk)
        return self._decoder.open_once(request, reply, sk)


def cost(space, pk):
    certificate = support.certify(space.layout)
    count, width = len(certificate.kept_c0), int(pk.q).bit_length()
    kept = sum(map(len, certificate.kept_c0))
    return {"full_body_bytes": (2 * count * pk.n * width + 7) // 8,
            "recipe_only_body_bytes": (count * pk.n * width + 7) // 8,
            "support_only_body_bytes": ((count * pk.n + kept) * width + 7) // 8,
            "combined_body_bytes": (kept * width + 7) // 8,
            "public_index_seeds_bytes": space.columns * count * 32,
            "trusted_answer_public_seeds_bytes_per_token": count * 32,
            "cached_reconstructor_native_words_bytes_model": 2 * space.columns * count * pk.n * 8,
            "existing_private_fingerprints_and_tokens_removed": False,
            "scope": "Bit-packed coefficient bodies; envelopes, private provisioning, PRG work and native allocation overhead excluded."}
