"""Variable-time radix fixture client; ciphertext equality gates all private work.

The full expected response must be obtained independently in the local fixture.
No receipt, GPU authentication, constant-time guarantee or production API is
provided. Existing native owner arithmetic and all original clients are kept.
"""

import heapq

from experiments.bfv_search_lab import owner_bgv as owner, compact_bgv as compact
from experiments.bfv_search_lab import compressed_response_bgv as response_codec
from experiments.bfv_search_lab import compressed_query_bgv as query_codec
from experiments.bfv_search_lab import transport_bgv as wire, results_bgv as results
from experiments.bfv_search_lab.native_owner_bgv import NativeTernaryProduct


class RadixClient(owner.OwnerClient):
    def finish_radix_fixture(self, packet, expected, count, layout, plan, *, packed=False, vectorized=False):
        wire.require_expected_fixture(packet, expected)
        if type(packed) is not bool or type(vectorized) is not bool:
            raise ValueError("Radix implementation selections must be bool")
        layout.validate(self.pk.n, self.pk.t, count)
        raw = layout.unwrap(packet, count, "response")
        bounds = list(plan.terminal_bounds)
        groups = layout.groups(count)
        if plan.response_drop is not None:
            raw, bounds = response_codec.expand(
                raw, self.pk, count=groups, dimension=layout.dimension,
                bits=plan.terminal_bits, bounds=bounds, dropped_bits=plan.response_drop,
                backend="native")
        if bounds != list(plan.final_bounds):
            raise ValueError("Wrong owner-pinned radix precision plan")
        modulus = compact.terminal_modulus(self.pk.q, self.pk.t, plan.terminal_bits)
        # Every ciphertext is parsed and checked before the first private operation.
        if packed:
            self._check()
            with self._lock:
                self._check()
                if not isinstance(self._product, NativeTernaryProduct):
                    raise ValueError("Packed radix finishing requires the native owner")
                pairs = wire._unpack_fields(raw, self.pk, count=groups, dimension=layout.dimension,
                                            modulus=modulus, bounds=bounds)
                native = query_codec._implementation("native")
                for pair in pairs:
                    for coefficient_bytes in pair:
                        native.validate_coefficients(coefficient_bytes, self.pk.n, format(modulus, "x"))
                plaintexts = [self._product.decrypt_packed(pair, modulus, self.pk.t) for pair in pairs]
        else:
            parsed = wire.unpack_fixture(raw, self.pk, count=groups, dimension=layout.dimension,
                                         modulus=modulus, bounds=bounds)
            plaintexts = [self.decrypt_compact(c) for c in parsed]
        decode = layout.decode_numpy if vectorized else layout.decode
        distances = tuple(decode(plaintexts, count, self.pk.n, self.pk.t))
        top = tuple(heapq.nsmallest(3, enumerate(distances), key=lambda pair: (pair[1], pair[0])))
        return results.SearchResult(top, distances)
