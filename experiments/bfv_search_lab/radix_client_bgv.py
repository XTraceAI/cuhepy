"""Variable-time radix fixture client; ciphertext equality gates all private work.

The full expected response must be obtained independently in the local fixture.
No receipt, GPU authentication, constant-time guarantee or production API is
provided. Existing native owner arithmetic and all original clients are kept.
"""

import heapq

from experiments.bfv_search_lab import owner_bgv as owner, compact_bgv as compact
from experiments.bfv_search_lab import compressed_response_bgv as response_codec
from experiments.bfv_search_lab import transport_bgv as wire, results_bgv as results


class RadixClient(owner.OwnerClient):
    def finish_radix_fixture(self, packet, expected, count, layout, plan):
        wire.require_expected_fixture(packet, expected)
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
        # Every ciphertext is parsed and checked before the first private operation.
        parsed = wire.unpack_fixture(raw, self.pk, count=groups, dimension=layout.dimension,
                                     modulus=compact.terminal_modulus(self.pk.q, self.pk.t, plan.terminal_bits),
                                     bounds=bounds)
        plaintexts = [self.decrypt_compact(c) for c in parsed]
        distances = tuple(layout.decode(plaintexts, count, self.pk.n, self.pk.t))
        top = tuple(heapq.nsmallest(3, enumerate(distances), key=lambda pair: (pair[1], pair[0])))
        return results.SearchResult(top, distances)
