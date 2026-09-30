"""Analytical CRT support versus independent complete linear decoder columns."""

import random

from experiments.bfv_search_lab import decryption_support as support
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import score_layout


def test_mixed_leaf_and_legacy_supports_match_every_decoder_matrix_column():
    for n, paths, counts in ((32, ("",), (19,)), (32, ("0", "1"), (12, 4)),
                             (64, ("0", "10", "11"), (9, 5, 1)),
                             (32, ("0", "1"), (35, 9))):
        ctx = tree.context(n, paths, 17)
        for constructor in (tree.layout, score_layout.layout):
            layout = constructor(ctx, (2,) * len(paths), counts)
            certificate = support.certify(layout)
            assert certificate == support.matrix_oracle(layout)
            rng = random.Random(62001)
            for _ in range(8):
                phase = [[rng.randrange(17) for _ in range(n)] for _ in certificate.kept_c0]
                reduced = [[x if i in indices else 0 for i, x in enumerate(row)]
                           for row, indices in zip(phase, certificate.kept_c0, strict=True)]
                assert tree.unpack(layout, phase) == tree.unpack(layout, reduced)


def test_old_complete_count_vector_misses_decoder_support_price():
    result = support.equal_old_cost_counterexample()
    assert result["balanced_projected_body_bytes_model"] == 192
    assert result["skewed_projected_body_bytes_model"] == 224
