# Dyadic rank/capacity, cache and epoch validation

2026-09-27, `experiment/creative-search-algebra`.

## Tests and checks

```bash
.venv/bin/python -m pytest -q experiments/bfv_search_lab/test_{dyadic_crt,rank_partition,affine_crt,dictionary_intervals,witness_packing,owner_residuals,certified_filters,adaptive_refinement,deferred_bgv,answer_oracles,aggregate_bgv,syndrome_oracle,butterfly_bgv,trace_bgv,shallow_bgv}.py
.venv/bin/ruff check --no-force-exclude \
  experiments/bfv_search_lab/{dyadic_crt,rank_partition,test_dyadic_crt,test_rank_partition}.py \
  benchmarks/{dyadic_layout_lab,dyadic_bgv_native,dyadic_state_epoch_lab}.py
.venv/bin/mypy --explicit-package-bases --follow-imports=silent \
  experiments/bfv_search_lab/{dyadic_crt,rank_partition}.py
```

**235 passed in 6.56 s**, including 31 new tests. Ruff passes seven files;
Mypy passes both new modules. No production client, native code or CUDA kernel
changed. This is a focused research regression suite, not the whole repository,
a new security audit or a repeated sanitizer/timing-assurance run.

Tests include independent direct polynomial remainders and schoolbook products,
equality with the old CRT under root permutation, and complete homemade BGV
output-polynomial comparisons. Unequal degrees, empty leaves, partial tiles,
multiple replies, invalid cover/root/context/padding and malformed shapes are
covered. Rank repair preserves every score and stable-ID ties. Exact fixed-map
capacity matches exhaustive small allocations. Flat/coalesced allocation has
the same charged product count and unique-map body. Coverage/duplicate/map-size
mutations, in-span row changes and stale/reordered local epochs are rejected.
These checks do not authenticate remote ciphertexts or bind external IDs.

## Reproduction

```bash
OPENBLAS_NUM_THREADS=1 .venv/bin/python benchmarks/dyadic_layout_lab.py \
  --cache-dir ../research-data/uci-20260927 \
  --json-out benchmarks/results/dyadic_layout_lab_20260927.json
OMP_NUM_THREADS=8 OPENBLAS_NUM_THREADS=1 .venv/bin/python benchmarks/dyadic_bgv_native.py \
  --cache-dir ../research-data/uci-20260927 --seed 3002 \
  --json-out benchmarks/results/dyadic_bgv_mushroom_split2_20260927.json
OMP_NUM_THREADS=8 OPENBLAS_NUM_THREADS=1 .venv/bin/python benchmarks/dyadic_bgv_native.py \
  --cache-dir ../research-data/uci-20260927 --seed 3001 \
  --json-out benchmarks/results/dyadic_bgv_mushroom_split1_20260927.json
OMP_NUM_THREADS=8 OPENBLAS_NUM_THREADS=1 .venv/bin/python benchmarks/dyadic_bgv_native.py \
  --cache-dir ../research-data/uci-20260927 --dataset uneven \
  --json-out benchmarks/results/dyadic_bgv_uneven_20260927.json
OPENBLAS_NUM_THREADS=1 .venv/bin/python benchmarks/dyadic_state_epoch_lab.py \
  --cache-dir ../research-data/uci-20260927 \
  --json-out benchmarks/results/dyadic_state_epoch_lab_20260927.json
```

All completed. Timed benchmark processes ran sequentially and did not overlap
builds or tests. Public fixture hashes are pinned by the existing
[`fetch_binary_fixtures.py`](../fetch_binary_fixtures.py) and loader; raw datasets
remain outside Git. The native runs used approved local GPU access outside the
sandbox. Hardware is Ryzen 7 5800X with eight OpenMP threads and RTX 3080 10 GiB.
No installation was needed.

Artifact source revisions are `26c5c47` (model), `8db3cb9` (all three native
runs), and `80fcf00` (cache/epoch controls). Use their recorded commits for exact
reproduction and a different output path rather than overwriting retained
results. Every one of the **99 source/binary hashes matches**: source against
its recorded Git commit, native extensions against installed binaries.

Model coverage is 72 successful configurations × 16 queries = **1,152** exact
all-distance/stable-top-3 cases, plus six explicit fit rejections. Mushroom uses
three index split seeds (3001, 3002, 3101); Semeion uses 3101. Model holdout
positions 80:96 and native positions 120:128 are disjoint; native warmup is 119.
Fitting sees index data only. Both synthetic controls have 8,192 distinct rows.

Native coverage is eight modes × two devices × nine queries on each public
split and five modes × two devices × nine queries on the unequal synthetic
fixture: **378** complete local encrypted searches including warmups, with
**336** measured searches. Every score/stable winner matches XOR/popcount, and
complete CPU/CUDA response bytes agree for all 189 mode/query pairs. Equal-tree
codec controls additionally preserve every index/query plaintext coefficient
and share the corresponding flat control's prepared encrypted index.

All native modes use the same full `N=16384`, `t=1153`, 120-bit RNS `Q`, secret,
`eta=21`, conservative bounds, 30-bit gadget digits and 32-bit terminal precision
within each run. Client transforms, encryption, query expansion, evaluation,
packing, decryption and final selection are timed. Setup/network/authentication
are separate. Eight samples support exploratory medians, not p95 or general
claims about small GPU differences.

The owner-cache control reconstructs every row from packed pivots/maps and
checks 54 complete cache queries including warmups across packed/compressed
modes. Cache query timings include unpacking/decompression and use the same
public/synthetic query sequences as the corresponding native runs. Compressed
body bytes are not working-memory or production wire-format claims. The
single-row update compares four old/new/repaired/allocated representations on
16 queries each (64 exact all-score cases), and rejects the stale map/epoch.
Reported update times are full owner rebuilding/certification, excluding HE
re-encryption, native index replacement and reviewed epoch authorization.

Five JSON artifacts publish only aggregate counts/sizes/timings, public source
IDs, parameters, paths and hashes. They contain no raw maps, rows, pivot caches,
secret keys, query values or ciphertexts. Failed fits, excess-state candidates,
codec regressions and complete plaintext cache/scan controls are retained.

All **87 relative file links** in the six updated research/sandbox/validation
documents resolve; `git diff --check` passes. The new
checkpoint is `checkpoint/dyadic-rank-capacity-2026-09-27`; the previous
`checkpoint/affine-components-2026-09-27` and earlier company/research checkpoints
remain intact. A verified full-history Git bundle with an independent mirror
restore is kept in `checkpoints/dyadic-rank-capacity-2026-09-27/` in the workspace.

See [the report](../../docs/research/dyadic-rank-results.md) for mathematical
scope, storage categories, measured results, literature and next experiments.
