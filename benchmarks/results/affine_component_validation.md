# Affine component / encrypted lookup validation

2026-09-27, `experiment/creative-search-algebra`.

## Tests and static checks

```bash
.venv/bin/python -m pytest -q experiments/bfv_search_lab/test_{affine_crt,dictionary_intervals,witness_packing,owner_residuals,certified_filters,adaptive_refinement,deferred_bgv,answer_oracles,aggregate_bgv,syndrome_oracle,butterfly_bgv,trace_bgv,shallow_bgv}.py
.venv/bin/ruff check --no-force-exclude \
  experiments/bfv_search_lab/{affine_dictionary,crt_multiplex,private_residual_lookup,test_affine_crt}.py \
  benchmarks/{component_dictionary_lab,component_bgv_native}.py
.venv/bin/mypy --explicit-package-bases --follow-imports=silent \
  experiments/bfv_search_lab/{affine_dictionary,crt_multiplex,private_residual_lookup}.py
```

**204 passed in 6.11 s**, including 23 new tests. Ruff passes all six changed/new
Python files; Mypy passes the three new modules. No production client or native
kernel was modified. This is a focused research regression suite, not a complete
repository/security audit or a fresh GPU sanitizer run.

Tests cover exhaustive binary queries for tiny affine spaces; constant/dummy
features; exact pivot reconstruction and epoch rejection; non-sign field
coefficients in compiled query masks; CRT round-trip and independent twisted
schoolbook products; existing homemade BGV butterfly execution with empty/tail
components and multiple replies; and whole-polynomial projection equality with
an independent integer oracle. A row that adds the 65th direction doubles padding
and is rejected by the old map. Invalid fields, roots, padding, ranges and map
pivots are rejected. Encrypted address/sign selection covers absent residuals.
A plausible wrong score passes local decoding deliberately: these helpers do
not authenticate server output or authorize remote decryption.

## Reproduction and retained artifacts

Download public fixtures with the existing pinned fetcher if needed:

```bash
.venv/bin/python benchmarks/fetch_binary_fixtures.py --cache-dir ../research-data/uci-20260927
OPENBLAS_NUM_THREADS=1 .venv/bin/python benchmarks/component_dictionary_lab.py \
  --cache-dir ../research-data/uci-20260927 \
  --json-out benchmarks/results/component_dictionary_lab_20260927.json
OMP_NUM_THREADS=8 OPENBLAS_NUM_THREADS=1 .venv/bin/python benchmarks/component_bgv_native.py \
  --cache-dir ../research-data/uci-20260927 \
  --json-out benchmarks/results/component_bgv_mushroom_masks_20260927.json
OMP_NUM_THREADS=8 OPENBLAS_NUM_THREADS=1 .venv/bin/python benchmarks/component_bgv_native.py \
  --cache-dir ../research-data/uci-20260927 --seed 3002 --parts 16 \
  --json-out benchmarks/results/component_bgv_mushroom_split2_20260927.json
OMP_NUM_THREADS=8 OPENBLAS_NUM_THREADS=1 .venv/bin/python benchmarks/component_bgv_native.py \
  --cache-dir ../research-data/uci-20260927 --dataset piecewise \
  --json-out benchmarks/results/component_bgv_piecewise_20260927.json
```

All completed; native timing runs were sequential and did not overlap builds
or tests. The initial three-mode dense-only run is separately retained in
`component_bgv_mushroom_20260927.json` with source `4bb59bb`. The model records
`cfb7ef0`; the three four-mode native runs record `d6d9ad8`. Later docs/tests do
not change measured sources. Use recorded commits to reproduce exact revisions;
do not overwrite retained artifacts when running a later version.

The model checks every distance and stable top-3 for 46 configurations × 16
queries = 736 cases. Public split seeds are 3001/3002, model holdout positions
64:80, native positions 104:112 with 103 as warmup. Fitting sees only index rows.
Public fixtures are hash pinned; raw data is outside Git. Both synthetic indexes
contain 8,192 distinct vectors; the favorable one has given block structure.

Every native run uses one warmup and eight fresh paired queries, checking every
score/stable winner plus complete CPU/CUDA response byte equality per mode.
CPU and CUDA reuse identical fresh query ciphertexts within each mode; evaluation
order is shuffled. Timings include query transforms/encryption/expansion,
evaluation, response packing, decryption and decoding/selection. Setup, network,
authentication and private side-channel assurance are separate. Eight samples
support exploratory medians, not p95 or broad hardware/data claims.

All modes use our homemade BGV, full `N=16384`, `t=1153`, 120-bit RNS `Q`,
`eta=21`, 30-bit gadget digits, conservative bounds and 32-bit terminal precision.
Hardware: Ryzen 7 5800X, eight OpenMP threads, RTX 3080 10 GiB. Local GPU execution
used approved access outside the sandbox; no installation was needed. The older
`t=1031` experiments remain separate controls, not denominator timings here.

The five JSON artifacts contain aggregate sizes/timings, public source IDs,
parameters, commands, source/binary and map hashes; no raw private maps, raw
datasets, secret keys, query contents or ciphertexts are published. Dense-only
regressions, failed storage cases and full-plaintext local-search controls remain.

**97 source/binary hashes match**: sources against each recorded Git commit and
binaries against the installed extensions. All **83 relative file links** in the
six updated research/sandbox/validation documents resolve, and `git diff --check`
passes. The checkpoint for this cycle is
`checkpoint/affine-components-2026-09-27`; prior company and research checkpoints
are retained. A separately verified Git bundle is kept in the workspace's
`checkpoints/affine-components-2026-09-27/` directory before remote publication.

See [the report](../../docs/research/affine-component-results.md) for measured
tables, storage categories, mathematical identities, literature boundaries and
the next creative experiments.
