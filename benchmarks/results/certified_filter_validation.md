# Certified lookup, coordinate folding and refinement validation

2026-09-27, branch `experiment/creative-search-algebra`. Implementation commits
`b5f5825`, `6beacea`, and model-control update `b2937b8`.

## Correctness and static checks

```bash
.venv/bin/python -m pytest \
  experiments/bfv_search_lab/test_certified_filters.py \
  experiments/bfv_search_lab/test_adaptive_refinement.py \
  experiments/bfv_search_lab/test_deferred_bgv.py \
  experiments/bfv_search_lab/test_answer_oracles.py \
  experiments/bfv_search_lab/test_aggregate_bgv.py \
  experiments/bfv_search_lab/test_syndrome_oracle.py \
  experiments/bfv_search_lab/test_butterfly_bgv.py \
  experiments/bfv_search_lab/test_trace_bgv.py \
  experiments/bfv_search_lab/test_shallow_bgv.py -q
```

**150 passed in 6.71 s**, including 49 new tests. Covers exhaustive small
query/block cases, complemented coordinates, perturbed templates, ties,
empty/tail/multiple-response packing, large integer corrections, malformed
certificates, modular unwrapping and actual homemade encrypted evaluation.
The adaptive test deliberately demonstrates that untrusted high bounds can
omit a winner: the oracle does not masquerade as remote authentication.

Ruff passes for the four new modules, two test modules and two benchmarks,
using `--no-force-exclude`. Mypy passes for `linear_packing.py`,
`folded_filter.py`, `certified_lookup.py`, and `adaptive_refinement.py` with
`--explicit-package-bases --follow-imports=silent`.

The later benchmark-only change adds unrelated-query/overcompression fixtures;
it does not change the modules covered by these tests. No full production,
GPU sanitizer, security-parameter or side-channel audit rerun is claimed.

## Measurements

```bash
OPENBLAS_NUM_THREADS=1 .venv/bin/python benchmarks/certified_filter_lab.py \
  --json-out benchmarks/results/certified_filter_lab_20260927.json
OMP_NUM_THREADS=8 OPENBLAS_NUM_THREADS=1 .venv/bin/python benchmarks/folded_bgv_native.py \
  --json-out benchmarks/results/folded_bgv_native_20260927.json
```

Both completed. Measurements run sequentially, outside tests/builds. The
model benchmark evaluates three public-table ranks, three data seeds,
favorable/adverse queries and whole-tile refinement; its tiny encrypted pilot
includes one warmup plus seven shuffled paired rounds.

The native benchmark has one warmup plus seven shuffled paired rounds over
8,192 distinct 512-bit vectors. It checks every decrypted distance, stable
top-three result and complete CPU/CUDA response equality. The ring/moduli,
precision and native API are matched. A 65-vector N=1024 CPU/CUDA smoke test
also passed before the full-size measurement.

The restricted sandbox could not access CUDA; the same local synthetic
benchmark passed with approved GPU access outside that sandbox. This was an
environment restriction, not a crypto or CUDA-kernel correctness failure.

Host: AMD Ryzen 7 5800X (8 cores, 16 threads), NVIDIA RTX 3080 (10,240 MiB),
driver 580.173.02. Python/platform versions, public parameters, commands,
sample timings, setup and source/binary hashes are recorded in the JSONs.
No secret keys, actual query/vector contents or ciphertext bodies are saved.

Source hashes are checked against the artifact's recorded Git commit. The
native measurement at `6beacea` includes the earlier model-helper file; the
later `b2937b8` edit only adds model controls, leaving the native fixture
generator and timing helper unchanged. Native shared-object hashes are checked
against the installed binaries.

All 26 recorded source/binary hashes match those references. All 116 relative
file links in the updated research/sandbox/validation documents resolve, and
`git diff --check` passes.

Interpretation, limitations and next experiment cards are in
[the results report](../../docs/research/certified-folding-results.md).
