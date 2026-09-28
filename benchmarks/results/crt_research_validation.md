# E29 validation record — 2026-09-28

Source checkpoints: `26e8ffb` and `b6e41c8`. The [report](../../docs/research/crt-masked-query-results.md)
states assumptions and costs. Existing production and earlier research modules
are unchanged. No Microsoft HE implementation is used by these checks.

## Correctness regressions

```bash
.venv/bin/python -m pytest -q experiments/bfv_search_lab/test_{crt_masked_bgv,crt_linear_check,crt_native_bgv,matrix_bgv_oracle,matrix_masked_query,matrix_linear_check,dyadic_crt,rank_partition,affine_crt,dictionary_intervals,witness_packing,owner_residuals,certified_filters,adaptive_refinement,deferred_bgv,answer_oracles,aggregate_bgv,syndrome_oracle,butterfly_bgv,trace_bgv,shallow_bgv}.py
```

Result: **336 passed in 8.58s**. [Retained output](crt_research_validation_pytest.txt).
The 28 E29 cases include complete-polynomial equivalence to the old butterfly,
noisy phase bounds, every output coefficient, field wraps, all binary queries
on a small private affine fixture, multiple replies, empty tails, map replicas,
double consumption, stale epochs, poisoned trusted state, deterministic-mask
recovery, canonical/rounded output rejection and native signed-word boundaries.

## Native arithmetic and static checks

The optional extension built successfully with `g++ -O3 -std=c++17 -Wall -Wextra`.
A separate unchanged-source build used `-O1 -g -fsanitize=undefined
-fno-sanitize-recover=all`. Loading it under the normal module name and running
`test_crt_native_bgv.py` gave **5 passed in 0.17s**, with no UBSan diagnostics.
This includes minimum/maximum signed 64-bit corrections, canonical coefficient
boundaries and malformed buffers. This was not a CUDA or memory-sanitizer run.

```bash
.venv/bin/ruff check --no-force-exclude \
  experiments/bfv_search_lab/crt_query_space.py \
  experiments/bfv_search_lab/crt_masked_bgv.py \
  experiments/bfv_search_lab/crt_linear_check.py \
  experiments/bfv_search_lab/crt_native_bgv.py \
  experiments/bfv_search_lab/test_crt_masked_bgv.py \
  experiments/bfv_search_lab/test_crt_linear_check.py \
  experiments/bfv_search_lab/test_crt_native_bgv.py benchmarks/crt_masked_bgv_lab.py
.venv/bin/mypy --explicit-package-bases --follow-imports=silent \
  experiments/bfv_search_lab/crt_query_space.py \
  experiments/bfv_search_lab/crt_masked_bgv.py \
  experiments/bfv_search_lab/crt_linear_check.py \
  experiments/bfv_search_lab/crt_native_bgv.py
```

Both passed. Source whitespace checks passed before committing.

## Full-size encrypted execution

The four `crt_masked_bgv_{affine,raw}_{3001,3002}_20260928.json` artifacts each
contain one warmup plus three measured queries on 7,996 distinct public Mushroom
rows, with `N=16384`, `t=1153`, `eta=21`. Affine uses 40-bit Q/four checking
rounds; raw uses 32-bit Q/five rounds. These are correctness-bound profiles,
not approved security parameters. Each artifact pins source commit `b6e41c8`,
23 source/binary hashes, public fixture digest and exact heldout query IDs.

The [integrity manifest](crt_research_manifest_20260928.json) checks all four
artifact digests and all 92 source/binary entries. The 22 unique source files
also match their bytes in the recorded Git commit; the local extension's hash
is recorded separately for rebuilding. Relative links in the updated reports
were checked against existing local files.

Across **16 encrypted searches**, every distance and stable top-three result
matches independent plaintext Hamming distance. Every C++ ciphertext coefficient
and public bound equals the GMP result. Every conditional check precedes HE
decryption. Token pools and their trusted fingerprints are prepared before
selecting online queries. Enrollment, checker setup, per-token work and unused
token communication are charged separately from online times.

The benchmark deliberately keeps the reference in the comparison. It does not
measure an attested deployment, end-to-end network latency, equal-contract
production CPU/GPU speedups, tail latency or adaptive security. Private Python
code and in-memory replay budgets remain outside any production assurance claim.
