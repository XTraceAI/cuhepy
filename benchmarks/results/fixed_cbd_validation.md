# E32 validation and measurement provenance

2026-09-29. [Result and derivation](../../docs/research/fixed-batch-noise-results.md).
Retained measurement source: `a55bfac93d9bf17547451a3c46173f01211f962d`.
Only experiments, benchmark harnesses/results and documentation changed.
The production Paillier/BFV/BGV and C++/CUDA code are preserved.

## Checks

- **387 tests passed in 9.68 s**, including 20 new E32 cases and the retained
  E19–E31 suite. [Transcript](fixed_cbd_validation_pytest.txt).
- Exact sampler entropy and weighted-distribution oracles, schoolbook
  negacyclic phases, invalid-independence counterexamples and large-integer
  bound rounding pass. The small encrypted fixture covers all 32 binary
  queries, three replies and simultaneous correction degrees 1,2,4.
- Complete-tail/certificate/request/context mutation is rejected before
  private multiplication. Replay, concurrent release and receipt substitution
  are tested. The existing q32 deterministic gate remains rejecting.
- Ruff passes the five new implementation/benchmark/test files and the
  separate summary script with `--no-force-exclude`. Mypy passes the two new
  explicitly named implementation modules with imported-module analysis.
- **72 full-size encrypted searches**, including warmups, on **36 distinct
  dataset/query IDs**. Every distance/stable top-three result is exact; every
  GMP/C++ response coefficient agrees.
- The separate owner diagnostic reconstructs and checks **1,179,648 unreduced
  integer phase coefficients**. It is excluded from online timing. These
  tests/observations do not measure a 2^-128 failure probability.

```bash
.venv/bin/python -m pytest -q experiments/bfv_search_lab/test_{crt_noise_budget,fixed_batch_bgv,hierarchical_query_basis,shared_query_basis,correlation_pool_limits,crt_masked_bgv,crt_linear_check,crt_native_bgv,matrix_bgv_oracle,matrix_masked_query,matrix_linear_check,dyadic_crt,rank_partition,affine_crt,dictionary_intervals,witness_packing,owner_residuals,certified_filters,adaptive_refinement,deferred_bgv,answer_oracles,aggregate_bgv,syndrome_oracle,butterfly_bgv,trace_bgv,shallow_bgv}.py
.venv/bin/ruff check --no-force-exclude benchmarks/{fixed_batch_noise_lab,fixed_batch_noise_summary}.py experiments/bfv_search_lab/{crt_noise_budget,fixed_batch_bgv,test_crt_noise_budget,test_fixed_batch_bgv}.py
.venv/bin/mypy --explicit-package-bases --follow-imports=silent experiments/bfv_search_lab/{crt_noise_budget,fixed_batch_bgv}.py
```

## Retained data

- [Mushroom split 3001](fixed_batch_noise_mushroom_3001_20260929.json),
  [log](fixed_batch_noise_mushroom_3001_20260929.log).
- [Mushroom split 3002](fixed_batch_noise_mushroom_3002_20260929.json),
  [log](fixed_batch_noise_mushroom_3002_20260929.log).
- [Semeion split 3001](fixed_batch_noise_semeion_3001_20260929.json),
  [log](fixed_batch_noise_semeion_3001_20260929.log).
- [Semeion split 3002](fixed_batch_noise_semeion_3002_20260929.json),
  [log](fixed_batch_noise_semeion_3002_20260929.log).
- [Eight profile/stage rows](fixed_batch_noise_stages_20260929.csv).
- [24 fixed-pool utilization models](fixed_batch_noise_utilization_20260929.csv).
- [Four paired payload/link models](fixed_batch_noise_comparisons_20260929.csv).
- [Source/artifact manifest](fixed_batch_noise_manifest_20260929.json).

The manifest audits **100 source/binary hashes** across four reports. Tracked
source matches both the worktree and exact measurement commit objects; the
ignored native binary matches its local hash. No new timings are created by
the summarizer. CSVs use LF endings. Native ABI/storage stays u64; no binary
rebuild, sanitizer run, GPU benchmark or network/TEE measurement was performed.

Reproduce each combination of dataset mushroom/semeion and seed 3001/3002
serially, without concurrent tests/profiling. One warmup is excluded from each
case's eight timing samples. Fresh HE/check randomness means exact phases and
timings will differ; fixtures and query IDs are pinned.

```bash
.venv/bin/python benchmarks/fixed_batch_noise_lab.py \
  --cache-dir /home/pete/yavor-projects/xtrace-work/research-data/uci-20260927 \
  --dataset mushroom --seed 3001 --repeats 8 \
  --json-out /tmp/fixed_batch_noise_mushroom_3001.json
.venv/bin/python benchmarks/fixed_batch_noise_summary.py
```

Pilot JSON/logs are exploratory and excluded from the retained timing table.
The final runs charge constructor/query-transform/mask-fixing work that the
early pilot did not separately time. All requests/corrections precede index
encryption. The 1,024-request budget is an upper bound, not permission to append
queries after the nine-request batch has been enrolled. Utilization models
charge all nine prepared answers even when fewer are used.

The smaller modulus's CBD correctness certificate, hidden-checker integrity
model and RLWE security requirements are separate. No production parameter
approval or adaptive transcript proof is implied by passing these checks.
