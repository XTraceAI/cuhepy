# E31 validation and provenance

2026-09-29. The [report](../../docs/research/hierarchical-query-basis-results.md)
uses benchmark source `80f3cc469e3c44efa5bdf92dd87e43af7b21cbba`.
No production source or C++ implementation changed. The subsequent summary
script exports existing observations and explicit models; it does not add
encrypted timing samples or enable the prospective q32 noise profile.

## Checks

- **367 tests passed in 9.53 s**, including the ten new E31 cases and the
  retained E19–E30 suite, with the native extension installed.
  [Transcript](hierarchical_basis_validation_pytest.txt).
- New oracles enumerate all 64 ordered subspace pairs in `F_5^2`, 625 four-leaf
  tuples with all 20 `F_17^2` common-space candidates, and all 24 permutations
  of a grouping example. Binary queries, unequal leaves, dummy/replicated
  forms, empty/multiple replies and independent schoolbook corrections pass.
- Three simultaneous native degree groups agree with GMP. Independent shifted
  fingerprints agree. Complete-response tail mutation and changed-schedule
  substitution are rejected before private decryption. Both E29 and E30
  legacy binding bytes are checked.
- Ruff passes all six changed/new measurement/implementation/test Python files,
  and the separate summarizer. Mypy passes five explicitly named modules.
- **64 full-size encrypted searches** across sixteen cases: every distance,
  stable top-three result and complete GMP/native ciphertext matches. This
  reuses eight distinct held-out queries; it is not 64 independent data draws.

The first attempt used the standalone `pytest` entry point, which lacked the
repository namespace on its import path and failed collection. The retained
command uses `python -m pytest`; no test assertion failed in that attempt.
Pilot results under `/tmp` are exploratory and are not the retained timings.
The C++ binary is unchanged; earlier UBSan results are historical, not rerun here.

```bash
.venv/bin/python -m pytest -q experiments/bfv_search_lab/test_{hierarchical_query_basis,shared_query_basis,correlation_pool_limits,crt_masked_bgv,crt_linear_check,crt_native_bgv,matrix_bgv_oracle,matrix_masked_query,matrix_linear_check,dyadic_crt,rank_partition,affine_crt,dictionary_intervals,witness_packing,owner_residuals,certified_filters,adaptive_refinement,deferred_bgv,answer_oracles,aggregate_bgv,syndrome_oracle,butterfly_bgv,trace_bgv,shallow_bgv}.py
.venv/bin/ruff check --no-force-exclude benchmarks/{crt_masked_bgv_lab,hierarchical_query_basis_lab,hierarchical_query_basis_summary}.py experiments/bfv_search_lab/{hierarchical_query_basis,test_hierarchical_query_basis,crt_query_space,test_shared_query_basis}.py
.venv/bin/mypy --explicit-package-bases --follow-imports=silent experiments/bfv_search_lab/{hierarchical_query_basis,crt_query_space,crt_masked_bgv,crt_native_bgv,crt_linear_check}.py
```

## Retained measurements and models

- [Mushroom 3001](hierarchical_query_basis_mushroom_3001_20260929.json) and
  [log](hierarchical_query_basis_mushroom_3001_20260929.log).
- [Mushroom 3002](hierarchical_query_basis_mushroom_3002_20260929.json) and
  [log](hierarchical_query_basis_mushroom_3002_20260929.log).
- [Semeion 3001 curves](hierarchical_query_basis_semeion_3001_20260929.json) and
  [log](hierarchical_query_basis_semeion_3001_20260929.log).
- [Semeion 3002 curves](hierarchical_query_basis_semeion_3002_20260929.json) and
  [log](hierarchical_query_basis_semeion_3002_20260929.log).
- [46 curve/control rows](hierarchical_query_basis_curves_20260929.csv).
- [144 lifetime models](hierarchical_query_basis_lifetime_20260929.csv): serial
  recorded-stage work/byte sums at different token utilizations, not elapsed
  workloads, network latency or throughput measurements.
- [46 prospective noise-bound rows](hierarchical_query_basis_prospective_noise_20260929.csv):
  explicitly unimplemented correctness projections. Their independence and
  lifetime assumptions are stated in the report; 128 denotes a proposed
  correctness-failure budget, not lattice security.

Example commands; repeat with seed 3002. Run measurements serially, not alongside
test or profiling workloads:

```bash
.venv/bin/python benchmarks/hierarchical_query_basis_lab.py \
  --cache-dir /home/pete/yavor-projects/xtrace-work/research-data/uci-20260927 \
  --seed 3001 --repeats 3 \
  --json-out /tmp/hierarchical_mushroom_3001.json
.venv/bin/python benchmarks/hierarchical_query_basis_lab.py \
  --cache-dir /home/pete/yavor-projects/xtrace-work/research-data/uci-20260927 \
  --dataset semeion --seed 3001 --curves-only \
  --json-out /tmp/hierarchical_semeion_3001.json
.venv/bin/python benchmarks/hierarchical_query_basis_summary.py
```

The [manifest](hierarchical_basis_manifest_20260929.json) records artifact hashes
and **108 source/binary comparisons**, 27 paths in each of four reports.
All source hashes match local files and the exact recorded commit objects;
the ignored native binary matches its local hash. Per-query score digests
agree across all eight variants of each split, and every wider owner-state
total equals its component sum. Fixture contents are hash-checked by the loader.
CSV output uses LF endings. Public benchmark mask seeds are reproducibility
fixtures, not deployment randomness.
