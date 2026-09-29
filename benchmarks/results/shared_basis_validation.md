# E30 validation and artifact provenance

2026-09-29. The [report](../../docs/research/shared-query-basis-results.md)
uses source commit `185ffc7a3b6f2d378b06f72edf0d735b38dbeb1a`, following the main
implementation at `fc5aa84`. The second commit clarifies the original affine
cache control and adds the public-linear mask-pool failure tests. No production
files or C++ implementation changed.

## Correctness and static checks

- **355 passed in 8.74 s:** the expanded E19–E30 regression command below,
  with the native extension present. [Transcript](shared_basis_validation_pytest.txt).
- **2 passed:** exhaustive positive/negative mask-pool distribution tests.
  [Transcript](correlation_pool_validation_pytest.txt).
- Ruff passed for the eight changed/new Python implementation, benchmark and
  shared-basis test files, and separately for the pool-limit test file.
- Mypy passed for `shared_query_basis`, `crt_query_space`, `crt_masked_bgv`,
  `crt_linear_check` and `crt_native_bgv` with explicit package bases and silent
  imported-module checking.
- **48 full-degree encrypted searches** across twelve cases: one warmup and
  three measured queries per case. Every distance and stable top-three result
  is exact; all GMP/native ciphertext coefficients agree. The conditional
  fingerprint check executes before HE decryption.

```bash
.venv/bin/python -m pytest -q experiments/bfv_search_lab/test_{shared_query_basis,crt_masked_bgv,crt_linear_check,crt_native_bgv,matrix_bgv_oracle,matrix_masked_query,matrix_linear_check,dyadic_crt,rank_partition,affine_crt,dictionary_intervals,witness_packing,owner_residuals,certified_filters,adaptive_refinement,deferred_bgv,answer_oracles,aggregate_bgv,syndrome_oracle,butterfly_bgv,trace_bgv,shallow_bgv}.py
.venv/bin/python -m pytest -q experiments/bfv_search_lab/test_correlation_pool_limits.py
.venv/bin/ruff check --no-force-exclude benchmarks/{crt_masked_bgv_lab,shared_query_basis_lab}.py experiments/bfv_search_lab/{shared_query_basis,test_shared_query_basis,test_correlation_pool_limits,crt_query_space,crt_masked_bgv,crt_linear_check,crt_native_bgv}.py
.venv/bin/mypy --explicit-package-bases --follow-imports=silent experiments/bfv_search_lab/{shared_query_basis,crt_query_space,crt_masked_bgv,crt_linear_check,crt_native_bgv}.py
```

The pool-limit file received a later comment clarification about known
*transformed* coordinates; its executable test logic is unchanged. Its final
source hash is included separately in the manifest. The C++ source and binary
are unchanged from E29; its earlier UBSan result is not a new E30 sanitizer run.

## Retained results and audit

[Manifest](shared_basis_manifest_20260929.json) records artifact SHA-256 values
and the 25 source/binary paths from each benchmark. All **100** recorded hashes
were checked against local files; the 24 versioned sources in each run were
also checked against their exact Git commit objects. The native binary is
ignored by Git and was checked locally.

- [Mushroom 3001](shared_query_basis_mushroom_3001_20260929.json) and
  [log](shared_query_basis_mushroom_3001_20260929.log).
- [Mushroom 3002](shared_query_basis_mushroom_3002_20260929.json) and
  [log](shared_query_basis_mushroom_3002_20260929.log).
- [Semeion 3001 curves](shared_query_basis_semeion_3001_20260929.json) and
  [log](shared_query_basis_semeion_3001_20260929.log).
- [Semeion 3002 curves](shared_query_basis_semeion_3002_20260929.json) and
  [log](shared_query_basis_semeion_3002_20260929.log).
- [Curve CSV](shared_query_basis_curves_20260929.csv): 558 modeled trajectory
  points plus four measured global/raw controls. Semeion curves do not contain
  encrypted timing results.

Per-query score digests agree across all six representations of each split.
Every wider owner-state total equals its recorded component sum. The corrected
cache field is explicitly `baseline_original_affine_cache_modeled_bytes`;
mixed coordinates use the separately charged field-residue body model.
Pinned fixture hashes are checked by the loader and rechecked for this audit.

An exploratory pilot and pre-correction diagnostic runs are retained outside
the worktree under the local checkpoint directory. They are not the source of
the report's final timing tables. Fixed PRNG mask seeds are public benchmark
fixtures; encryption and hidden checker randomness are fresh. These results
are correctness/performance evidence, not full protocol or parameter assurance.
