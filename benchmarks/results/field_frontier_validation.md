# E34/E35 validation record

Measurement source: `461bb10f75f23a5f230bb7375cfd08e61e2b9c24`.
Retained runs use the same source and native binary; no source edits occurred
between runs. Four runs were executed serially, not concurrently. They each
have one warmup and eight measured queries for two encrypted cases.

The selected mathematical/CRT/masking regression group, including the 18 new
tests, was run using the repository virtual environment:

```bash
.venv/bin/python -m pytest -q experiments/bfv_search_lab/test_{adaptive_masking_oracles,field_frontier,crt_noise_budget,fixed_batch_bgv,hierarchical_query_basis,shared_query_basis,correlation_pool_limits,crt_masked_bgv,crt_linear_check,crt_native_bgv,matrix_bgv_oracle,matrix_masked_query,matrix_linear_check,dyadic_crt,rank_partition,affine_crt,dictionary_intervals,witness_packing,owner_residuals,certified_filters,adaptive_refinement,deferred_bgv,answer_oracles,aggregate_bgv,syndrome_oracle,butterfly_bgv,trace_bgv,shallow_bgv}.py
```

Result: **405 passed in 9.88 s**. The complete output is in
[field_frontier_validation_pytest.txt](field_frontier_validation_pytest.txt).
This is a selected research regression group, not a claim to run every
production/GPU integration test in the repository.

```bash
.venv/bin/ruff check --no-force-exclude \
  benchmarks/field_frontier_lab.py benchmarks/field_frontier_summary.py \
  experiments/bfv_search_lab/{adaptive_masking_oracles,field_frontier,integer_phase_audit,test_adaptive_masking_oracles,test_field_frontier}.py
.venv/bin/mypy --explicit-package-bases --follow-imports=silent \
  experiments/bfv_search_lab/{adaptive_masking_oracles,field_frontier,integer_phase_audit}.py
.venv/bin/python benchmarks/field_frontier_summary.py
git diff --check
```

Ruff: all checks passed. Mypy: no issues in three source files. Whitespace
checks pass, CSV line endings are LF, and local links in the report, priorities,
literature agenda and sandbox README resolve.

The retained-data audit independently recomputes absolute universal bounds,
fingerprint-round inequalities and the field-selection objective from JSON.
It checks paired score digests, the adaptive winner/candidate policy, every
phase/ciphertext equality flag, body counts/round trips and online stage sums.
It checks 108 source/binary hashes; tracked source also matches the recorded
Git commit. The manifest contains 72 encrypted searches, 36 distinct
dataset/query IDs and 1,179,648 phase coefficients. The exported frontier has
122 accepted profile models and 171 rejected candidates.

The native binary SHA256 is
`ecd3611af5fd16077afcb050af555374b4d9659a50e397a72a0295c2a6abb07d`.
It is unchanged from E32. The pilot had fewer samples and preceded the final
body-parsing stages; it is excluded from the retained timing table.

These checks establish local exactness and reproducibility. They do not
constitute a reviewed HE transcript proof, RLWE parameter estimate, private
side-channel audit, malicious-preprocessing protocol or production approval.
