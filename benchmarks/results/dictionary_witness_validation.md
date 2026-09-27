# Dictionary, interval, witness and owner-residual validation

2026-09-27, branch `experiment/creative-search-algebra`.

## Checks

```bash
.venv/bin/python -m pytest -q experiments/bfv_search_lab/test_{dictionary_intervals,witness_packing,owner_residuals,certified_filters,adaptive_refinement,deferred_bgv,answer_oracles,aggregate_bgv,syndrome_oracle,butterfly_bgv,trace_bgv,shallow_bgv}.py
.venv/bin/ruff check --no-force-exclude \
  experiments/bfv_search_lab/{adaptive_refinement,folded_dictionary,interval_filter,witness_packing,binary_fixtures,owner_residuals,test_dictionary_intervals,test_witness_packing,test_owner_residuals}.py \
  benchmarks/{dictionary_layout_lab,dictionary_bgv_native,fetch_binary_fixtures}.py
.venv/bin/mypy --explicit-package-bases --follow-imports=silent \
  experiments/bfv_search_lab/{adaptive_refinement,folded_dictionary,interval_filter,witness_packing,binary_fixtures,owner_residuals}.py
```

**181 passed in 5.74 s**, including 31 new tests; Ruff and Mypy pass. Coverage:
exhaustive small query/radius intervals, stable original-ID ties after physical
reordering, witness positions versus complete tiles, malformed offsets/entries,
complemented columns, sparse signed corrections, one- and two-byte position
boundaries, public-data schema and hash pinning. Homemade encrypted pilots
verify zero support, mixed trace scales, partial tiles, full two-round search,
owner residual correction and added phase bounds. Foreign contexts, overlaps,
unsafe noise and unsupported placements are rejected.

Adversarial fixtures deliberately show that false bounds can suppress a winner
and false template scores can give plausible wrong distances. These helpers
are not authentication or authorization APIs. No production/security-suite,
GPU sanitizer, private timing audit or new parameter-assurance claim is made.

## Measurements

```bash
.venv/bin/python benchmarks/fetch_binary_fixtures.py --cache-dir ../research-data/uci-20260927
OPENBLAS_NUM_THREADS=1 .venv/bin/python benchmarks/dictionary_layout_lab.py \
  --cache-dir ../research-data/uci-20260927 \
  --json-out benchmarks/results/dictionary_layout_lab_20260927.json
OMP_NUM_THREADS=8 OPENBLAS_NUM_THREADS=1 .venv/bin/python benchmarks/dictionary_bgv_native.py \
  --cache-dir ../research-data/uci-20260927 \
  --json-out benchmarks/results/dictionary_bgv_native_20260927.json
```

All completed. Model source is `f49b5f8`; native source is `21f598a`. Later
benchmark commits added the explicit plaintext local-search and compressed
storage controls, without changing the model modules. Dataset URLs, hashes,
commands, platform, setup, samples and source/binary hashes are recorded.
Only aggregate results/public source IDs are saved, not secret keys, hints,
raw datasets, ciphertexts or query contents.

The model covers 75 configurations × 32 queries × five methods (12,000 exact
top-3 checks), two public split seeds and favorable/adverse synthetic controls.
The native measurement is sequential and separate from tests/builds, with one
warmup and eight fresh paired queries across four modes and CPU/CUDA. Every
intermediate score and final top-3 agrees with an independent plaintext oracle;
complete response bytes match between CPU and CUDA for all modes and rounds.
Subset preparation, Python fusion and owner residual correction are charged.
Eight samples establish exploratory medians, not p95 or broad generalization.

Local CUDA execution used approved access outside the restricted sandbox.
No kernel changes or installations were needed. Hardware is the same Ryzen 7
5800X / RTX 3080 10 GiB used by the preceding checkpoint.

Source hashes are verified against each artifact's recorded Git commit and
binary hashes against the installed extensions. Link resolution and
`git diff --check` are checked before checkpointing.

All **32 source/binary hashes** match and all **77 relative file links** in the
updated research/sandbox/validation documents resolve. `git diff --check` passes.
Checkpoint name for this cycle: `checkpoint/dictionary-residuals-2026-09-27`.

Interpretation, byte categories, private-state costs, dataset attribution and
the next experiments are in [the report](../../docs/research/dictionary-witness-results.md).
