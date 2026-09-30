# E36–E40 validation and preservation record

2026-09-30, `experiment/creative-search-algebra`. This validates the isolated
research additions, not every production/GPU integration path in the repo.
Company Paillier/BFV and the general BGV/CUDA evaluator remain unchanged.

## Frozen source and retained measurements

| Work | Source commit |
|---|---|
| E36 norms | `01a73752e8c2f98f9dd5be0e2497f0f8ed13fad8` |
| E37/E38 checkers, codec and schema | `9f7cbd80a6553939548b1a8217f0129a2bfed253` |
| E39 controls and planner; all retained E37 timings | `a8aff07c301974a394945f7940e4f1f1a5ccd26f` |
| E40 ring models | `c210d0b8dfbb1eeb53a3dacbf9d054c73a0731cf` |

The four retained E37 runs execute serially with unchanged source and release
binaries: two datasets, two split seeds, three profiles, one warmup and eight
measured queries per profile. Every profile follows the same adaptive query
path. All four checkers process the same response before one secret decryption;
reported deployment totals are paired sums of measured stages. Gate order
rotates and public GMP/native evaluation order alternates. Independent
reference hashing, codec comparisons and full integer-phase diagnostics are
outside online timings.

The one-sample pilot preceded the final source freeze and is excluded. An
initial pair of Mushroom runs briefly overlapped and was replaced by a clean
serial pair. Both excluded runs and the pilot are retained in the external
checkpoint directory; none supplies a final timing table or figure. E40 is a
separate plaintext/capacity/phase model, not a lower-degree encrypted benchmark.

## Regression and static checks

```bash
.venv/bin/python -m pytest -q experiments/bfv_search_lab/test_{ring_capacity_frontier,answer_summary_limits,portfolio_costs,correction_image_bounds,polynomial_fingerprint,schema_metric_oracles,adaptive_masking_oracles,field_frontier,crt_noise_budget,fixed_batch_bgv,hierarchical_query_basis,shared_query_basis,correlation_pool_limits,crt_masked_bgv,crt_linear_check,crt_native_bgv,matrix_bgv_oracle,matrix_masked_query,matrix_linear_check,dyadic_crt,rank_partition,affine_crt,dictionary_intervals,witness_packing,owner_residuals,certified_filters,adaptive_refinement,deferred_bgv,answer_oracles,aggregate_bgv,syndrome_oracle,butterfly_bgv,trace_bgv,shallow_bgv}.py
```

**478 passed in 12.53 s**, including 73 added tests. Complete output:
[pytest transcript](verification_frontier_validation_pytest_20260930.txt).

```bash
.venv/bin/ruff check --no-force-exclude \
  benchmarks/{correction_image_lab,verification_frontier_lab,verification_frontier_summary,verification_frontier_plot,ring_capacity_frontier_lab}.py \
  experiments/bfv_search_lab/{correction_image_bounds,polynomial_fingerprint,native_linear_check,coefficient_body,schema_metric_oracles,answer_summary_limits,portfolio_costs,ring_capacity_frontier,test_correction_image_bounds,test_polynomial_fingerprint,test_schema_metric_oracles,test_answer_summary_limits,test_portfolio_costs,test_ring_capacity_frontier}.py
.venv/bin/mypy --explicit-package-bases --follow-imports=silent \
  experiments/bfv_search_lab/{correction_image_bounds,polynomial_fingerprint,native_linear_check,coefficient_body,schema_metric_oracles,answer_summary_limits,portfolio_costs,ring_capacity_frontier}.py
git diff --check
```

Ruff passes; Mypy reports no issues in eight source files. The final artifact
audit checks LF CSV endings and local Markdown links as well as hashes.

## Native sanitizers

Release build:

```bash
make -C experiments/bfv_search_lab/_fingerprint PYTHON=../../../.venv/bin/python
```

The isolated C++ code accepts no HE private key. It does process hidden
integrity keys; private timing assurance is still unresolved. Separate copies
were built at `-O1 -g -fno-omit-frame-pointer` with
`-fsanitize=address,undefined` and `-fsanitize=undefined,bounds` respectively.
The loaders install each copy under the canonical extension name before
running the same 30 independent fingerprint/codec/gate tests:

```bash
LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8:/lib/x86_64-linux-gnu/libstdc++.so.6 \
  PYCRYPTODOME_DISABLE_DEEPBIND=1 ASAN_OPTIONS=detect_leaks=0 \
  UBSAN_OPTIONS=halt_on_error=1 \
  .venv/bin/python /tmp/cuhepy-fingerprint-sanitizer-20260930.py
UBSAN_OPTIONS=halt_on_error=1 \
  .venv/bin/python /tmp/cuhepy-fingerprint-ubsan-20260930.py
```

ASan/UBSan: **30 passed in 0.89 s**;
UBSan/bounds: **30 passed in 0.64 s**.
Transcripts: [ASan](verification_fingerprint_asan_20260930.txt),
[UBSan/bounds](verification_fingerprint_ubsan_20260930.txt).
An initial ASan attempt stopped because PyCryptodome uses `RTLD_DEEPBIND`,
which conflicts with sanitizer interposition. Its supported environment flag
above resolves that loader issue without editing the installed dependency.
Python/dependency leak detection is disabled. These runs check memory and
undefined behavior, not constant-time execution, HE privacy or key security.

| Host-specific Python 3.12 binary | SHA256 |
|---|---|
| Public `_crt_subring`, unchanged from the earlier checkpoint | `ecd3611af5fd16077afcb050af555374b4d9659a50e397a72a0295c2a6abb07d` |
| New release `_fingerprint` | `273413089b89db47eb76e083504d0f260a970b17ec310501f358038738466458` |
| New ASan/UBSan copy | `73c09402495c1fcdf0bab4d555db987bc9c26f4600b1069bc2610c59eb96df51` |
| New UBSan/bounds copy | `bc0315dd547bbfbc47ab17a2dbb6a329465325e9e143b5dd8d28f32dd89f1a96` |

## Retained-data and figure audit

```bash
.venv/bin/python benchmarks/verification_frontier_summary.py
MPLCONFIGDIR=/tmp/cuhepy-matplotlib-config-20260930 \
  /tmp/cuhepy-research-plots-20260930/bin/python benchmarks/verification_frontier_plot.py
.venv/bin/python benchmarks/verification_frontier_summary.py
```

The last summary run records the final figure manifest. The isolated plotting
environment uses Matplotlib 3.11.2; its
[package list](verification_frontier_plot_environment_20260930.txt) is retained.
It does not change the repo's dependencies. SVG and standalone PDF figures
use retained observations/models only; observed ranges are not confidence
intervals. Both rendered figures were visually inspected.

The [manifest](verification_frontier_manifest_20260930.json) checks **203
source/binary hashes**, including tracked-source agreement with recorded Git
commits. It checks all **108 full-size encrypted searches**, **36 distinct
dataset/query IDs**, **1,769,472 unreduced phase coefficients**, and
**10,540,800 correction-generator coefficient comparisons**. It also verifies
complete score and stable-top-three agreement, every GMP/native/codec reference,
adaptive paths, exact body counts, stage sums and conditional collision bounds.
Exports retain 96 stage rows, eight norm rows, 12 paired comparisons, 96 serial
link/pool scenarios, 12 gate policies, 22 valid ring models and six rejections.
Default production contracts reject every current research candidate.

The separate [figure manifest](verification_frontier_figures_20260930.json)
binds source reports, stage CSV, plotting code and all four SVG/PDF artifacts.
The main manifest additionally binds the reports, validation transcripts,
system/paper synthesis, priorities, literature agenda and sandbox README.

## Checkpoint and scope

The final report commit is preserved in the annotated tag
`checkpoint/verification-frontier-2026-09-30`, on the research branch. A full
history bundle, native/sanitized binaries, loaders, excluded runs and restore
verification are kept under:

```text
/home/pete/yavor-projects/xtrace-work/checkpoints/verification-frontier-2026-09-30/
```

`verification.json` there records the exact remote branch/tag refs, bundle
SHA256, fresh bare restore/fsck, eight older checkpoint ancestors, and restored
source/artifact hashes. Binaries are retained separately because they are
host-specific and intentionally not committed. Restoring Git history is not
restoring the virtual environment or certifying a deployed service.

The experiments establish local exactness and reproducibility. They do not
provide a reviewed complete HE transcript theorem, malicious-preprocessing
protocol, RLWE parameter estimate, durable token lifecycle, private timing
audit, AWS deployment or production authorization. Follow the
[system/paper roadmap](../../docs/research/research-synthesis-and-system-roadmap.md)
for the specific remaining proofs, matched baselines and discriminating tests.
