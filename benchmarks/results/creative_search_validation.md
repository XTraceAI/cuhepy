# Creative algebra experiment validation

2026-09-27, implementation commits `b972353` and `a23d813` on
`experiment/creative-search-algebra`. This is validation of isolated research
code, not a production security audit or a whole-repository/CUDA test run.

## Correctness

```bash
.venv/bin/python -m pytest \
  experiments/bfv_search_lab/test_deferred_bgv.py \
  experiments/bfv_search_lab/test_answer_oracles.py \
  experiments/bfv_search_lab/test_aggregate_bgv.py \
  experiments/bfv_search_lab/test_syndrome_oracle.py \
  experiments/bfv_search_lab/test_butterfly_bgv.py \
  experiments/bfv_search_lab/test_trace_bgv.py \
  experiments/bfv_search_lab/test_shallow_bgv.py -q
```

**101 passed in 4.21 seconds**, including 76 new tests and 25 existing BGV
reference regressions. The [captured output](creative_search_validation_pytest.txt)
contains the exact final result. The tests include:

- Formal automorphed secret terms versus direct integer-ring projection, all
  modeled delay depths, tails, incorrect secret-basis shortcuts and carries.
- Homemade encrypted E20 against independent per-tile trace and plaintext
  distances, plus bounds and malformed key/input contexts.
- Three independent histogram constructions, exhaustive stable-ID recovery,
  duplicate/tied distances, field aliases and moment collisions.
- Complete repeated-multiplication BGV histogram/prefix fixtures and rejection
  when their conservative modulus bound is exhausted.
- Exhaustive safe block bounds, overlap/equality counterexamples, public rank
  factorization, and one-hot/factorized layouts through actual BGV encryption.

## Static checks and artifacts

Ruff passed with `--no-force-exclude` over the five new implementation modules,
four new test files and two benchmark entry points. Mypy passed for the five
new implementation modules with:

```bash
.venv/bin/mypy --explicit-package-bases --follow-imports=silent \
  experiments/bfv_search_lab/reduction_oracles.py \
  experiments/bfv_search_lab/deferred_bgv.py \
  experiments/bfv_search_lab/answer_oracles.py \
  experiments/bfv_search_lab/aggregate_bgv.py \
  experiments/bfv_search_lab/syndrome_oracle.py
```

The source-hash manifests in both JSON artifacts were checked against the
committed source files. Relative documentation links/headings and
`git diff --check` were also checked before the report checkpoint.

The encrypted pilots are seven paired rounds plus one excluded warmup. They
check exact answers in every round and include all samples, not just medians.
The E19 workload is a deterministic plaintext selectivity/cost model; its small
encrypted regression establishes the layout, not encrypted throughput. No
large-workload encrypted speedup, full adaptive privacy protocol, parameter
approval or new side-channel assurance is claimed.
