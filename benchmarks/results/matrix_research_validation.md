# Matrix arithmetic and masked-query validation

2026-09-28, `experiment/creative-search-algebra`.

The new code is in `87e4b21`. Benchmark follow-up `aa1dc75` places private
fingerprint preparation before online query selection. See the
[research report](../../docs/research/matrix-arithmetic-results.md) for the
mathematics, primary reading, negative results and limits of the experiment.

## Checks

```bash
.venv/bin/python -m pytest -q experiments/bfv_search_lab/test_{matrix_bgv_oracle,matrix_masked_query,matrix_linear_check,dyadic_crt,rank_partition,affine_crt,dictionary_intervals,witness_packing,owner_residuals,certified_filters,adaptive_refinement,deferred_bgv,answer_oracles,aggregate_bgv,syndrome_oracle,butterfly_bgv,trace_bgv,shallow_bgv}.py
.venv/bin/ruff check --no-force-exclude \
  experiments/bfv_search_lab/{matrix_bgv_oracle,matrix_search_cost,matrix_masked_query,matrix_linear_check,test_matrix_bgv_oracle,test_matrix_masked_query,test_matrix_linear_check}.py \
  benchmarks/{matrix_arithmetic_lab,matrix_masked_query_lab}.py
.venv/bin/mypy --explicit-package-bases --follow-imports=silent \
  experiments/bfv_search_lab/{matrix_bgv_oracle,matrix_search_cost,matrix_masked_query,matrix_linear_check}.py
```

**308 passed in 8.20 s**, including **73 new tests**; the
[pytest transcript](matrix_research_validation_pytest.txt) is retained.
Ruff passes nine files; Mypy passes four modules. This is a focused research
regression suite, not the complete repository or a production security audit.
There are no changes to native backends, CUDA kernels or production clients.

The tests compare ring arithmetic with the independent integer schoolbook
oracle and source expansions with direct noisy matrix phases. They check
rectangular inputs, output-column projection, commuting-entry source counts,
field interpolation, every binary query in small fixtures, partial tiles,
duplicate rows and stable original-ID ties. Context, bound, source, digit,
shape, epoch, token and coefficient-range failures are included.

Retained negative controls show that:

- treating the matrix secret as a commuting scalar gives the wrong product;
- omitting gadget noise control corrupts decryption;
- masking outside the chosen query subspace leaks a coset;
- recreating a consumed private token defeats the local lease and exposes a
  query difference; an in-memory flag is not durable rollback protection;
- prime-field fingerprint bounds cannot be silently applied to composite
  moduli;
- the online fingerprint accepts a poisoned offline answer when that answer
  is incorrectly trusted. It does not authenticate preprocessing.

All output coefficient positions are mutated against fresh check tickets.
Failed and successful check attempts both consume their ticket. A concurrent
mask-consumption test permits exactly one successful call. These are local
mechanism tests, not end-to-end malicious-security or side-channel assurance.

## Reproduction

```bash
.venv/bin/python benchmarks/matrix_arithmetic_lab.py \
  --json-out /tmp/matrix_arithmetic_reproduction.json
.venv/bin/python benchmarks/matrix_masked_query_lab.py \
  --json-out /tmp/matrix_masked_query_reproduction.json
```

The retained runs were sequential, without concurrent tests. Neither needs a
GPU or external HE library. Benchmarks import our Python matrix/gadget oracle;
the conditional checker uses only GMP's primality predicate. Small Python
stage times are diagnostic and must not be compared with the earlier secure-
parameter native CPU/CUDA benchmarks as if the security/workload matched.

[Matrix/gadget results](matrix_arithmetic_lab_20260928.json) contain 190
complete encrypted searches, five variants, four fixtures and 100 structural
cost configurations. [Masked-query results](matrix_masked_query_lab_20260928.json)
contain 44 complete searches, both mask spaces, three fixtures and 48 state/
communication configurations. Every distance and stable top-3 is exact.
The 22 constant-mask searches verify the online relation before decryption,
with check tickets prepared in the offline pool.

The pilots use ring degree 2/4/8, module rank 1/2/4, `q=2^61-1`, `t=97`,
eight-bit gadget digits and error coefficients in `[-1,1]`. Inputs are tiny
public deterministic fixtures. They do not constitute secure cryptographic
parameters. Model-only examples hold `n*k=16384`, use 120-bit coefficient
bodies, 30-bit digits and `t=65537`. Those models count operations, keys and
state; they do not establish equivalent security or a latency improvement.

The original index, converted index, token answer, offline query and online
query are separate storage/traffic categories. Seeded uniform-mask sizes are
modeled separately from unseeded coefficient bodies. The masked online body
is actually encoded as byte-aligned field residues; epoch/ID framing and
authentication are extra. Mask-seed bodies are not Python working-memory
measurements. No terminal response compaction is implemented in this oracle.

The matrix and masked artifacts pin commits `87e4b21` and `aa1dc75`; their
12 recorded source hashes match both those commits and the retained sources.
All 75 relative file links in the five updated research/sandbox/validation
documents resolve, and `git diff --check` passes.
The previous company and E27 checkpoints remain intact. The new checkpoint
name is `checkpoint/matrix-query-space-2026-09-28`.
