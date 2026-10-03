# Q59 / B4 first component: exact index-state updates, generic containment

2026-10-03. The bounded fixed-coins **public algebra diagnostic** is complete.
Compiled query adjoints can be updated exactly from encrypted-index deltas;
the equally specialized generic affine/adjoint control obtains the identical
state. This is a useful known-control prerequisite, not an original H2 survivor
or approval to reuse protected coins. **Do not start Q60 on this result alone.**
Authenticated live GPU tile replacement, atomic epoch publication, durable
attempt state, rollback/fork behavior, the adaptive reuse argument and measured
update costs remain unimplemented in this component. It does not close the full
Q59 service contract or supersede the [assurance review](native-complete-admission-review-20261003.md).

[Q57 source/dependency result](operator-state-discriminator-20261003.md),
[homemade incremental algebra](../../experiments/bfv_search_lab/operator_incremental_state.py),
[27 tests](../../experiments/bfv_search_lab/test_operator_incremental_state.py),
[bounded runner](../../benchmarks/operator_incremental_state_lab.py).
New raw evidence is
`../research-data/native-verification-system-20261003/operator-state/update/operator-incremental-state-results.json`.
No timing, GPU/TEE execution, HE key generation, actual owner update, entropy
security claim, secret-key operation, parameter modification or production API
change is reported here.

## Exact algebra and scope

Q57 established the invariant for the existing native butterfly: every affine
coefficient term contains at most one fixed convolution polynomial; an
index-dependent term is degree one in a single encrypted tile component and
occurs only in the **original-query coefficient maps**. Canonical full-Q digit
extraction remains a nonlinear cut. It is never moved across an update formula.

For a fixed cut program and public diagnostic row/coefficient weights `(u,v)`,
form the two original-query adjoints

`h_k(I) = sum_rows u[row] * L_(row,k)(I)^T(v)`.

The exact identities `M_k^T=M_(k(X^-1))` and
`sigma_a^T=sigma_(a^-1)` give a matrix-free transpose with the correct negacyclic
signs. A separate dense coefficient-basis transpose is the oracle. Keeping the
same weights and all graph/key identities gives

`h_k(I+delta) = h_k(I) + A_k(delta)^T(u,v)`.

Here delta is the **difference between approved encrypted-index polynomial
components**, not a presumed plaintext delta encryption or low-rank edit. The
code filters index terms, rejects changed switching keys/identities, and checks
that every non-query coefficient map has zero index dependence. The generic
control is given exactly these identities and delta accumulation. No new
cryptographic theorem follows from linearity.

Two toy polynomial-shaped instances (`N8/D4/three partial-group tiles` and
`N16/D8/eight full-group tiles`) cover all three Q57 policies. Four diagnostic
edit supports, two small diagnostic primes and three public-weight rounds give
**144 exact state comparisons /3,456 query-adjoint coefficients**. Incremental
matrix-free state equals fresh matrix-free state, and each delta equals the
independent dense control. The tiny dispersed support is explicitly a toy
support, not32 encrypted record updates. The separate large script below has
exactly32 dispersed records.

27 tests additionally cover individual operator transposes on ten
partial/full geometry/prime combinations, malformed key/graph deltas,
index-dependent non-query maps, full residual coverage, empty edits and changed
coins. Changing the coefficient challenge changes the state; old fixed-coins
delta state cannot be called a fresh-epoch enrollment.

## Existing large geometry: exact support counts, not latency

Translate rows to their actual32-record tile. Scripts are row17; all32 rows of
tile0;32 evenly spaced rows in distinct tiles; and the whole snapshot. The Q57
dictionary is the immutable input to the24 static cards (two geometries ×three
policies ×four scripts). The table shows maximal affine elimination; every-local
and product-cut rows are retained in raw evidence.

| Records | Edit | Changed tiles | Invalidated formal index atoms | Descendant canonical values that may change | Dependent terminal polynomials | Changed encrypted-tile Q120 body MiB |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
|8k|One row|1|523|10|2|0.46875|
|8k|One tile|1|523|10|2|0.46875|
|8k|Dispersed32 rows|32|16,865|98|2|15|
|8k|Whole snapshot|256|135,681|767|2|120|
|32k|One row|1|523|10|2|0.46875|
|32k|One tile|1|523|10|2|0.46875|
|32k|Dispersed32 rows|32|16,804|72|4|15|
|32k|Whole snapshot|1,024|542,722|2,046|4|480|

Updating one plaintext row usually replaces its encrypted tile, so the row and
tile scripts have equal tile support. This count model does not claim they have
identical owner encryption, application or network cost. Body sizes exclude
IDs, approved bounds, framing, manifests, hashes, receipts and GPU buffers.

Under fixed coins the checking coefficient state for **all non-query sources**
is unchanged, although their runtime canonical values may depend on changed
records. The fully accumulated original-query checking state changes in only
two vectors per prime/check round: the two-prime/three-round Q57 uint64 model changes
1.5 MiB, independent of edited tile count. Preparing that difference still
uses the affected coefficients, operator paths, private weights and arithmetic;
no constant-time or sublinear-update latency is inferred from the final1.5MiB
state size. Atomic basis invalidations and bundled vector counts are different
representations, neither a minimum.

Fresh epoch coins invalidate **all** chosen materialized adjoints. The simple
fully bundled maximal-cut control models2,414,346,240 bytes at8k and
6,437,732,352 bytes at32k, plus row/coefficient weights, context and workspace.
The full preparation must be charged. Other generic materialization schedules
can trade memory, witness traffic and computation; these are not lower bounds.
No statement here combines free local updates with unpaid fresh challenges.

## Security and implementation handoff

These coins are public deterministic diagnostic samples. They do not provide
false-admission protection. A deployment using the identity must protect the
checking vectors/weights, authenticate the owner-approved index difference and
perform trusted or correctly certified delta preparation. It must publish
evaluator/checker state atomically under the same snapshot identity and reject
old/new mixtures. An untrusted host returning `h_delta` is not sufficient.

Reusing coins across owner-approved epochs remains a conditional protocol
optimization. The proof must account for updates chosen from past verdicts,
first false acceptance, every retry/failure/process/clone/epoch, and leakage.
Simply asserting that the same secret weights stay uniformly distributed after
observed rejection is invalid. Existing tiny protected-affine arguments do not
automatically supply the missing native/update lifecycle proof. Fresh coins are
the initial safe control and their entire rebuild remains charged.

The next engineering prerequisite is an authenticated tile-replacement API
whose evaluator/checker state matches fresh enrollment, followed by complete
epoch/fault tests. Originality requires an additional contribution beyond this
known affine delta update and mutable generic/cache controls. This first
component supplies exact source and state equations but **no distinct algorithm,
performance result or independently surviving H2 candidate**.
