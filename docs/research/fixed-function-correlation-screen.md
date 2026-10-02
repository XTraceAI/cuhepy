# E82: finite joint projections and a multi-coordinate VOLE candidate

2026-10-02. Q1/Q2 finite return, following
[Q0](closest-control-cost-cards-20261002.md). Homemade
[oracle](../../experiments/bfv_search_lab/secret_code_mask_oracle.py),
[tests](../../experiments/bfv_search_lab/test_secret_code_mask_oracle.py),
[runner](../../benchmarks/secret_code_mask_lab.py),
[immutable raw](../../benchmarks/results/publication-secret-code-mask-screen-20261002.json).
Thirteen tests pass. No new PCF, MAC, encrypted token or direct authenticated
backend is implemented; the earlier token/client code is preserved.

## Shared and secret mask projections

Individually uniform block masks can have an exact public joint relation. The
toy projection `(s0,s1,s0+s1)` has three uniform marginals but joint rank two;
the same linear combination of public deltas exposes the query combination.
Full joint rank restores uniformity but removes this entropy saving.

For a secretly chosen nonzero line in F3^3 and fresh uniform line coefficients,
we enumerate complete transcript distributions, including the unknown offset.
Two translated single-query worlds have total variation **4/13**. A fixed
uniform affine offset makes repeated constant-query worlds identically
distributed, yet known-query/challenge-query worlds still differ by **4/13**.
The raw records eight cases, including three-query repetitions. The offset
case is not rejected using the incorrect claim that it leaks every repeated
unknown constant. These are exact finite controls for these recipes, not
cryptanalysis of published secret-code constructions or 128-bit parameters.

**Stop those literal pads.** Sparse/noisy/computational alternatives require a
different specified distribution and paid correction; E74 remains a separate
negative. A full-domain independent error repairs uniformity but restores a
full fresh correction in this linear decomposition.

## A concrete general-projection attempt

Following [secret-replication PCFs, §§3,6](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.ITC.2026.7),
test several selected codeword coordinates rather than one full-field scalar
coordinate. For b bits construct the **linear source code**

```
C(a,b_0,...,b_(b-1)) = (b_i, b_i + 2^i*a) for each i.
receiver selects coordinate bit_i in pair i
x = sum_i 2^i*bit_i,  B = sum_i b_i
y = sum selected values = a*x + B.
```

Use canonical binary encodings of uniform `x in F_q`, not uniform b-bit strings
reduced modulo q. Sender gets the entire source; receiver gets its b selected
coordinates and selection indices. Independently uniform intercepts make the
receiver's extra observations uniform conditioned on their sum. A simulator
can sample b-1 observations and determine the last. This is an elementary
conditional-distribution argument for this candidate; computational PCF
security would still require the real source PCF and its exact theorem.

The two independent full-law checks cover **3,206 target-plus-extra-view
samples** in F3/F5 and agree exactly. Algebra and recipient views therefore
survive this screen. The cost does not:

**Restricted support lemma.** For b>=2 and nonzero weights, this source has
exactly `b + 2^b` minimal nonempty support sets. If a=0, a minimal codeword has
one nonzero intercept and supports its pair. If a!=0, each pair has at least
one nonzero value. A pair with both nonzero contains a smaller pair-supported
codeword; every remaining minimal word selects exactly one coordinate per
pair. All `2^b` such transversals exist and are minimal. This proves the formula
for this code, not a lower bound for all multi-coordinate projections.

All **6,693 source codewords** in five F3/F5 configurations independently
confirm that support enumeration equals the formula. Receiver-selected b
coordinates intersect all minimal supports except their complement transversal,
so its key count is `b+2^b-1`. The ordinary line construction has q and q-1
keys. At q=193 the sender counts are **264 versus 193**; q=257 gives **521
versus 257**; q=65537 gives **131,089 versus 65,537**. Source-coordinate count
`2b` hid exponential minimal-support expansion. Puncturing can compress stored
keys, but does not make this evaluation cost disappear.

**Stop this specified bit-line recipe.** It supplies no complete advantage over
the existing scalar-line control, even before MACs, vector expansion, setup and
HE conversion. It is a useful restricted negative and candidate-selection
lesson, not an original complete protocol or a resolution of the general open
question. The broader PCF/trapdoor alternatives remain open.

## Field and interface return

The t=5 centered-lift counterexample `lift(2)+lift(2)-lift(4)=5` is nonzero
modulo Q=17. A field correlation cannot simply authenticate the old full-Q
response. Neither E82-T nor E82-D receives missing fresh encryption, provenance,
MAC, setup or lifecycle functionality from the finite projection oracle.

**Q2 → R6 return:** bounded candidates stopped; no complete mechanism selected,
no broad R4/P-package/security gate completed. Next Q3 tests E83 code/operator
structure, then Q4 compares actual survivors. Retain all earlier outcomes.


Final source-pinned repeat: [immutable result 02](../../benchmarks/results/publication-secret-code-mask-screen-20261002-02.json). Exact experiment/count fields agree with the initial run; Q0's archive cohort grows from 40 to 46 papers. The [execution receipt](fixed-function-execution-validation-20261002.json) records source closure, preservation and checks. The [latest return](construction-selection-20261002.md) governs current priorities.
