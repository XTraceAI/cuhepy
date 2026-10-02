# E84: exact selection requires integer counts and a real packing conversion

2026-10-02. Q5 finite return after the
[preregistration](exact-bucket-release-preregistration-20261002.md). Homemade
[oracle](../../experiments/bfv_search_lab/exact_bucket_release_oracle.py),
[tests](../../experiments/bfv_search_lab/test_exact_bucket_release_oracle.py),
[runner](../../benchmarks/exact_bucket_release_lab.py),
[initial raw](../../benchmarks/results/publication-exact-bucket-release-screen-20261002.json).
Twenty scoped tests pass. No encrypted selector or proof backend is implemented.

## Exact reference and coverage

Counting buckets with attached stable IDs matches an independent lexical sort
for **all 1,024 five-row distance assignments** in 0..3. Equal distances use
ascending IDs; zero/one/two live rows work. The complete integer verifier reads
all scores and IDs. It rejects wrong counts, omitted rows, repeated winners,
bad cutoff, changed IDs and overflow. It is a reference, not a cheap proof.

Two score assignments can have the same histogram and different correct IDs.
Field count residues also alias: 0 and 193 both represent zero modulo 193.
Thus a polynomial histogram identity or bucket sum alone is not an exact
integer/ID/coverage certificate.

## The small-field grand-product candidate fails

Let `P_c(Z)=product_h (Z-h)^c_h`, with all counts nonnegative integers and
the exact total fixed. At scores 0 and 1, compare

```
c_left=(q,1),  c_right=(1,q),  row_count=q+1.
P_left(Z)=Z^q*(Z-1),  P_right(Z)=Z*(Z-1)^q.
```

At **every Z in F_q**, Frobenius makes both equal to `Z*(Z-1)`. These valid
histograms have different top-3 distances: (0,0,0) versus (0,1,1). The raw
exhausts **1,506 challenge points** in six fields, including 193/257/1031.
This is a counterexample to the proposed base-field relation; it is not an
attack on a published lookup proof whose theorem uses stronger challenges and
binding. Repeating more base-field challenges cannot fix it.

For monic equal-degree histogram polynomials with at most q rows, equality at
all q field points does force polynomial equality: their difference has degree
at most row_count-1<q. The example at q+1 rows makes this cutoff sharp for
this all-base-field test. Sampling a few points has its separate degree/order
bound and still needs committed, complete original-score binding.

An independent F25 quotient-field control detects the F5 collision at all
twenty points outside the base subfield, while the five base points still
miss. This repairs that arithmetic counterexample, not the HE/proof protocol.
An 8,192-row degree bound and a one-query 128-bit target need extension degrees
**19/18/15/9** over 193/257/1031/65537. At 1,024 attempts they become
**20/19/16/10**. These are exact fixed-polynomial count targets; field
conversion, commitment, score extraction, prover work and feedback remain paid.

## Prefix polynomials and real lanes

Known Lagrange interpolation computes `1[h<threshold]` exactly on all admitted
scores; **122** whole-domain checks pass in three toy profiles. It generally
has high degree. Reusing powers is a known polynomial-evaluation control, and
encrypted threshold/count handling remains additional. Distinct integer scores
must have distinct field representatives; exact coverage counts need lifts
or a complete carry/range relation.

More fundamentally, applying a polynomial to a coefficient-packed plaintext
is ring arithmetic, not applying it independently to each coefficient. The
counterexample `(1+X)^2=2X` in F5[X]/(X^2+1) demonstrates this directly.

For power-of-two N and odd prime t, all roots of X^N+1 have order 2N; their
Frobenius orbit length is `ord_(2N)(t)`. Hence the ring has N/orbit_length
extension-field factors. The exact count cards are:

| N | t | Factor degree | Extension-field slots |
|---:|---:|---:|---:|
| 2048 | 193 | 64 | 32 |
| 2048 | 257 | 16 | 128 |
| 16384 | 1031 | 4096 | 4 |
| 16384 | 65537 | 1 | 16384 |

This does not invalidate the fast linear BGV search. It identifies why a
nonlinear selector needs a compatible conversion or different ring parameters.
[Algorithms in HElib](https://eprint.iacr.org/2014/106) supplies strong SIMD,
Frobenius/trace and linear-transform controls; the downloaded version is in the
[archive](prior-work-archive.md). Its existence prevents calling a generic
trace or coefficient-to-slot conversion our new primitive.

## Q5 → Q4/R6 return

Stop the small-field grand-product recipe. Keep exact ID/count oracles and
extension/packing controls. A full encrypted lookup/tournament/TFHE adapter is
still an implementation gap. No complete new step beat RevoLUT, a strong
tournament, full-score/local top-3 or paid output compaction here.

Next ask whether **a restricted conversion-and-coverage construction can share
work for our actual coefficient/CRT layouts**. It must bind the original
encrypted scores, carry exact integer counts/IDs, preserve query privacy, and
cost the whole bridge. A full-field SIMD backend is a paid competing mode.
Develop a concrete transcript/primitive ledger before writing the converter.
The [new R6 return](construction-selection-20261002.md) governs this step;
reference/native/CUDA promotion still depends on a viable selected mechanism.


Final source-pinned repeat: [immutable result 02](../../benchmarks/results/publication-exact-bucket-release-screen-20261002-02.json). Exact experiment/count fields agree with the initial run; Q0's archive cohort grows from 40 to 46 papers. The [execution receipt](fixed-function-execution-validation-20261002.json) records source closure, preservation and checks. The [latest return](construction-selection-20261002.md) governs current priorities.
