# Q44/E118: public nonunit-projection assurance oracle

2026-10-03. **The bounded oracle passes. Retain the unit-free ideal correctness
consequence; actual seeded transfer, parameter approval and originality remain
open.** This packet supplies public mathematical code and finite assurance,
not encryption, a secret sampler, a private release verifier or a new setup API.

The [frozen specification](nonunit-projection-preregistration-20261003.md)
predated all new implementation/tests/main execution. The selected
[raw result](../../benchmarks/results/publication-nonunit-projection-20261003.json)
contains exactly the registered three components: all6561 N8/Q17 ternary
diagnostics, two N4/Q17 full-mask contexts of83521 masks each, and one large
drop23 literal model compared with the independent E115 card. No actual
private secret, HE key, GPU/native kernel, timing, parameter grid, estimator or
proof backend was used. Existing sampler, codecs, production source and guards
are unchanged.

## 1. Implementation and independent controls

The homemade public module is
[`nonunit_projection.py`](../../experiments/bfv_search_lab/nonunit_projection.py).
Its large `norm_certificate` uses only N,Q and a public squared-norm envelope;
it does not accept a large secret. Integer matrices/root inspection are
explicitly restricted to public dimensions2/4/8. A context checks exact integer
grammar, the existing E113 unsigned64 prime diagnostic, full splitting and a
primitive2N root. This admission is not HE parameter or OS-entropy assurance.

The certificate is for **nonzero** integer polynomials within the stated norm
bound. Its exact integer comparison is
`Q^K <= norm2^(N/2) < Q^(K+1)` (with dimension clipping if K=N). The mathematical
proof uses irreducibility, determinant rank-divisibility, Parseval and AM-GM.
Zero is a separate exception, not inferred to satisfy the nonzero theorem.
The fixed consecutive prefix guarantee is derived from the zero-root
Vandermonde parity checks. It is not a claim for every coordinate subset.

The [runner](../../benchmarks/nonunit_projection_lab.py) implements genuinely
separate finite controls:

- literal schoolbook multiplication/monomial columns versus the module's
  signed Toeplitz matrix;
- fraction-free Bareiss determinant with exact division checks, covered by
  independent Leibniz/pivot/singular-matrix unit regressions;
- division-free modular echelon versus normalized Gaussian elimination;
- direct power-sum root-zero membership versus Horner zero-root evaluation;
- exhaustive full-mask histograms, complete image fibres and translated cosets.

Root-zero checks compare membership at each root, **not equality of every
numeric nonzero evaluation**. Logical comparison counts below are neither
elapsed times nor machine-operation performance claims.

## 2. All6561 ternary diagnostics: N8/Q17

Use primitive16th root3, with every polynomial in{-1,0,1}^8. The public norm
envelope gives `17^2 <= 8^4=4096 < 17^3`, hence K2 and fixed prefix length6.

| Finite class | Exact count |
| --- | ---: |
|Nonzero units / nullity0|4000|
|Nonzero nonunits / nullity1|2048|
|Nonzero nonunits / nullity2|512|
|Zero exception / nullity8|1|
|Total|6561|

Every6560 nonzero polynomial has a nonzero integer determinant, determinant
divisible by17^actual_nullity, absolute determinant within its **actual**
squared-norm envelope and the shared4096 envelope, rank matching its zero-root
count, nullity at most2, and prefix rank6. The zero polynomial has determinant0,
rank0 and prefix rank0 and is explicitly excluded from that claim.

The independent controls perform419904 integer matrix-coefficient comparisons
and52488 root-zero membership comparisons. There are42 distinct determinant
values in this tiny domain. Complete public records are archived externally
in `research-data/nonunit-projection-20261003/all-6561-public-ternary-records.json`,
SHA256`aac60147a180085e8c9246a8ab9f77d75dc5452e769c3d8a5b18d8f1dab7aae4`.

These counts describe **only N8/Q17**. They do not estimate the selected large
secret's unit probability, justify independent root-zero events, or replace
the actual ternary sampler by a uniform ring distribution.

## 3. Exactly two exhaustive uniform-mask contexts

Both contexts use N4/Q17 and primitive8th root2. The diagnostic polynomials are
public and **nonternary**, deliberately chosen to test the general image-code
lemma. Neither is an actual secret draw or a company-key fixture. Enumerate all
17^4=83521 canonical masks in each context, exactly167042 in total. Compare all
668168 product coefficients against the independent schoolbook oracle.

| Public diagnostic s | Zero roots | Nullity | Fixed prefix length | Prefix bins | Mask mass per bin |
| --- | --- | ---: | ---: | ---: | ---: |
|X-2|2|1|3|4913|17|
|X^2-4|2,-2|2|2|289|289|

The full images have4913 and289 vectors with uniform fibres17 and289,
respectively. They therefore are **not** uniform over all83521 ring vectors.
The prefix is uniform because its projection is surjective, not because the
full nonunit product is assigned IID. The fixed translation(1,2,3,4) preserves
each complete prefix histogram. Complete image/translated-image vectors satisfy
the appropriate homogeneous/affine root parity checks.

The second context retains the required arbitrary-subset negative:

```
product[2] = 4*product[0] mod17.
```

Coordinates(0,2) have rank1, only17 bins, and mass4913 per occupied bin. A
two-dimensional uniform law would have289 bins. Consecutive coordinates(0,1)
do have the guaranteed rank2/uniform histogram. This explicitly rejects an
every-subset/MDS claim while validating the registered fixed-prefix lemma.

All complete histogram caches are outside Git:
`X_minus_2-exact-full-histograms.json`, SHA256
`a88506a76e2b8d2cb1251de16be9767fe58272804265c1254cd36c70ad787a4a`, and
`X2_minus_4-exact-full-histograms.json`, SHA256
`d601db88cdcbc40dcd5cbcb353081b82115798e45d2fa528fe9a259d4b7d9c6f`.
They are exact finite probability inventories, not timing or throughput results.

## 4. One large public model and independent E115 equality

The single large literal model uses only the frozen N16384,d512,count8192,
t1031,CBD21,radix15,drop23,Q1152921504606748673,P4294953991 profile. The module
reconstructs the norm/nullity cap, common bounded-digit maintenance, strict
terminal radius and threshold, exact biased quantizer/CBD MGF, omitted suffix,
complete output/lifetime union, and unconditioned raw zero-secret mass from
public inputs. It does not read E115 outputs when constructing them.

The runner then checks26 exact common fields against the independently written
[E115 mathematical card](query-secret-law-card-20261003.md)'s frozen calculator
result. All26 agree, including rational exponent, per-output/lifetime tail,
once-setup budget and the current general key-generation guard's refusal.
The generic-ratio comparison is additionally checked under its separate name.

| Public model quantity | Exact result |
| --- | ---: |
|Nullity cap K / uniform prefix m|1911 /14473|
|Omitted pointwise codec+CBD phase cap|174435342101748|
|Safe complete Q-phase radius|574193413656199173|
|Original / retained random thresholds|1028574808980193 /854139466878445|
|Floor of conservative rational log exponent|2185|
|Complete lifetime union|2^46|
|Nonzero-secret ideal lifetime tail|at most2^-2138|
|One unconditioned raw zero-secret setup mass|3^-16384, at most2^-25968|
|Single setup plus ideal lifetime|at most2^-2137|

Only the14473-prefix atoms get the independently uniform codec law. The1911
suffix terms are charged by their full support, even if correlated with every
retained atom. All reused maintenance terms remain pointwise. No full-vector
IID, independent digits, Gaussian tail, observed failure rate or adaptive
post-key setup probability is introduced. The exact setup mass applies once
per one unconditioned raw IID ternary setup draw; multiple fresh setups require
their own full epoch count.

This is an **ideal full-uniform-mask correctness model**, not actual SHAKE/ROM
assurance or a2^-128 production forecast. The current general key-generation
guard refuses the large profile; no secret was generated and no guard bypass
or new owner-only setup API was implemented. The one model is not a native
execution or an end-to-end system result.

## 5. Validation, controls and return

56 distinct final scoped tests pass, with exact argv/exit, JUnit and unique
case inventory archived. The tests cover independent schoolbook/Leibniz/field
controls, explicit nonunit and zero cases, the arbitrary-subset dependency,
a separate tiny correlated-codec image with complete CBD coin weights,
norm-certificate forgeries, strict composite/nonsplitting/root/number grammar,
suffix/terminal/union/setup accounting and outward dyadic bounds. They do not
repeat the full registered panels inside every test. Initial50/56 development
snapshots are kept separately and not added to the final56 distinct count.
Explicit nonempty Ruff over the module, test file and runner passes. Main exits0
and has no recorded development/test/scientific failure.

Before the cohort, all16 source/reference paths and exact main argv were frozen,
including the external E115 reference/calculator/receipt. The frozen prereg is
SHA256`479ad6d8c90de7127fe5b96a9c7aacd40b6ddea32285ce41073904589bfeca7d`.
The source/argv receipt is SHA256
`d0e0054ce126815695c32a167d6aff3dd55b211f2a301242ce246ab837b1bc03`.
Source snapshots, logs, tests and full public finite laws reside under
`research-data/nonunit-projection-20261003/`. Existing source/raw inputs are
unchanged. The normal result directory is ignored by default; root can include
the selected final raw in the branch checkpoint. Full finite caches stay
outside Git. Independent read-only module/test/runner review found no material
mathematical blocker; its root-count/provenance clarifications were resolved
before the cohort.

A generic evaluator **given the derived fixed-projection lemma** receives all
the same geometry and bounds and gets ratio1. This is not evidence that the
precise combined consequence was already published. The algebra/concentration
ingredients are standard; closest-theorem separation and originality of the
consequence remain unconfirmed. Finite oracle success is assurance for the
specified construction, not a general cryptographic proof or novelty pass.

Return to R6 with the conditional theorem/certificate retained. Next decisions
require direct prior-theorem comparison and a reviewed computational marginal
transfer for the actual public-seeded sampler, including truncation, complete
query/trace binding, enrollment and adaptive epoch/release assumptions. The
accepted-source/runtime relation, RLWE parameter and private side-channel
assurance remain separate. This packet does not authorize another parameter
grid, service, private callback or production deployment.
