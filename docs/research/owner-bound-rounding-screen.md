# E97/E98 return: cheaper owner control, qualified setup-key screening

2026-10-02. Parent `ae79347`, branch `experiment/owner-bound-rounding-20261002`.
E97's bounded fixed-input control and E98's exact setup samples, distribution
and limited cost/applicability screens are complete. They do not select an
original complete main protocol or approve deployment/security parameters.

## What changed and what it establishes

Owner-controlled stochastic rounding needs no auxiliary owner secret product
or CBD draws. It has the same first passing degree as the shared-zero control
in all720 modeled tuples, at the same unseeded upload size. This is a useful
homemade reference simplification, **not a measured speedup** or new rounding
primitive. The equally shared strongest known stochastic control is identical,
so generic stochastic-rounding originality stops here.

Deleting encrypted-zero messages changes the public transcript. E98 proves an
exact independent sample subset from **the actual diagnostic switching-key
setup**. A sample-budget audit qualifies the first estimator results: after
excluding costs requiring nonexistent samples and adding a preregistered
finite-sample control, eight large-ring/prefix512 profiles remain sub128 in
the named classical heuristics. Others remain unapproved. The earlier E96
fresh-zero findings are preserved for their different4096-zero transcript.

## Reproducible code, controls and results

| Component | Homemade code / specification | Exact/count scope |
|---|---|---|
| Owner coins and fixed-input precision | [scheme/receiver](../../experiments/bfv_search_lab/owner_bound_rounding.py), [tests](../../experiments/bfv_search_lab/test_owner_bound_rounding.py), [runner](../../benchmarks/owner_bound_rounding_lab.py), [preregistration](owner-bound-rounding-preregistration-20261002.md), [lemmas](owner-bound-rounding-lemmas-20261002.md) |225 scalar contexts/2045 coins;729 fixed-secret/origin families;59049 fresh-coin branches;944784 integer phase equalities;11664 exact conditional mean/variance checks |
| Setup source annihilation | [public transform](../../experiments/bfv_search_lab/switch_key_prefix_samples.py), [tests](../../experiments/bfv_search_lab/test_switch_key_prefix_samples.py), [runner](../../benchmarks/switch_key_prefix_lab.py), [preregistration](switch-key-prefix-preregistration-20261002.md), [lemmas](switch-key-prefix-lemmas-20261002.md) |177147 complete formal cases/354294 equations, with559872 CBD1 coin-weighted cases;42 actual small whole key contexts; exact CBD21/r257 mass;44 setup inventories/12 full-ring inventory controls |
| Initial pinned cost cohorts | [runner](../../benchmarks/switch_key_prefix_security_lab.py) |Each:176 calls,60 finite/116 nonfinite;12 raw below128 flags. Twelve finite default MATZOV costs are inapplicable because original m exceeds available setup samples. |
| Budget applicability and replacement | [guard](../../experiments/bfv_search_lab/estimator_sample_budget.py), [regressions](../../experiments/bfv_search_lab/test_estimator_sample_budget.py), [runner](../../benchmarks/switch_key_sample_budget_lab.py), [new preregistration](switch-key-sample-budget-preregistration-20261002.md) |Each:44 finite sample-aware DH calls,44 budget checks pass; qualified combined minima stop8 profiles. All original outputs retained. |

Eight immutable result files have four independently matching pairs. Every
declared result/context/model/source field matches except UTC, command path
and estimator-call execution seconds. These seconds are **not** measured HE
or executed-attack runtime. Fresh BGV differential outputs contain aggregate
facts only; secrets/errors/coin realizations do not enter the public receipts.
No SEAL/Microsoft HE code is used by these new diagnostic controls.

- E97 [initial](../../benchmarks/results/publication-owner-bound-rounding-screen-20261002.json), [repeat](../../benchmarks/results/publication-owner-bound-rounding-screen-20261002-02.json).
- E98 exact [initial](../../benchmarks/results/publication-switch-key-prefix-screen-20261002.json), [repeat](../../benchmarks/results/publication-switch-key-prefix-screen-20261002-02.json).
- E98 original cost [cohort01](../../benchmarks/results/publication-switch-key-prefix-security-01-20261002.json), [cohort02](../../benchmarks/results/publication-switch-key-prefix-security-02-20261002.json).
- E98 budget/DH [cohort01](../../benchmarks/results/publication-switch-key-sample-budget-01-20261002.json), [cohort02](../../benchmarks/results/publication-switch-key-sample-budget-02-20261002.json).

## Precision, lifecycle and attack-premise controls

The exact rounding numerator for fixed x is `Q*Ber(r/Q)-r`, r=Bx mod Q.
It has mean0 and variance r(Q-r), including odd/even Q and noncoprime B/Q.
Fresh independent coefficient coins work for every fixed bounded target T:
no IID posterior-secret or uniformly distributed switched ciphertext premise.
Negation complements U to Q-1-U. Signed/permuted prescribed views share coins
but require the correct maps and a whole-family union; they are not independent.
Old key errors, actual S-squared residual and source phase remain paid.

The N128/Q4/B2 control has a genuine exact nonzero tail about1.91418e-5 at
threshold97 (bounded by2^-8), while a post-coin input/reuse falsifier has failure
about0.999894 at its incorrectly claimed threshold86. Reusing one coin across
all128 mask positions gives failure1. The tiny full-family threshold is vacuous,
explicitly; these are order/freshness falsifiers, not attacks on production HE.

The public diagnostic recomputes the full approved original/coin relation.
Seventy-seven false certificates reject before the opaque callback, as do
same-ID packet replacement and replay. Reserve before sampling, bind the
specific packet after sampling, consume before callback; callback failures
burn the slot. The ledger is volatile, without durable rollback/fork protection,
sampling attestation or compact original-score/PBS authentication. The callback
is not secret-decryption authorization.

Two fresh ordinary homemade BGV families reuse one target/switch key set and
decode all16 coefficients correctly through the toy mixed-key adapter. A
separate fresh BGV source key checks all40 extracted setup equations. These
N8/GMP checks are neither PBS execution nor production parameter/private assurance.

## Costs and target security qualification

E97 independently reproduces all8640 E96 precision points before adding720
cards. The standard stochastic and zero routes need the same first passing
degree (or both have none), at every registered support/source/lifetime tuple.
Two unseeded coin polynomials equal the zero packet's two polynomial bodies;
uniform sampling changes N to2N draws. The coin route removes one auxiliary
owner secret product and2*eta*N CBD bits per family. Key setup, every server
switch, full verifier repeat, lookup/PBS/proof, original query bodies, durable
state and retained plaintext cache costs stay explicit. No actual remainder-
specific Bernstein benefit is credited to large cards without actual inputs.

For reused keys with l levels and skip u, E98 supplies
`(floor(l/2)+floor((l-u)/2))*floor(N/p)` independent setup-only rows. It does
not multiply by4096 queries or use all ring rotations as IID. Error variance
is693525 with gapped support, not CBD21 or a claimed identical Gaussian.

| Qualified no-zero setup control | Profiles | Applicable combined minimum log2(ROP) | Decision |
|---|---:|---:|---|
| N16384, p512, four source-Q contexts, skip0/1 |8|53.560–65.109|Stop128-bit design claims under these named heuristics |
| N16384, p1024 |8|221.530–273.270|Not approved; missing full transcript/noise/other-attack assurance |
| N2048, p512, two source-Q contexts, skip0/1 |4|568.939–594.898|Original raw117.498–124.311 estimates required unprovided samples; qualified screen does not establish security |
| Remaining p2048/p4096 or small-ring p1024 |24|Higher finite DH costs or qualified primal controls|Unapproved; beta/model/full-noise limitations remain |

Pinned external lattice-estimator53da598, Sage10.9, generic exact-mean/variance/
bounds/density Xe descriptor, MATZOV-classical/GSA primal costs and the named
finite-sample DH control. Tool internal Gaussian/simulation and beta-cap
heuristics remain disclosed. No lattice reduction/recovery, quantum/full attack
coverage, seeded-mask argument, auxiliary-key graph reduction or parameter
approval is supplied. The twelve inapplicable default costs remain raw, not
silently rewritten. E96's sample-rich4096-zero context does not have this
particular original-m shortage; its raw findings and historical scope stay intact.

## Return and next executable question

Keep the exact homemade adapters, premises, negative controls and budget audit.
**422 scoped CPU tests in19 files** pass,57 new; explicit Ruff includes all10
new Python paths. Two primary PDF/text pairs bring the archive to64, with
targeted reviews and no new author HE artifact execution. Frozen revalidation,
production code and main/staging remain unchanged.

Next [Q25/E99](key-transcript-precision-plan-20261002.md) asks for a coupled
key-transcript/precision discriminator: characterize overlapping source-
annihilator mask rank and exact correlated noise; compare a hidden sparse
full-ring target against the already stopped public-prefix control; price any
surviving gadget/noise rule with the strongest general matrix and sparse-key
controls. A reduced support count is not a reduced unknown dimension when its
positions are hidden. This is a proposed unimplemented candidate, not an
accepted new mechanism. No new generic MGF/rounding or CUDA packet replaces
the missing original contribution. Q6–Q10 and broad gates stay conditional.

Full [identity manifest](publication-owner-rounding-execution-manifest-20261002.json)
and [validation receipt](owner-rounding-execution-validation-20261002.json)
pin raw/source/paper/tool and scoped test evidence. The
[closest-work review](owner-bound-rounding-closest-work-20261002.md) states
the novelty boundary and primary-source reading scope.
