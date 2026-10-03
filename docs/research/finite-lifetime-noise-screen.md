# E102 return: sound restricted reuse control, no original mechanism selected

2026-10-03. **Q28's bounded discriminator is complete; stop the generic
candidate as an original research mechanism.** Every one of 648 paid model
cards is identical to the matched registered conditional MGF plus uniform
setup-norm adapter. Retain the homemade exact controls and the concrete
freshness regressions as assurance/reference work. This is not an approved
parameter set, confidentiality proof, production release gate or speedup.

[Preregistration](finite-lifetime-noise-preregistration.md),
[implementation](../../experiments/bfv_search_lab/finite_lifetime_noise.py),
[tests](../../experiments/bfv_search_lab/test_finite_lifetime_noise.py),
[runner](../../benchmarks/finite_lifetime_noise_lab.py), and
[raw result](../../benchmarks/results/publication-finite-lifetime-noise-20261003.json).
Earlier [E94](committed-precision-lemmas-20261002.md),
[E97](owner-bound-rounding-lemmas-20261002.md), and
[E99](gadget-dependency-lemmas-20261002.md) remain unchanged.

## Restricted graph and the important conditioning distinction

The actual `shallow_bgv` primitive performs **one ciphertext multiplication**,
leaving secret degree two. The bounded packet does not implement or claim
multiplicative depth two. Its full local reference follows the existing
degree-two product, canonical relinearization, monomial shift, trace rotations,
tile packing and exact trace decoder. No modulus switching/PBS is added.

Fix once-sampled setup Z: original secret, public-key errors, enrolled owner
index ciphertexts/errors, all relin/rotation keys/errors, and their dependencies.
Fix the complete prior history and next legal query message/mask before drawing
fresh CBD query error E. Seeded owner encryption has query phase `u+t*E`; an
index tile has integer phase I. The original product is

```
I*u + t*I*E.
```

Each output coefficient's fresh part has fixed signed negacyclic weights
`w_j=t*I[(k-j) mod N]` with the appropriate wrap sign. Its exact rational
power MGF is the product of the CBD generating functions, after aggregating
any shared atom aliases. The CBD distribution has mass
`binom(2*eta, eta+e)/4^eta`; no Gaussian approximation is needed.

For a public-key query, the phase is
`u_msg + t*(e_pk*U + E0 + E1*S)`. Condition on the newly generated ternary U
and CBD E1 before averaging **only E0**. The old public-key error/secret remain
fixed, and E1 is not assigned its original law after conditioning on a digit
polynomial that depends on it. The paid model uses owner-seeded enrollment
and gives this public-key-query route its full extra deterministic residual.
Public-key enrollment would need its larger index-phase bound separately.

The seeded path initially has `C2=index_c1*query_c1`, so its first relin digits
are independent of E. **Later rotation digits are generally functions of E**,
because the relinearized mask includes the product's cross terms. The concrete
N8/D2 diagnostic has one first-relin digit tensor and nine later-rotation digit
tensors across its sixteen literal two-atom coin outcomes. This invalidates an
attempt to average setup errors as if fresh independent digits fixed their
weights. It does not establish an attack on the deployed implementation.

## A restricted uniform maintenance lemma

Let a registered switch-key family have L independent honest CBD error
polynomials `e_j` of full dimension N. Its fixed realization has

```
A = sum_j ||e_j||1.
```

For every coefficientwise canonical digit polynomial `0 <= d_j,i < B`, even
one adaptively selected from query errors/key bodies/history,

```
||t*sum_j d_j*e_j||inf <= t*(B-1)*A.
```

This follows directly from the integer negacyclic convolution triangle
inequality. It holds pointwise; no independence between digits and errors,
no resampling of old errors, and no posterior secret distribution is used.
It covers canonical decomposition only. A malformed or unauthenticated
noncanonical witness still needs a complete pre-secret-use verifier.

Before setup is published, each honest CBD atom has exact absolute generating
function `H(r)=sum_e Pr[E=e]*r^abs(e)`. At rational `r>1`,

```
Pr[A > a] <= H(r)^(N*L) / r^(a+1).
```

The experiment minimizes this outward exact rational bound over the fixed
grid `r in {5/4, 3/2, 2}` and uses zero tail at full support `N*L*eta`.
For J registered relin/rotation families, allocate setup failure `epsilon/J`
to each and union them. Joint independence between families is unnecessary
for that union; the within-family IID honest CBD sampler is a premise.
Good-setup membership is analytical and is **not** key rejection sampling.
All generated epochs/families must count; arbitrary post-publication key
registration, omitted error families and setup-dependent resampling are outside
the statement.

On the good-setup event, use the resulting uniform K for every switch residual.
For trace factor D and T tiles in a response group, the complete conservative
phase bound is

```
T * (D*(original_score_bound + K) + (D-1)*K).
```

Each trace step adds a rotated copy and a new uniformly bounded residual.
The expression pays every doubling/packing multiplicity; orbit and tile
views are not independent fresh samples. The main cards pay `T=D` and all
N coefficients of each permitted tile, even when the decoder exports fewer.
Different bounds per rotation could improve this known control, but were not
selected after generic containment became conclusive.

For every good fixed setup and every supported adaptive next-message/history,
the still-fresh affine CBD law gives the original-score conditional failure
bound. The tower property and union yield

```
Pr[any honest correctness failure] <= epsilon_setup + sum_i delta_i.
```

All generated queries, including abandoned ones, consume the lifetime. Replay
is the same random event, not an independent trial. The cards use separate
setup and query lifetime budgets `2^-kappa` each and report their actual sum.
They do not claim `2^-128`; their registered kappa values are 8/16/32.

## Exact findings and resource screen

| Registered scope | Result |
| --- | --- |
| Six N2 supported fixed setups; all nine messages and sixteen literal CBD coin strings | 54 message contexts, 864 coin outcomes, 3,456 integer phase coefficient equalities; canonical relin phase agrees with the independent schoolbook oracle |
| Small-ring exact coefficient tail versus rational Chernoff | 1,350 checks pass |
| Twelve weighted CBD literal laws | 275,124 literal coin outcomes; eta1/2/3, signed weights and products match integer laws |
| Fifteen independent absolute-CBD polynomial laws | 195 further exact tail/Chernoff checks and 36 exact setup-cap checks pass |
| Actual Python trace/decoder API, synthetic N16/D8 setup | All 256 binary queries × four rows = 1,024 exact distances match; masks/errors are supported deterministic diagnostics, not honest key sampling |
| Actual N8/D2 rotation dependency slice | 16 outcomes of two varying query atoms, with other errors fixed to zero; 256 uniform residual coefficient checks pass; this is not the whole N8 error law |
| Paid model grid | 648 cards; full-N key support, every key family, relin/trace/packing multiplicities, query/setup lifetimes and raw coefficient/seed bytes retained |
| Uniform setup cap versus full support maintenance | Improves 546 cards; largest model phase ratio versus E94 with support maintenance is `426038/166163` (about 2.56×) |
| Conditional original source versus all-support source | Improves 448 cards |
| Matched registered standard adapter | **Exactly equal on all 648 cards** |
| Fixed four-bit radix/registered level count | Only 24 cards even have enough digit capacity for the correctness-only required Q bit count |
| Scoped tests | **50 passed** |

The 648-card comparison expands the candidate's registered formula into the
same standard-adapter expression and verifies arithmetic equality. It is
**scoped algebraic containment**, not an independent empirical reproduction
of a competitor or a claim to have compared every possible noise bound.
The raw field name `strongest_known_adapter_phase` means strongest among
this packet's registered formulas. The separate literal-law/phase tests are
independent finite checks of those stated controls.

The raw 2.56× ratio is a **bound ratio**, not a CPU/GPU performance ratio.
The registered toy sizes N8/32/128 and eta1/2/3 differ from large deployed
settings. A smaller correctness bound does not justify shrinking Q; a new
modulus may change level counts, RNS arithmetic, hardness, keys and enrollment.
The four-bit radix and two/four registered levels allow only 8/16 Q bits;
`shallow_bgv.key_gen` requires at least 32 requested Q bits. Consequently
**none of the 648 analytic cards is a direct parameter candidate for that
actual API**, including the 24 toy digit-capacity-compatible cards. The model
also fixes t=5: D4 trace arithmetic can be counted, but a dimension-three/four
Hamming decoder requires `t > 2*dimension` and cannot be instantiated with
that t. These are analytic circuit counts, not deployable search geometries.
The separate actual-API diagnostics use Q61 and matching t5/N8/D2 or
t17/N16/D8; their correctness checks do not approve those synthetic contexts.
The raw 32-bit terminal response bytes are a fixed hypothetical layout count,
not a proven terminal switching setting. Prime/RNS feasibility, actual compact
rounding, envelopes, full response/proof binding, updates and private backend
costs are uninstantiated. The 24 capacity-compatible cards are not approved
parameters or complete matched resource winners.

The first test run found one **oracle normalization error**: the affine-law
implementation removes zero-weight atoms and consequently has a reduced
denominator, while a literal coin enumeration retains their multiplicity.
Comparing exact normalized Fractions resolves it without changing the law.
The original failed outcome is preserved in the test receipt; the corrected
50-test run and final source hashes are recorded. No old experiment was rerun
or overwritten.

A final validation repeat after removing an unused import and adding the
underlying polynomial/sampler module to source provenance reproduces every
exact count, model card and scope field. The first new raw result and its
matching source versions are retained in the outside-repository packet cache;
the canonical raw file describes the final reviewed source. Ruff was invoked
with `--no-force-exclude` so the repository's research-directory exclusion did
not turn lint into an empty check.

## Falsifiers and decision

One fresh CBD atom counted twice has exact two-sided tail `Pr[|2E|>=2]=1/2`;
two falsely independent atoms predict `1/8`. A coefficient chosen from its
own fresh atom gives `E*E`: its positive tail at one is `1/2`, versus `1/8`
for the invalid independent product `E*E'`. At rational MGF base two those
models give `3/2` versus `17/16`. Four queries sharing one setup atom have
probability `1/2` that all four errors are nonzero; resampling setup per query
incorrectly gives `1/16`. The conditional lifetime theorem above makes none
of those independence substitutions.

These finite falsifiers expose invalid modeling premises. The generic uniform
L1 good-setup event and exact fresh-query MGF are useful correct controls, but
standard norm/Markov/Chernoff mathematics already supplies the same certificate.
The [closest-work review](closest-work-roadmap-refresh-20261002.md#5-closest-work-for-a-finite-reused-key-noise-theorem)
already identifies dependency tracking and conditional concentration as occupied
territory. This packet does not demonstrate a new case with a distinct useful
cryptographic consequence. It therefore **stops as original**, retains the
assurance regression/reference, and returns to the roadmap rather than opening
a native optimization task for this generic construction.

Computational lattice hardness, related-key assumptions, honest entropy/order,
index/query provenance, a compact complete verification/release mechanism,
durable state and private-side constant time remain separate obligations.
