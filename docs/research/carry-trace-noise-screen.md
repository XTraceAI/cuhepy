# Q31/E105: exact full-support carry and joint-noise screen

2026-10-03. **Completed; stop the literal full-state/carry adapter.** The
registered tiny conditional law is now exhaustive, and the error dependence at
the later rotation is explicit. Complete digit states did not merge. The paid
carry factor used more registered logical arithmetic visits and more cached
integer coefficients than the stronger binary control. This packet accepts no
original mechanism, security parameter or measured performance claim.

The [frozen preregistration](carry-trace-noise-preregistration.md),
[implementation](../../experiments/bfv_search_lab/carry_trace_noise.py),
[tests](../../experiments/bfv_search_lab/test_carry_trace_noise.py),
[runner](../../benchmarks/carry_trace_noise_lab.py) and
[raw result](../../benchmarks/results/publication-carry-trace-noise-20261003.json)
record the bounded experiment. Detailed exact joint-vector laws and immutable
source/result receipts live outside the repository at
`../research-data/carry-trace-noise-20261003/`. The result directory is ignored
by default; this final raw is selected for inclusion in the research checkpoint.
The full joint-law caches remain outside git.

## What was exhausted

The graph uses the actual `shallow_bgv` product and `trace_bgv` rotation/decoder
APIs with N8, D2, t5, Q=2^61-1, one product, one relinearization and one rotation.
Its product has secret degree two; this is not multiplicative depth two. The
supported setup is the disclosed deterministic
`test_finite_lifetime_noise.synthetic_context(8,2)` fixture, not honest key
sampling. Its fixed index phase is `(1,6,-4,-1,4,-4,0,5)`.

Two original mask polynomials were each drawn once with OS-backed
`secrets.randbelow(Q)` and frozen before enumeration. The fixture SHA256 is
`67865c3a405f9fde1257685cd4d384c107e1fde557ac7781bb5daac3be1f4c78`.
These are ideal-uniform coefficient draws used in the conditional algebra
diagnostic, not an execution or entropy audit of the production SHAKE-seeded
encoder. Conditioning four message laws on the same query mask does not
authorize deployed mask reuse or establish multi-query privacy.

All four legal binary queries to records `(0,0), (0,1), (1,0)` were evaluated.
For each query the experiment exhausted all 3^8=6,561 unique fresh CBD1 vectors.
Their integer weights are `2^(number of zero coefficients)` and sum to
4^8=65,536. A separate enumeration of all 65,536 literal two-bit coin strings
confirmed those weights and their aggregation into the archived law using
the state-to-phase map. Independent phase correctness comes from the actual
API comparisons below. Across the four contexts:

- 26,244 weighted states represent 262,144 literal coin outcomes.
- 78,732 decoded record distances matched the literal Hamming distances.
- 209,952 complete phase coefficients matched the actual API independently.
- Direct, signed binary and carry representations gave identical complete
  maintenance polynomials in every state.

The scoped tests also check a local `(distance, record ID)` ranking adapter
with nonpositional IDs `(20,40,10)`. Queries 00 and 11 exercise stable ties.
This is score/ID adapter coverage; the production ranking implementation was
not invoked by this packet.

## The joint law matters at the rotation

For fresh error E the rotation source is

```
z(E) = can_Q(beta_query + t * sigma_9(X^-1 * index_mask * E)).
```

The earlier relinearization source is fixed independently of E. The later
canonical rotation digits depend on the same E that appears in the original
score phase P(E). The experiment preserves the complete pair `(P(E),R(E))`,
including all eight coefficients, before computing `P(E)+R(E)`.

Sixteen of the 32 coefficient/query laws have a nonzero exact covariance and
are not products of their marginals. The remaining original-phase
coefficients are zero in this trace projection. For query 00/coefficient 0:

- Covariance is exactly `4246825/16384`.
- `(P,R)=(-236,90)` has mass `1/32768`; the product of separately computed
  marginals would give `215/536870912`.
- The true tail `Pr[abs(P+R)>=354]` is `25037/65536`. Convolving those
  marginals gives `198646015/536870912`, a difference of
  `6457089/536870912`.

That independent-marginal convolution is a falsifier, not a valid bound. The
full-domain law closes E102's limited two-atom dependency diagnostic for this
one frozen graph; it is not a general setup/adaptive-query theorem.

The matched fixed-setup pointwise L1 control remains valid in every state.
The exact finite maxima are smaller:

| Query | Exact final full-phase maximum | Matched all-support bound |
| --- | ---: | ---: |
| 00 | 1,515 | 7,335 |
| 01 | 1,496 | 7,331 |
| 10 | 1,624 | 7,331 |
| 11 | 1,475 | 7,335 |

These are conditional diagnostic maxima, not proposed encryption parameters.
The raw contains exact rational coefficient tails at toy targets 1/16 and 1/256.
The smallest nonzero mass is at least 2^-16. Neither a zero observed failure nor
those finite quantiles certifies 2^-128 reliability in a real deployment.

## Complete states do not compress in this fixture

The affine rotation-mask map has an exact modular inverse, verified in both
matrix multiplication orders. The unprojected original-source map also has
a verified inverse. An invertible map modulo Q is injective on the bounded
ternary E support; canonical digit expansion retains the complete source.
This is elementary known algebra, not a new result.

All 6,561 complete canonical source/digit states were distinct for each query;
all 26,244 sources were distinct across the four contexts. Full-tensor grouping
therefore cannot merge these error states. The projected source has field
rank at most four, but its bounded ternary support still contains 6,561 distinct
vectors; a rank bound alone does not show finite-support collisions. This
does not rule out an application-specific decoder summary, whose sufficiency
and costs would need a separate argument.

A one-unit change to fresh E adds a full-Q public ciphertext-mask column to
the canonical source. Small decryption noise does not imply a small numeric
digit perturbation or rare/local carries. No independent-digit or rare-carry
law was inferred from scalar rounding examples.

## Matched controls and the negative carry result

Before the main run, peer review strengthened all relevant controls without
changing the law/domain: exact linear grouping of error kernels, signed and
negacyclic kernel normalization, public monomial normalization of chunk
positions, zero-chunk skipping and public-width clipping. The carry route
receives the same grouping/cache facilities and pays its extra beta/delta
digit extraction, wrap/carry construction, output accumulation and storage.
The outside `pre-main-execution-control-review.json` records this addendum.

This deterministic setup is especially structured. Its 16 error rows have
three distinct polynomials, two primitive signed-monomial orbits and an exact
rank-two kernel span. Period-three rows satisfy `e0+e1+e2=0`, so ordinary
linearity reduces the generic functional to two kernels. Both generic routes
receive this reduction. Q61's radix16 digits are fifteen 15s followed by 1;
five three-row cycles cancel, making the Q-wrap kernel exactly `e15`. The
carry-correction family also receives the same rank-two grouping. These
aliases/cancellations are diagnostic structure, not an honest-IID key benefit.

| Registered representation | Heterogeneous logical integer visits | Cached chunk entries | Stored chunk integer coefficients |
| --- | ---: | ---: | ---: |
| Grouped generic direct | 9,167,929 | 104,607 | 1,255,284 |
| Grouped generic signed binary | 22,462,184 | 160 | 1,920 |
| Grouped carry factor | 39,107,968 | 320 | 3,840 |

The carry route additionally stores 52,520 beta/delta output coefficients in
4+6,561 whole-state entries. The table omits common graph preparation and
object/key overhead; the raw separately lists preparation, compilation,
probes, misses, additions, products, coefficient visits and extraction counts.
Exact rational span-compilation counts are recorded separately and are not
folded into the heterogeneous integer-visit sum. Integer coefficient counts
are not resident bytes, and logical visits are not calibrated CPU/GPU cycles
or elapsed time. Direct evaluation uses fewer registered visits while binary
evaluation stores far fewer entries; neither comparison is a native timing
claim or a global strongest-algorithm claim.

The extra carry output reuse occurs while computing a finite conditional law
across four diagnostic messages. It does not define an online encrypted-search
optimization. The literal carry candidate loses this registered discriminator
and is stopped; the exact law and binary cache control are retained as
reusable validation tools.

## Review, reproducibility and return to the plan

The frozen preregistration SHA256 is
`790889624fab7b87ec2f762dd3ee611b80c134db5dd8b6a07e828978f8a1ccbf`.
Final scoped verification is 24 tests passed and Ruff passed with
`--no-force-exclude`. The runner command is:

```
.venv/bin/python benchmarks/carry_trace_noise_lab.py \
  --fixture ../research-data/carry-trace-noise-20261003/frozen-fixture.json \
  --law-cache ../research-data/carry-trace-noise-20261003/full-joint-laws-reviewed \
  --output benchmarks/results/publication-carry-trace-noise-20261003.json
```

Peer review found that the carry grouping's sign-coherence bound applies to
registered Q61, not arbitrary canonical Q. A Q17 counterexample was added,
and the carry adapter now explicitly rejects other Q. The general scalar
carry identity remains tested at Q17 and Q97. Initial raw/source versions were
preserved before this guard change, and the reviewed repeat retained every
exact scientific/count field and every full joint-law archive hash. Only
run/source metadata and archive paths changed. A subsequent fixed-ID tie
observation changed only the test source; its source-pinned repeat again
retained all scientific/count fields. Receipts identify all versions/hashes.

This packet modifies research files only. It performs no production gate,
native timing, parameter approval, side-channel approval, security reduction
or novelty acceptance. Return to the
[D4 boundary selection](boundary-reuse-selection-20261003.md): the next bounded
question is a strongest complete native rotated/terminal/BFV boundary adapter,
not another carry variant. Its specification/queue entry is a
separate packet; E105 executes no follow-up automatically.
