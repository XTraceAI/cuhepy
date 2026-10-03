# Q31/E105: full-support joint source and rotation-carry discriminator

2026-10-03. Frozen before packet execution, after the
[D4 boundary pivot](boundary-reuse-selection-20261003.md). This follows
[E102's two-atom diagnostic](finite-lifetime-noise-screen.md), whose uniform
setup cap remains a sound matched standard control. No parameter, timing,
security-proof, privacy or originality claim is in scope.

## Fixed actual graph and conditional law

Use actual supported N8/D2/t5/Q61 arithmetic, one ciphertext product (secret
degree two), one relinearization and one trace rotation. Reuse the supported
deterministic setup from `test_finite_lifetime_noise.synthetic_context(8,2)`;
its secrets, errors and evaluation-key masks are fixed diagnostics, not a claim
to have sampled a production key honestly. Draw the original index and query
mask polynomials once with OS-backed `secrets.randbelow(Q)` and freeze their
entire canonical realizations in an outside-repository fixture receipt before
enumerating query errors. These ideal-uniform coefficient draws are not an
execution of the production SHAKE-seeded query encoder.

Enroll the three D2 binary records `(0,0), (0,1), (1,0)` in one tile. Pin its
supported integer error polynomial once. Exhaust all four legal binary queries
and **all** eight fresh CBD1 coefficients: 3^8=6,561 unique error vectors with
exact masses `2^(number of zero coefficients)`, denominator4^8=65,536. The
four conditional query contexts contain26,244 weighted states and represent
262,144 literal coin outcomes. The same fixed query-mask realization across
contexts is a conditional-law diagnostic, not deployed mask reuse or a
multi-query confidentiality assertion. No error/key is resampled to fit data.

For every state compute exact integer original-score phase P(E), complete
maintenance R(E), and final phase P(E)+R(E). Preserve their **joint** law, not
independent marginals. Original relin digits are independent of E; the later
rotation input is `can_Q(beta_query + t*linear(index_mask,E))`. Its canonical
digits/carries depend on E. Verify the complete graph against the existing
actual product/trace/decoder API for every weighted state and against a
separate literal two-bit-per-coefficient multiplicity oracle. Include all N
coefficients, not only the three exported distances. All setup stays fixed;
the good-setup event from E102 is not reaveraged for each query.

## Registered representation hypotheses and matched controls

For beta and delta canonical modulo Q, write each rotation coefficient as
`x=beta+delta-Q*wrap`. With radix16 and16 levels, exact addition/borrow carries
obey

```
digit_j(x)=digit_j(beta)+digit_j(delta)-wrap*digit_j(Q)
           +carry_j-16*carry_(j+1), carry_0=carry_16=0.
```

Test only this standard identity's possible reuse effect:

1. Cached generic direct digit-functional evaluation, with precomputed affine
   source/mask maps and matched exact kernel/chunk memoization.
2. A stronger ordinary binary-plane control for radix16 digits, sharing kernel
   lookups across bit planes and scalar signs/weights. Do not compare only to
   repeated full cryptographic evaluation or a naive uncached enumerator.
3. The carry-factor adapter: cache delta's digit-functional result across the
   four contexts, compile constant beta/Q and adjacent-row carry kernels, then
   reconstruct the complete same-error residual exactly. It receives the same
   affine preparation/canonical outputs as the controls and separately pays
   carry construction, cache probes/misses/entries, kernel applications and
   integer accumulation work. No generic LUT/Freivalds/carry identity is new.

All routes may normalize the same exact signed/negacyclic kernel orbits and
use identical four-coefficient chunks. Charge compilation/storage/operations
explicitly; structured deterministic setup can cause unusually many kernel
aliases, so a favorable count cannot be generalized to honest large keys.
Cache statistics are logical counts, not measured memory or wall-clock time.
Require exact joint output equivalence, including stable record tie behavior,
and retain every route even if the literal carry route loses.

Compare exact finite tails and covariance with the E102 uniform pointwise
source/maintenance cap. A convolution of separately sampled marginals is only
a falsifier/control, never the joint law or a valid independence theorem.
Report any absence of a counterexample just as bounded evidence. The smallest
nonzero probability in this law is at least2^-16; do not claim that observed
absence or finite quantiles certifies2^-128 in the real graph.

## Budget, provenance and stop rule

One graph/law component and one representation/count component. Run only the
bounded exact runner and meaningful scoped tests after this preregistration
has been hashed/notified. Raw file:
`benchmarks/results/publication-carry-trace-noise-20261003.json`; report:
`carry-trace-noise-screen.md`; receipts/cache:
`../research-data/carry-trace-noise-20261003/`. Record this file, all new source
and tests, actual reused helper/API source hashes, frozen mask values, failed
outcomes and final counts. Preserve initial raws when source review necessitates
a repeat. Production, old experiments and canonical plans remain untouched.

Stop the literal algorithm if an equally optimized registered generic/binary
control contains its savings or the paid carry/state representation does not
improve them. Even a positive logical count is an engineering hypothesis,
not conference originality, a general adaptive-message/setup theorem or a
security parameter decision. Return surviving nontrivial hypotheses to the
root for code review before any further native work.
