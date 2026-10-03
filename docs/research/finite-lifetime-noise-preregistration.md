# Q28/E102: restricted finite lifetime and maintenance-noise discriminator

2026-10-03. Preregistered before this packet's execution. This is a bounded
correctness/count experiment under the [route B roadmap](contribution-roadmap-refresh-20261002.md#5-route-b-a-finite-certificate-across-adaptive-reuse),
not a security proof, approved parameter set, timing result or release gate.
Production modules and the old E94/E97/E99 records remain unchanged.

## Actual circuit and two dependency components

The actual `shallow_bgv` evaluator supports **one ciphertext multiplication,
secret degree two**; it does not support multiplicative depth two. Study the
seeded owner query phase `u+t*E`, the once-enrolled index phase `I`, same-key
canonical relinearization, and the existing monomial/rotation/trace graph.
All polynomial products are in the integer negacyclic ring before Q reduction.
The complete decoder still requires the final phase to stay within Q/2.

1. Fix all once-sampled setup/index/secret/errors and the complete prior
   history. Pin the next message and public query mask before the fresh CBD
   query error. Original score noise `t*I*E` is affine in these fresh atoms.
   Its exact finite MGF and integer concentration controls are known. A
   public-key query additionally requires fixing its ternary `u` and CBD `e1`
   before averaging only `e0`; its canonical digits cannot be treated as
   independent of `e1`. No posterior secret law is assumed.
2. In the seeded path, first relinearization digits depend on masks, not E.
   Later rotation digits generally depend on E. Study a **uniform good-setup
   event** bounding the aggregate L1 norm of each once-sampled switch-key error
   family. Then `t*sum(d_j*e_j)` is bounded for **every** canonical digit
   polynomial, including adaptive digits. Pay its one-time failure mass from
   the exact absolute-CBD generating function. Propagate all maintenance and
   packing multiplicities deterministically. Compare the identical strongest
   standard norm/Chernoff adapter; a generic combination is not new research.

Draw order and shared atom labels are premises, not verified by metadata.
Good-setup membership is an analytical event, not an implemented key-rejection
sampler. All relevant enrolled error families count toward its union bound;
secret support is full N. Setup cannot be reaveraged independently per query.

## One finite/count component and fixed budget

- Complete small laws: six registered N2, eta1 seeded fixtures, each with all
  nine centered query messages and all sixteen literal query CBD coin strings.
  Independently verify integer ring phase, canonical relinearization and
  exact coefficient tails. An N16 synthetic same-key fixture exercises the
  actual Python product/trace/decoder APIs over all 256 binary queries in D8
  and an additional N8/D2 trace fixture over all 16 coin outcomes of two
  selected CBD atoms, with the other query errors fixed to zero. This latter
  slice is not an enumeration of the whole N8 fresh error distribution.
  Synthetic masks/key errors are fixed diagnostics, not production sampling.
- Independent exact distribution checks cover CBD eta1/2/3, signed/aliased
  weights, and absolute-CBD sums up to eight variables. Rational bases
  `5/4, 3/2, 2` replace floating exponentials. Compare exact tails to rational
  Markov/Chernoff and all-support controls. Tail optimization is only over
  that declared grid, not an assertion of global optimality.
- Model cards use N8/32/128, eta1/2/3, 2/4 digit levels, 2/4 trace factor,
  query lifetimes1/8/64, correctness exponent8/16/32, and seeded-owner versus
  public-key query conditioning. Total648 cards.
  Allocate separate setup and query failure budgets. Record all known controls,
  no measured CPU/CUDA/WAN times, changed-Q/key enrollment or parameter claim.
- Falsifiers: reused CBD atoms versus distinct atoms; a weight depending on
  the same fresh atom; resampling one setup error per query; and rotation
  digits depending on seeded query E. These invalidate proposed premises and
  are not attacks on a deployed scheme or on a cited paper.

All probability values are integers/Fraction. The integer subgaussian threshold
uses the established E94 conservative control and outward integer square root.
No Monte Carlo or fitted Gaussian certifies negligible probabilities.

## Return and stop rules

Run only the scoped tests and one light exact/count runner after this file
has been written and its scope communicated. Raw result:
`benchmarks/results/publication-finite-lifetime-noise-20261003.json`; report:
`finite-lifetime-noise-screen.md`. Hash the preregistration, code, tests, old
dependencies, result and test receipt in the outside-repository cache.

Stop this candidate as original if the standard conditional MGF plus uniform
L1 maintenance control supplies the same certificate, if its complete useful
bounds are vacuous, or if membership/maintenance/authentication costs are
being hidden. A sharply scoped false-independence finding is useful assurance
but does not by itself meet the roadmap's novelty/resource gate. No native
kernel work, external artifact, lattice estimator or full security reduction
is authorized by a correctness-only passing result.
