# Q23/E97: owner-bound stochastic rounding as a complete strong control

2026-10-02. **Proposed, unimplemented and unselected.** R6 returns after
[E95/E96](late-owner-precision-screen.md). The immediate missing competitor
is a fixed-input precision method that needs neither a new target secret nor
an owner encrypted zero. Do not inherit p512's unapproved security assumptions.
The broader original contribution still needs a new complete score/provenance/
proof or correlated compressed-query consequence beyond known controls.

## Question and prior-work boundary

Owner-approved originals and canonical reused keys uniquely determine every
unrounded reply before fresh owner coins. Randomize the *rounding* of its two
components instead of multiplying an owner mask by the secret. This is standard
randomized modulus switching, not an invented HE scheme. A targeted primary
search finds [FINALLY, section 3.5, Definition 3.9](https://eprint.iacr.org/2024/1505.pdf),
which uses unbiased Bernoulli rounding and attributes it to FHEW. The cited
FHEW control and drift/mean-compensation/verified-execution adaptations require
full relevant reading before E97 runs. The FINALLY lead is recorded but not yet
downloaded/hash-pinned; no author artifact or whole noise proof was reproduced.

Execute this packet as a missing **strong baseline**. Generic stochastic
rounding, fresh nonces, union bounds and composing a generic proof remain known.
Only a demonstrably cheaper complete authenticated relation, source-query
representation or valid joint resource theorem could become the new step.

## Restricted law to prove before implementation

For fixed canonical x, set `r=(B*x) mod Q`. Draw U independently uniformly
from `0..Q-1`, and use `floor(B*x/Q) + int(U<r)`. Its integer rounding numerator
is `Q*int(U<r)-r`, with exact mean zero and range width at most Q. This holds
for any fixed input, odd/even Q and a fixed target key; no posterior-IID or
mask-uniformity assumption is used. These proposed identities are to be checked
independently, not copied from a Gaussian heuristic.

Use independent coins for component coefficients within each view. If shared
coin polynomials are reused across prescribed replies/signs/stages, establish
each view's marginal law and pay a whole-family union without independent-view
assumptions. Do not silently equate stochastic negation with negative rounding.
For ternary T with support cap p, the mask-plus-body rounding term has the
proposed conservative twice-proxy `Q^2*(p+1)/2`; old switching errors, actual
derived S-squared residual and source phase stay paid. Compare sharper exact
MGFs, deterministic caps, E95's bound and the strongest standard adapter.

Original relation/order and coin provenance are binding obligations. Server-
chosen coins, grinding, post-coin input choices or repeated coins at adaptive
inputs must not be accepted as fresh. Fix originals locally before sending
coins with the query, without charging either baseline an unnecessary RTT.
Conditional correctness/feedback coupling, all generated/discarded families
and durable replay/rollback/fork protection remain distinct from confidentiality.

## Components and required return after each

1. Read/cache the relevant FHEW/randomized-switching control and FINALLY's exact
   definition; compare drift/mean compensation and complete proof baselines.
   Specify input binding, honest coin source, target distributions, lifetime
   and the concrete resource that a later new mechanism would improve.
2. Preregister one homemade integer oracle. Exhaust scalar input/coin laws,
   odd/even moduli, rounding wraps/signs, all fixed bounded target secrets,
   whole correlated view families, exact nonzero tails and adversarial ordering/
   reuse/grinding controls. A vacuous toy threshold is not a negligible tail.
3. Add a full public diagnostic original/coin/rounding subrelation with malformed
   and reordered witnesses rejected before an opaque callback. A hash/label
   is not a sampling proof and this is not yet compact verification/decryption
   authorization. Demonstrate actual homemade BGV differential semantics only
   under the declared toy scope. Keep private errors/secrets off outputs.
4. Price the control with the same source, support, original precision grid,
   sparse/dense outputs and setup/lifetime states as E95/E96. Two unseeded
   coin polynomials have approximately the same body traffic as E95's full zero,
   although no owner secret product/CBD error or additional owner-zero LWE rows are
   needed. Report exact packets and verifier/prover work, not estimated elapsed.
   Standard shared stochastic rounding receives identical sharing and state.
5. Return to R6. If it contains the proposed precision improvement, stop generic
   late-entropy originality and keep the best company control. A new proposal
   should target the still-large source-query body or complete original-score
   proof: specify an actual correlated expansion law/shared relation and full
   closest comparator before another bounded oracle. Do not pick kernels as
   the next research mechanism merely because an arithmetic bound improves.

## Seeds, assurance and evaluation gates

True uniform independent coefficient coins come first. A 32-byte public nonce
expanded with SHAKE has a publicly testable deterministic relation and is not
information-theoretically independent uniform coins. An optional ROM route
needs fresh post-binding seed generation, prior query/guess/grinding/collision
budgets, canonical rejection sampling, domain separation and adversarial
schedule/lifecycle arguments. It is a separate proposed lemma, not free
compression or ordinary PRG substitution.

Use E96's stopped-prefix statuses at the registered horizon. Prefer full-ring
controls or explicitly limited larger-support contexts pending full classical/
quantum/structured/key-graph/sampling assurance. No stochastic rounding removes
the HE security requirement or the final PBS margin. No shared algebra alone
proves original scores, stable IDs, coverage or safe secret release.

Only after an original complete useful mechanism survives R6 should Q6 homemade
reference, Q7 profiling/native/CUDA, Q8 complete reduction/private audit, Q9
matched measured lifecycle/network/cache evaluation and Q10 paper/artifact
activate. Keep the larger matched BGV/Paillier lookup-hybrid panel as an
independent evaluation task. Existing fast engineering and negative controls
are valuable; a conference claim needs a precise surviving new result.
