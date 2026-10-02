# Q21/E95: one late owner zero across a verified reply family

2026-10-02. **Historical proposal; bounded E95 scope now executed, generic
composition stopped as original.** See [the E95/E96 return](late-owner-precision-screen.md)
and [current Q23 proposal](owner-bound-rounding-plan-20261002.md). The text below
retains the original proposed tasks and unfulfilled complete-protocol obligations.
This was the next R6 return after [E93/E94](committed-precision-epoch-screen.md). E94's source bound
restores headroom without changing the modeled depth-one Q, while E93 still
requires fresh target keys for new adaptive inputs. Test a different source of
rounding randomness before another parameter/kernel optimization.

## Candidate and restricted mathematical question

Keep an existing target key T with approved bounded coefficients/support; do
not assume its posterior is IID. Fix the original encrypted query/index,
canonical switching keys/output relation and every permitted reply/stage
**before** a fresh honest owner draws a true-uniform polynomial rho over R_Q.
The owner encrypts zero under T as `(-rho*T+E0, rho)`, with fresh independent
CBD error E0. Add this one zero to every compatible two-component reply.
Bind the exact owner packet and its generation order in the accepted relation.

For any fixed prior history, T, original switched mask A, and odd Q/dyadic B,
`A+rho mod Q` is uniformly distributed coefficientwise. The exact rounding
numerators `Q*round(B*x/Q)-B*x` permute the centered residues modulo Q because
gcd(B,Q)=1 and there is no half tie. Consequently the mask rounding variables
are fresh, independent and mean zero **even for a fixed posterior target key**.
Prove the all-T conditional law, rather than reusing E93's secret-averaged MGF.

Use a deterministic bound for old switching errors/original S^2 residuals,
not a fresh law for their reused keys. Average the new uniform rounding
variables and independent zero error only. Cover every prescribed coefficient,
sign and pre-PBS stage across all replies by one union event. Their common zero
creates dependence between views; it does not justify independent-view tails.
Reusing a zero at a new adaptive input is outside this rule.

This is known rerandomization/MGF/ACER mathematics. The proposed research step
must be a **cheaper complete late-entropy/provenance/binding interface across
the actual reply family**, compared to the strongest equally shared known
control. If that control already supplies the full step at the same resources,
stop generic composition as original and retain the correct company adapter.
No claim that rerandomization, refresh, common randomness or a Hoeffding bound
is new. Full-score compact replies can be a first use case; encrypted stable-ID
selection adds a separate complete PBS/coverage obligation.

## Finite proof/oracle tasks, with R6 after each

1. Review the full relevant drift/ACER and quality-rerandomization premises,
   malicious verified FHE and shared-output/ciphertext compression controls.
   Specify whether the expected full protocol offers a new resource theorem,
   not a renamed standard shared zero or a per-slot-key strawman.
2. Prove the odd-Q/dyadic-B residue permutation and fixed-key conditional
   MGF. Exhaust small Q, all source offsets/target secrets, fresh uniform mask
   and CBD coins. Compare per-view marginal and whole correlated family,
   reused-zero/post-zero input choice, source/key-body-dependent offsets,
   zero-body substitution, rounding ties and repeated error coins.
3. Test the order boundary explicitly: original input relation can be computed
   by the server later, but its unique value must be fixed by the owner-bound
   original inputs/keys before rho. A server-selected digest, output commitment
   unrelated to originals or self-selected zero/error witness is insufficient.
4. State the conditional accepted-feedback lemma across adaptive queries,
   source(E94), zero/rounding, residual/PBS and proof failure budgets. Retire
   each generated zero after its one approved family, including abandoned
   attempts. Address rollback/fork/registration, updates and private work order.
   Source/target key cycles and RLWE parameter assurance remain explicit.
5. Only then build a bounded homemade public original-plus-zero arithmetic
   oracle/certificate. Full recomputation is a diagnostic control, not the
   compact verifier or decryption authorization. Compare a strongest generic
   proof/folding relation that already includes addition and canonical rounding.

## True-uniform first; public seeded masks need a different proof

Start with actual independent uniform Q coefficients and two full coefficient
bodies. A 256-bit public seed expanded with SHAKE is **not** an information-
theoretically uniform R_Q polynomial. Publishing that seed makes its deterministic
expansion relation publicly testable; ordinary PRG indistinguishability does
not justify replacing `(seed,G(seed))` by `(seed,uniform)`.

A seeded optimization needs a separate ROM/sampling/provenance argument:
fresh domain-separated seed only after the original family is pinned, prior
oracle-query/guess/collision budget, honest generation and no server grinding.
Precomputed private owner zeros need a reviewed independence/state rule before
later query choices. Do not silently copy the unseeded statistical theorem.
E94's fresh-query-error bound does not need uniform masks and remains distinct.

## Paid system screen before implementation expansion

Compare one unseeded zero shared by all compatible replies against equally
shared standard rerandomization, fresh target per adaptive query, deterministic
reusable keys, drift quality control, high-precision PBS and permitted caches.
Count its owner polynomial product/error/mask sampling and 2*N*logQ upload
bits, one zero per family rather than per coefficient/reply. At h independent
seeded query columns this is roughly 2/h extra query coefficient traffic,
before framing/proof; that is a conditional count, not observed overhead.
Include source query expansion/compressed-query controls. E94's IID-column
error formula cannot be copied to their correlated expansion noise.

Avoid a new RTT if the zero is chosen after pinning the original query locally
and sent with it: the fixed original score relation need not already have been
evaluated on the server. Prove that this ordering is enough. Price enrollment,
reusable public keys, client/owner CPU/GPU, all upload/reply/proof bodies,
private state/RSS, refresh and durable authenticity. Owner zero encryption is
not free; the raw/query-cache and vectorized preparation controls remain allowed.

If only compact full-score download is useful, report that exact function
and keep local stable top3. Do not imply a small PBS degree from a large
pre-PBS torus modulus or claim client/server elapsed by summing model stages.
The original encrypted-query gate's large upload/private state is a real
competitor constraint; a better precision theorem alone does not repair it.

**Advance** only with a genuinely new complete binding/resource consequence,
valid fixed-key history proof, secure parameters and a matched useful operating
point. **Stop** if a required entropy/provenance assumption is false, known
shared controls contain the recipe, or paid costs lose. Q6–Q10 stay conditional.
Full closest-baseline adapters and a larger matched BGV/Paillier experiment
remain independent useful evaluation work; they do not establish originality.
