# E90 return: exact signed carries survive; hoisting is the strong control

2026-10-02. [Preregistration](orbit-remainder-preregistration-20261002.md),
[targeted comparison](orbit-remainder-closest-work-20261002.md),
[raw exact/count result](../../benchmarks/results/publication-orbit-remainder-trace-screen-20261002.json).
**29 scoped tests pass.** No PBS, succinct proof, new timing or production
security result is claimed.

## Exact law and complete public subrelation

Let L_i be the remaining even dyadic modulus, H_i the half bit of the original
coefficient at that stage, and U_i/R_i its unreduced quotient/remainder.
Negating a canonical initial coefficient x mod B gives

```
R_i' = -R_i - L_i H_i
U_0' = -U_0 + H_0 + T_0*1[x != 0]
U_i' = -U_i + H_i - T_i*H_(i-1), i > 0.
```

This follows from centered remainder uniqueness and the fact that the prior
correction is a multiple of the next modulus. It preserves every public
coordinate and full integer phase, including the S-squared family. Plain
sign flips fail at half residues; reducing the quotient modulo its target
loses the integer lift required by the reference relation.

The homemade receiver checks owner-approved complete torus components,
ordered blocks, epoch/context/key identifier, centered traces, half predicates
and all outputs before any private callback. Its digest identifies that
approved public context; it is neither an upstream score authenticator nor
a proof of PBS/IDs. Full public recomputation, data and output checking are
paid. The server witness contains no private phase, secret or plaintext winner.

Checks: **3,976** signed multi-stage equalities; **89,856** complete integer
phase equalities; **439,164** public output step cells; **196** corrupt
transcripts rejected without a callback. Corruption coverage is every
single-cell quotient/remainder/bit change plus framing, not all error vectors.

## Sharp odd-grid count, with a restricted proof

For odd Q, B and A powers of two, A>=2 and L=B/A>=2, exactly

`2*floor((Q+L)/(2L))`

source residues x in [0,Q) satisfy `round(B*x/Q) mod L = L/2`.
Thus zero ties for every source residue is equivalent to **Q<L**. Under these
integer constraints this sharpens the earlier proposed sufficient B>=A*Q
condition to an exact characterization, not just a heuristic estimate.

Proof: each half center has index `(2j+1)B/(2A)`. A source point rounds to it
precisely when the odd integer `y=2Ax-(2j+1)Q` satisfies `|y|<Q/L`.
Because gcd(Q,2A)=1, every such odd y fixes exactly one j in [0,A), then one
x in [0,Q); L>=2 keeps x within the range. Counting positive/negative odd y
gives the formula. Odd Q excludes nearest-rounding endpoint ties.

Distinct stages' half sets are **disjoint**, because their remaining moduli
have different powers of two. An original coefficient has at most one half
stage, not independent Bernoulli half bits. This is a derived restricted
arithmetic lemma; priority and a complete-system research contribution are
unestablished. It does not assume evaluated ciphertext masks are uniform.

The closed formula agrees with independent residue and interval enumeration
on **2,304** geometries and **152,064** complete source residues. The even-Q6,
B8,A2 counterexample has zero ties while the odd formula predicts two.

## Paid comparison and R6 return

**96** cards separate sparse/dense, one/two masks, stages, block widths and
repeated queries at N2048/N16384. Standard hoisting gets identical source
reuse. Our complete original-body reference does equal or more division work
than a strong hoisted mask/selected-body control; no advantage over it follows.
Trace materialization is not mandatory response traffic: full recomputation
can regenerate the trace locally, while a succinct method must pay its proof.
Known compact HomTruncRepeat key/work terms and compatible iteration reuse
are included. Actual generation, noise, signed-key compatibility, original
score/PBS/winner authentication and complete lifecycle costs remain open.

Of **64** conditional odd-grid cards, the B64 subset is uniformly tie-free
at every specified stage in **22/32** cards; B128 in **32/32**. B128 keys,
arithmetic and traffic are not free, and are not implemented by this bounded
B64 reference. These are exact counts at modeled Q, not failure probabilities
for real evaluated ciphertexts or approved parameter sets.

Keep the carry/grid controls. Stop treating shared decomposition alone as an
original authenticated selector. Q6 remains conditional. Next finite question:
can a deterministic public rounding certificate exploit the actual relation
between S and S-squared, rather than treating derived key coefficients as
independent? Compare the proposed [E91 screen](quadratic-drift-plan-20261002.md)
against known exact drift and canonical-embedding bounds first.
