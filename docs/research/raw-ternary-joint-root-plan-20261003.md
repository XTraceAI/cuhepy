# Creative next packet: raw-ternary joint-root defect certificate

This proposed, unimplemented branch investigates an actual missing joint-root certificate. It changes no sampler or parameters. The fixed N16/q97 meet-in-the-middle comparison is only a possible bounded counterexample gate and needs its own source/root/orbit/work preregistration before any computation. The structured-packet extremality conjecture is fragile and may fail; keep the strongest exact zero-only packet control. A useful large-prime result needs a genuine theorem and complete lifecycle/verification costs, rather than extrapolation.

Source-card SHA256 `ecf5a5b6c1211bcce1304e4b912e4fdf11e2d3254b3a2299a315a2c93cc8ae8a`, corrective-symbolic supplement `ce4d5d3ab034574d26df96d7c2e7ae1b45f71d3dee70b1a6ff64c14a4cdb33e6`. No experiment or parameter probability has been run.

---

# Proposed small rank-defect theorem gate: raw ternary secrets

2026-10-03. **Prior/theorem-only proposal; no parameter probability, root/rank
sample, key, coefficient-law change, numerical certificate, experiment or
implementation was performed.** No production, security, originality or
activation approval follows. This is supporting future correctness work, not
an accepted original paper mechanism. Q47's separately registered tiny
joint-law gate and useful known company controls can proceed independently.

## Exact question and scope

Keep the existing formal sampler unchanged: the integer coefficients of S are
independent uniform values in {-1,0,1}, then reduced modulo the existing
coefficient modulus. `src/cuhepy/bfv/scheme.py:245-246` implements
`secrets.randbelow(3)-1`; `shallow_bgv.key_gen` calls that sampler after its
unchanged guard. This assumes the intended independent uniform coins, not an
entropy-source audit. No rejection of zero or nonunits, sampled-key selection,
new root, new prime, enrollment retry, or general key-generation guard bypass
is proposed.

For each fixed existing split prime q_i, write R_i for the N distinct roots of
X^N+1 and k_i(S)=#{alpha in R_i:S(alpha)=0}. The targeted setup event is

    Good = {max_i k_i(S) <= 3}.

The question is whether a rigorous, affordable certificate can bound
Pr(not Good) tightly enough for a preregistered enrollment-epoch budget. This
card does not assign that probability or claim this event is likely enough.
It does not change E120's selected profile/drop or continue its stopped suffix
recipe. A later useful consequence must pay complete noise, terminal, lifetime,
payload, verification and owner-enrollment costs against the same-informed
generic control.

**Joint roots are essential, joint-prime independence is not.** The elementary
union bound already gives

    Pr(not Good) <= sum_i sum_{T subset R_i, |T|=4} Pr(S(alpha)=0 for all alpha in T).

This is sound with the SAME integer S across all limbs. Multiplying marginal
limb probabilities would be unjustified. A mixed-prime theorem could improve
the bound but is not necessary for this max-nullity target. The all-zero secret
is included by every four-root event; do not add it again to a bound that
already includes it. If treating zero separately, subtract/exclude that atom
consistently before adding its exact raw-law mass 3^-N once per epoch.

## Closest retained theorems and direct containment

1. **Attema--Lyubashevsky--Seiler, Practical Product Proofs for Lattice
   Commitments, retained ePrint2020/517, Section3, Lemmas3.1--3.3, printed
   pp9--11.** The full retained text of all three statements/proofs was read.
   Their Fourier analysis permits the actual symmetric ternary p=1/3 law and
   fully splitting X^N+1. Lemma3.2 gives an explicit scalar residue maximum;
   Lemma3.3 reduces its sum by multiplicative root symmetries. The text's
   random-walk discussion expressly distinguishes expected mixing behavior
   from exceptional slower cases. Its printed small examples do not certify
   our source primes. These are the strongest directly applicable retained
   distributional controls; no source-prime evaluation was done.

   A further **already contained structured joint control** follows by reducing
   S modulo X^r-a, when its r roots form a valid power-of-two multiplicative
   packet contained in R_i. Its r remainder coefficients use disjoint integer
   coefficient classes modulo r; they are independent. Each is a scalar walk
   of length N/r, so their zero-event probability is the product of their
   scalar probabilities (or bounded by the product of the paper's scalar
   bounds). The paper explicitly permits the binomial factors to be reducible.
   In particular +/- pairs and quartic packets must receive this strong
   control. It does NOT cover an arbitrary four-root subset by replacing it
   with an arbitrary binomial packet. No independent-NTT-slots claim follows.

2. **Lyubashevsky--Seiler, Short, Invertible Elements in Partially Splitting
   Cyclotomic Rings, EUROCRYPT2018, Lemma2.7 and full Lemma3.1 proof, printed
   pp12--13.** These give deterministic ideal-lattice norm/index bounds and
   small-element invertibility conditions. Applying the same ideal to a chosen
   root set has index q^|T|, and intersecting constraints across distinct primes
   has the product of the indices. This is the same known ideal/resultant
   ingredient behind our worst-case nullity bound. The theorem is not a
   probabilistic small-defect bound for raw dense ternary coefficients, and its
   favorable partially splitting examples cannot be transferred to our fully
   splitting ring without checking their hypotheses.

No new literature was acquired. This is a bounded reading of two retained
primary sources, not an exhaustive novelty search. Fourier inversion,
ideal-lattice counting, recurrence analysis and the union bound are known
mechanisms; merely assembling them is not claimed original.

## Exact joint law: a sound starting point, not an efficient certificate

For a fixed root tuple T over one prime q, index its distinct roots as alpha_a,
1<=a<=r. Put phi(u)=(1+2*cos(2*pi*u))/3. Fourier inversion gives exactly

    P_T = q^-r * sum_{h in F_q^r}
                  product_{j=0}^{N-1} phi((sum_a h_a*alpha_a^j mod q)/q).

Representatives modulo q can be chosen consistently because phi is periodic.
The triangle-inequality bound replaces every factor by its absolute value.
The zero dual vector contributes q^-r; it does NOT make the rest negligible.
The signs of the ternary characteristic function can matter; one may not drop
negative factors or use a centered-binomial nonnegative-characteristic formula
without a proved comparison for this actual law.

For constraints across primes, use the product group and one product over
coefficients, with phase

    sum_i sum_a h_{i,a}*alpha_{i,a}^j/q_i  modulo 1.

The coefficient products do NOT factor by prime because S is shared. This
identity is standard multivariate Fourier inversion, not a new theorem. Its
direct q^r dual enumeration and all root-subset enumeration are not an
acceptable source-profile computational plan.

Full rank of the r-root Vandermonde matrix only supplies a weak distribution
bound: condition on all coefficients except the first r. At most one first-r
ternary tuple can satisfy all equations, hence P_T<=3^-r. This proves neither
q^-r behavior nor a useful union bound. Likewise, rank of consecutive columns
does not imply that an arbitrary column set is MDS or that the ternary image
distribution is uniform.

## Proposed missing lemma and possible creative proof direction

One genuinely missing mathematical object is a **uniform or orbit-classed
upper bound for arbitrary four-root zero events at the fixed source primes**,
with a sound finite certificate whose size avoids q^4 or all-root quadruples.
Its desired strength must be set by a separate enrollment/lifecycle freeze,
not chosen after evaluating a favorable key or root tuple. No such lemma or
certificate currently exists in this work.

A plausible research direction is to classify four-root tuples under the
actual signed cyclotomic automorphism action, isolate binomial/subgroup packets
covered above, and analyze the remaining dual sequences

    lambda_j = sum_a h_a*alpha_a^j  in F_q.

Every such sequence obeys the order-r recurrence with characteristic polynomial
product_a(X-alpha_a). A sufficient mixing certificate would control the
aggregate absolute characteristic products for ALL nonzero h, potentially via
an independently proved bound on centered-residue energy plus a rigorous count
of low-energy recurrence sequences. Counting low-energy sequences is as
important as bounding a single minimum: there are q^r dual vectors. An
ideal-lattice/theta formulation is an alternative for certifying the same
ternary-cube count; it must preserve the finite ternary distribution, explicitly
pay Gaussian-envelope slack if used, and not substitute an unproved smoothing
parameter or uniform lattice-point heuristic.

**Unavoidable structured obstructions:** for +/- root pairs, suitable dual
combinations vanish on every odd or every even coefficient position. Quartic
packets can leave only one of four coefficient classes active. Thus a claim
that every dual sequence mixes in all N positions is false; the proof must
allow these packet types and match the disjoint-class scalar control. CRT root
events can also share integer algebraic causes and the zero-secret atom.
Neither root-orbit symmetry nor a cyclotomic automorphism makes events
independent. Source-specific arithmetic may be needed; applicability to fixed
large primes remains unknown.

This is potentially an applied joint-root certification problem beyond the
retained scalar theorem, but originality is unconfirmed. If the best result is
only ALS's packet product or the deterministic norm bound, stop any distinct
mechanism claim and retain it as an ordinary control.

## A sharper creative hypothesis and a possible finite falsifier

An explicitly UNPROVEN alternative is: at fixed N and q, among all r-root
subsets of X^N+1, a structured binomial packet X^r-a maximizes the raw ternary
annihilation probability. If true with the needed hypotheses, this would turn
the arbitrary-set union into a bound using the ordinary structured-packet
scalar theorem. Neither ALS2020 nor the retained ideal-norm theorem proves this
extremal statement. It may be false even for small examples; equal root
marginals and automorphism symmetry do not imply it. A surviving tiny test
would not establish it for the source primes or a general theorem.

A possible SEPARATELY FROZEN first discriminator is the formal degree16,
q97, r4 case, below the actual HE modulus floor. Fix and strictly validate one
primitive32nd root BEFORE any mass calculation. Its odd powers index the16
roots. The ordinary binomial packets consist of four odd exponents spaced8
modulo32. Compare their exact zero-event masses against ALL four-root subsets,
using only orbit reductions whose completeness and signed-coefficient action
have first been proved. The Galois maps X->X^g for odd g modulo32 permute
coefficients with signs; the symmetric IID ternary law is preserved. No
stronger arbitrary exponent shift or unsigned action is silently granted.

Exact counting can use a meet-in-the-middle split into two eight-coefficient
halves: enumerate the two ternary halves, aggregate their four-root projected
sum vectors with multiplicities, and sum opposite-vector count products. This
is an exact alternative to full-vector enumeration, not a sampling estimate;
it retains the zero secret and all collisions. Work, orbit coverage and memory
must have a separately registered finite cap before root/orbit/mass execution.
No root, orbit count, mass, chosen class, computational cap outcome or resulting
conjecture evidence has been computed here. A nonpacket mass greater than every
packet mass immediately rejects the extremal hypothesis. If it survives, the
next obligation is still an actual theorem with all prime/root exceptions,
not an empirical extrapolation or an independent-root forecast.

## First falsifiers, caps and full-system gate

Before any actual-prime calculation, separately preregister one proof/sanity
gate with these explicit controls:

- For a full N-root tuple in degree N, all evaluations vanish iff S=0; the
  probability is exactly 3^-N, not q^-N. This immediately falsifies a blanket
  independent/uniform-root theorem. A tiny full-root symbolic example suffices;
  no new sample dataset is required by this card.
- +/- and quartic packets must reproduce the known disjoint coefficient-class
  factorization. An arbitrary-root class must have its own proof, not a packet
  surrogate. Roots/primes are fixed public inputs, not selected by observed
  secret rank or empirical absence of bad keys.
- Every orbit reduction, signed action, low-energy count and interval/rational
  characteristic-function majorant needs a reproducible certificate covering
  ALL remaining tuples/dual vectors. If it requires source q^4 enumeration,
  a hidden root grid, guessed independence, unavailable theta estimates or an
  unbounded proof search, stop this first gate rather than run it.
- A later preregistration must specify one finite certificate size/work cap
  BEFORE source arithmetic. This theorem-only card supplies no numerical cap,
  budget, computed beta, sampled maximum or source-prime probability.

If a setup bound beta is eventually proved, sum it over all honest enrollment
epochs (or a documented deterministic upper count). It is not multiplied by
query count merely because the same S is reused, but per-query fresh-mask/noise,
ROM/prequery freshness, finite-stream abort and output union costs still are.
For adaptive public epochs, a uniform conditional beta requires source parameters
selected before that epoch's independent raw secret; a claimed single fixed-prime
certificate cannot silently cover adversarial parameter changes or setup chosen
after inspecting S. Failed/aborted/retried enrollments and rollback are paid;
conditioning on observed successful key/response status requires a new argument.

Only under a sound good-setup event may a later correctness proof use common
window length N-3 in place of the worst-case common-window length. Add bad-setup
probability unconditionally; do not silently condition the deployed secret
distribution on Good or infer HE privacy from a correctness theorem. Admission
must not expose a secret-dependent decision. A unit-conditioned/rejection-sampled
key is a different law and cryptographic system, not the proposed fix.

Finally grant the same lemma, setup budget and full owner contract to the
generic comparator. A reduced-nullity theorem is useful only if a separately
frozen unchanged-candidate complete correctness/communication/verification
consequence becomes material after all paid controls, terminal and lifecycle
costs. No magnitude or speed improvement is forecast here.


---

# Supplement: structured extremality is already a fragile hypothesis

2026-10-03. This supplement records the root's supplied pre-execution
symbolic observation. It does not revise the unchanged proposed card or its
receipt, run the proposed oracle, select a root, calculate any source-prime
probability, or approve the extremal hypothesis.

For the fixed formal degree16/q97 proposal, a binomial four-root packet is the
zero set of X^4-a with a primitive eighth root modulo97. Reducing S modulo
X^4-a yields four independent length-four ternary coefficient classes. For
one nonzero such class c, regarded as an integer element of Z[X]/(X^4+1),
irreducibility makes its negacyclic determinant nonzero and

    |det(M_c)| <= ||c||_2^4 <= 4^2 = 16 < 97.

If c(a)=0 modulo97, the determinant would be divisible by97, a contradiction.
Thus all four remainder classes vanish only when every class is zero, i.e.
S=0. Every structured quartet has exactly the raw zero-secret mass 3^-16.
This is a symbolic determinant argument, not a measured or enumerated mass.

Consequently ANY nonzero raw ternary degree16 polynomial vanishing at four
roots modulo97 would immediately falsify the proposed universal
structured-packet extremality, because its zero-event mass includes both
itself and S=0. The general degree16 determinant bound does not rule out such
a dense witness: it permits the needed fourth-power prime divisibility for
sufficiently large ternary support. No witness, support search, root-orbit
classification, meet-in-the-middle table, or probability has been computed.

The proposed fixed N16/q97 gate should therefore be described as a bounded
counterexample discriminator, not a likely confirmation. Its strongest
ordinary packet comparator is this exact zero-only argument, not a weaker
numerical scalar bound. A discovered counterexample would stop the universal
extremal conjecture; it would not stop a separately scoped genuine arbitrary-
four-root Fourier/recurrence theorem or the known useful cyclic-window control.
Absent a proof, tiny survival provides no source-profile certificate.
