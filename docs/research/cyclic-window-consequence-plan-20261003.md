# Q47/E121 handoff after the E120 suffix stop

E120 first component returned to R6 with `suffix_consumes_registered_margin`. The single candidate saves 12,288 bytes (about 6%) in the hypothetical owner HE schema, but has no correctness certificate from the fixed-prefix/pointwise-suffix recipe. Stop that recipe without changing its selected candidate.

Next, separately freeze a tiny public all-window/joint-law oracle under the specification below. A pass can support a later independently registered, efficient, one-candidate owner consequence using the unchanged E120 candidate and complete setup/lifetime/terminal ledger. The concentration mechanism is directly known; useful application consequences and originality are unresolved. No key, sampler, native, service or production activation follows.

The following source card and corrective supplement were independently reviewed symbolically. Draft hashes: `65cbbef510f9835fad6d7412d08123441a0d775664b15a845eeef6161653909b` and `775f3beb73241d9a4235b56e11e400f2a31773098ba688b852a9a5ac5cc29ad2`. The public oracle still requires its own preregistration before code or execution.

---

# Prospective cyclic-window correctness packet

2026-10-03. **Symbolic proposal and prior review only. Not activated.** Wait
for the registered E120 first-component return and a distinct source/prereg
freeze and GO before any new calculation, tiny oracle, MGF, setup-norm card,
test or implementation. This note executes none of them. It changes no
repository file, governance, earlier receipt, sampler, API guard or service.

## 1. Decision and exact prior status

The proposed all-cyclic-window lemma and ordinary Hölder bound are valid under
the conditional ideal-mask premises below. They remove the deterministic
omitted-coordinate charge, replacing it with an MGF scale inflation N/m.
That is a different sufficient bound from the fixed-prefix/suffix control;
it is not automatically a smaller tail, approved precision, implementation
speedup or whole-system winner.

The concentration mechanism is **directly known**. Pelekis–Ramon–Wang,
[arXiv1511.07204v1](https://arxiv.org/abs/1511.07204v1), recalls ordinary
Hölder in §1, proves its equal-multiplicity independent-set argument for
Theorem2.2 in §3, and explicitly extends the method to independence systems
in §5. Cyclic windows and their subsets form such a system, with a regular
cover. No dependency graph or independent-input Finner/read-k representation
needs to be inferred. The rendered full mathematics on PDF pages2,4,7,8,14
was inspected; this comparison is not based on an abstract. The related
norm/divisor and Vandermonde ingredients remain known controls from the
retained E115/E118/E119 audits. This review has not established whether the
complete exact-codec, nonunit, CRT, authenticated-owner/lifetime consequence
has previously been published. Originality is unconfirmed.

The E102 `finite-lifetime-noise-screen.md` already stops ordinary conditional
fresh-error MGF and reused-key setup-norm machinery as an original mechanism.
It gives exact equality against its matched standard adapter. It does not
implement this cyclic codec law or an owner-index squared-error event.
Grant every new lemma and optimization equally to the generic control.

## 2. All cyclic windows: the required algebra

Fix a power-of-two N, a nonzero signed integer secret s of degree<N, and
pairwise distinct fully split primes q_a with q_a=1 modulo2N. Let Q be their
product. Fix the complete owner index, error realizations, evaluation keys,
graph, legal query message and prior history before the current independent
ideal full-ring mask A and fresh IID CBD error vector E. No unit-conditioned
sampler, seed grinding, secret-root selection or real setup is introduced.

For each limb let Z_a be the distinct roots at which s vanishes and k_a its
size. A public deterministic certificate supplies k_a<=K<N for every
supported nonzero s; for CRT use K=max_a K_a. The joint resultant implication
is product_a q_a^k_a dividing the nonzero integer determinant, not
Q^max_a(k_a). Put m=N-K and require m>=1.

For each j modulo N, let W_j be the m consecutive coefficient positions
j,j+1,...,j+m-1 modulo N. Its complement consists of K consecutive cyclic
positions. The image of multiplication by s over F_q_a has the parity checks

```
sum_i v_i*alpha^i = 0  for every alpha in Z_a.
```

Choose any k_a consecutive complement columns. For a start b, lift their
exponents to b,b+1,...,b+k_a-1 before reducing indices modulo N. Reducing a
wrapped exponent multiplies that column by a sign, because alpha^N=-1.
The resulting minor is a nonzero row-power diagonal times a Vandermonde
matrix on distinct roots times a nonzero column-sign diagonal. It is
invertible. Thus every assignment on W_j extends to the image. This works
for **every cyclic start**, not just the original first prefix.

Uniform A makes A*s uniform on its image. Conditional on the ENTIRE E, the
actual c0=message+t*E-A*s is uniform on a translated image. Consequently
c0 restricted to any W_j is uniform over F_q_a^m and independent of all E.
Conditional on the fixed shared integer s/setup, CRT limbs of an ideal
whole-Q uniform mask are independent, so the same window is jointly uniform
modulo Q. Keep the existing canonical whole-Q codec; limb rounding is a
different map. No Gaussian, arbitrary-subset/MDS or full-N IID conclusion
follows. For example, the retained X²-4 nonconsecutive-subset negative control
still matters.

Importantly, W_j is the literal sequence of actual coefficient positions.
The minor's column signs prove rank; they do not authorize flipping actual
rounded coefficients or replacing a biased codec error by its negative law.

## 3. Window independence is enough for the MGF

Let Delta_i=delta(c0_i)/t use the exact existing scalar codec distribution
under a uniform canonical coefficient in[0,Q). Define Z_i=E_i+Delta_i.
Within each W_j, the Z_i are IID: its Delta vector is uniform-codec IID and
independent of the entire fresh IID E vector. Windows can overlap and have
arbitrary dependencies with one another. They are not independent blocks.

For an original product coefficient let the fixed signed weights be

```
w_i = t*I[(r-i) mod N] times its negacyclic wrap sign,
Y_i = w_i*Z_i,
T_fresh = sum_i Y_i,
G(u) = E exp(u*Z).
```

The index phase I and the weights are fixed before the current mask/error,
even if they depend on the secret or old setup. No weight may be selected
from the current seed, E, c0 or observed outcome unless a separately proved
pointwise envelope removes that dependency.

Every coordinate occurs in exactly m of the N windows. Apply ordinary
N-factor Hölder to the positive variables
exp((theta/m)*sum_{i in W_j}Y_i). Their product equals exp(theta*T_fresh):

```
E exp(theta*T_fresh)
  <= product_j [E exp((N*theta/m)*sum_{i in W_j}Y_i)]^(1/N)
  = product_i G((N*theta/m)*w_i)^(m/N).
```

For equal weights this is G((N*theta/m)*w)^m. For a signed cap |w_i|<=t*W,
retain both endpoints of the convex weight MGF, including codec bias; a
one-sided endpoint is not automatically sufficient. Homogeneous capped
weights are a conservative comparator, not a substitute for the heterogeneous
formula. Hölder makes no assertion about independence between windows.

A future tiny exact check can avoid irrational roots. For one preregistered
rational r>1 and integer Y_i, the equivalent inequality is

```
[E r^(m*T_fresh)]^N
    <= product_j E r^(N*sum_{i in W_j}Y_i).
```

All expressions can use exact integer/Fraction arithmetic on a bounded
finite law. This note does not evaluate a law or choose a rational base for
an actual large-profile tail.

## 4. Biased-codec and squared-norm option, separately gated

Let mu=E Delta under the exact WHOLE-Q PMF, including its incomplete cycle
and last radix bin. The fresh CBD mean is zero, but mu need not be zero.
Let ell be the span of Delta, not its largest absolute value. Ordinary
Hoeffding's bounded-variable lemma and the exact centered CBD cosine-hyperbolic
MGF give a centered scalar variance proxy

```
v_Z = eta/2 + ell²/4.
```

The cyclic-window inequality then gives the centered proxy

```
V = (N/m)*v_Z*sum_i w_i²
  = (N/m)*v_Z*t²*||I||₂²,
E T_fresh = mu*sum_i w_i.
```

These are inequalities, not an assertion of a Gaussian distribution or
Gaussian variance correctness. A two-sided tail at radius h must charge
the exact mean shift or a uniformly valid bound on it. For example, the
usual subGaussian expression applies only with h>|mu*sum_i w_i| and the
retained radius h-|mu*sum_i w_i|. Silently setting mu to zero is invalid.
The strongest generic comparator gets the exact MGF as well as this coarse
Hoeffding control. The looser proxy may fail even when an exact tail passes.

There is a possible **separate owner-index setup event**. Under independent
honest CBD_eta index errors e_i, the standard identities are

```
E e_i² = eta/2,
E e_i⁴ = 3*eta²/4 - eta/4,
Var(e_i²) = eta²/2 - eta/4.
```

With c=eta²-eta/2 and v=eta²/2-eta/4, standard Bernstein for the centered
bounded e_i² terms can bound sum_i e_i² above N*eta/2+x using
exp(-x²/(2*(N*v+c*x/3))). Threshold, setup budget, every enrolled polynomial,
generated/abandoned epoch and the numerical certificate must be frozen before
its calculation. Condition on a good fixed setup for all later queries;
charge its failure once per actual setup family/epoch, without secret/key
rejection or posterior-IID assumptions.

On sum_i e_i²<=C_e and I=M+t*e,

```
||I||₂ <= ||M||₂+t*sqrt(C_e) <= sqrt(N)+t*sqrt(C_e).
```

A prospective exact backend can use certified integer square-root bounds or
a fixed rational Young inequality instead of untracked floating roots. It
must also pay the original message-product term; the existing d*W support
cap remains valid, and any sharper norm cap needs its own complete pointwise
argument. Retaining only the fresh random term is insufficient.

This is not E102's L1 **evaluation-key** event. E102 bounds the once-sampled
switch error against adaptive digits pointwise. The proposed L2 event here
would bound a different once-sampled family: the **owner-index** errors in I.
Both families, all relin/rotation keys and all index updates remain accounted
for separately. Later digits generally depend on fresh E, so neither event
allows averaging reused key errors as independent of those digits. The
Bernstein/moment/norm ingredients are known; no generic mechanism novelty is
approved.

A separately registered consequence could avoid enormous rational MGF
powers altogether. For a fixed public setup exponent k_setup, an exact
integer x satisfying x²>=2*k_setup*(N*v+c*x/3) certifies the Bernstein
upper at most2^-k_setup, using e>2. One predetermined Young choice can give
the integer owner-phase cap

```
C_I = ceil((33/32)*t²*(N*eta/2+x)+33*N).
```

This follows by taking the te term with factor33/32 and the message term
with factor33; it is not a selected optimum. The exact biased-codec mean
also needs no PMF enumeration. Define F(0)=0 and, for L>=1,

```
k_L = floor((L-1)/t),
F(L) = t*k_L*(k_L-1)/2 + k_L*(L-k_L*t).
Q = a*R+v_R,
mu = [floor(K_R/2)*Q-a*F(R)-F(v_R)]/Q.
```

The full codec span is K_R for the selected admitted radix R<Q. The
conservative bias radius |mu|*t*ceil_sqrt(N*C_I) and proxy
(N/m)*t²*C_I*(eta/2+K_R²/4) are therefore exact rational/integer expressions.
A fixed query exponent would need the centered tail exponent at least
k_query+1 before charging the two sides, all generated-query/output
coordinates and epochs. Every setup polynomial/family and its union must
likewise be paid before fixing exponents. No illustrative budget is adopted
or evaluated here. This efficient known-control option requires its own
freeze, tiny checks and conditional complete ledger, and may simply fail
the unchanged candidate. It is not an approved method or numerical result.

## 5. Complete phase, lifetime and paid controls

Keep the E15 actual joint-support identity: each final coordinate has D times
one shifted original product, plus the complete maintenance envelope. All
positions, missing-tail groups and unused output coefficients remain paid.
The candidate cannot replace S_broad by a canonical-only or favorable sampled
switch value. Use the actual strict Q centering and compact-v1 P rounding
conditions, signal cap, original source fields and full canonical response.
The Hölder MGF bounds the original fresh sum, while maintenance remains a
pointwise envelope valid for every admitted common bounded witness.

The ideal setup-plus-lifetime consequence still needs every raw all-zero
secret draw/epoch, all setup-norm bad events, all generated/abandoned queries,
all output coordinates and any ideal-mask/XOF/finite-stream transfer losses.
The all-zero setup event cannot be inferred from a posterior selected key.
Concrete public SHAKE seeds do not information-theoretically sample these
full uniform windows. E115's explicit transfer/freshness/lifecycle caveats
remain; a new Q120 rejection budget is not copied from Q60. No parameter,
entropy, RLWE/KDM, authentication or private side-channel assurance follows
from this symbolic inequality.

At a later usefulness gate compare, without changing the E120 profile or
candidate after its result:

* registered deterministic full-support and fixed-prefix/suffix controls;
* cyclic exact biased MGF and the separate centered norm/Hoeffding bound;
* the equally informed generic independence-system/conditional norm adapter,
  with identical premises, preprocessing and arithmetic precision;
* the stronger canonical-only admission control, with its different contract
  and unknown verification cost clearly separated;
* full protected replay, known Slalom affine controls, strong ring/proof
  controls and permitted owner plaintext caching, all with actual lifecycle,
  setup/update, complete response and traffic/state costs.

The concentration control can be identical to the candidate. That stops a
new mechanism claim. A smaller conditional ideal bound alone is not the
material complete application consequence required for a paper.

## 6. Bounded proposed gate after E120 returns

First return to the plan after E120. If this route is selected, activate only
a **tiny theorem/conformance discriminator**, not a large tail backend:

1. Freeze the inherited public N4/Q17 nonternary X-2 and X²-4 contexts from
   E118, with their actual m3/m2 information-set controls. Do not relabel
   these as supported ternary HE keys. Use all cyclic windows, including
   wrapped starts, and the retained translated-image and nonconsecutive
   negative controls. Any new mask/error dataset requires its own prereg
   and cap; none is generated by this note.
2. Independently check every window's rank/constant projection multiplicity
   and its invariance under fixed entire-E translation. Freeze one small
   signed heterogeneous weight vector and a public rational power base
   before comparing the root-free exact Hölder inequality. Keep both codec
   signs/mean; do not replace it with full-N IID or a fake dependency graph.
3. Give an independently derived ordinary independence-system adapter the
   same cover and compare exact equality of formulas. Its direct containment
   status is already known. Preserve failures and source versions.

A proposed ceiling for that future tiny diagnostic is the existing60-second/
256-MiB arithmetic budget; the actual finite work count must be registered
before GO. No HE/native/sampler/estimator/service code belongs in this gate.
Stop on any wrapped-window, whole-E, heterogeneous-weight, mean, source or
resource failure. No extra profile/drop/base/candidate search is a fallback.

Only after that return may root separately register an efficiently certified
one-profile consequence. It must use the unchanged E120 selected candidate,
pay the full unbiased/biased tail and terminal/lifetime terms, and freeze a
numerical method/cap before execution. The owner L2 event is an optional
distinct gate, not a quiet premise added to make the first result pass.
No future gate is activated by this note.

## Provenance and review limits

Read retained `finite-lifetime-noise-screen.md`, its preregistration and
`finite_lifetime_noise.py`; `query-secret-law-card-20261003.md`;
`nonunit_projection.py`; `squarefree_projection.py`; the retained source/prior
cards and the prospective E120 contract. Downloaded exactly one new primary
PDF/text pair into this new folder, rendered/inspected its full cited math
pages, and wrote acquisition/read receipts. No old paper, source registry,
scientific raw or frozen cache was overwritten. The initial sandbox DNS
failure is separately retained; the official download then succeeded under
the authorized read-only acquisition.

The PDF's exact arXiv label is v1/23 Nov2015, whereas the retrieved title page
prints September29,2018. Both are recorded without inventing revision dates.
This bounded review is not exhaustive closest-work search, a reproduced
author performance result, a new formal verification artifact, a new
arithmetic/theorem experiment, or production/security/originality approval.


---

# Optional tiny gate supplement: proposed, not executed

2026-10-03. This is a NEW prospective addendum. It leaves the completed
`proposed-next-packet.md`, its reading receipt, source entry and all historical
artifacts unchanged. Wait for E120's return, a separately frozen tiny
specification and root GO. No oracle, dataset, parameter arithmetic, MGF,
test, source implementation, sampler or HE operation is executed here.

Root's optional diagnostic can use inherited public controls only:

* The N8 ternary polynomial X³-X²-1 over q17: check every cyclic window's
  exact projection rank/negacyclic minor. Use the inherited certificate's
  public window length. Do NOT enumerate its entire high-dimensional image
  or demand an unpriced N8 full histogram under a tiny-work label.
* The two retained N4/q17 nonternary controls X-2 with m3 and X²-4 with m2:
  use an independently selected column basis to enumerate the uniform IMAGE,
  not rerun the old full-mask cohort. The retained image/fibre identities
  are4913/17 and289/289 respectively. Validate independence, completeness
  and constant fibres by independent matrix/rank counting; preserve their
  status as public algebra controls, not supported ternary HE keys.

For the N4 images, every cyclic-window histogram, including wrapped starts,
can be checked. The proposed codec context is whole-Q Q17/t3/drop2, signed
weights(1,-2,0,1), CBD_eta1, and the proposed rational power base is2.
These are prospective fixed tiny inputs, not chosen from a new execution.
Q17 is below the actual HE coefficient-encoding API's16-bit modulus floor.
Use the formal scalar map/QuantizerLaw and public matrix oracle only; this
does not instantiate an HE context, query codec through a key, or API bypass.
The exact root-free comparison is

```
(E 2^(m*sum_i Y_i))^N
    <= product_j E 2^(N*sum_{i in W_j}Y_i).
```

**Critical full-law distinction:** codec/CBD MGF factoring is valid for the
window RHS, because each c0_window is uniform independent of the ENTIRE E.
It is not automatically valid for the full-vector LHS. The full codec vector
can depend on E through its affine-image coset

```
c0 = fixed_message+t*E-image_element  modulo Q.
```

The literal LHS oracle must average each supported E vector with its own
translated uniform image and the correct CBD masses, or prove a separate
special-context factorization. Multiplying an unshifted full-image codec MGF
by an independent CBD MGF would ordinarily reintroduce the false full-vector
independence assumption. Freeze the exact finite Cartesian work, caching,
mass normalization and cap BEFORE implementing that joint oracle. Do not
silently exceed the inherited60-second/256-MiB arithmetic ceiling.

For provenance, root's initial informal tiny proposal used the wording
“CBDeta1 factoredmgfs” without distinguishing the full LHS from the window
RHS. That premature full-vector-factoring possibility is retained here as a
REJECTED shortcut, not a valid mathematical premise or an executed failure.
The reviewer identified the E-dependent coset obstruction before any new
oracle work. Root agreed and refined the prospective joint-law contract:

```
fixed M = (1,-1,0,0),
E ranges over {-1,0,1}^4,
mass(E) = product_i binom(2,1+E_i) / 4^4,
c0 = M+t*E-image_element  modulo17.
```

All81 supported E vectors contribute to the exact full LHS. Root's proposed
exact Cartesian work is81*4913 and81*289 image/E tuples respectively;
retain those integer products in the future freeze, rather than rounding
the actual counter. Root's informal398k/23k estimates were only descriptive.
No product was evaluated or tuple visited by this review. Each tuple has
joint mass product_i binom(2,1+E_i)/(4^4*image_count).
Define the literal observable as

```
Y_i = weights_i*(E_i+delta(c0_i)/t),
literal_LHS = [sum_joint mass*2^(m*sum_i Y_i)]^N.
```

The RHS alone may use window-factored MGFs after the conditional
whole-E/window premise is independently checked. Propose E_star=(1,0,0,0)
as the one future fixed nonzero translated-histogram control, alongside E=0,
with the same fixed M. Freeze it before any execution; record two shifts
times all four window histograms per N4 context, rather than duplicating81
histogram panels. This does not omit E states from the full LHS.
The N8 control remains rank-only for one public ternary witness. Neither
the joint-law correction nor a cap failure permits another context/base or
an expanded resource budget within this packet.

Expected future observables, not results: eight N8 window ranks; the two
N4 basis ranks, image uniqueness and uniform-fibre certificates; exact
all-window histograms under both fixed shifts; normalization of all81 CBD
states and the full joint image/E law; signed scalar codec law/mean;
literal full LHS and independently factored window RHS as Fractions; the
powered Hölder comparison and equality with the ordinary cover adapter;
exact visited-tuple/scalar counters; resource exit and source receipts.
The N8 public witness's norm3 certificate supplies inherited window length7;
this is not the all-ternary norm envelope or a general private-secret claim.
That rank control does not
add any N8 histogram, mask, CBD or MGF cohort. All this future work remains
inside the single60-second/256-MiB cap; inability to complete is a preserved
resource stop, not permission to expand the diagnostic.

An additional indicator-only falsifier needs no CBD/codec independence:
use the UNTRANSLATED X²-4 image, separately from the fixed-M codec joint
oracle. With M=0 and E=0, take weights supported on positions0 and2 and
Y_i=1{c_i=0}. The retained relation c2=4*c0 modulo17 makes those indicators
equal. It must not be asserted for an arbitrary translated coset; the
fixed nonzero M above generally changes that relation. Root's symbolic
comparison is E2^(Y0+Y2)=20/17, whereas a false IID
product gives(18/17)^2. The all-window heterogeneous Hölder bound equals
20/17 in this special indicator case. These fractions are the proposed
symbolic check, not a new executed outcome. Keep the arbitrary-subset
negative distinct from the valid consecutive-window law.

The ordinary independence-system adapter must receive the SAME windows,
actual joint law, weights, translation and scalar means. Its direct method
containment remains unchanged. Any useful large-profile consequence needs a
later separate numerical/lifecycle/terminal/communication ledger; no
parameter, security, performance, publication or originality approval follows
from this optional public assurance gate.

Known containment is not a reason to abandon a useful correct control.
After separate activation and meaningful tests, homemade assurance code
could be retained and eventually integrated even if the generic comparator
matches it. Label the concentration mechanism **known/unselected as the
original paper main**. A possible original application consequence needs
a precise prior-separating complete theorem and a material system benefit,
both still unknown. The prospective owner law is not the current typed API:
trusted phase/norm metadata is not an authenticated enrollment or proof,
Q42 remains unimplemented, and no key/query/support guard is bypassed.
Full original-query/common-witness/terminal/full-response admission and
the protected verifier's residency, preparation, recomputation, attestation,
attempt/rollback lifecycle and traffic remain paid unknowns. A successful
tiny inequality or ideal byte consequence cannot assign those costs zero
or approve a production release gate.

One prospective arithmetic option for a LATER efficient consequence can fix
the ordinary rational upper ln(2)<7/10 before its card, instead of the
coarser e>2 conversion in the unchanged proposal. A small independent
method control would certify the exact finite inequality

```
sum_{j=0}^{20} 7^j/j! > 2^10.
```

That sum is a lower bound for exp(7), so the stated log upper follows.
Then a natural-exponent certificate at least7*k/10 suffices for a one-sided
2^-k target, and at least7*(k+1)/10 suffices before charging two sides.
This is a proposed fixed, ordinary arithmetic control, not a new logarithm
evaluation or proved experiment result in this review. Its finite check,
source and method must be frozen and independently checked at the later
gate; all setup/query/output/epoch unions still apply. Do not adapt that
constant or add numerical precision after observing a candidate failure.
Give the matched generic the identical option. Neither this addendum nor
E120's current separate GO activates any tiny oracle or numeric consequence.
