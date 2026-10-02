# E95/E96 restricted laws and their boundaries

2026-10-02. These are conditional arithmetic/sample arguments, not a reviewed
HE security reduction. Implementations stay in `experiments/bfv_search_lab/`.
The [E95](late-owner-precision-preregistration-20261002.md) and
[E96](target-prefix-security-preregistration-20261002.md) preregistrations
specify controls, finite scopes and return rules.

## 1. Odd-modulus rounding is a residue permutation

Let Q be odd, B a power of two, H=(Q-1)/2, and
`d(x)=Q*floor((2*B*x+Q)/(2*Q))-B*x`, for x in 0..Q-1.
There is no half tie: a half tie would require `2*B*x=Q*(2k+1)`, which has
an even left side and odd right side. Thus `-H<=d(x)<=H`. Modulo Q,
`d(x)=-B*x`. Since gcd(B,Q)=1, this is a bijection modulo Q; the integer
d values are exactly -H..H. This statement needs neither primality nor a
distributional approximation. Even-Q upward ties and non-coprime B do not
satisfy this registered permutation statement.

For any fixed polynomial offset A and independently uniform rho in R_Q,
the coefficients of A+rho mod Q are independently uniform. Their rounding
numerators are therefore independent uniform centered residues. A may depend
on the old public key bodies, original secrets/errors and previous history.
It must not depend on this fresh rho. Different stages/signs/replies can be
dependent functions of the same rho; only their per-view marginals are used.

## 2. Fixed-target conditional precision

Fix a target T whose coefficients are in {-1,0,1} and vanish outside an
approved prefix p; do not assume its posterior is random. Condition on any
history, T, original inputs/canonical keys and complete finite view family,
then generate fresh uniform rho and independent CBD_eta error E0. Adding
`Z=(-rho*T+E0,rho)` to a switched two-component output preserves its phase
up to E0, modulo Q. Rounding both components to B gives the numerator identity

`Q*rounded_phase - B*original_phase
 = d_body + d_mask*T + B*E0 + B*old_KS_error - B*residual*S^2 (mod Q*B)`.

Original S-squared remains the derived secret. Old switching errors remain
fixed reused-key quantities. They are not averaged as fresh errors. Body
rounding is bounded pointwise by H; it can depend on T, rho and E0.

For a coefficient, each mask-rounding variable X is centered in[-H,H].
The exponential chord bound gives `E exp(lambda*X)<=cosh(lambda*H)
<=exp(lambda^2*H^2/2)`. Independent coefficients with fixed signed T weights
thus have MGF at most `exp(lambda^2*H^2*sum(T_i^2)/2)`. CBD_eta contributes
`exp(lambda^2*eta*B^2/4)`. Consequently the twice-proxy is at most

`2V = 2*H^2*p + eta*B^2`.

For K approved coefficient/sign/pre-PBS-stage events and confidence kappa,
`a=ceil_sqrt(2V*(kappa+ceil_log2(2K)))` gives whole-family failure at most
2^-kappa by Chernoff/union, using ln2<=1. No independence between views is
needed. The actual public bound `sum(abs(d_mask signed prefix weights))+B*eta`
is also valid for every supported T; taking the smaller bound is safe. Public
body/key/residual terms are then added, without changing the prior event.

Selection of any later subset is contained in the complete-family event.
New post-zero sources, key/body-driven changes to the prescribed function,
post-PBS transformations and reuse of this zero on a new adaptive family are
outside the law. A server-chosen self-consistent zero is not an honest draw.
Tests explicitly demonstrate these boundaries, including known zero phases
that cannot be attested by shape/hash checks alone.

## 3. Adaptive histories and accepted feedback

Let at most M owner zeros be generated, including burned attempts. Before
each fresh draw, the approved original family is uniquely fixed by the original
query/index and canonical key/evaluation relation. It need not have already
been computed by the server. This is a uniqueness/binding prerequisite, not
a requirement for another RTT. Owner and client colocated can generate either
a zero OR fresh target keys locally after pinning inputs and upload with the
query. A separate provisioning RTT is a deployment assumption, not a universal
lower bound for the fresh-key competitor.

For family r, condition on all prior history and current originals/secret/key
errors. The bound in section2 holds uniformly over this conditioning, including
any posterior target key. Give every family kappa_z=129+ceil_log2(M), apply
the tower property and union over generated families. Total zero-rounding
failure is at most2^-129. E94's distinct conditional source event at kappa_s129
adds at most2^-129, hence these two arithmetic terms sum to at most2^-128.
Key-error support/provenance, source correctness, PBS and proof failures require
their own genuine arguments; they are not implicitly zero.

Assume a reviewed pre-secret verifier binds originals, approved keys/coins,
complete finite arithmetic/precision and output coverage/IDs. Outside verifier
and actual noise failures, couple accepted releases to the correct ideal
function, with identical public rejection behavior. Observable accepted-result
feedback then differs only on those bad events. This conditional correctness
coupling is not a confidentiality reduction. HE assumptions, parameter/key
graphs, seeds, adversarial enrollment/updates, durable state and private work
remain unproved. The volatile ledger is not an attestation mechanism.

## 4. Shared zero does not give independent fresh ciphertexts

For two fixed masks A1/A2 plus one shared rho, their difference is always
A1-A2. For two independent fresh masks it equals that value with probability
Q^-N. Thus the joint distributions are distinguishable. Similarly, old phase
noise is preserved; adding one bounded zero is not fresh encryption of the
whole message/error distribution.

The [drift paper](https://eprint.iacr.org/2024/1718), Proposition 3.5, requires
statistical rerandomization to fresh encryption before its full ACER conclusion.
We have not established that premise or its joint/circuit requirements here.
Sections 5.1/5.2 already include zero addition and quality tests. Give the strong
standard adapter identical sharing, context binding, tests and resources.
Generic shared rerandomization is not a new mechanism. The finite E95 law can
be retained without asserting full ACER or sIND-CPAD security.

## 5. Publicly known prefix means a smaller unknown LWE dimension

For the same honest public zero, let T have p unknown positions 0..p-1 and
known zeros elsewhere. For k=jp+p-1, with j=0..floor(N/p)-1, all indices
k-i for i=0..p-1 are in 0..N-1, so no negacyclic wrap occurs. The public
coefficient equation is

`-Z_body[k] = sum_i rho[k-i]*T[i] - E0[k] (mod Q)`.

These rows use disjoint blocks of independent uniform rho coordinates. Their
errors use distinct independent CBD coefficients; negation preserves the CBD
law. Different honest zeros use fresh independent masks/errors. Therefore
L published zeros give **L*floor(N/p) genuine independent p-dimensional LWE
samples**, not merely a correlated-rotation approximation. With uniform ternary
prefix generation, the unknown secret distribution is ND.Uniform(-1,1) in
dimension p. Known zero positions do not contribute secret entropy. Using
dimension N or random-location sparse-key entropy would model a different key.

This exact subset enables a relevant generic estimator screen. It does not
make heuristic attack-cost estimates a proven running-time bound or recover
an actual secret key. Only the named cost-estimator functions are executed, not
lattice reduction. Above128 in this limited screen is not approval; below128
stops treating that context as a128-bit candidate under the named model.
Full-ring company parameters and prior estimates remain separate records.

## 6. True uniform masks and public seeds

The unseeded law needs actual independent uniform Q coefficients. A public
deterministic seed expansion is not interchangeable with independent uniform
coefficients paired with that public seed. Nor may an adversary grind coins
or choose the original family after their expansion is known.

A future seed reduction needs an explicit computational/ROM provenance and
adaptive scheduling argument, prior oracle-query/guess/collision bounds and
one-use state. No such replacement is implemented here. Owner-bound stochastic
rounding is a separate strong control to review: it can supply fresh rounding
randomness without an encrypted zero, but must prove its own coin/binding law
and complete cost. Neither approach obtains originality from standard MGFs.
