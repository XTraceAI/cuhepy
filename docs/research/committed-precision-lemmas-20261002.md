# Restricted precision/lifetime lemmas for E93 and E94

2026-10-02. Derived conditional arithmetic controls, not a reviewed complete HE
security reduction. See the [execution report](committed-precision-epoch-screen.md)
and [closest controls](committed-precision-closest-work-20261002.md). The MGF,
conditioning, union and coupling arguments below are standard mathematics.
No computational hardness, original mechanism or private implementation gate
is accepted from them.

## Exact sampler MGFs and integer thresholds

For independent uniform ternary T, `E exp(x*T)=(1+2*cosh(x))/3 <= cosh(x)
<= exp(x^2/2)`. For CBD_eta, formed by eta independent differences of
Bernoulli(1/2) bits, `E exp(x*E)=cosh(x/2)^(2*eta) <= exp(eta*x^2/4)`.
The latter is a sampler law, not an assumption that the error is Gaussian.

Thus a sum of independent ternary and CBD variables with fixed integer
weights has MGF at most `exp(V*lambda^2/2)`, where
`2V=2*sum(ternary_weights^2)+eta*sum(CBD_weights^2)`.
If the same random variable appears several times, add its weights before
squaring. Distinct output events need not be independent.

Chernoff and the two-sided bound give
`Pr(|Z|>a) <= 2*exp(-a^2/(2V))`. For K permitted events let
`L=kappa+ceil_log2(2K)` and `a=ceil_sqrt(2V*L)`.
When V>0, the event probability is at most `2*exp(-L)`; using
`exp(-L)<=2^(-L)` and a union gives at most `2^(-kappa)`.
For V=0 the sum is identically zero. These conservative integer operations
use no floating logarithm, Gaussian quantile or root rounded down.

## E93: source commitment before independent target coins

Fix a finite source family before sampling a fresh target secret T, key masks
A_l and independent CBD errors E_l. Condition on any original S, source
ciphertexts and their dependence, then on the fresh masks. Canonical source
digits are fixed. The switched mask uses those digits and A_l only; it is a
function of neither target T nor key bodies. Its signed rounding weights w
are consequently fixed before averaging T/E_l. This is an unconditional
generative argument. It is **not** a claim that T remains IID after conditioning
on published key bodies or later accept/reject observations.

With a low C2 residual P, the rounded phase numerator is, modulo Q*B,

`d_body + d_mask*T + B*sum_l digit_l*E_l - B*P*S^2`.

The first term is bounded pointwise by floor(Q/2), or its exact public value.
The last uses an all-original-S deterministic bound; small target support
does not bound S^2. A coefficient's centered random middle has

`2V=2*sum(prefix signed d_mask weights^2)
     + eta*B^2*sum(all retained digit coefficients^2)`.

The whole approved sign/coefficient/pre-PBS-stage family is included in K.
Source or key errors shared between views are not resampled. After this
whole-family event is bounded, even arbitrary postselection of a subset does
not add a noise trial. A mask transformation using key bodies, a new original
query after seeing this T, a posterior-key assumption, or a post-PBS mask is
not covered by this argument. All generated/discarded target epochs must be
counted. Key-mask rejection based on bodies is not silently honest sampling.

The public implementation fully recomputes every permitted view and binds
the owner-approved originals/epoch/keys. It does not prove key sampling, the
source score relation, unit conversion provenance, PBS or IDs. Its opaque
callback is not an instruction to decrypt.

## E94: conditional fresh-query errors over any fixed supported index

Let h enrolled integer phase polynomials I_j satisfy `|I_j,i|<=F` for all
coefficients, where `F=floor(t/2)+t*eta` for seeded owner encryption. This is
a support guarantee for every source key/index error. At fresh query r,
condition on the entire prior history, source secret, fixed index phases and
newly pinned query messages u_j. They may be mutually dependent. Require
`|u_j,i|<=M=floor(t/2)` and draw independent honest CBD_eta errors E_j only
after this fixation. The score phase before Q reduction is

`Phi_r=sum_j I_j*u_j + t*sum_j I_j*E_j`.

Each mean coefficient is bounded deterministically by `N*h*F*M`. Each noise
coefficient is a linear combination of distinct fresh error coefficients,
with squared scaled weights at most `t^2*N*h*F^2`. The conditional MGF
therefore uses `2V<=eta*t^2*N*h*F^2`. It holds uniformly for every supported
fixed index and every adaptive centered query message. It does not average
the index, S, or the query message, and never treats the product of reused
noises as independent Gaussian noise.

For r_max fresh generated queries, R permitted replies and all N coefficients,
K=`r_max*R*N`. Allocate the same conditional per-event tail before every fresh
draw; the tower property and union bound give whole-lifetime source failure
at most `2^(-kappa_s)`, even with adaptive messages/history. The usable phase
bound is the smaller of the all-support `N*h*F^2` and

`N*h*F*M + ceil_sqrt(eta*t^2*N*h*F^2*(kappa_s+ceil_log2(2K)))`.

Replay of an already bound ciphertext does not create fresh randomness;
abandoned generated queries do consume the lifetime. Source/index changes
after the current errors, adversarial error choices, reused or correlated
query errors, and expanded packed queries with correlated errors are outside
this specific IID-column formula. Honest enrollment and independent OS error
sampling are prerequisites, not facts certified by the public budget object
or its volatile reservation ledger. No durable/fork/rollback guarantee is added.

## Conditional accepted release and what remains open

Assume an independently reviewed verifier binds every accepted result to the
correct original query/index, approved key/coin provenance, complete arithmetic,
all source/rounding/PBS budgets, output coverage and stable IDs. Require that it
finishes before secret-key work, and that its public failure behavior/private
implementation meets the chosen threat model. These are hypotheses here.

Couple real and ideal executions using the same original honest inputs and
public verification decisions. Outside proof failure and all genuine noise
failure events, every accepted release decodes the approved function; every
observable success/reject/result consequence can then be the ideal one.
Their total statistical discrepancy is bounded by the sum of those failure
probabilities. This does not say every correct ciphertext is accepted: public
precision checks can conservatively reject without secret work.

For E94 source kappa_s129 plus **one** E93 target epoch kappa_t129, the two
arithmetic terms sum to at most 2^-128. For m fresh target epochs, use
`kappa_t=129+ceil_log2(m)` each, or report the actual sum. The E94 count
checks that one precommitted batch and m fresh per-query epochs have equal
lifetime allocation. Repeated subset selection within one approved family
does not multiply its failure term; new family/key epochs do. Query/PBS/proof
failures and side channels have not been instantiated and are not zero.

A confidentiality reduction still needs the exact HE assumption/sampler/seed
model, original-message leakage, sink-to-source key-graph hybrids or explicit
cycle assumptions, malicious registration/updates, adaptive verification soundness
and the complete private release implementation. Ternary MGFs, public hashes,
tests, IND-CPA alone or perfect verification of an over-noisy arithmetic circuit
do not supply these missing premises.
