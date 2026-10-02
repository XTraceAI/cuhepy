# Q24/E98: known-prefix samples from actual switching-key setup

2026-10-02, parent `ae79347`, branch `experiment/owner-bound-rounding-20261002`.
R6 return after E97: direct stochastic rounding removes owner zero rows, so
E96's particular 4096-zero sample costs must not be automatically transferred
to its new transcript. No small support is approved by deleting those samples.
Freeze this follow-up before its exact oracle or estimator run.

## Exact transcript relation to prove

The diagnostic keys have rows `(a_j,b_j=g_j*V-a_j*T+e_j)` over R_Q, where
g_j=radix^j, V is original S or its actual derived S-squared, and key errors
are independent raw CBD_eta. Adjacent retained levels yield

`A=a_(j+1)-radix*a_j`, `B=b_(j+1)-radix*b_j`,
`B+A*T=e_(j+1)-radix*e_j (mod Q)`.

Disjoint adjacent pairs use different original rows. Their mask polynomials
are independent uniform if those original rows were honestly independently
sampled, since each second mask is uniform regardless of the first. Their
noise coefficients are independent copies of E2-radix*E1. No independence
of S and S-squared is assumed or needed for exact cancellation. Public known
prefix p then gives floor(N/p) disjoint no-wrap uniform p-dimensional rows
per paired polynomial, using E96's exact coefficient positions. Do not count
all rotations, overlapping key-row pairs or repeated downloads as IID samples.

This concerns the registered homemade functional-switching diagnostic keys,
not arbitrary library keys or a production attack. Public seed-expanded masks
are not automatically true uniform. Auxiliary key graphs/other structures
still need separate arguments. The primary HE security guidelines and existing
key-switching controls warn that distributions/dimensions must match actual
keys; generic cancellation or a cost estimate is not originality.

## Registered finite and differential checks

1. Formal N2/Q3/radix3 consecutive multipliers1/3, every target in {-1,0,1}
   at prefix1, every original ternary S of length2, all81 mask-pair vectors
   and all81 CBD1 error-support pair vectors with exact weights. Check both
   coefficient equations, derived public mask uniformity and independent rows.
   This formal two-row example is not a complete q3 gadget key context.
2. Whole actual homemade key contexts N2/4/8, radix3 and q97/1009, all retained
   C2 omission levels. Check pairing inventory, exact source and actual S-squared
   cancellation, disjointness, support/extraction framing and unwrapped private
   witness equation. No secret/error witness enters the returned public object.
3. Exact CBD1/radix3 distribution from all16 Bernoulli coins; general CBD21/
   radix257 distribution from binomial masses. Check mean0, variance
   eta*(radix^2+1)/2, bounds+/-eta*(radix+1), support and zero mass. The large-
   radix noise has gaps; do not substitute a claimed identical Gaussian.
4. One fresh ordinary public-key homemade BGV source key and fresh honest
   target/switch keys in the same toy style as E97. Check all extracted rows;
   no actual recovery/lattice reduction, customer key or remote service.

## Limited pinned cost screen, after exact relation checks

Use the same six exact E94 Q/N contexts, radix257, eta21 and p512/1024/2048/
4096 when p<=N, with both C2 skips0/1:44 profiles. A newly enrolled reused key
set exposes `floor(levels/2)+floor((levels-skip)/2)` disjoint paired polynomials,
hence that times floor(N/p) independent rows. This is setup-only; 4096 queries
do not multiply the count. Retain full-N row inventory as an unestimated control.

Use Sage10.9 and unchanged lattice-estimator revision53da5982597709ba0fdf94ea37a84d822310fd84,
MATZOV classical/GSA, max-beta cap recorded and usvp/bdd/dual/dual_hybrid only.
Describe Xe with its exact mean, variance, bounds and zero density through the
tool's generic NoiseDistribution descriptor, is_Gaussian_like=False. The tool's
heuristic costs use these summary statistics; no proof they exploit the actual
gapped mass function or cover all attacks is claimed. Preserve failures needing
unsupported distribution functionality. No Gaussian replacement masquerading
as the actual distribution. Xs is uniform ternary in unknown dimension p.

Each selected cost call gets a parent-enforced10-second isolated-worker cap,
serially, two fresh immutable cohort paths. Preserve failed, missing and nonfinite
results and availability differences; compare all overlapping finite costs and
model/context/source fields excluding execution seconds/UTC/command only. These
are estimator computations, not measured HE or executed attack performance.

Any returned cost below128 stops that no-zero setup profile as a128-bit candidate
under this named heuristic. Above128/missing is not approval: other/quantum/
structured attacks, actual seeded masks, key graphs, protocol/proof/private
assurance remain open. Do not broaden the claim to production full-ring keys.

Return to the plan after relation/distribution, differential and cost components.
Keep company controls/negative results and earlier transcripts intact. A later
new source-query or proof mechanism must pay the actual approved target context;
neither generic randomized switching nor setup-row cancellation is selected as
an original complete paper contribution. Q6–Q10 stay conditional.
