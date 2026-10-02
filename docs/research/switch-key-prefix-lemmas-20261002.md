# E98 exact setup-row law and estimator applicability

2026-10-02. Registered homemade functional-switching diagnostic keys only;
not arbitrary production/SEAL/TFHE key formats or a computational security proof.

## 1. Exact source annihilation

For consecutive retained rows `(a_j,b_j)` with
`b_j=r^j V-a_j T+e_j mod Q`, let
`A=a_(j+1)-r a_j`, `B=b_(j+1)-r b_j`.
Then `B+A T=e_(j+1)-r e_j mod Q`. This cancels V exactly for either original
S or **its actual derived S-squared**; no independence of those secrets is used.
For honestly independent uniform masks, A is uniform conditional on the first
mask. Disjoint adjacent pairs use disjoint masks/errors and therefore give
independent paired polynomials and independent coefficients of the stated law.
This is not a claim that overlapping pair errors are independent.

## 2. Public prefix and sample budget

If T_j=0 is publicly known for j>=p, choose coefficient positions
`p-1,2p-1,... < N`. These coefficients have no negacyclic wrap and each mask
window uses p distinct, previously unused uniform coefficients. Negating B
gives `b=<a,T[:p]>+r e_j-e_(j+1) mod Q`. Thus each paired polynomial supplies
floor(N/p) independent p-dimensional rows. With l gadget levels and C2 skip u,
the independent subset count is

`m=(floor(l/2)+floor((l-u)/2))*floor(N/p)`.

Downloading/using the same keys4096 times does not change m. Full-ring p=N
gives one row per paired polynomial, not N IID rotations. A hidden support of
size p is a different secret distribution and does not license this prefix
extraction. Seed-expanded masks need a separate computational/ROM argument.

## 3. Exact noise, no Gaussian identity

For independent CBD_eta E1/E2 and integer radix r, noise E2-r E1 has mean0,
variance `eta*(1+r^2)/2` and bounds `+/-eta*(r+1)`.
For eta21/r257 the exact variance is693525, standard deviation about832.781,
bounds+/-5418, and there are1849 support values with gaps. The exact binomial
mass and its ordered hash are pinned in the raw results. Scalar negation has
the same law by symmetry. The generic estimator descriptor records these
summary statistics with `is_Gaussian_like=False`; no exact-noise attack or
security theorem follows from that descriptor.

## 4. Cost applicability is a prerequisite

All44 E98 setup budgets satisfy m<p. At pinned estimator53da598,
`estimator/lwe.py:13` binds `LWE.dual_hybrid` to MATZOV. Its cost function
defaults original m to dimension p, and the optimizer fails to pass the actual
sample count to that function. Twelve returned finite costs therefore require
unprovided samples. Keep them as **inapplicable raw controls**, including four
small-ring512 negatives; do not use their minima as transcript attack costs.
Nonfinite costs are preserved and never treated as security approval.

The registered follow-up uses the distinct finite-sample DH function in
`estimator/lwe_dual.py`, whose dual_reduce clamps original m to the given
budget. All44 finite follow-up calls return m<=available, in both identical
cohorts. The applicable primal/ordinary-dual results and this DH follow-up
give eight sub128 profiles, all at N16384/p512, with minima53.560–65.109
log2 modeled operations. Four N2048/p512 profiles have only much higher
applicable returned costs here. This does **not** restore their assurance:
the full correlated/structured transcript, other and quantum attacks,
distribution approximation and protocol/key/private implementation remain open.

No lattice reduction, key recovery, remote customer data or private witness was
executed/returned. These are exact public relations plus limited heuristic
cost-tool computations, separate from production keys and HE timing panels.
