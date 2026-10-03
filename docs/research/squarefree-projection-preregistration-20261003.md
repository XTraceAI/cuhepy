# Q45/E119: squarefree CRT fixed-prefix discriminator

2026-10-03. Register before new code, tests and cohort. This follows the
[E118 return](nonunit-projection-screen-20261003.md) and the
[closest mathematical controls](nonunit-projection-closest-work-20261003.md).
It is public mathematical research; no actual secret/key, HE evaluator,
sampler, native/CUDA, proof backend, estimator, service or timing work.

## Hypothesis and falsifiers

For distinct fully split prime limbs q_i and power-of-two N, a nonzero integer
secret polynomial has nonzero multiplication determinant Delta and
`product_i q_i^k_i | Delta`, where k_i is its prime-limb nullity. A fixed
prefix of length `N-max_i K_i` is jointly uniform modulo the whole squarefree
Q when every k_i<=K_i and the mask is uniform in the whole ring. The determinant
norm ingredient, CRT and Vandermonde controls are known. A common prefix is
not arbitrary-subset independence, and Q is not a field.

Falsify incorrect `Q^max(k_i) | Delta`, full uniformity from `Q>norm_cap`,
prime-power admission, duplicate/nonsplitting limbs, limb-codec substitution,
or a hidden large-key/parameter/security claim. The equally informed generic
control receives the same valid CRT theorem; this is not a novelty pass.

## Exact finite scope

1. One genuine ternary N8/Q1649 witness `s=X^3-X^2-1`, limbs17 and97,
   primitive16th roots3 and8 respectively. Compare independent integer
   determinant, schoolbook matrices, field ranks and zero-root memberships.
   Use actual norm squared3, determinant norm cap81, and independent
   prime-limb norm certificates. Show that the product-as-field shortcut
   cannot justify prefix8; the common norm-guaranteed prefix7 is valid.
   No mask enumeration for N8, secret search, other witnesses or new primes.
2. Exactly two N2/Q65 full-mask diagnostics, primes5 and13, primitive4th
   roots2 and5. Public nonternary `s=X-2` and `s=X-5`; enumerate all65^2=4225
   masks each,8450 total. Compare schoolbook whole-Q output to prime-limb/CRT
   output, complete image fibres, the fixed prefix from actual public limb
   rank, and its translated coset using fixed shift(1,2). Distinguish this
   actual public-rank prefix from the conservative norm-only certificate:
   for `X-5`, norm squared26 permits a vacuous5-limb norm cap2.
3. Exactly one whole-Q codec-law panel: Q65,t3,drop2, all65 canonical
   coefficients. Check the independently derived quantizer mass inventory
   against the existing exact codec law. Include the fixed coefficient8
   negative comparing whole-Q reconstruction with separately rounded5/13
   limbs followed by CRT. This rejects substituting a limb codec for the
   whole-Q canonical codec. It is not an actual RNS ciphertext experiment.

No parameter/drop/radix grid, large profile, Gaussian tail, unit-probability
estimate or new performance frontier is included. A subsequent large
whole-modulus consequence would need a separate registered card and a
complete actual RNS/sampler/admission contract.

## Ownership and provenance

Owned new paths only: `experiments/bfv_search_lab/squarefree_projection.py`,
`experiments/bfv_search_lab/test_squarefree_projection.py`,
`benchmarks/squarefree_projection_lab.py`,
`benchmarks/results/publication-squarefree-projection-20261003.json`, and
`docs/research/squarefree-projection-screen-20261003.md`. Archive at
`WORK/research-data/squarefree-projection-20261003/`. Existing E118 sources
and every company/native/production path remain unchanged.

Use distinct meaningful tests for exact CRT, rank/determinant/projection and
codec controls, strict integer/prime/split/root admission, and zero handling.
Do not repeat the full registered panels inside each test. Freeze source/argv
before the one main cohort; preserve logs, failures, original/corrected source
versions, collected test IDs and selected raw. Use explicit nonempty3-path
Ruff and independent read-only mathematical review. Wall clocks are provenance
only. Return to R6 after the bounded result; no service or native activation.
