# E89 return: full odd LUT works; final precision still needs a reviewed backend

2026-10-02. [Preregistered scope](odd-domain-lut-preregistration-20261002.md),
[initial exact/count result](../../benchmarks/results/publication-odd-domain-lut-screen-20261002.json).
Sixteen scoped tests pass. Known plaintext/test-vector arithmetic only, not
an encrypted programmable bootstrap or new scheme.

For odd t, folded centers of `round(2M*k*h/t)` are exactly the rounded
`M*j/t` grid: multiplication by 2k permutes residues. If M≥t, centers are
distinct, with minimum cyclic separation floor(M/t). Assign each desired
output with the sign of its unfolded center, and keep each neighborhood
within half that separation. The guaranteed integer error is
`floor((floor(M/t)-1)/2)`. This allows **arbitrary** full odd-domain values;
it is a known control, described in Hippogryph section 2.2.3/Equation 1,
which credits earlier p-encoding work.

The ideal full-torus margin is about 1/(4t), rather than ordinary decoding's
1/(2t). E85's full eight-point even-domain negative remains valid but must
not be generalized to odd domains. This is a stronger control, not a new
claim about E85's raw result.

Checks: **40,560** message/function/permutation/admitted-error cases, **3,222**
independent explicit ring-monomial rotations, and **405** complete cases across
all 3³ small output functions. Even incompatible antipodes and insufficient
degree are rejected. An explicit original zero phase under Q65537, four
unit secret coefficients and valid public masks rounds to rotation2 under
target8, outside the degree4/t3 lookup's zero-error margin.

**160 precision cards / 1,440 rank-width shapes** retain original unit noise,
both-family illustrative switch-key noise and the final componentwise switch
to 2M. They include center quantization and a worst-case prefix-secret L1
control. All original modeled-Q sufficient bounds fail (0/160). In **145**
cards, even an arbitrarily larger Q cannot make *that particular worst-case
bound* pass; this includes all **96** degree≤8192 cards. In the other **15**,
an optional new prime/identity-unit/NTT context satisfies the modeled strict
bound with its gadget levels recalculated. Secure key noise, original phase
bound validity in that new context and PBS noise/security are still unapproved.

Example: t193/degree2048/prefix512 permits four integer rotation positions of
error; the rounding/center bound is 257 before input noise. Raising Q cannot
fix that inequality. Degree131072 gives 339 allowed positions and admits a
conditional 47-bit Q versus the original 44-bit Q. This is expensive and is
**not** a recommended parameter set. Higher rank can make some CM *product
counts* beat scalar shared PBS, but key/state/proof cost and whole latency
remain unpaid. No timing or security ratio follows.

Known probabilistic/bias-corrected switching and high-precision methods can
beat this worst-case control. The newly retained **Meta-PBS** primary paper
targets this exact redundancy problem, using quotient/remainder extraction,
repeated blind rotation and HomTruncRepeat packing. Its Algorithm1/Theorem2
has explicit divisibility, redundancy/truncation and Gaussian/binary-secret
premises. Those cannot be assumed for our BGV product noise and signed orbit
secrets. Large-precision sign/floor and refined full-domain/digit methods are
also retained controls; their author artifacts have not been run.

**R6 return:** advance known odd-domain LUT; stop unpriced small-ring precision
and arbitrary giant-CM backend selection. No original complete main mechanism
is selected. Next [Q16/E90](orbit-remainder-trace-plan-20261002.md) asks whether
the orbit family can share a *complete, authenticated* quotient/remainder/
packing trace against Meta-PBS, hoisted standard switching and HasteBoots.
Explicit even-modulus half ties are now required: E87's odd-Q negation rule
cannot be copied into a power-of-two torus remainder pipeline.
