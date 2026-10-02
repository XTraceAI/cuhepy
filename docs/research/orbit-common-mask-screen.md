# E88 return: reusable orbit blocks work; nonlinear CM work is still paid

2026-10-02. [Preregistered scope](orbit-common-mask-preregistration-20261002.md),
[initial exact/count result](../../benchmarks/results/publication-orbit-common-mask-screen-20261002.json).
Sixteen scoped tests pass. Homemade reference arithmetic only: no CM bootstrap,
succinct verification, timing or production parameter claim.

For every original coefficient, use common mask C1 (and C2) and slot secret
`u[k,j]=S[k-j]` for j≤k, `-S[k-j+N]` otherwise. Commutativity of convolution
gives the original phase exactly. This is a bijective public re-expression
of the original components, with no additional packing key, rounding or
ciphertext coefficient. Conditional standalone privacy is inherited from
the original valid ciphertext/evaluation view. Additional evaluator keys,
decrypt/abort feedback and independent Matrix-LWE assumptions do not follow.

For block start d, use mask coordinate
`a'[j]=a[(j+d) mod N]`, negated when j+d≥N. The same canonical slot secrets
for positions 0..w-1 then recover bodies C0[d:d+w]. Thus one canonical
block-key family could serve every block start in that owner epoch.
After the **known** packed switch to a public prefix-D secret, the union
support has exactly min(N,D+w-1) positions. Direct S² instead has at most
min(N,2D-1) prefix support and non-ternary values. No general CM evaluator
or bootstrap is supplied by these view identities.

Checks: **14,580** whole tiny original phases, **43,256** block phases,
**336** public prefix/width support cases and **6,651** complete ternary
source-key laws. The orbit law has 3^N possible full matrices, rather than
the 3^(N²) possibilities for independent full ternary columns. That is a
different distribution, not an attack on either encryption assumption.

The next operation matters: a ring multiplier commutes with the signed
shift T. A diagonal D commutes with T exactly when all diagonal entries
are equal. Across **276** complete binary diagonals, **270** nonconstant
ones leave this compact ring algebra. Across **1,332** all-diagonal/all-input
toy checks, **924** results reject the forced one-ring-multiplier surrogate.
This stops that literal shortcut; block/matrix/CM-GGSW methods remain possible.
Repeating one secret as well as one mask would also expose message differences;
the valid orbit view does not make that substitution.

**96 conditional key cards** compare against an ordinary *shared* PBS key
used across every extracted score, not separate keys per block. They include
the common-mask paper's Table 7 forms and all four Appendix C.1 compact-key
terms plus regeneration/residency obligations. At N16384/prefix512/width8,
the orbit union is 519. With illustrative PBS rank1/degree2048/levels4,
unseeded CM key storage per binary indicator is 2.755 GB versus 134.22 MB
for the ordinary shared key. The dense external-product model uses 2.566×
as many products after block amortization. These are conditional array/operation
counts, not secure parameters or latency measurements. Rank, precision,
layout and optimized CM operations can change them; do not reject all CM.

Table 7's reported seeded CM-GGSW/BSK expression differs from independently
seeding each constituent CM ciphertext. Both counts are retained, with the
adapted serialization/artifact review explicitly open. No paper error or
implemented key compression is asserted. Appendix C.1 is a stronger known
control than simply paying the full unseeded download, but does not make
runtime key generation or the proof of it disappear. Signed/ternary and
S² gates, exact selection/IDs and authentication remain unpaid.

**R6 return:** retain useful exact orbit/block/support interfaces. Stop free
independent-key/one-ring-diagonal PBS claims. No original complete mechanism
is selected. Before another native optimizer, settle the actual full score
domain's negacyclic-LUT/noise interface: odd plaintext moduli can avoid exact
antipodal collisions, but require a different margin than ordinary decoding.
Then price modulus switching, bootstrap rank/degree, the strongest known
large-precision controls and complete proof/coverage. A fixed-rank count
does not select or reject a full CM implementation.
