# E77 preregistration: factor packed-query checking by the public seed

Return after the R2/E76 usefulness screen to R3-B1/B2. Hypothesis: for fixed
original C1 and owner-pinned expansion keys, E73's expansion is affine in
original C0. If S_j selects residue j and multiplies it by H, then

```
expanded_j = (S_j(original_C0), 0) + delta_j(original_C1).
```

Every gadget decomposition acts on C1. Its carries are public-seed dependent;
do not assume gadget inversion is globally field-linear. Check the identity
modulo full Q against complete canonical expansion, including arbitrary C0,
mixed-degree/non-power-of-two columns and wrap signs.

Compose S_j's transpose with the existing projected ciphertext operator's
private row. This yields at most N actual C0 input coefficients rather than
2hN coefficients of expanded queries. Seed-specific constant beta is obtained
from canonical zero-C0 expansion and **all** Z0/Z1 terms. An owner-local factory
may supply beta once per independently fresh original C1. The online receiver
must bind original input, seed hint, IDs/epoch, keys and the full projected body
before any secret use; shared volatile attempts count malformed/replays too.

## Finite discriminator

Implement the homemade oracle and bounded trusted factory/receiver. Exhaust
the seven retained N32/t17/eta1 binary-query schedules, same keys/index as the
complete E73 client-expansion gate. Compare every ciphertext coefficient and
score/ID/top-3; test exact adjoint, C0 affinity, changed seed/expansion/output,
omitted beta, cross-context and replay/reused C1. A synthetic zero-C0 query is
only public arithmetic; do not decrypt it or attach a plaintext validity claim.

Measure factory seed expansion + beta work, online registration/pinning/check,
server expansion/product, response bytes and setup. Count online receiver
vectors, its challenges, factory's retained expanded fingerprints, pending
hints, originals and required freshness. Do not call moved owner state/work a
whole-system saving. No fresh ciphertext/quotient factory is required, but a
fresh private scalar hint **is** required by this literal design.

## Advance/stop and novelty boundary

Affine hoisting, coefficient selection and linear fingerprints are known
ingredients. This can be a strong new control, not automatically an original
construction. Advance only if the seed constants can be obtained safely with
less complete trusted work/state than the E72/E73 gate and caches, or a
precise new certified-generation step is specified. Stop a literal claim if
the large fingerprints merely move to a trusted helper or every fresh seed
still costs a full canonical expansion. No CUDA/native code follows a failed
screen. Parameter/KDM, hidden-state reaction privacy, timing and durability
require a matching argument and independent review.
