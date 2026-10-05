# Query-mask preprocessing: known-method containment

2026-10-05. This is a targeted preimplementation comparison made while the
registered R3 timing action runs. It reads no partial timing values, changes no
frozen runtime source, and activates no experiment. It neither selects R4 nor
fulfills the required implemented creative extension.

A possible construction-route adaptation is to prepare encrypted random query
masks in advance and send a small plaintext correction online. The basic
algebra has a close predecessor: [ZipPIR v1, §4.1](https://arxiv.org/html/2603.09190v1#S4.SS1)
describes an encrypted random component plus a plaintext message offset, and
evaluates the expensive part of a linear function offline. Its concrete
Paillier compression protocol has a different PIR functionality and database
contract. We must grant the compatible algebra to our reference, rather than
claim it as an invention.

[Slalom v2, §2](https://arxiv.org/html/1806.03287v2#S2) also prepares one-time
input masks and their linear images offline. Its weights and trusted-processor
boundary differ from our encrypted owner index.
[Incremental Offline/Online PIR](https://www.usenix.org/conference/usenixsecurity22/presentation/ma)
already addresses preserving preprocessing across database changes. These
differences require an adapter; they do not erase the predecessors. This is
targeted construction reading, not reproduction of any author implementation.

## Two literal adaptations to compare if R3 makes them relevant

The following are our analytical adaptations, not claims about those papers'
exact execution or measured costs. Let `b_i` be the encrypted feature
polynomial, `x_i` the query's signed bit in F_t, and `r_i` an independent
owner-held uniform element of F_t. For one use send
`delta_i = x_i - r_i (mod t)`.

1. **Prepare the query prefix.** Expand the encrypted packed `r` before the
   query, then add constant plaintext `delta_i` to each expanded ciphertext.
   The ordinary encrypted feature products, complete admission and terminal
   conversion remain online.
2. **Prepare the base score.** For an immutable encrypted physical base, prepare
   and admit `C_r`, the complete common-Q ciphertext of `sum_i b_i*r_i`.
   Online, form `C_r + sum_i delta_i*C_i` modulo Q, where `C_i` is the original
   encrypted feature. Check this entire relation before terminal conversion
   and private decoding. This moves encrypted products/relinearization into
   preparation and leaves plaintext scalar products online. It remains a
   known offline/online linear decomposition.

The second variant must retain the common-Q score. Adding a correction after
terminal modulus conversion is a different operation; nearest coset rounding
need not commute with addition. Neither variant may replace a native relation
with a signature over an unchecked result.

For the existing N=16,384, d=512, Q120, two-limb representation, these are
**analytic coefficient bodies**, not timings or measured resident memory:

| Resource | Body alone |
| --- | ---: |
| Online correction, 512 canonical u16 field values | 1,024 B |
| Owner's one-use mask, same u16 representation | 1,024 B |
| Expanded two-component, two-limb query prefix | 268,435,456 B per mask |
| Two common-Q base-score components | 491,520 B per mask per group |
| Existing packed common-Q query c0 | 245,760 B, before seed/envelope |

These counts exclude signatures, IDs, recipes, parser staging, preparation
traffic and transient state. They are not a response-download reduction. Each
mask is consumed once, so its offline work and unused/expired state must be
paid; it cannot be amortized over unrelated queries. The score variant is
base-dependent. Changed logical rows can use the already-known owner-held
replacement control, but that does not make base-plus-replacement original.

## The safety boundary is earlier than private finish

Reusing a mask for two different queries exposes their difference from the
two public corrections. Therefore trusted consumption must occur **before
the correction leaves the owner**, even if no response is accepted. Consuming
only the later private callback cannot repair that disclosure. A complete
adapter needs crash/concurrency/multi-device nonreuse, exact retry of already
published bytes, and bound tenant/key/base/profile/pad/query identities.
No such adapter is implemented by this note.

Plaintext corrections also change the public support argument: use centered
representatives and bound their complete coefficient contribution before
applying the terminal phase bridge. The old bound must not be copied unchanged.
Query privacy would require an actual augmented-HE/one-use-mask composition
argument under the declared feedback and leakage. No security theorem follows
from the offset identity alone.

## Decision

Close the claim that encrypted-mask or precomputed-score hoisting is itself a
new algorithm. If completed R3 costs make preprocessing relevant, this belongs
among the strongest compatible known controls. A prospective R4 claim must
identify additional necessary work or a guarantee that survives this control,
and include total lifetime costs and permitted owner caches. No contained
variant is scheduled merely to add an experiment row. R3's actual complete
return and the existing single-extension eligibility gate remain next.
