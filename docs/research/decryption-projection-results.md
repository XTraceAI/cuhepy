# E62/E63: decoder dependencies change the verification and wire objective

2026-09-30. A bounded P10/P02/P07 alternative after the lifetime-policy negative.
This experiment asks what must be authenticated/transmitted to preserve exact
scores **before a long-lived HE secret is used**. It changes the checked
relation in a separate research profile; existing full-ciphertext clients,
company code and production eligibility are unchanged.

The positive primitive is a known ingredient. RLWE/GLWE-to-LWE sample
extraction selects a ciphertext body coefficient while retaining the mask
coefficients needed by its secret-key product; see the
[TFHE author's derivation](https://www.zama.org/post/tfhe-deep-dive-part-4).
Coefficient selection, a new wrapper and linear fingerprints are not novel
by themselves. The research hypothesis is a compiler/protocol consequence
from jointly selecting representations, decode dependencies and authentication,
with a defensible lifecycle game and useful measured effect.

## Restricted implemented profile

`experiments/bfv_search_lab/decryption_projection.py` accepts exactly one
full-ring **score-only** CRT leaf. Row scores use a prefix of C0 coefficients
on each reply, but C1*S can depend on every C1 coefficient. The response keeps
all C1 and only used C0. Owner-pinned counts/order/Q determine parsing; residues,
padding, bounds, epoch/context/token and full supplied-coordinate relation are
checked before `_selected_phase` uses SK. Malformed bodies also consume the
verification attempt/token. A single volatile global budget is supplied.

Private challenges are uniform on kept C0 and all C1 in the ideal field game,
with zero weights on omitted C0. Existing adjoint preparation is reused in a
**Python/GMP reference checker**. Accepted selected coordinates equal the
owner-approved public evaluation except for the conditional fingerprint error.
They inherit the honest phase certificate. A dedicated decoder computes only
those field phases. Its internal zero-padded check carrier must **never** be
passed to ordinary BGV decryption: omitted coordinates have no phase guarantee.
Legacy layouts and split CRT are rejected by this implementation.

Six tests cover constant/nonconstant/multi-reply scores, canonical wire
roundtrips, every C1 dependency, altered kept C0/C1, malformed objects/bodies,
one-use state and a spy proving rejected cases do not invoke selected SK
arithmetic. Native/GMP ciphertexts and ordinary full decryption agree on
selected coordinates. These are correctness/security regressions, not a
reviewed projection protocol or assurance of private timing/parameters.

Two public fixtures, split3001, one warmup plus three timed queries per N,
new direct score-only global-affine indices with direct fresh owner answers,
t193/257, Q32/eta21. Both full reference gates and unreduced integer audits
run outside prototype timing. Every16 encrypted score arrays/top3 agree.

| Fixture / full N | Full coefficient body | Projected actual body | Body reduction |
|---|---:|---:|---:|
| Semeion1465 /2048 | 16,384 B | 14,052 B | 14.23% |
| Semeion1465 /16384 | 131,072 B | 71,396 B | 45.53% |
| Mushroom7996 /2048 | 65,536 B | 64,752 B | **1.20%** |
| Mushroom7996 /16384 | 131,072 B | 97,520 B | 25.60% |

For R replies, m direct score coefficients and full N, exact coefficient count
is `m+R*N` instead of `2*R*N`. Framing/owner authorization are additional.
Only unused C0 capacity is removed; C1 and the full secret-key dimension stay.
The nearly-full Mushroom2048 case is an essential negative: there is little
padding to remove. At complete occupancy the method saves **zero** bytes.
Do not choose a larger ring merely to advertise a larger reduction fraction.

The Python checker is not the stronger native full-vector implementation.
Prototype stage sums are retained (e.g. Semeion2048 ~15.18 ms,16384 ~94.00 ms),
but are **not a native/complete-cost speedup**. Layout, gate and decoder differ
from the earlier legacy-global controls. Setup/token/hint work is separate;
no socket, GPU or equal-assured-security comparison is claimed.

Raw: `publication-decryption-projection-{semeion,mushroom}-20260930.json`;
entry point `benchmarks/decryption_projection_lab.py`.

## The tempting unsafe projections

A structural oracle gives every omitted C1 coordinate a valid ternary-secret
witness affecting any kept phase coefficient. This is a direct coefficient-
deletion dependency statement, not a lower bound on public reconstruction,
key switching, different protocols or special ciphertext distributions.

Reducing C0 to plaintext-field values is also unsafe even when **every** C0%t
value is kept. With Q257,t17,C0=15 and fixed C1*S product5, the phase20 decodes
to3. Changing C0 to134 keeps C0%17=15, but phase139 wraps to−118 and decodes
to1. Thus plaintext-field equality does not authenticate centered-Q decryption.
This is the same kind of carry obstruction that E47 warned about, with a
direct decoder counterexample. Lossy sketches/modulus compression need their
own reviewed verification/reconstruction argument; SK must not be used merely
to discover whether their missing information was legitimate.

## Exact public support oracle and a new cost tension

E63's `decryption_support.py` does **not** deploy a split-CRT projected gate.
It derives the public decoder's C0 support for legacy/output-only schedules.
For a row at local coefficient p in a leaf of degree L, repeated CRT reduction
uses positions `{p+j*L : 0<=j<N/L}`. All root factors and inverse padding are
nonzero in the approved odd field. Union these sets over every output row in
each reply. All C1 coefficients are retained.

An independent oracle applies the actual field decoder to **every unit basis
column**, completely determining its linear support on tiny layouts. Eight
mixed/legacy/score-only/multi-reply cases agree; randomized full field phase
vectors decode identically after unsupported coordinates are zeroed. This
certifies the omission identity in that public decoder. It is not proof that
arbitrary aggregates or plaintext-field projections commute with HE decryption.

There is now a concrete joint-choice discriminator:

| N32/t17 two-leaf score-only layout | Old complete resource vector | Kept C0 | New projected body model |
|---|---|---:|---:|
| Balanced counts(8,8) | Same h/F/W/R/body/bound/check counts | 16 | 192 B |
| Skewed counts(12,4) | Same vector as balanced | 24 | 224 B |

Both old full responses cost256 B. The resource vectors are exactly equal,
but projected-body cost differs because the decode supports overlap
differently. This **does not** prove that the earlier DP pruned incorrectly:
it retained its declared boundary semantics and optimized a full-response
objective. It shows that a new projection objective must price support/alignment
rather than only rank/capacity/full-check length. Counts/metadata differ under
the allowed public-geometry policy; identical leakage is not claimed.

Raw: `publication-decryption-support-oracle-20260930.json`; entry point
`benchmarks/decryption_support_lab.py`. Sample extraction and set-union/support
costs remain known ingredients. Originality is still a hypothesis requiring
targeted literature comparison and a stronger algorithm/protocol result.

Return to the plan: formalize the supported-coordinate decoder/game first,
then a separately tested split/legacy gate and exact support-aware planner.
Benchmark against **native full gates, ordinary layouts, E48 public C1 recipes,
authenticated caches and original low-state EMVP**, charging setup/state and
all unused tokens. Reject the hypothesis if support becomes dense, known
simple alignment matches it, or pre-decryption checking erases the practical
effect. The E54/E56/E59 conditional draft does not silently certify E62/E63.
