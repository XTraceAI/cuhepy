# E108: complete native scalar relation and strongest shared compiler

2026-10-03 UTC; parent `be8e275`; branch
`experiment/native-proof-interface-20261003`. Execute the frozen
[registration](native-proof-interface-preregistration.md),
[bit-folding amendment](native-proof-interface-control-amendment.md) and
[unsigned-quotient amendment](native-proof-interface-quotient-amendment.md).
[Raw exact/count result](../../benchmarks/results/publication-native-opening-20261003.json),
[primary/interface audit](native-proof-interface-audit.md) and
[return/next task](native-proof-interface-selection-20261003.md).

**Result:** all three homemade transparent constraint models bind the complete
selected native BGV computation on the unchanged E106 toy fixture. Eight original
query packets reproduce the E106 native-agreed response hashes, all72 distances,
stable top-three ties and256 preterminal/256 terminal coefficients per model.
An independently streamed sparse `Az*Bz=Cz` check agrees with direct field
satisfaction for all24 model/query pairs. No new native output execution, GPU
run, binary rebuild, timing panel or external cryptographic proof was performed.
These are arithmetic constraints and complete local checks, not succinct proofs.

## Relation and reduction in representation cost

One shared scalar bit string encodes each canonical source belowQ. Its four
30-bit slices determine the global digits used in both60-bit Q limbs. Exact
source range/slack and centered terminal remainder range prevent CRT aliases.
The affine graph includes all10 switching cuts,112 rows and the partial-tail
rotations. The E107 remainder-first relation binds every native compact-v1
output coefficient. The folded model derives preterminal C from that remainder
in both limbs instead of transmitting a redundant C witness.

Bit coefficients are folded modulo each native prime, and the owner computes
query-dependent public RHS locally. Width-only quotients eliminate redundant
quotient slack while using the **actual looser bit bound** in every no-wrap
certificate. Base source/remainder Q comparisons remain exact. All integer
residual bounds are below the selected Spartan prime scalar field. Field
congruence alone is never treated as an unbounded integer equality.

These are standard substitutions, constant folding and bounded quotient
representations. The generic compiler receives all of them. Candidate-to-best
shared-generic ratio is1; no distinct original main mechanism is demonstrated.
A stronger specialized lookup/range frontend may improve them further.

| Exact logical count / declared serialization | Original tight baseline | Folded tight control | Strongest folded width-only control |
| --- | ---: | ---: | ---: |
| Base value/slack pairs | 144 | 112 | 112 |
| Base Boolean constraints | 34,560 | 26,880 | 26,880 |
| Modular quotient coordinates | 320 | 256 | 256 |
| All Boolean witness variables | 109,158 | 30,878 | 28,879 |
| Linear constraints | 784 | 624 | 368 |
| Total logical R1CS constraints | 109,942 | 31,502 | 29,247 |
| A nonzeros | 731,119 | 521,339 | 515,086 |
| B nonzeros; C is zero | 219,100 | 62,380 | 58,126 |
| Public field slots | 48 | 256 | 256 |
| Largest compiled quotient bit width | 124 | 12 | 12 |
| Largest integer residual bound bit length | 184 | 121 | 121 |
| Author-interface padded row/variable dimensions | 131,072 / 131,072 | 32,768 / 32,768 | 32,768 / 32,768 |
| Literal scalar assignment,32 bytes/variable | 3,493,056 B | 988,096 B | 924,128 B |
| Declared transparent bit tape | 13,645 B | 3,860 B | 3,610 B |
| Full static sparse matrix stream,41 bytes/nonzero | 38,958,979 B | 23,932,479 B | 23,501,692 B |
| Actual cryptographic proof/setup/opening bytes | Unknown | Unknown | Unknown |

The strongest control uses **73.4% fewer logical constraints** than the original
baseline (about3.76x); this is not a measured search/prover/verifier speedup.
The actual limb quotients have widths3–12; terminal quotients have width6.
The initial14/7-bit bounds were conservative sufficient bounds, not observed
widths. Raw histograms retain every width. Base range bits account for26,880
of28,879 strongest witness variables, making them a precise possible target
for future representation work.

The48 original public coefficients mean16 expanded query and32 parsed response
coefficients. Folded256 public RHS slots are derived locally from those inputs;
a server cannot declare trusted RHS values. All circuits are static across the
eight queries and reuse index/key preprocessing. Current pinning still validates
and hashes the full Context/index/keys on every call and retains the sparse
matrix. This is not yet a low-state/sublinear client. Context traversal,
residency, actual PCS, generators, computation commitment, openings, backend
memory/time and authenticated cache/update lifecycle are explicitly unpriced.

The response remains211 bytes (128-byte coefficient body), original query172
bytes. Adding the strongest literal bit tape gives3,821 response+tape bytes,
roughly18.1x the bare211-byte response; adding query gives3,993 bytes. These
are declared transparent encodings, not proof payload forecasts or lower bounds.
Do not call smaller constraint counts a communication win until a real backend's
complete bytes and client work are measured.

## Adversarial and independent validation scope

The main frozen cohort flips one low value bit in **all1,200 logical range
coordinates** across the three models:464 baseline,368 folded-tight,368
folded-width. It rejects46 complete packet/owner-binding cases per model
(138 total), including all32 output coordinates, unused score coefficients,
missing/duplicate/reordered groups, modulus/header/nonminimal MessagePack,
extra body bytes and independently pinned query/context/index/key/epoch/IDs.
The additional three rejection cases per query/model give72 local pre-callback
checks. No rejected diagnostic invokes its decoder callback.

The honest-output false canonical affine kernel is unrepresentable by the
canonical shared bit tape. This is a representation rejection, not an executed
cryptographic proof forgery. `Switch.source`, output and richer terminal-lift
metadata are eliminated where the representation derives them; arbitrary
unused metadata is not separately authenticated by this reduced tape.

**103 scoped tests** pass on final current source in one new module;103 distinct
IDs were separately collected. Tests exercise every logical value/slack where
present and every quotient through selected low-bit mutations, independently
stream the sparse matrices, prohibit graph replay in the verifier, retain the
Q21 idempotent7/independent-limb lesson and unbounded-quotient field alias,
check no-wrap/ranges/centered remainder, strict types and complete response
binding. These are not every-bit enumeration or exhaustive adversarial security.
Initial59/88-case development snapshots/logs remain separate and are not added
to103. Prior227/113/448/1,965 scopes remain historical, unchanged and not rerun.
Explicit nonempty lint covers exactly the three new Python files.

Only honest checked main outputs reach the variable-time **disclosed toy** secret
arithmetic diagnostic; this is not the production private decoder, a constant-time
assurance or an authenticated release service. Compilation/instance are trusted
owner-local artifacts; a server must never supply replacement rows. Correctness
of the transparent relation does not establish PCS soundness, reviewed ROM/
extractability/lifetime composition, attestation, rollback or parameter security.

## Primary correction and return

The new audit archives four additional PDF/text pairs: the separately pinned
corrected2025/286 revision, Spartan, GlueLUT and official BatchPackProve slides.
All77 older source records/pairs are retained. Corrected range/CMC and oracle
packing/sparse commitments are mandatory controls; old range timing estimates
are not a complete corrected baseline. See the audit for exact assumptions,
hashes, selected pages and explicit unexecuted artifact/full-paper scopes.

E108 completes its bounded interface and tiny relation/count components as a
known comparison prerequisite. Specialized/cryptographic proof costs remain
unknown; no broad research/production gate passes. Return to R6:
[Q35/E109](native-proof-backend-plan-20261003.md) is a proposed capped actual
backend/control pilot. Three narrower creative leads are preserved there with
specific paid targets and first falsifiers; none is promoted without a concrete
uncontained mechanism. Earlier homemade HE backends, main/staging, historical
raws/timings/checkpoints and old negative findings remain unchanged.
