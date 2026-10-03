# E108 component 1: applicable proof interface and closest controls

2026-10-03 UTC; parent `be8e275`. This targeted primary/source review follows
[Q34](native-opening-discriminator-plan-20261003.md) and the frozen
[registration](native-proof-interface-preregistration.md). It selects a concrete
scalar R1CS interface for a homemade transparent relation adapter. It does not
execute a cryptographic proof backend or approve a deployed verifier.

## Interface that fits the unchanged native graph

[Spartan](https://eprint.iacr.org/2019/550) accepts sparse rank-one constraints
over a prime scalar field. The [author artifact](https://github.com/microsoft/Spartan/tree/d62b961f9497e3c07a921b6da1457cad467598d9)
is pinned to `d62b961f9497e3c07a921b6da1457cad467598d9`, Cargo version0.9.0,
MIT license. README, library, scalar, group, transcript and commitment source
snapshots are archived read-only. No build or proof run occurred. The default
Ristretto255 scalar field is
`ell=2^252+27742317777372353535851937790883648493`, **not** the curve's base
field `2^255-19`. A sparse instance supplies A/B/C matrices and assignments
ordered as private variables, constant1 and public inputs. Logical Boolean
and linear constraints can be exported to that interface.

The artifact's SNARK interface has public instance encoding/commitment and
size-dependent generators. Its argument uses discrete-log assumptions and
Fiat-Shamir/ROM (Merlin transcripts); a transparent setup is not an absence
of preprocessing. Binding instance, exact original query/response, context,
index/key/epoch/IDs, retry and attempt domain separation, challenge security,
extractability and lifetime composition must accompany an actual backend.
This audit identifies the contract, not a reviewed composed reduction.

For this toy adapter, the owner pins context/index/key/layout/epoch/IDs and
locally expands the original compressed query/SHAKE stream. It strictly
parses and reserializes every output coefficient. This public work is paid
outside the relation and does not evaluate the encrypted search. Common
scalar bits, exact canonical ranges, bounded integer quotients and no-wrap
bounds below ell bind the two Q limbs. The E107 centered remainder binds exact
terminal P bytes. The stronger [shared compiler amendment](native-proof-interface-control-amendment.md)
is available equally to a generic baseline: eliminate redundant preterminal
C and fold bit coefficients modulo each prime. Its [unsigned quotient amendment](native-proof-interface-quotient-amendment.md) also
omits redundant quotient slack while certifying the actual bit-width bound.
Its public RHS slots are
locally derived from the original query and parsed output; they are never
trusted as server inputs. Actual dimensions and costs belong to component2. Current host pinning validates
and hashes the entire owner Context/index/keys on each call and retains the
static matrix. No low-state or sublinear verifier is implemented by this API;
context traversal/residency are additional unpriced costs. An authenticated
immutable enrollment cache is a shared future optimization, not a current gain.

## Mandatory specialized comparisons

| Work | Exact applicable premise and difference | What this review establishes |
| --- | --- | --- |
| Corrected [2025/286](https://eprint.iacr.org/2025/286), revision2026-10-01 | Ring arithmetic, nondeterministic switch/rescale decompositions and a corrected auxiliary-prime lookup/integer-consistency protocol. General PIOP is a real comparison; its particular proof-friendly CKKS evaluator is a different native graph. | Section4.3 and complete pages7/20/21/26/27/32 inspected. Remark4.12 states the earlier CRT-alignment flaw and correction. Remark6.1 explicitly says old application range estimates were not updated to the corrected protocol. Preserve both downloaded versions; do not use old estimates as a complete corrected baseline. |
| [GlueLUT2026/494](https://eprint.iacr.org/2026/494), revision2026-09-30 | Existing cross-modulus consistency plus auxiliary-field lookup;4Sq/Fold tradeoffs, integer/range and PCS requirements must all be paid. | Complete pages17/21/24/25 inspected. Theorem6 needs `p_aux>max(Q,2^(mu+1)*floor(Q/2)*floor(p_min/2)^2)`. Native terminal P32 fails this premise. The selected ell can satisfy that numeric bound for n=16,384 in the inspected bound; n=65,536 fails. This is a numeric premise
check, not a complete protocol adaptation or arbitrary scaled-workload claim. Root generation and proof commitments are not free. Its Section7 prototype times exclude commitments and PCS opening verification.
No author prototype reproduced. |
| [Batch, Pack, and Prove official FHE.org2026 slides](https://fhe.org/conferences/conference-2026/resources/slides/1440_Guimaraes.pdf) | Existing virtual oracle packing, BatchFold and SparsePack; proof-friendly almost-splitting rings allow extension-field challenges/isomorphism. | Complete slides34/42/44/47/53/59/61/63/70/75 inspected. These make packing, batching and sparse commitments mandatory controls. Talk slides are not the full CCC+26 paper/proof or a same-contract benchmark. Full paper URL was not found in the bounded search. |
| Earlier2024/032,2024/1764 and current2025/719 archive | Double-CRT/shared switch witnesses/delayed operations; proof-friendly ring verification; small-prime sumcheck/lookup commitments. | Earlier scoped readings retained. Different arithmetic/security/graph premises cannot be silently transferred to native Q120/P32. No complete native adaptation or cost claim is supplied here. |

Corrected2025/286 Theorem4.11 gives error
`(m/theta)^kappa + (ell_star-m)/|S| + (ell_star-m)/p_aux + delta_field`.
The latter terms have no kappa multiplier. Setting only the first term to
2^-128 is insufficient for a complete128-bit claim over fully split roughly
60-bit components; repetition, commitment and attempt/lifetime errors require
separate accounting. This is an applicability qualification, not an attack
allegation against the corrected paper. The author's almost-splitting
extension-field evaluator and unchanged native fully splitting primes must
remain distinct.

## Archive and bounded return

New PDF/text pairs and exact acquisition/source hashes are outside Git at
`../research-data/native-proof-interface-20261003/primary`, with rendered-page
and reading receipts. The77 earlier source entries and archives stay unchanged.
The current2025/286 version is appended under a distinct revision ID. Initial
sandbox DNS failure and one corrected404 scalar-source path are retained as
acquisition history; authorized retries succeeded. No imported HE code was
added. The homemade BFV/BGV/Paillier/native/CUDA backends remain intact.

Component1 passes the bounded **interface applicability** prerequisite for
scalar R1CS, with all backend/security costs still unknown. Return to R6:
execute component2 on the frozen E106 fixture, compare baseline and strongest
shared compiler, and stop any literal novelty claim if both receive the same
representation. None of the broad publication or production gates passes.
