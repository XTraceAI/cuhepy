# Post-execution closest-work return

The targeted registry now contains 102 pinned PDF/text pairs; all earlier101
source entries are unchanged. The additional [KeyMemRT](https://arxiv.org/abs/2601.18445v1)
read covers typed evaluation keys and shared lifetimes/hoisting/scheduling,
with scope/hashes in the registry. No artifact or performance reproduction is
claimed. The [actual operator comparison](operator-state-discriminator-20261003.md)
finds non-additivity but the equally specialized generic compiler has every same
choice; the [update comparison](operator-incremental-state-20261003.md) obtains
the same affine state as the generic delta control. Thus neither literal H1 nor
literal H2 establishes an original-main mechanism. Complete native correctness
is a retained engineering result. The [claim/architecture return](native-verification-selection-20261003.md)
records conditional skips and future proof/deployment obligations.

The initial planning comparison below is preserved; its source counts and
candidate language describe that earlier review, not current acceptance.

---

# Closest work for the complete-system blueprint

2026-10-03. Read with the [blueprint](system-research-blueprint-20261003.md)
and [evidence review](research-evidence-review-20261003.md).
This is a targeted primary-source reassessment, not exhaustive novelty clearance
or a reproduction of every author artifact. The existing 100 paper/text pairs
are retained; one incremental-PCP paper is added. Versions, hashes and reading
scope are in the [registry](publication-literature-sources.json) and
[new reading record](system-blueprint-literature-review-20261003.json).
Old source entries and experiment conclusions are not overwritten.

## 1. What the comparison changes

The closest baseline is more specific than “a TEE reruns the server.”
[Verifiable FHE](https://arxiv.org/html/2301.07041v2), Section 5.2 and
Appendix D, already proposes untrusted acceleration of FHE tensor products with
randomized ring equality checks and discusses batching. The complete rendered
Appendix D page was checked in this review. Its implementation is
[FHE-in-TEE](https://github.com/zkFHE/FHE-in-TEE); the current README describes
`ecall_VerifyMult`, an Open Enclave/SEAL setup and a closed-source `polytools`
dependency. We have not reproduced it. That dependency is an artifact limitation,
not evidence of a performance win for our code.

Consequently, neither using a TEE with FHE nor offloading products and checking
them randomly is our contribution. The candidate difference is an exact,
matrix-free compilation of the **whole maintained BGV graph**, including shared
canonical integer boundaries, operator-state cost and owner updates. Existing
ring proof systems already handle substantial ciphertext maintenance; we cannot
claim that these operations have never been verified.

## 2. Integrity and protected computation: direct controls

| Primary work and reviewed scope | What is already known | Consequence for our candidate / comparison obligation |
|---|---|---|
| [Slalom](https://arxiv.org/abs/1806.03287v2), §3.2–3.3, previously rendered relevant pages | Trusted preprocessing and randomized verification of linear work on an untrusted accelerator. | Give its specialization to our public ciphertext graph shared adjoints, batching, packing and immutable context caching. “Avoid recomputation with a random projection” is already contained. |
| [vFHE / FHE-in-TEE](https://arxiv.org/html/2301.07041v2), §5.2 and Appendix D; original artifact README refreshed | FHE integrity analysis, a malicious-server notion and a concrete outsourced-tensoring control. | Align the full graph and challenge/error budget. Our new claim must extend beyond this known product delegation; no cross-paper speed ratio from different circuits. |
| [CHEX-MIX](https://eprint.iacr.org/2021/1603), retained system/model reading | HE and protected execution can be combined for private inference. | The hybrid trust architecture and moving selected operations into a TEE are prior art. Compare precisely which secrets each trusted component holds. |
| [Maverick](https://arxiv.org/abs/2609.10264v1), retained delegation/model-private appendix passages | Private/verifiable matrix-vector delegation with coded structure and paid correction work. | Fixed-operator preprocessing and its storage/correction costs are strong controls. Different inference/output contracts are not direct exact-search timings. |
| [Structured matrix-vector verification](https://arxiv.org/abs/1704.02768v1), retained §§2–5 and private-check discussion | Verification can exploit sparse or structured operators rather than treat them as dense matrices. | Count normalized operators and their adjoints; compare against a structured generic implementation. A dense control would manufacture a win. |
| [DataSeal](https://arxiv.org/abs/2410.15215v1), retained algorithms and decryption/check order | Algebraic checking information accompanies encrypted computation. | Distinguish result-integrity checking from admission before a long-lived HE secret is used. Do not assert a newly reproduced attack or malicious-server equivalence from this reading alone. |

H1's bilinear challenge and first-false-accept analysis are supporting known
tools. Reusing a hidden vector, grouping equal operators or proving an ordinary
union bound is not a prior-separated mechanism. The unproved question is whether
the exact native graph has a compact verification representation **after** the
strongest such specialization, with a useful complete resource tradeoff.

## 3. Public and designated-verifier proofs

| Primary work and scope | Relevant capability | What must be aligned before claiming an advantage |
|---|---|---|
| [Verifiable FHE via lattice-based SNARKs](https://eprint.iacr.org/2024/032), retained double-CRT and maintenance reading | Ring-aware proof design and scheduling of HE operations. | Include the same rotations, key switching, canonical conversions and terminal binding. Deferred maintenance is not new by itself. |
| [Verifiable computation for approximate HE](https://eprint.iacr.org/2025/286), current corrected revision | Ring arithmetic and maintenance/range relations; the publisher page explicitly reports a range-check correction. | Use the pinned corrected relation and its common-integer requirements. Old application estimates cannot be transferred unchanged to the corrected protocol or our BGV graph. |
| [GlueLUT](https://eprint.iacr.org/2026/494), current abstract refreshed; retained CMC and 4Sq/Fold reading | Explicit CRT alignment problem, common-integer consistency and lookup PIOPs over residue rings; folded checks are already present. | Per-prime membership is insufficient. The candidate's shared full-Q source is a canonical control, not a new solution to CRT alignment. A PIOP microbenchmark omitting commitments/openings is not a complete proof-service cost. |
| [BitZ](https://eprint.iacr.org/2026/2141), current page and retained mathematical sections | Packed binary commitments supporting claims in other rings, with bit/range machinery. | Our earlier Boolean/odd-ring boundary is not a new PCS. Implement or cost the complete adapter before using scalar Spartan as the sole proof baseline. Current page and cached version are separately recorded. |
| [LaBinius](https://eprint.iacr.org/2026/2103), retained commitment/extraction reading; [BrakingBase](https://eprint.iacr.org/2024/1825), retained preprocessing reading | Strong additional binary/lattice and field-flexible commitment controls. | Preserve their extraction, norm, commitment and setup premises. Existence of these controls is not proof that any automatically implements our full native relation. |
| [Batch, Pack, and Prove](https://fhe.org/conferences/conference-2026/resources/slides/1440_Guimaraes.pdf), official 2026 slides | Specialized CKKS verification direction with packing and batching. | Conference slides are retained as slides. No full-paper reproduction or complete-current-protocol comparison is claimed; locate the full artifact before a final novelty claim. |
| [HELIOPOLIS](https://eprint.iacr.org/2023/1949), retained IOP/terminal interface reading; [publicly verifiable FHE](https://eprint.iacr.org/2024/1764), retained ring interface | Native-ring verification and public-verification constructions are established research directions. | Match statement, allowed witness relation, decryption validity and full response. Our protocol uses trusted private verification, so advantages must disclose the stronger trust assumption. |
| [Spartan](https://eprint.iacr.org/2019/550), retained paper plus actual E109 backend | General-purpose proof control with an actual small local reproduction. | E109 proves only its declared adapter scope. The 135,200-byte toy proof and large materialized instance are neither a ring-proof lower bound nor a full service. E112's external witness-commitment integration is still missing. |
| [Phalanx](https://eprint.iacr.org/2025/302), current CCS revision | SNARK computation designed to work efficiently under FHE. | Separate proving a plaintext computation under encryption from certifying the exact native ciphertext evaluator and admission relation. Published timings on different proof circuits are not comparable to our bare server latency. |

A fair paper can report a complete TEE-assisted result without implementing every
proof system. It must identify the closest applicable proof control, document
the exact adapter and disclose unknown/unavailable measurements. An unavailable
adapter is never counted as an infinite cost or a win. Supporting proofs should
be migrated to a homemade implementation only when that is the selected research
path; importing an author backend as a labeled control remains useful.

## 4. Search, communication and output semantics

| Primary work / retained reading | Contract distinction and implication |
|---|---|
| [BioZKFHE](https://arxiv.org/html/2607.22065v1), §§III, V-C, VII-D/E; V-C refreshed here | Closest application-level control: encrypted biometric similarity, a snapshot-bound BGV trace, parallel proof decomposition and committee-mediated opening. Its current prototype includes the relinearization-dependent multiplication path, but explicitly excludes rotations, modulus switching and bootstrapping. Its contract requires every gallery block before decryption. Our candidate instead targets the homemade rotation/compact-response graph with a protected verifier and single-owner client. Different score encoding, committee trust, hardware and measured boundaries prevent a direct speedup claim. |
| [HERS](https://arxiv.org/abs/2003.12197v3), retained search/packing reading; [SANNS](https://www.microsoft.com/en-us/research/wp-content/uploads/2019/04/SANNS-Scaling-Up-Secure-Approximate.pdf), retained author paper | Encrypted representation search, batching and secure nearest-neighbor selection have substantial prior work. Separate exact distance evaluation from approximate search and secure top-k. Do not claim encrypted nearest-neighbor search itself is new. |
| [PANTHER](https://eprint.iacr.org/2024/1774), retained model/results reading; [Tiptoe](https://eprint.iacr.org/2023/1438), retained system reading | Private approximate retrieval/web-search systems provide stronger application baselines than only comparing HE schemes. Their leakage, approximation and retrieval contracts require separate rows. |
| [EMVP](https://eprint.iacr.org/2025/858), retained full version and partial original-author reproduction | Fixed-private-matrix delegation and preprocessing are direct controls for our earlier proposed fixed-operator mechanisms. Keep the original cached/key-only measurements and full-reply adapter scope; do not imply a reproduction of every paper mode. |
| [ZIP-PIR / smaller FHE responses](https://arxiv.org/abs/2303.09043v2), [SIMD-aware compression](https://arxiv.org/abs/2408.17063v1), retained papers | Response conversion, packing and high-rate communication are known goals and techniques. Compare query, reply, keys, encrypted index, preprocessing and decoder cost together. |
| [Spiral](https://eprint.iacr.org/2022/368), [YPIR](https://eprint.iacr.org/2024/270), retained papers | Efficient composed HE and amortized/silent preprocessing are established. Retrieval of a selected item is not our all-distance output relation. |
| [Private non-comparison sorting](https://petsymposium.org/popets/2025/popets-2025-0093.pdf), [NOMOS](https://eprint.iacr.org/2026/2262), retained selection readings | A future exact-top-three-only fork must pay selection, ties and coverage. It is not a free compression of the current protocol. Prior E84/E85 selection results already constrain this direction. |

The owner explicitly permits plaintext retention. Authenticated local
raw/compressed/mutable caches therefore belong in the main evaluation. This is
a problem-definition constraint from the user, not a conclusion imported from
a paper. Our small-data measurements favor caching; the encrypted service must
justify its own deployment regime rather than hide that result.

## 5. Compilation, updates and assurance

| Primary work / scope | Containment or useful comparison |
|---|---|
| [Fhelipe](https://people.csail.mit.edu/devadas/pubs/pldi24_fhelipe.pdf), [Porcupine](https://cs.stanford.edu/~trippel/pubs/porcupine-pldi-21.pdf), retained compiler papers | Packing/layout optimization and synthesis for vectorized HE are known. The intended new objective couples exact verification boundaries, retained state and updates to the evaluator. Establish that difference on an executable graph, not just a cost-function name. |
| [Libra](https://www.usenix.org/system/files/usenixsecurity26-bian-song.pdf), retained pinned paper | Cross-scheme/GPU scheduling is a strong compiler control. Merely adding CUDA, choosing a scheme or selecting a layout does not establish our main claim. No newly reproduced result is implied here. |
| [Fast homomorphic linear algebra with BLAS](https://arxiv.org/abs/2503.16080), retained v1/v2 | Matrix/gadget representations and GPU-friendly linear algebra precede our functional-key experiments. Preserve version differences and the E110 containment decision. |
| [Rogue](https://eprint.iacr.org/2026/1890), current abstract plus retained lookup/update reading | Updatable matrix commitments/lookup arguments directly constrain originality claims about authenticated changing data. Compare update, commitment and coverage obligations; it is not automatically an HE evaluator proof. |
| [Authenticated incremental PIR](https://eprint.iacr.org/2026/1077), current abstract plus retained definitions/update reading | Authentication and incremental retrieval already have a dedicated protocol literature. H2 must isolate a new dependency/state result beyond adding a version counter and linear delta. |
| [Incremental PCPs](https://eprint.iacr.org/2019/1407), new cached paper, abstract/intro scope only | Incrementally verifiable computation concerns maintaining proofs as a computation progresses. This is relevant background, but not the same problem as changing an encrypted database between queries. Do not present this paper as a measured dynamic-BGV implementation. |
| [Fherret](https://eprint.iacr.org/2025/700), [vCCA](https://eprint.iacr.org/2024/202), [exact-FHE CPAD attacks](https://eprint.iacr.org/2024/127), retained targeted security readings | Malicious-server/reaction security, correct-and-honest evaluation and appropriate verification notions already exist. Prove a composition for our implementation and leakage model; finding a reaction attack or verifying before decryption is not a new standalone contribution. |
| [BGV dependency analysis](https://arxiv.org/abs/2504.18597v3), [average-case critique](https://eprint.iacr.org/2025/1036), [HE implementation guidelines](https://eprint.iacr.org/2024/463), retained sources | Dependencies and concrete parameter/implementation obligations constrain aggressive reductions of modulus or noise margin. Empirical decryptions and ideal sampler toys cannot supply an approved lifetime failure bound. |
| [Random-polynomial universality](https://arxiv.org/abs/2201.06156v2), retained exact theorem reading | Prescribed multiple-root near-uniformity has direct prior work. The latest Fourier attempt reaches the same bound as its known control. Park this as supporting analysis unless a genuinely stronger, applicable lemma is produced. |

## 6. Required originality card before the full build

For the single selected transformation, write these six items on one page:

1. Exact input/output and trust contract, including updates and feedback.
2. Prior construction specialized with the same ring structure and preprocessing.
3. New algorithm/representation in equations or pseudocode, with its invariant.
4. A family or concrete matched instances where the resource difference persists.
5. What is proved, what is modeled and what is measured, including all paid costs.
6. A falsifier: an existing specialization reproduces the gain, a boundary is
   unchecked, or a mandatory cost removes the useful operating point.

The review supports **a focused research opportunity**, not a priority claim.
The complete paper can be an original systems result with known cryptography;
it need not invent a new primitive. It cannot use ordinary batching, an absent
artifact, an old uncorrected proof, or incomparable benchmark rows as novelty.
