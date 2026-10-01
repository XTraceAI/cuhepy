# Contribution reassessment and closest-work comparison

Execution update: the finite E80/E78/E81/E79 returns and next proposed E82
are in [the current selection review](construction-selection-20261001.md).
The recommendation below remains the initial planning record and closest-work
comparison, not the current next-task selection.

2026-10-01. Planning revision based on the protected E01–E77 evidence at
`0d12afd5e0cdb7171a282fdfccc53087caff816b`. This review runs no new performance
experiment and establishes no new security theorem. It supersedes the
*prioritization* in the [preceding selection review](publication-mechanism-review-20261001.md).
The [canonical plan](publication-research-plan.md),
[construction specifications](construction-hypotheses-20261001.md), and
[machine tasks](publication-work-packages.json) are the execution entry points.

## Recommendation

Build toward **verified evaluation of owner-encrypted linear operators whose
subring structure survives the entire protocol**. The first construction
question is whether a module representation can reduce registration and
verification costs without creating fresh owner work, enlarging the query, or
losing exact decoding. This is a selected research hypothesis, not a selected
paper result.

Keep a competing experiment in **proving the composed query-to-answer relation**,
using the E77 decomposition to avoid separately certifying unnecessary expanded
query objects. A third, smaller mathematical screen asks whether a bounded
family of noncanonical traces can preserve exact BGV outputs while simplifying
the proof. None of these phrases is itself a novelty claim. The specifications
identify the additional algorithm/theorem each would have to supply.

The intended contribution is not another general-purpose HE library, a list of
speedups, or merely adding a proof to search. It would be a restricted
construction with a useful resource improvement, an argument covering its
actual rejection behavior, and a homemade implementation. A strong systems
paper can use established cryptographic assumptions and primitives; it need not
invent an encryption scheme. Conversely, implementing a known composition alone
does not establish an original cryptography contribution.

The main deployment should use **owner-generated registration** first. The owner
already knows and authorizes the index and may prepare a digest/private checker
once. This is not a fresh per-query verifier duplicating server work. Fully
outsourced malicious registration is an optional stronger mode with extra
extraction and auxiliary-key obligations. Comparing these as though they were
the same contract would either overburden our baseline or overstate its security.

## What the evidence supports

The following observations have different scopes. Their ratios must not be
multiplied or plotted as equal-security alternatives without an adapter.

| Evidence | Observation | Consequence for the research direction |
|---|---|---|
| Historical homemade BFV/BGV CPU/CUDA, E26/E27 | The paired Mushroom CPU scope fell from about 639–640 to 206–214 ms; CUDA moved from about 53.5–54.3 to 50.9–51.1 ms | Useful company arithmetic exists. A large CPU algebra gain can leave a different GPU bottleneck. Preserve these implementations as controls |
| E29–E37, E43/E49 | Linear online evaluation is fast, but fresh trusted correlations are paid; stronger vectorized preparation reverses earlier factory/sparse-repair wins | Removing a factory operation is more interesting than moving it into an offline column |
| E51 and E75/E76 | Smaller global layouts improve the complete returning-client HE pilot, yet caches still win | Compare the best existing layout, not only a convenient large-ring layout |
| E61, 32,768 distinct Connect-4 rows | About 102.46 ms online plus 71.16 ms fresh preparation/check; 262,144 B reply. Local queries about 3 ms; compressed snapshot 247,388–305,261 B once | More rows alone do not establish an outsourcing advantage |
| E47/E68 | The encrypted operator has compact generators, but a demonstrated outer registration still has large H/H-prime objects; arbitrary gadget limbs do not commute with matrix multiplication | Structure must survive registration, packing, bounds and release, not just the multiplication kernel |
| E72/E73 | Fresh encrypted queries remove per-query owner answers; packing makes the tiny query 924 → 231 B. Dense private checks, expansion keys, larger Q and canonical client expansion remain | Query compression is known and not an end-to-end win here |
| E77 | The fixed-C1 affine identity shrinks toy receiver vectors 4,096 → 512 B, while the factory retains the original vectors; client plus factory is 4.7–7.8% slower | The small receiver exposes a useful interface, not a solved preparation problem |
| E65 and E74 | Strong simple layout controls recover the screened planner frontier; the one-level public-code mask loses to the actual small row matrices | Retire those specific mechanisms. Do not revive them with weaker baselines |

Evidence: [historical synthesis](research-synthesis-and-system-roadmap.md),
[global service](enrolled-global-service-control.md),
[Connect-4](connect4-encrypted-controls.md),
[registration](structured-registration-results.md),
[query packing](packed-query-expansion-control.md),
[seed-affine gate](seed-affine-gate-control.md),
[planner](support-planner-results.md), and
[programmed masks](programmed-mask-block-results.md).

The E76 raw provides the cleanest current service anchor:

| Same enrolled-client CPU harness | Mushroom: 7,996 × 126 bits | Semeion: 1,465 × 256 bits |
|---|---:|---:|
| Complete HE query wall, median | 46.794 ms | 15.778 ms |
| HE application traffic per query, including fresh answer upload and framing | 98,912 B | 25,275 B |
| Of that, ciphertext reply body | 65,536 B | 16,384 B |
| Retained owner raw-data local query, median | 0.887 ms | 0.182 ms |
| Downloaded zlib1 snapshot retained as raw data: subsequent local query | 0.710 ms | 0.146 ms |

Source: [immutable E76 raw](../../benchmarks/results/publication-enrolled-global-service-control-20261001.json).
Four queries per mode, first warmup and three timed; same-process persistent TCP,
not independent endpoint CPU/RSS or WAN measurements. Private bootstrap was
already pinned. N2048/Q32 are research profiles, not approved parameters. Nested
server/RPC stages are already inside query wall. These are useful negative
controls, not a universal impossibility of remote search.

## Closest constructions and the exact comparison required

The [source registry](publication-literature-sources.json) now pins **32 primary
PDFs**. Four were added for this revision. Reading is targeted, not a full proof
audit or an exhaustive novelty search. The earlier
[comparison](closest-work-comparison-20260930.md) and
[construction cards](protocol-baseline-cards.md) retain the fuller history.
“Not executed” below is an evaluation gap, never evidence of inferior speed.

| Work / reviewed location | What is already supplied | Required distinction or comparison | Local evidence |
|---|---|---|---|
| [VeriSimplePIR](https://www.usenix.org/system/files/sec24summer-prepub-480-de-castro.pdf), §§2.2, 4, Appendix B | Extractable bounded linear-function commitments, strict response checking, reusable preprocessing with refresh after rejection | A module proposal must redo the relevant binding/extraction and feedback argument; a ring-shaped matrix is not automatically covered. Owner-authorized data is a separate binding requirement | Newly pinned publisher prepublication PDF; targeted reading, no execution |
| [ReinsPIRe / vReinsPIRe](https://eprint.iacr.org/2026/1934.pdf), §4, Algorithm 4 | Efficient packing compilation and reusable verification of a linear response map | Compare **all** H/H-prime/Z, admissible norms, auxiliary encryption and client finalize costs. Applying it to our public ciphertext operator is a serious baseline | Pinned upstream 59 tests and bounded 4 MiB PIR pilot; not matched Hamming |
| [Verifiable PIR with Small Client Storage](https://eprint.iacr.org/2025/1714.pdf), §3, Figure 5 | Smaller retained verification state via auxiliary encrypted correction and its key lifecycle | Compare complete setup and per-query correction, not just private-state bytes; do not import its ephemeral-key argument into arbitrary decryption | Author artifact inspected, not run |
| [EMVP](https://eprint.iacr.org/2025/858.pdf), §§2.1, 4.1, 7.4 | Hidden-matrix products using secret dual codes; additive-HE compression of the correction is already proposed | Match matrix ownership, field/code parameters, state, and a malicious release gate. Uncompressed EMVP alone is not the strongest wire comparator | Original unchanged author artifact plus our exact adapter and separate gate; partial profiles |
| [Practical Secure Delegated Linear Algebra with Trapdoored Matrices](https://arxiv.org/abs/2502.13060v3), Protocol 3 / Appendix A | Recursive private setup and delegated linear algebra with auditing | Strongest recursive client-state tradeoff, setup proof and audit semantics must be compared; auditing is not automatically per-reply pre-key verification | Simpler unified-artifact modes run; strongest recursion not reproduced |
| [Verifiable Fully Homomorphic Encryption](https://arxiv.org/abs/2301.07041v2), §§III–IV | Malicious-server/reaction threat and verifying the authorized computation before release | Our own regression is valuable evidence, but neither this threat nor generic verify-before-decrypt is a new discovery | Targeted pinned reading; own attack regressions are separate |
| [Verifiable FHE via Lattice-based SNARKs](https://eprint.iacr.org/2024/032.pdf), §§3, 5, Appendix A.2 | Double-CRT proof decomposition including maintenance operations; a slot-addition rewrite delays key switches to reduce proof layers | A proposed “hoisted” expansion proof must improve the complete relation beyond this scheduling idea, with keys/state counted | Newly pinned; targeted construction and optimization reading; no execution |
| [Verifiable Computation for Approximate HE](https://eprint.iacr.org/2025/286.pdf), §§3.4, 4–6 | Ring arithmetic and range-check proofs; bounded relaxed maintenance relations; proof-friendly arithmetic | Exact BGV needs a universal exact-decoding argument, not approximate correctness. The paper itself notes potential BGV applicability; “adapt CKKS to BGV” is insufficient originality | Newly pinned; microbenchmarks and application estimates distinguished; no local execution |
| [HasteBoots](https://www.usenix.org/system/files/usenixsecurity26-liu-fengrun.pdf), §§3–6 | Batched quotient-ring arithmetic, coefficient-domain commitments, canonical integer range/decomposition checks and specialized TFHE proofs | A fused contraction must beat this style of batched proof, not only a scalar circuit/zkVM. Include PCS costs, proof bytes and verifier time | Newly pinned publisher paper; no local execution |
| [Fully Homomorphic Encryption with Efficient Public Verification](https://eprint.iacr.org/2024/1764.pdf), §§2, 4–5 | Ring R1CS including gadget/modulus operations; lattice commitments and a semi-active privacy target | Ring-native verification itself is occupied. Compare challenge domains, norms, commitment setup and actual key assumptions | Pinned targeted reading; no execution |
| [BioZKFHE](https://arxiv.org/html/2607.22065v1), §§III, V, VII and Supplement V | BGV biometric matching, coefficient value packing and decomposed proof batches with committee-governed opening/release | Compare both encrypted computation and integrity, while separating quantized biometric utility and committee trust from our owner/full-score contract. Committee removal alone is not novel | Pinned v1, refreshed targeted review; SEAL prototype is author-reported, not locally reproduced |
| [HELIOPOLIS](https://eprint.iacr.org/2023/1949.pdf), §3.1 / construction | Verifiable computation and compression over HE with a specified verifier-privacy game | Its exclusion of verification/subsequent-output feedback must remain explicit. A stronger feedback contract requires a different proof, not an accusation of an out-of-model attack | Pinned targeted reading; no execution |
| [ZipPIR](https://arxiv.org/abs/2303.09043v2), §§3–4; [rate-1 linear-decryption HE](https://eprint.iacr.org/2019/720.pdf), §4 | Terminal compression using decryption structure, with additional assumptions/keys | Price independent keys, field conversion, carries, server compression and malicious release. Known extraction or seeded serialization is not the new result | Pinned; no matched adapter |
| [SealPIR](https://eprint.iacr.org/2017/1142.pdf), §3.3 / Appendix A; [MulPIR](https://www.usenix.org/system/files/sec21-ali.pdf), §3 | Packed queries and expansion via automorphisms/key switches | E73 is a homemade control. Packing must pay keys, Q growth, expansion and original-query binding | E73 own control executed, not full author systems |
| [Ring-LPN PCGs](https://eprint.iacr.org/2022/1035.pdf); [any-field PCGs](https://eprint.iacr.org/2025/169.pdf); [trapdoored-matrix algorithms](https://arxiv.org/abs/2502.13065v2), §3 | Efficient structured correlations and algebraic algorithms under specific distributions | Our fixed private matrix, fresh HE distribution, small actual block widths and full-Q authentication must all survive conversion. E74 is not a refutation of these constructions | Pinned; ideal-share and public-code controls only |
| [SANNS](https://www.microsoft.com/en-us/research/wp-content/uploads/2019/04/SANNS-Scaling-Up-Secure-Approximate.pdf); [SophOMR](https://www.usenix.org/system/files/conference/usenixsecurity26/sec26_prepub_lee.pdf) | Encrypted nearest-neighbor selection and efficient sparse-result retrieval under their contracts | Exact top-3 needs stable ties and omitted-row coverage before output compression. Changed metric, approximation and trust get separate panels | Pinned; no matched complete selector |
| [Fhelipe](https://people.csail.mit.edu/devadas/pubs/pldi24_fhelipe.pdf); [Porcupine](https://cs.stanford.edu/~trippel/pubs/porcupine-pldi-21.pdf) | Automated HE layout and kernel optimization | A new planner needs a new protocol-dependent constraint and gains beyond simple local refinement; E65 does not supply that yet | Pinned, own stronger planner controls |
| [Unified private vector-search benchmark](https://arxiv.org/abs/2608.01192v1), §§2–4 / Appendix A | Cross-scheme client/server/communication evaluation, including GPU modes | A benchmark collection is already occupied. Our measurements must distinguish directly measured, projected, adapted and assumption-mismatched modes | Partial pinned unified artifact and exact adapters executed |

### Three changes caused by this review

**Canonical expansion certification becomes a control before it is a candidate.**
The newly read CIC 2024 and CRYPTO 2025 constructions already address maintenance
operations. E78 must identify a saving in the *composed, owner-bound relation*,
not claim novelty for digit constraints, proof parallelism or delaying switches.

**The outer-construction experiment becomes specific.** Instead of repeatedly
making D implicit while leaving the remaining objects dense, try a common
subring/module representation for the query, digest, check and finalization.
The proposed algebra, an owner-generated baseline transcript and dimension
ledger are in H1's specification. Structured query hiding changes the hardness
model; compressed finalization and optional malicious registration remain
discriminators. They are not details postponed until after benchmarking.

**Semantic trace flexibility is worth a bounded exact-arithmetic screen.**
It may be unnecessary to prove a unique ciphertext trace when every admitted
trace provably decodes to the same exact scores. This direction has clear prior
art in approximate HE. A useful new result would need a stronger exact,
adversarially chosen trace theorem and a concrete cost consequence specific to
our release/representation; otherwise retain it only as an adapter.

## The paper we should try to earn

One main result, with supporting measurements, is preferable to several weak
claims. Candidate structure:

1. A precisely defined operator/release class and a construction that avoids a
   demonstrated registration or per-query preparation cost.
2. A theorem identifying exactly when the representation remains closed under
   evaluation, verification and bounded decoding, plus a conditional privacy
   and integrity argument for the implemented transcript.
3. An end-to-end homemade system and evaluation showing where the new method
   improves the resource frontier, where it loses, and when authorized caching
   is preferable.

A restricted theorem plus a convincing implementation could support a paper;
no claim of acceptance or originality is made now. A useful implementation of
known methods remains a company deliverable even if the research candidate
fails. The existing engineering checkpoints should not depend on paper gates.

The first resource target is **total registration/private state or trusted work**,
with online latency and full communication constrained and reported. Do not
assert that remote search must beat a client that already holds all data. A
remote advantage for new clients, large datasets or changing data needs measured
evidence from those starting states. Caching stays on every relevant frontier;
small fixtures remain regression cases, not the only intended evaluation scale.

## Next decisions

Execute H1's closure/norm/cost card first, then the E78 composition card. Give
each a finite two-session construction screen before a proof-system port or
new native backend. If one survives, select its theorem and preregister the
evaluation. Run H3 only when a measured or counted canonical-range bottleneck
justifies it. The existing E79 bootstrap/resource work is independent and must
finish before claiming a deployment frontier. R4 correlations and R5 selection
remain alternatives, not obligations to complete every possible experiment.

No construction has yet passed the originality, usefulness and assurance gates.
This revision makes the next attempts more concrete rather than treating the
absence of a winner as a reason to tune another kernel.

Validation: [planning/source receipt](contribution-plan-validation-20261001.json).
It records documentation and retained-evidence checks, not new benchmark or
cryptographic test execution. Prior execution receipts remain unchanged.
