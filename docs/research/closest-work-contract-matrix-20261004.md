# Closest work for the selected exact-search system

2026-10-04. Original comparison evidence baseline:
`3ecef8eeb86bdc1e2c33ce568557debdea8949e9`.
The current implementation is `50840499716d353c76a0052417aaea546d2b95cd`;
the [paper-facing rereading receipt](paper-contribution-review-20261004.json)
records this later planning return separately from the original review.
Read with the [execution plan](system-contribution-execution-plan-20261004.md),
[claim cards](system-contribution-claim-cards-20261004.json),
[targeted reading receipt](system-contribution-review-20261004.json), and
[source registry](publication-literature-sources.json).
The [previous detailed comparison](closest-work-contribution-design-20261004.md)
and [broader system comparison](closest-work-system-blueprint-20261003.md)
retain the earlier inspected passages and version qualifications.

This review adds four cached primary papers, inspects ten rendered pages and
selected adjacent text, and checks the new revision metadata. It does not
reproduce a proof backend or audit all earlier papers. Priority clearance is
still open. Reading a paper is not evidence that its strongest applicable
specialization is slower or incapable of supporting our contract.

## The comparison contract

Our selected experiment uses an owner-hidden binary index and query,
exact all-distance Hamming output, complete ordered IDs and client top-k.
The owner may cache all plaintext. The server is malicious and may observe
public admission feedback. The proposed protected checker holds no HE
decryption secret, but correctness/freshness of its authorization is trusted.
This selected service is not deployed. The N16/N32 public native core and local
owner-authenticated factory pass their bounded gates. The later
[Q76.3a local lifecycle return](native-shared-query-lifecycle-20261004.md)
adds tested durable state under trusted non-rollback storage. Source-scale
correctness, remote freshness/private release and real attestation remain open.

There are three different comparison classes:

| Class | Purpose | Rule |
| --- | --- | --- |
| Same protected contract | Establish a useful complete-cost region. | Matched homemade replay, exact full admission and delegated-product/protected-suffix controls get identical optimizations and paid state/links. |
| Different cryptographic/trust contract | Establish what the construction already achieves and what assumption buys a performance difference. | Public/committee/blind proofs, protected plaintext search, approximate retrieval and multi-party protocols receive explicit scope rows; no cross-paper ratio. |
| Mechanism/compiler predecessor | Test originality of a proposed transformation or selection rule. | Specialize compatible known methods with the same ring, graph, origin and preprocessing before claiming a new mechanism. |

Unknown capabilities or costs are marked unknown. We have not inferred
absence from a prototype limitation or from the passages inspected here.

## Most direct predecessors

| Work, primary source and reading | Existing result relevant to us | Contract/adaptation obligation | Current conclusion |
| --- | --- | --- | --- |
| **Cascudo et al., corrected CRYPTO 2025 revision**, [2025/286](https://eprint.iacr.org/2025/286), retained §§3.4, 4.1/Remark4.1 and correction review | Ring-oriented verification, bounded alternative decomposition and noise-aware maintenance relaxation, including the key-switch route for automorphisms. | Apply the corrected common-integer/range relation to exact BGV and our terminal guard. Pay all larger-Q and transformation costs. Approximate CKKS bounds cannot be copied unchanged. | Spare noise, noncanonical gadget witnesses and verifying maintenance are known. Q75's algebraic claim is contained; a complete-cost result remains unmeasured. |
| **vFHE**, [Viand et al.](https://arxiv.org/html/2301.07041v2), retained malicious-server model, V-B and AppendixD; [author artifact](https://github.com/zkFHE/FHE-in-TEE) | Malicious-server FHE integrity analysis and TEE-assisted outsourced tensor products, including private polynomial-challenge equality checking. | Pay protected query expansion, maintenance and terminal/frame work. A deterministic product checker does not reproduce the randomized optimization: align its actual-limb, commitment, feedback and lifetime soundness assumptions before a broad comparison. The author artifact has not been reproduced in this review. | TEE plus HE and delegated product checks are known. A full maintained-graph system needs a measurable distinction beyond them. |
| **BioZKFHE**, [2607.22065v1](https://arxiv.org/html/2607.22065v1), retained §§IV, V-C, VII and concrete formulation | BGV similarity search, packing, blockwise proofs and committee-governed opening/release, with query/gallery context and full block coverage. | Preserve its quantized metric and trust/committee contract. Its stated prototype excludes rotations, modulus switching, bootstrapping and encrypted top-k; a complete adaptation to our expanded-query graph must supply and pay those boundaries. | Encrypted similarity plus verification, context binding and release are prior work. Our stronger protected-verifier assumption cannot be called cryptographic dominance. |
| **HERS**, [2003.12197v3](https://arxiv.org/abs/2003.12197v3), retained §3.2/AppendixB Algorithm7 | Transposed feature packing and encrypted matching with client score decryption/selection. | The exact binary adaptation receives one expanded query and delayed relinearization; optional lossy dimension reduction is excluded from an exact-distance control. | Feature-major layout is known; Q74 validates our implementation, not its originality. |
| **PEEV**, [2024 paper](https://doi.org/10.1109/ACCESS.2024.3424420), retained §§IV–VI and pinned [author source](https://github.com/TrustworthyComputing/PEEV-verifiableFHE/tree/2fb6bfb3de42acb92ddc373ec9829f1299377c02) | A program-to-BGV-to-ring-proof framework with verify-before-decrypt flow and small Hamming workloads. | Determine the complete maintenance/common-Q/terminal adapter for our circuit before performance comparison. Original artifact execution remains unknown; homemade arithmetic is not a scientific distinction by itself. | A verifiable HE compiler and encrypted Hamming computation are already established. |

**Additional direct comparator: [Laminate, corrected May2026 revision](https://eprint.iacr.org/2025/2285).**
It combines blind proofs with GKR, supports slot-independent and cross-slot
payloads, and trades proof noise against communication. The correction adds
ciphertext well-formedness checks to transcript packing. Remark3.5 explicitly
allows encrypted-input leakage when a prover sees its verdict. Section8 uses
operation counts and microbenchmarks; §9 leaves full implementation open.
Inspected PDF pages17,37,48,49,61,65; no backend reproduction.

For our comparison, the feedback contract must be aligned and the corrected
checks charged. A whole-trace ciphertext relation is distinct from a blind
proof of the plaintext computation. Neither distinction establishes novelty
by itself. We cannot import the paper's proof-size/runtime estimates into our
search table. The actual complete adapter cost remains unknown.

## Compiler and assurance predecessors added in this review

| Work / inspected primary scope | Existing contribution | What our proposed claim must add |
| --- | --- | --- |
| **CirC**, [2020/1586](https://eprint.iacr.org/2020/1586), introduction and rendered page2 | Shared compiler IR/infrastructure for constraints, proofs, SMT and optimization, including combining backend capabilities. | Specific native HE representation/origin/noise/frame effects and a demonstrated complete-cost consequence. A shared IR or certificate is not automatically new. |
| **Silph**, [2023/060](https://eprint.iacr.org/2023/060), introduction and §§3.1–3.3; rendered pages2/4 | Hybrid cryptographic protocol assignment, conversion-aware cost models, graph partitioning and optimization on CirC. Its implemented backend has a two-party semi-honest contract. | Our adversarial common-integer/maintenance correctness and protected-release constraints need their own proof and runtime. A hybrid planner, ILP/DP, partitioning or adding conversion costs is known. |
| **Casas et al., FHE compute-engine verification**, [author DAC2023 paper](https://web.cecs.pdx.edu/~zhenkun/pub/dac2023.pdf), introduction/§§II–III and rendered page2 | Compositional semantic-preserving transforms and formal accelerator/NTT verification; the paper distinguishes completed hardware/micro-sequencer verification from remaining stages. | An exact owner-input-to-release certificate and explicitly stated assurance for our implementation. Do not claim the first formally verified FHE compiler/accelerator from a scoped model proof. |

These are design/theory controls. Their published performance is not a direct
benchmark of our protected exact-search implementation.

## Known ingredients that every compatible control receives

| Ingredient | Primary predecessor / retained reading | Comparison requirement |
| --- | --- | --- |
| Predivided coefficient-query expansion | [SealPIR](https://eprint.iacr.org/2017/1142), pinned original client/server source; [MulPIR](https://www.usenix.org/system/files/sec21-ali.pdf), §§3.1–3.2 | Once-per-query expansion, seeded symmetric queries and compatible pre-normalization are credited. Bind all expanded branches to the original owner ciphertext. |
| Bounded gadget propagation | [2022/347](https://eprint.iacr.org/2022/347), §§4.1–4.2,6.2–6.3; [bivariate decomposition](https://eprint.iacr.org/2023/771) | Include every convolution cross term, common integer, norm/carry cost and extra state. Q74's sibling identity does not reopen E110. |
| Lazy maintenance, hoisting and scheduling | [BGV matrix triples](https://eprint.iacr.org/2023/593), §4.4; [Chen](https://arxiv.org/abs/1711.06319v1); [KeyMemRT](https://arxiv.org/abs/2601.18445v1) | One relinearization per feature sum, paired products, cached roots/maps and streamed lifetimes are granted equally. No schedule lower-bound claim from our implementation. |
| Structured randomized delegation | [Slalom](https://arxiv.org/abs/1806.03287v2), §§3.2–3.3 and retained structured-check controls | Use structured adjoints, batching and charged preprocessing rather than an artificially dense baseline; hidden-challenge lifetime and feedback assumptions are part of the protocol. |
| Layout/dataflow compilation | [Fhelipe](https://people.csail.mit.edu/devadas/pubs/pldi24_fhelipe.pdf), [CiFlow](https://arxiv.org/abs/2311.01598v4), retained readings | Grant layout, key-switch/dataflow optimization, common expressions and fusion. The planned verified-cost objective must have an executable consequence. |
| Ring/common-integer proofs | [lattice vFHE](https://eprint.iacr.org/2024/032), [GlueLUT](https://eprint.iacr.org/2026/494), retained maintenance/CRT alignment readings | A per-prime range check is not a shared integer. A scalar or product-only proof is not the only applicable proof control. Full commitments/openings/parser/frame obligations are paid. |
| Malicious evaluation and private reactions | [vCCA](https://eprint.iacr.org/2024/202), [Fherret](https://eprint.iacr.org/2025/700), [exact-FHE CPAD attacks](https://eprint.iacr.org/2024/127), retained readings | Verify-before-decrypt and reaction-security goals are established. An accepted ciphertext algebra trace still needs correct plaintext/noise guarantees and the actual leakage contract. |

The larger archive also retains SANNS/PANTHER/Tiptoe, EMVP/ReinsPIRe,
Spiral/YPIR, selection, authenticated-update and binary/ring proof controls.
Their retrieved-item/approximation/private-server-data/interaction contracts
remain distinct. We do not count all source records as newly reviewed proofs.

## What remains plausibly original, and how to disprove it

| Candidate result | Current evidence | Missing discriminator | Falsifier |
| --- | --- | --- | --- |
| A certificate/effect model for a complete exact native search plan | Small reference, native core and owner-authenticated factory bind all sources, limbs, outputs and frame; bounded trusted local lifecycle passes. Source scale and remote release remain unfinished. | An independently checked native specification spanning origin, representation, public bounds and release; applicable prior compiler comparison. | A free input, wrong frame or false semantic/noise implication; known certificate/compiler covers the same claimed design result. |
| A useful jointly selected verification/evaluation/state plan | Q75 contains real modeled tradeoffs; ordinary finite Pareto selection is known. | Same-backend complete measurements and held-out ablation showing a concrete decision/cost change under fixed budgets. | Equally specialized prior/replay gives the same paid frontier, or the difference is only a renamed objective. |
| A reproducible useful protected-search system | Strong earlier unverified BGV engineering; cache wins local returning queries. | Complete acquisition, protected admission, updates, real deployment and truthful trust/feedback scope. | Replay/cache removes all justified operating regimes, or the advantage requires hiding cost or assuming forbidden caching. |
| A security/assurance contribution suitable for formal analysis | Full common-Q/frame counterexamples and public-bound lessons are retained. | Actual conditional composition/mechanization and externally reviewed implementation boundary. | Raw algebraic integrity is presented as CCA security, or a theorem omits origin, noise, freshness or private feedback. |

This is a set of testable opportunities, not a declaration that we are first.
E101/E110/Q57/H1/Q59/H2 negative originality gates remain closed. Q74/Q75's
known-composition containment is preserved. A strong engineering artifact and
a main original paper are separate decisions.

## Executable closest-work obligations for the paper

The later targeted rereading sharpens the controls without adding papers or
rerunning their artifacts. The existing 114 registry records and PDF versions
are retained. The proposed distinction below is ours to demonstrate; an
unimplemented adaptation is unknown, not a slower competitor.

| Comparator | Strong specialization to credit | Concrete remaining task | What a successful comparison would mean |
| --- | --- | --- | --- |
| HERS + SealPIR/MulPIR + ordinary delayed maintenance | Feature-major index, one original-query expansion, seeded uploads and one relinearization per sum. | Use the identical paid graph for the known-composition alias. | Q75 already establishes algebraic containment. No new layout/expansion claim survives merely because our code is homemade. |
| vFHE / FHE-in-TEE | Offloaded products with protected maintenance and private randomized checking, not only a slower deterministic checker. | Q76.4 adaptation card: exact aggregate statement, actual-prime challenge law, committed operands, adaptive attempt budget, paid rounds/state and complete release. | A scoped full-cost difference could support a system finding. A copied product-checking technique cannot be the main new primitive. |
| Silph / CirC | Conversion-aware assignment, with values represented in multiple domains when that avoids conversions. | Give the generic planner the same legal choices, input effects, retained-state budgets, lifetimes and cost data as our selector. | Held-out selection benefit against evaluator-only policy is evidence of usefulness. Benefit absent against this stronger specialization closes the algorithmic claim. |
| Fhelipe / HEIR / KeyMemRT | Layout, noise management, relinearization placement and explicit key lifetimes. | Attribute these mechanisms; separately demonstrate the admission/release constraints and measured system finding. | A new cost name, delayed switch or streamed key is insufficient. Compiler differences require an executable consequence. |
| PEEV + corrected Cascudo ring/range methods | Program-to-HE-to-verification and maintenance/common-integer constraints. | Specify our source-origin/phase/frame effects and prove the complete invariant independently of the optimizer; do not infer absent capabilities from inspected examples. | A coherent assured artifact may be valuable, but certificate novelty is open until this comparison and external review. |
| BioZKFHE / Laminate | Bound inputs/coverage and encrypted similarity verification, or blind proofs with corrected packing checks. | Keep committee/public-verification and verdict-feedback assumptions separate; supply a paid coefficient-ring/maintenance adapter before timing. | Different trust, metric or feedback can explain costs. It cannot establish domination by our protected verifier. |
| Permitted owner cache | Compact authenticated backup, returning-device local search, mutable updates and background acquisition while a remote first query runs. | Charge acquisition/invalidation/overlap and grant both selectors the same horizon information. | Only surviving cold-device/resource regions justify outsourcing. Prohibiting cache or forcing HE-index acquisition is an invalid advantage. |

Silph's multiple-representation assignment is particularly relevant: a control
that forces every value into one domain can overpay conversion and manufacture
an apparent advantage for our planner. Its MPC threat model differs from ours;
that difference calls for a new correctness argument, not a claim that cost-aware
selection or representation duplication was invented here.

Likewise, vFHE's challenge variable combines **ciphertext components with
ring-valued coefficients**. It is not our rejected shortcut of checking one
physical NTT coordinate. Do not dismiss the strongest delegated-product
control using the counterexample to that different shortcut. The common-Q,
noise, maintenance and release obligations still have to be supplied.

The corrected Cascudo metadata inspected again reports the 2026-10-01 range
protocol correction. Laminate's retained May2026 text includes packing
well-formedness and its verdict-leakage qualification. These are the versions
to compare; the earlier PDFs remain archived for provenance.

## Before claiming a comparison with a blind/public proof system

Write one scoped adapter card before any new full proof build:

1. List the exact statement, output/decryption predicate and what server
   verdict/application feedback is permitted. Include owner snapshot/query,
   complete IDs/coverage and terminal conversion.
2. Specify field/slot semantics. Our current t=1031/N=16384 coefficient ring
   does not have 16,384 independent base-field slots. The public modular-order
   calculation gives order4096 modulo32768 and four irreducible factors.
   Identify a valid coefficient/extension-field adapter or a separately paid
   batching profile; do not use an assumed full-SIMD speed estimate.
3. Include corrected well-formedness/range checks, commitments, openings,
   preprocessing, extra HE depth/moduli and verifier work.
4. State artifact availability/version and the actual reproduced scope.
   Missing full execution remains unknown, not infinite cost.
5. If verdict privacy needs a wrapper or a public ciphertext-statement
   adapter, describe/prove and pay it. A trust change is a separate row.

This card is a design comparison within Q76/Q79, not an additional preliminary
encrypted experiment. It cannot license skipping a stronger known control.

## Archive and scope receipt

The registry retains all **110 previous source entries byte-equivalent** and
adds four PDF/text pairs, for **114 source records**, not 114 distinct newly
audited papers. New PDFs/text, primary revision metadata, ten rendered pages
and failed/successful retrieval receipts are under
`/home/pete/yavor-projects/xtrace-work/research-data/system-contribution-refresh-20261004`.
The main ePrint PDF downloads returned403; the IACR mirror supplied the PDFs,
with exact hashes and origin recorded. The compute-engine paper came from its
author's university page. No author code, HE experiment, timing panel or
parameter/security estimate was executed in this targeted review.
