# Closest work after measurement revalidation

2026-10-02. Read this with the [execution plan](contribution-plan-20261002.md)
and [canonical entry point](publication-research-plan.md). Evidence baseline:
`f1b755254cfe148868f43ce9df0113650500c528`, checkpoint
`checkpoint/measurement-revalidation-2026-10-01`. This is a literature and
planning review, not a new benchmark, protocol, security proof or novelty claim.

## What changed in this review

The strongest additional comparator is **Maverick**, including its private-matrix
extension, rather than only its public-model headline. Its presence makes a
generic “private and verified matrix–vector search” claim insufficient. New
correlation-function work also explicitly connects to EMVP post-processing.
Non-comparison top-k and updatable matrix lookups are established research
directions. These findings sharpen the proposed differences below; they do not
establish that the remaining differences are original.

The [source registry](publication-literature-sources.json) preserves its existing
32 PDF identities and adds eight primary PDFs and extracted-text hashes in
`../research-data/literature-post-revalidation-20261002`. The two retrieval
receipts retain the initial sandbox DNS failures and successful retry. Targeted
construction, threat-model and limitation reading is recorded per source. No
new author artifact was executed. Prior artifact reproductions retain their
original scope; author timings are not measurements of our system.

Searches covered fixed-matrix correlations, PCGs/PCFs, private delegated linear
algebra, structured verification, encrypted selection and authenticated updates.
Citation following included Maverick's structured-verification predecessor,
the PCF application to EMVP, and counting-sort/CKKS selection controls. This is
a bounded closest-work review, not an exhaustive novelty search or proof audit.

## Comparison contract

The main functionality remains exact Hamming scores and stable IDs over an
owner-private index, with private adaptive queries and observable rejection.
One compute server may be malicious. The owner authorizes enrollment and may
retain all plaintext. Returning a top-3 subset, trusting an enclave, exposing
queries/candidates, or adding non-colluding parties creates a separate mode.

Every comparison needs ownership, output semantics, leakage, corruption model,
setup authority, fields/parameters, freshness/reuse, release order, retained
state, and full lifecycle costs. “Same dataset” is not enough. A plaintext
server-matrix protocol can sometimes act on our **public ciphertext operator**;
its conversion costs must be analyzed, not dismissed or silently omitted.

## Construction competitors

| Work and reviewed source | Existing capability and comparison boundary | Consequence / local reproduction |
|---|---|---|
| **Maverick**, [v1](https://arxiv.org/html/2609.10264v1), §§4–6, Appendix C/D | Encodes an output before sparse verification, with preprocessed `Q=G_y^T M`. Privacy uses precomputed `P=M G_x`; Appendix C adds a trapdoored mask to hide M. Public state can be large. Its application can defer verification. | Mandatory E82/E83 control, including private M. Test our thin/block matrices, paid state/acquisition, and verification before private release. General sparse coded checks, trapdoored masking and their composition are already supplied. No local artifact execution. |
| **EMVP**, [2025/858](https://eprint.iacr.org/2025/858.pdf), §§2.1,4.1,7.4, Appendix F | Secret dual codes hide both matrix and query; its correction has an additive-HE/secure-post-processing option. Field and code parameters matter. | Compare the strongest compressed correction, not only the larger raw reply. Original author and unified-artifact modes were partially reproduced; our extra gate is a separate adaptation. |
| **Recursive delegated algebra / BNTM**, [2502.13060v3](https://arxiv.org/html/2502.13060v3), Protocol 3, §7, Appendix A | Recursive trapdoors change client work/state; the audit-based online correctness contract differs from checking every answer. | Full recursive mode remains an implementation gap. The simple unified-artifact mode is insufficient as the only baseline. |
| **Trapdoored-matrix algorithms**, [2502.13065v2](https://arxiv.org/abs/2502.13065v2), §3 | Structured noisy/recursive matrices enable fast private products. | Low-rank-plus-noise is a known ingredient. E74's stopped public-code recipe neither reproduces nor refutes this construction. |
| **vReinsPIRe**, [2026/1934](https://eprint.iacr.org/2026/1934.pdf), §4/Algorithm 4 | Reusable verified linear responses with packing, hints and auxiliary material; honest-digest experiments and malicious-registration theorem have different premises. | Pay the full outer field, H/H-prime/Z and finalization. 59 author tests and a bounded native PIR pilot were reproduced; no matched encrypted-Hamming adapter. |
| **Small-state vLHE/vPIR**, [2025/1714](https://eprint.iacr.org/2025/1714.pdf), Figure 5/§3 | Trades retained hint for evaluated encrypted correction, using a specific ephemeral-key lifecycle. | Required small-client-state control. Artifact inspected previously, not run; no generic permission to decrypt arbitrary replies follows. |
| **VeriSimplePIR**, [USENIX paper](https://www.usenix.org/system/files/sec24summer-prepub-480-de-castro.pdf), §4/Appendix B | Bounded extraction and reusable verification with explicit failure behavior. | Reuse, retirement and admissible norms need the actual theorem. Targeted reading only. |
| **Dumas–Zucca**, [1704.02768v1](https://arxiv.org/abs/1704.02768v1), §§3–5/Appendix B | Public verification designed to preserve sparse/structured matvec costs; uses cryptographic checking machinery. | “Exploit a structured matrix to verify cheaply” is not new. Compare its complete cryptographic costs before an E83 claim. Newly pinned; not executed. |
| **Slalom**, [1806.03287v2](https://arxiv.org/abs/1806.03287v2), §§3.2–3.3 | Trusted masks and secret linear checking in an enclave-assisted outsourcing design. | Our owner factory/TEE is a deployment control; moving work there is not its elimination. No matched local reproduction. |

For Maverick specifically, the freshness of its verification challenge and
the storage/access cost of its public preprocessing deserve separate treatment
from our persistent hidden checker. Its Appendix C is an existing private-M
construction, not an extension we can claim. The proposed E83 question concerns
**our operator's compact representation through the complete checker**, with
ordinary authenticated access as a paid control. This is an inference about
where to investigate, not a gap proved absent from the paper.

## Correlations and output conversion

| Work and reviewed source | Existing capability / restriction | Required distinction |
|---|---|---|
| **Ring-LPN PCGs**, [2022/1035](https://eprint.iacr.org/2022/1035.pdf), §7.4 | Structured OLE, authenticated triples and matrix-product correlations. | Program the actual fixed private M and identify each recipient's shares. Random triples alone left E69's dense correction. |
| **Any-field PCGs**, [2025/169](https://eprint.iacr.org/2025/169.pdf), §§7–9 | Programmable correlations over finite fields, including authenticated and circuit-dependent uses. | Price dimensions, small-field embedding, setup and active checks. Its revised parameter discussion is not a blanket endorsement of our small blocks. |
| **Ring-LWR PCFs**, [2025/1637](https://eprint.iacr.org/2025/1637.pdf), §§5–7/Appendix A,C | Reusable correlation evaluation uses threshold BFV, pseudo-ciphertext bootstrapping and shared output conversion. Authentication adds encrypted MAC evaluation; decryption-to-shares has a noise premise. | E82 must price bootstrap/rounding/keys and fixed-M programming. A public random seed is not fresh ordinary BFV encryption. Generic circuit expressibility does not establish efficiency. Newly pinned; not executed. |
| **Secret-replication PCFs**, [ITC 2026](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.ITC.2026.7), §§4.2–4.3,5–6 | Symmetric-cryptography correlations for small scalar domains; authenticated scalar-vector variants and an EMVP application. Cost grows with scalar-domain and party count. | Composing a PCF with EMVP is already discussed. Small query bits do not make full-field masks or MAC keys small. The general-projection question in §6 is a possible research lead, not a solved adapter. Newly pinned; not executed. |
| **Rate-1 HE**, [2019/720](https://eprint.iacr.org/2019/720.pdf), §4; **ZipPIR**, [2303.09043v2](https://arxiv.org/abs/2303.09043v2), §§3–4 | Linear-decryption structure enables terminal compression with extra keys/operations and decoding premises. | Compare a complete compressor and malicious release boundary; extraction, key switching and short serialization are established components. No matched local adapter. |
| **HELIOPOLIS**, [2023/1949](https://eprint.iacr.org/2023/1949.pdf), §3.1/construction | Verification and compressed HE outputs under a specified verifier-privacy game. | Its excluded feedback oracles differ from our target. Credit the construction; do not describe an out-of-model difference as a discovered vulnerability. No local execution. |

E82 has two distinct targets. A **token adapter** must provide the existing
fresh-mask/fresh-encryption/full-Q provenance interface. A **direct alternative
backend** may return authenticated field outputs without manufacturing a BGV
token at all. Both implement the same search functionality only after complete
privacy, exactness and feedback arguments. This distinction avoids imposing an
unnecessary HE conversion on every non-HE candidate.

## Computation proofs, search and updates

| Work / reviewed source | What it already occupies | Matched comparison / reproduction gap |
|---|---|---|
| **Verifiable FHE**, [2301.07041v2](https://arxiv.org/html/2301.07041v2), §§III–IV | Reaction-oracle threat and checking authorized computation/input admissibility before release. | Our regression and generic verify-before-decrypt rule are supporting evidence, not new discoveries. |
| **Lattice-SNARK vFHE**, [2024/032](https://eprint.iacr.org/2024/032.pdf), §§3,5/Appendix A.2 | Double-CRT maintenance proofs and switch-scheduling optimizations. | E78 must outperform a complete ring-aware relation, not scalar arithmetic or a weak schedule. Targeted reading; not run. |
| **Approximate-HE verification**, [2025/286](https://eprint.iacr.org/2025/286.pdf), §§3.4,4–6 | Ring/range proofs and relaxed maintenance relations, with BGV relevance noted. | E81 needs a new exact-bound consequence plus measured prover benefit; simply porting relaxed traces is insufficient. |
| **HasteBoots**, [USENIX 2026](https://www.usenix.org/system/files/usenixsecurity26-liu-fengrun.pdf), §§3–6; **ring public vFHE**, [2024/1764](https://eprint.iacr.org/2024/1764.pdf), §§2,4–5 | Batched ring arithmetic and specialized proof relations. | Proof batching, ring commitments and digit/range checks are strong controls. Neither artifact was executed here. |
| **BioZKFHE**, [2607.22065v1](https://arxiv.org/html/2607.22065v1), §§III,V,VII/Supplement V | Packed BGV biometric scores and decomposed verification with committee-mediated opening and release. | Closest application/integrity comparator. Align exact binary semantics, complete block coverage, proof scope and committee cost. SEAL author prototype not locally reproduced. |
| **HERS**, [2003.12197v3](https://arxiv.org/abs/2003.12197v3); **practical biometric lookup search**, [publisher PDF](https://ris.utwente.nl/ws/portalfiles/portal/499572606/Practical_Biometric_Search_under_Encryption_Meeting_the_NIST_Runtime_Requirement_without_Loss_of_Accuracy.pdf) | Encrypted representation/packing and lookup-based matching with specified utility/comparator assumptions. | Do not claim uniqueness from compression or few multiplications. Exact Hamming, integrity and index/query disclosure need adapters. |
| **SANNS**, [paper](https://www.microsoft.com/en-us/research/wp-content/uploads/2019/04/SANNS-Scaling-Up-Secure-Approximate.pdf), §§III–IV; **Tiptoe**, [2023/1438](https://eprint.iacr.org/2023/1438.pdf), §§2–4 | Secure selection/approximate private retrieval, with different corpus ownership and output contracts. | Useful scale/selection controls. Approximate candidate discovery is not exact omitted-row coverage. |
| **RevoLUT / Blind Counting Sort**, [PoPETs 2025](https://petsymposium.org/popets/2025/popets-2025-0093.pdf), §§4–5/Appendix B | TFHE LUT-based counting, key-value top-k and private classification under an honest-but-curious server model. | Mandatory E84 primitive baseline. Histogram/radix selection and preserving attached values are not new; charge encrypted-index and integrity adaptation. Artifact available, not executed here. |
| **CKKS ranking**, [USENIX 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/mazzone); **NOMOS**, [2026/2262](https://eprint.iacr.org/2026/2262.pdf), §§3–5 | Parallel approximate ranking; NOMOS targets candidate-set top-k and an owner-side clustered mode. Its §3.2 excludes malicious integrity. | Compare approximate and exact settings separately; stable ties and full coverage remain our obligations. NOMOS newly pinned after browser access failed; no execution. |
| **SophOMR**, [USENIX 2026](https://www.usenix.org/conference/usenixsecurity26/presentation/lee-keewoo), §4 | SIMD-aware compression once a bounded sparse set is identified. | Required output-compaction control. The selection predicate, overflow and coverage are not supplied free. |
| **Fhelipe**, [PLDI 2024](https://people.csail.mit.edu/devadas/pubs/pldi24_fhelipe.pdf); **Porcupine**, [PLDI 2021](https://cs.stanford.edu/~trippel/pubs/porcupine-pldi-21.pdf) | Packing/layout optimization and synthesis. | Our static/causal planner negatives remain stopped. A larger search algorithm is not the next contribution. |
| **cFHE**, [2026/845](https://eprint.iacr.org/2026/845.pdf); **MOSAIC**, [2607.29221v2](https://arxiv.org/abs/2607.29221v2) | Approximate factorization/precision and masked private linear computation. | Approximate scores need an explicit certified-exact refinement or separate utility contract; no matched exact service reproduction. |
| **Single-pass preprocessing PIR**, [2024/303](https://eprint.iacr.org/2024/303.pdf), §§5–6 | Session/preprocessing and update tradeoffs. | Base-plus-delta and amortization alone are not original. |
| **Authenticated incremental PIR**, [2026/1077](https://eprint.iacr.org/2026/1077.pdf), §§2–4/§6 | Owner-digest authentication with incremental state/digest maintenance; honest-digest scope is explicit. | Previously metadata-only; full PDF now obtained and targeted sections read. Different retrieval/decoder contract; not a long-lived-BGV-key wrapper or local benchmark. |
| **Rogue**, [2026/1890](https://eprint.iacr.org/2026/1890.pdf), introduction/§§2–4 | Updatable matrix lookups over committed data and a database application. | Authentication of selected rows does not prove a matrix product or omitted-candidate coverage. Mandatory control if E83 uses succinct row access or E84 indexed coverage. Newly pinned; not run. |
| **Unified private-search benchmark**, [2608.01192v1](https://arxiv.org/html/2608.01192v1), §§2–4/Appendix A | Cross-scheme client/server/communication comparisons with differing search modes. | Our harness and GPU comparisons are supporting artifacts. Partial unified reproduction exists; distinguish native, adapted and projected measurements. |
| **Company Paillier work**, [2609.21364](https://arxiv.org/abs/2609.21364) | Batched encrypted binary Hamming computation. | Cite as prior company work. CPU/GPU/lookup/hybrid controls remain; BFV/BGV improvements need their own contribution. |

## Proposed novelty boundaries and decisive competitors

| Candidate | Already known / insufficient claim | Additional result to try to earn |
|---|---|---|
| E82 fixed-private-M correlations | Masked products, noisy secret codes, programmable/random triples, compressed EMVP and their generic composition | A specified fixed-function adapter or direct protocol that avoids the dense correction **for the actual thin/block operator**, with paid authentication, refresh and state. Identify a concrete distributional or algebraic step missing from the strongest controls. |
| E83 code and operator structure | Encoded sparse checks, structured matvec verification, ordinary authenticated row fetches, generic succinct openings | A code/representation whose complete authenticated check preserves the encrypted operator's compact generators and has a proved error-detection bound, reducing total verifier preparation/state without paying it per query elsewhere. |
| E84 exact top-3 | Counting/radix sort, tournament selection, OMR compression, proving a supplied candidate | A cheaper **complete** score-to-winner/coverage relation, possibly sharing exact carry/conversion work across packed scores. A top-3 packet alone supplies none of this. |

The nearest artifact to run depends on the surviving mechanism. Begin with
contract and operation-count controls for the **two** closest constructions,
then reproduce those at relevant geometry. Do not postpone falsifying our idea
until every paper in this table has a local implementation. An unavailable
artifact stays an open comparison, never a favorable invented timing point.

## Connection to the revalidated results

The [measurement report](measurement-revalidation-20261001.md) and
[frozen final synthesis](../../../research-data/revalidation-20261001/analysis-final-followups-04.md)
remain authoritative. Their strongest controls support four decisions:

- Preserve the native BFV/BGV/CUDA work. The compute and payload gains are real
  within their measured scopes; they do not establish a new protocol theorem.
- Optimize the complete cost. The Paillier lookup hybrid changes the local BFV
  latency ranking; E27's small complete-GPU ordering is unresolved.
- Keep preparation, verification state and acquisition in the objective.
  NumPy factory controls and allowed caches defeat several earlier proposals.
- Keep negative outcomes and conditional profiles. No refreshed timing removes
  an unproved security premise or makes old and new workloads comparable.

No reviewed source proves that our next ideas cannot work. Conversely, this
review has not found an established unoccupied claim. The next plan therefore
specifies mechanisms and falsifiers rather than promising originality.
