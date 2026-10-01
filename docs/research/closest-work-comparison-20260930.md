# Closest work and the remaining research opportunity

For the current recommendation, use the
[2026-10-01 contribution reassessment](contribution-reassessment-20261001.md)
and [construction packets](construction-hypotheses-20261001.md). The material
below retains earlier comparisons and experiment-by-experiment supplements.
The new review adds four pinned proof/verification sources; no historical
measurement or source version is replaced.

Review date: 2026-09-30. Current evidence: `6207455`,
tag `checkpoint/publication-controls-2026-09-30`; original E01–E40 baseline:
`02e06c0`. This review informs the
[publication research plan](publication-research-plan.md); it does not report
new benchmarks, certify security, or establish that an idea is novel.

## Recommendation

Prioritize a construction that reduces **per-query trusted preparation while
preserving exact, safely verified release**, with structured outer evaluation
as the leading hypothesis. The current static and causal representation
optimizers did not survive stronger controls. A larger optimizer is conditional
on first finding useful protocol choices. The final supplement below is the
current construction-level comparison; earlier tables retain the reasoning
that led to E41–E65, not an accepted novelty claim.

The comparison has materially changed our next steps. General encrypted
matrix-vector protocols and recent verifiable linear homomorphic encryption
(vLHE) are closer than a comparison confined to Paillier, SEAL, or biometric
packing. Reproduce the strongest applicable competitors early. In particular,
a representation should be tested over more than one backend before claiming
that its benefits require BGV.

## Scope and reading discipline

The target is an owner-authorized client searching an owner-encrypted binary
index on one untrusted server, with exact Hamming scores and stable identifiers.
The current fast experimental path lets that client learn **all scores** and
requires trusted, fresh, consumable preprocessing. A server holding a plaintext
corpus, a protocol returning only top-k, approximate nearest neighbors, and
multiple non-colluding servers solve different problems.

We searched primary papers and author artifacts for encrypted matrix-vector
products, secret dual codes, private vector search, vLHE/vPIR, private linear
algebra, packing compilers, exact biometric search, and updatable preprocessing.
We followed especially relevant references into the matrix and verification
constructions. The linked sections below were read at the stated depth;
neither all proofs nor all related literature have been audited. “Not
established in the sections reviewed” is not evidence of absence elsewhere.

The [source registry](publication-literature-sources.json) retains the original
15 primary PDFs and now pins nine additional PDFs in a separate cache, plus
five previously recorded artifact revisions and additional web readings.
The EMVP full version is dated August 24, 2026, although its conference paper
is CCS 2025. Paper and artifact versions must be distinguished. No external
artifact was executed or timed in the initial review snapshot; the supplement
below supersedes that status. Paper-reported speedups are
deliberately not placed alongside our local timings as matched results.

## Closest protocol competitors

| Work / primary source | What it supplies; important contract | Consequence for our claim and comparison |
|---|---|---|
| **EMVP**, Benhamouda et al., CCS 2025; [full version 2025/858](https://eprint.iacr.org/2025/858.pdf), §§2.1, 4.1, 7.4 | Hides a matrix and repeated query vectors using secret dual codes and trapdoored pseudorandom matrices. The main construction uses an LSN variant; an LPN alternative has different costs. The client retains a short key. Its core response is an `m × s` matrix, not one field element per score. §4.1 already discusses additive-HE response compression and secure post-processing. | **Required competitor.** Generic encrypted matvec, reduced client storage, and composing code-based evaluation with HE output packing are already covered. Test raw and exact-factorized inputs, paying code dimensions, field widths, client reconstruction, and any added integrity layer. Do not assume small plaintext fields inherit the large-field concrete parameters. |
| **Practical Secure Delegated Linear Algebra with Trapdoored Matrices**, Braverman–Newman, [2502.13060v3](https://arxiv.org/html/2502.13060v3), §§2–7 | Masks both operands using LPN-based trapdoored matrices; arithmetic outputs are exact. Includes recursive preprocessing and Freivalds-style checks. §7.2 distinguishes privacy against a dishonest server from its online correctness/detection guarantee: detecting a fraction of dishonest calls using additional queries is not automatically authentication of every answer. | **Required competitor.** Generic masked outsourcing and checking are not new. Reproduce its intended parameters and detection policy, then separately price the stronger per-response, owner-epoch binding that our target requires. Do not import a field soundness formula into an arbitrary composite ring. |
| **ReinsPIRe / vReinsPIRe**, Akhavan Mahdavi et al., [2026/1934](https://eprint.iacr.org/2026/1934.pdf), §§2–4, Algorithm 4, Theorem 9 | Linear-query evaluation and verification using precomputed packing represented as matrix operations; the server has the plaintext database. The malicious-security statement uses key-dependent RLWE, SIS, and correctness for an admissible database class. Experimental parameters assume an honest digest, a narrower case; noise analysis identifies an independence heuristic. | **Required verification/circuit comparison.** Eliminating online polynomial work and retaining small verification state are known directions. Its server-input model differs from an owner-hidden index. Owner authenticity of the specific database epoch must also be supplied. Compare against both its stated experimental contract and the stronger theorem contract. |
| **Verifiable PIR with Small Client Storage**, Rathee–Lee–Popa, [2025/1714](https://eprint.iacr.org/2025/1714.pdf), §§1.2, 3.1–3.4 | vLHE with small persistent client state, reusable verification material, and consumable query-level preprocessing. Uses an extractable database commitment and handles selective-failure issues. Its carefully constrained verification of a decrypted auxiliary value relies on an ephemeral secret; it is not a generic permission to decrypt arbitrary server ciphertexts. | **Required proof comparison.** Small hints, one-use preprocessing, and hidden linear verification alone cannot be claimed as ours. Compare state including ephemeral material and the exact security game. Our present long-lived-key path keeps its pre-decryption gate; importing another protocol requires its complete assumptions and lifecycle. |
| **HintlessPIR / LinPIR**, [2023/1733](https://eprint.iacr.org/2023/1733.pdf), introduction and §2.5; [author artifact](https://github.com/google/hintless_pir) | Supports linear queries, not only one-hot retrieval, with server preprocessing that removes the client's large database hint. The server holds its database in plaintext. | Use as a strong changed-contract baseline and a source of packing/preprocessing controls. Do not dismiss PIR as irrelevant to dense similarity queries; do not relabel query privacy as encrypted-index privacy. |
| **Slalom**, Tramer–Boneh, [1806.03287v2](https://arxiv.org/html/1806.03287v2), §§3.2–3.3 and Appendix B | Trusted preprocessing, fresh masking, and secret linear checks accelerate outsourced neural-network computation. Its input/model disclosure and trusted-device boundary differ from ours. | Credit the preprocessing/checking ingredients. A TEE producing correlations is a useful implementation option, not a sufficient novelty claim. Count factory state, production rate, unused masks, and its compromise/collusion boundary. |

## Closest search, packing, and representation work

| Work / primary source | What it supplies; important contract | Consequence for our claim and comparison |
|---|---|---|
| **BioZKFHE**, [2607.22065v1](https://arxiv.org/html/2607.22065v1), §§III, V-C, VII-D/E | BGV similarity evaluation with a committed gallery snapshot, proof families, threshold opening, and a public verification pipeline. Complete search requires every gallery block exactly once. Its stated prototype proof scope excludes several operations outside its compiled trace. Reported structure footprints are not automatically serialized network bytes. | The closest application/integrity comparison suggested by Liwen. Compare ciphertext circuit, coverage, proof/setup/release costs, and quantized metric. Distinguish our private verifier and trusted owner preprocessing from its threshold/public-verification contract. Reproduce an artifact's actual proof mode before using performance claims. |
| **HERS**, Engelsma–Jain–Boddeti, [2003.12197v3](https://arxiv.org/abs/2003.12197v3), introduction and representation-compression discussion | Encrypted gallery/query search, packing, and learned representation compression with a measured accuracy tradeoff. | Data-dependent compression for HE search is established. Our possible difference is exact preservation of every enrolled binary score, plus a state/update-aware algorithm. Compare against compression-free packing and show that our exactness is not merely high retrieval recall. |
| **Practical Biometric Search under Encryption**, Bassit et al., [primary full paper](https://ris.utwente.nl/ws/portalfiles/portal/499572606/Practical_Biometric_Search_under_Encryption_Meeting_the_NIST_Runtime_Requirement_without_Loss_of_Accuracy.pdf), §§V–VI | Vertical/chunked organization and lookup-based comparisons, with dynamic databases and no loss relative to its cleartext comparator. The comparator uses quantized feature/score tables; the stated encryption discussion concerns honest-but-curious protection. | Zero homomorphic multiplications and fast encrypted search are not unique to our response columns. Align comparator semantics, probe encoding/disclosure, setup and integrity before comparison. Include lookup baselines; zero multiplication count alone says little about full cost. |
| **Tiptoe**, Henzinger et al., SOSP 2023, [2023/1438](https://eprint.iacr.org/2023/1438.pdf), §§2–4 | LHE-based private search over a server corpus, preprocessing and private cluster retrieval. Clustering trades search quality for communication. Query privacy covers malicious servers; result correctness is explicitly outside its guarantees. | Strong scale and communication reference with a different data/output contract. Use its full-scan linear core where applicable and show approximate clustered results separately. Count its query-dependent/offline traffic consistently. |
| **SANNS**, USENIX Security 2020, [primary full paper](https://www.microsoft.com/en-us/research/wp-content/uploads/2019/04/SANNS-Scaling-Up-Secure-Approximate.pdf), §§I, III-C, IV-B | Approximate Euclidean nearest-neighbor search using HE, garbled circuits and oblivious access. Coefficient dot products and secure selection have separate costs. | Strong competitor for a future output-only selection track. It is not a matched baseline for owner-encrypted exact full-score Hamming search. Merely using coefficient packing or a mixed arithmetic/Boolean protocol is established. |
| **A Unified Benchmark for Privacy-preserving Vector Search**, Kermarrec et al., [2608.01192v1](https://arxiv.org/html/2608.01192v1), §§2–4 and Appendix A; [artifact](https://github.com/sacs-epfl/secure-vector-search) | Already compares plaintext, SAP/DCPE, EMVP, BNTM and Tiptoe, including CPU/GPU behavior, client/server stages and communication. Much evaluation uses IVF/recall; routing and privacy differ by backend. Some large-scale numbers are projections and some parameter choices are explicitly heuristic. | A new harness is supporting evidence. Reuse its baseline lessons and pin its artifact, while reporting exact full-scan results separately. Its client bottlenecks and GPU residency costs make server-only speedups an especially weak contribution. No claimed reproduction here. |
| **Fhelipe**, PLDI 2024, [primary paper](https://people.csail.mit.edu/devadas/pubs/pldi24_fhelipe.pdf), §§2, 5.1–5.4 | Automatic tensor packing, compaction, layout conversion and analytic layout assignment with backtracking; additional parameter/schedule optimization. | Automatic layout selection is already a major contribution elsewhere. Our proposed search must change private algebraic representations and account for authentication/lifetime constraints, beyond choosing a layout for a fixed tensor program. Compare strong packing controls and state precisely what is outside its optimization domain. |
| **Porcupine**, PLDI 2021, [primary paper](https://cs.stanford.edu/~trippel/pubs/porcupine-pldi-21.pdf), §§3–4 | Synthesizes correct vectorized BFV kernels using a specification/sketch and noise/latency models, with SEAL code generation. | Program search, exhaustive tiny optima and noise-aware cost functions are established. A proposed DP or synthesizer is not novel merely because it is homemade. The new mathematical search space, guarantee, or protocol consequence must survive this comparison. |
| **Compressed FHE (cFHE)**, Schoinianakis–Sabzevari, [2026/845](https://eprint.iacr.org/2026/845.pdf), selected §§3.1, 4.1, 5.3, 7.4 | Couples low-rank matrix factor chains with CKKS precision/parameter selection. Its approximation and encryption error budgets are co-designed, including tree evaluation; experiments encrypt input matrices. | “Low rank plus smaller HE parameters” is already occupied. Our potential difference is exact finite-field semantics, CRT occupancy, complete verification and lifetime. Any approximate alternative must be compared at an explicit certified error or retrieval contract. |
| **MOSAIC**, [2607.29221v2](https://arxiv.org/html/2607.29221v2), abstract and §4.1 | Outsourced private linear computation using low-rank masks and noise, designed for approximate AI computation; residual error terms remain in the result. | A useful competing non-BGV direction, not an exact Hamming drop-in. First derive a conservative error/rounding or certified-refinement bound at justified parameters. Its published artifact revision predates v2; code/paper equivalence is unverified. |
| **Single Pass Client-Preprocessing PIR**, Lazzaretti–Papamanthou, [2024/303](https://eprint.iacr.org/2024/303.pdf), §§1, 5–6 | Session-aware preprocessing and inexpensive updates to client hints. Discusses existing hierarchical/waterfall update methods. This retrieval construction has a different database/trust/output model. | Cheap preprocessing, amortization and base-plus-delta updates are not novel by themselves. Our update experiment must identify a new interaction with private representation, authenticated correlations, and capacity boundaries. |

Additional leads, not fully reviewed constructions: [fast bounded-independence
functions and duals](https://arxiv.org/html/2606.07009v1) §5.2 is relevant to
EMVP code generation; [compressed oblivious encoding](https://arxiv.org/abs/2109.07708)
to output compaction after matches are known; [HECO](https://arxiv.org/abs/2202.01649)
to compiler baselines; [CIPHERMATCH](https://arxiv.org/abs/2503.08968)
to matching-specific packing. Before promoting any corresponding experiment
to a paper claim, read its full relevant construction and citation neighborhood.
Our [own Paillier paper](https://arxiv.org/abs/2609.21364) is prior company work,
not an independent external baseline or a new result of this review.

## What our evidence actually supports

The complete [E01–E40 ledger](research-synthesis-and-system-roadmap.md) remains
the source inventory. The most discriminating results are:

| Evidence | Supported inference | What it does not establish |
|---|---|---|
| E26/E27, [affine/CRT](affine-component-results.md) and [dyadic repair](dyadic-rank-results.md): Mushroom CPU local time roughly 639–640 → 206–214 ms; CUDA roughly 53.5–54.3 → 50.9–51.1 ms | Rank/padding transformations can remove expensive CPU work, while leaving GPU/client costs dominant. | A universal GPU speedup or a comparison with a different protocol's security/setup contract. |
| E27: a 64→65 rank transition doubles fixed-layout products and nearly doubles switches; complete repair rebuilds the epoch | Updates can change discrete packing costs abruptly. | A working incremental update algorithm; the existing repair is a full rebuild. |
| E29, [reply columns](crt-masked-query-results.md) | Fresh trusted correlations yield a fully linear public online circuit and whole-ciphertext checking. | Free preprocessing, reusable masks, malicious setup security, or novelty of masked matvec. |
| E30/E31, [sharing](shared-query-basis-results.md) and [hierarchy](hierarchical-query-basis-results.md): 69–71% less query body in E31 but only 0.4–0.5% less online traffic, with worse state/time | Query rank, encrypted-column count, correction degree and reply capacity are different objectives. | That minimizing any one is the right system objective. |
| E35, [field/geometry](adaptive-field-frontier-results.md): 20% smaller bodies with deterministic adaptive correctness | Separating private grouping from final CRT factors can change a real modulus boundary. | A second 20% gain on top of E32; independent parameter security; free frontier exploration (the full grid took about 42–48 s). |
| E37, [paired verifier study](verification-frontier-results.md): old GMP → native same-family check 3.31–4.61×; alternative known hash adds 1.24–1.34× | Most of the check gain is implementation. Complete CPU stage totals improve 1.58–1.76×. | A newly invented hash or an observed network latency/GPU speedup. |
| E37 selected-field profiles: 131,072 B response body; Mushroom 523/596 B query, Semeion 2,802 B | Reply occupancy now dominates query-body improvements. | Those are full transport sizes: framing, authenticated setup and one-use answer packets are additional. |
| E36/E38–E40: norm tightening crosses no byte boundary; smaller fields can lose CRT capacity; smaller rings can require more replies | Joint integer/resource thresholds deserve algorithmic treatment. | The modeled 8× Semeion body reduction at N=2,048 is an encrypted measurement or an approved parameter set. |
| E25/E27 full plaintext-cache controls answer small public workloads in milliseconds | Client memory/state is a decisive baseline, not a footnote. | A deployment advantage if our client keeps as much useful information as a cheaper local cache. |

Do not multiply speedups across these rows. The workloads, circuits, field
profiles, preprocessing, checkers and measurement boundaries differ. The E37
data comprise 108 exact encrypted searches including warmups, two splits per
dataset, and eight measured queries per profile/run. They motivate broader
evaluation; they are not a population estimate or a p95 service benchmark.

## Initial novelty hypotheses, subsequently tested through E65

| Candidate | Already known | Difference we would need to demonstrate |
|---|---|---|
| Joint exact representation compiler | Factorization, layouts, CRT, parameter selection and DP | A precise optimization domain linking private map selection, final CRT capacity, complete-check cost and bounded client state; a restricted guarantee or materially better algorithm than independent rank/layout choices. |
| Updates with authenticated correlations | Incremental linear algebra, delta indices, updatable PIR, one-use masks | A safe dependency/invalidation rule and an algorithm trading cross-block sharing against update/token waste; quantify when saved rebuilds exceed extra steady-state work. |
| Multiple algebraic backends | HE and code-based matvec, including their composition | A representation effect that survives security-dimension floors and changes which backend wins, with same-contract evidence. A wrapper selecting libraries is insufficient. |
| vLHE over public ciphertext coefficients (proposed E47) | Private linear queries and layered encryption | Determine whether replacing owner mask-answer generation with a verified outer query is useful after full-Q field, matrix expansion and preprocessing costs. The composition alone is not a novelty claim. |
| Exact compact output | Packing, secure top-k and compressed match encodings | A new certified coverage/refinement or selection construction that pays for IDs, ties, all omitted rows and malicious responses. Existing moment summaries do not supply it. |
| Private complete linear verification | Freivalds/Rabin families, vLHE, authenticated outsourcing | A protocol theorem or compiler/verifier interaction beyond applying a known checker; account for adaptive failures and authentic owner inputs. |

These are **research hypotheses**. The current review identifies a plausible
gap at their intersection, not proof that no prior work fills it. Before a
novelty claim, complete forward/backward citation checks on the selected
mechanism and reproduce the closest applicable artifact. If the only win is
better native arithmetic, retain it for the company and narrow or change the
paper question.

## Reproduction order and comparison rules

1. Pin the target functionality/leakage and reproduce our E27/E35/E37 anchor
   comparisons from the protected checkpoint on one machine.
2. Run the author versions of EMVP/BNTM through the unified-search artifact
   on their intended parameters; verify its actual mode against each paper.
   Then make an explicitly separate exact-Hamming/full-scan adaptation.
3. Reproduce a vLHE reference, prioritizing vReinsPIRe and the small-state vPIR
   artifact. Record honest-digest versus malicious-setup assumptions and
   persistent versus ephemeral state.
4. Reproduce BioZKFHE's actual implemented proof path, and a strong packing
   baseline. Keep proof-disabled/decrypting shortcuts labeled and separate.
5. Compare proposed representations first as exact counts/oracles, then in
   matched complete encrypted requests. Use external software for reference
   and differential tests; the deliverable implementation remains homemade.

No competitor is to be weakened for a headline. Publish two panels where
contracts differ: its native intended setting, and the cost of a justified
adaptation to ours. An unimplemented adaptation is a model or an open task,
not an invented benchmark. A whole-database download plus local exact scan,
and a compressed local cache, remain mandatory controls.

## Execution supplement: evidence after the initial review

The unified author artifact at `519148cf3fddc11277a111774ca8cb92d891e0e3`
has now passed 78 CPU tests and two explicitly exact binary-Hamming/full-score
adaptations. [The reproduction report](baseline-reproduction.md) retains native
mode labels, all-score/top-three adaptation, query/reply models and compiler
override. This is partial reproduction, not the complete paper evaluation.
BNTM's client plaintext matrix is used online to compute `M*T`; its recursive
low-state Protocol 3 is not implemented by that artifact. Full ciphertext
matrix transposition for native verification is another recorded online cost.
The stronger low-state competitor remains an open reproduction task.

Targeted primary browser readings now cover incremental offline/online PIR
(2021/1438, two non-colluding HBC servers), single-pass PIR's §5 updates
(2024/303), and versioned/aggregated single-server hint updates (2026/030 §4.1).
Authenticated incremental PIR (2026/1077) remains abstract/metadata only because
full PDF access failed. These browser-only documents have no local pinned hash;
none is represented as a complete proof audit. Incremental hints, affine
reserves, rerandomization, CRT and HE-layout planning remain prior ingredients.

The new [execution log](publication-progress.md) records E43 complete lifecycle,
E48 response recipes, E49's failed speed hypothesis after a stronger control,
E50 compact local caches, E51 full-ring/capacity effects and E52 exact finite
lifetime DP. The counterexample requires retaining exact span and noise state;
it is not a novelty proof. Dynamic HE/compiler/update planning needs targeted
forward/backward citation review before any original algorithm claim. Existing
packing/rank/rerandomization improvements are retained for the company, with
the paper claim explicitly gated.

## Supplement after original artifacts and stronger controls

The [original EMVP Go/C++ artifact](https://github.com/SecretKeyCrypto/Encrypted-Matrix-Vector-Products),
pin `856762f5925fe873bb5cbc0401ceb5a44568efa9` from the full paper's Appendix F,
is now built and measured. [Original-artifact results](original-emvp-results.md)
retain cached-code and key-only modes, transient regenerated code state,
128 exact queries per fixture and a separate private full encoded-response
gate. Gated cached scans are5.942 ms for Mushroom and1.363 ms for Semeion,
with1,471,264 and205,100 B reply bodies. They are substantially faster CPU
controls with larger replies than our strongest global BGV profiles. Profiles,
entropy, integer widths and added integrity are distinct/unreviewed; no equal-
assurance ranking is implied. The paper's32-bit plots are not reproduced by
this64-bit author-library run.

OS-thread pinning in our adapter fixes an exact-result failure caused by
thread-local C-library random state; forced-GC/regeneration tests and every
output reference pass with pinning. The failed unpinned raw remains retained.
The author source is unchanged. A separate reused-static-code edit exposes a
binary toggle; it does not attack the published static protocol. Strong
recursive BNTM and compatible vLHE remain unreproduced requirements.

The user permits retaining **all** owned data. [Authenticated cache acquisition](cache-acquisition-results.md)
and [mutable private buffers](client-buffer-results.md) now supplement earlier
raw/zlib controls. [32,768 distinct Connect-4 rows](connect4-encrypted-controls.md)
give111/102 ms raw/affine HE CPU stage sums versus about3 ms per local cache
query. Cold/prepaid-owner bandwidth screens remain models with favorable
ready-remote omissions, not a demonstrated remote-deployment advantage. No
retention restriction or customer-device limit has been invented.

Additional targeted primary readings change the originality discriminator:

| Primary work / depth | Established ingredient or caution | Required distinction |
|---|---|---|
| [TFHE sample extraction](https://www.zama.org/post/tfhe-deep-dive-part-4), author tutorial, Sample Extraction subsection | A GLWE coefficient can be extracted as an LWE ciphertext using the full mask polynomial's permuted/signed coefficients; selecting the body coefficient is known | E62/E64's supported-C0/full-C1 selection is credited as a known ingredient. A new safe compiler/protocol consequence must be shown. |
| [TFHE-rs compression](https://docs.zama.org/tfhe-rs/fhe-computation/data-handling/compress), official list-compression/seeded-compression documentation | Compression before and after homomorphic evaluation already has concrete interfaces and costs | Do not claim post-evaluation compression as new. Compare key switching/noise/setup and exact returned functionality. No TFHE library was imported into our deliverable. |
| [Recifhe](https://arxiv.org/html/2607.15750v1), targeted introduction and §§II–IV | Multi-level CKKS/RNS compiler, common-subexpression elimination, offline-profile-guided ModDown hoisting/fusion and polynomial scheduling | Native polynomial/dataflow/profile optimization alone is established. Our proposed domain would need authentic decoder/lifetime/provenance constraints plus a useful algorithmic consequence. Artifact not executed. |
| [Compile-Time FHE via Algebraic Basis Synthesis](https://arxiv.org/html/2505.12582v1), targeted §§3.3,4.3,6.1–6.3 | Encrypted standard bases and a finite fresh-zero pool synthesize ciphertexts; the stated game supplies basis/pool to the adversary | Compare actual public visibility, freshness and related-ciphertext distributions against E49/E53. Do not borrow its IND-CPA label or assert a paper vulnerability without a separate audit. Artifact not executed. |

These web readings are not locally hash-pinned PDFs or full proof audits.
2026/030 was additionally checked at §2.3 for update/type/position/structure
leakage; it assumes a server-plaintext database. Authenticated incremental
PIR2026/1077 still has only metadata access. Original EMVP and unified-artifact
results are clearly distinguished in the source registry.

The [supported-relation argument](supported-decoder-relation.md) and
[E64 implementation](supported-decoder-results.md) give a concrete safe
coordinate-deletion domain, under explicit assumptions. The
[E65 static study](support-planner-results.md) supplies a stronger negative:
ordinary balancing plus one-row refinement recovers every tested frontier in
20 named and 32 irregular catalogs. Its one initially missed point is an 8 B
wire improvement at a 2 B owner-body tradeoff; global wire/client state is better.
This does not survive as a useful originality claim.

The [preceding plan §11](publication-research-plan-through-e65.md) prioritized
recipe/decoder controls and complete provisioning costs. The canonical plan
now turns that screening into a bounded control task before new protocol work.
Company engineering and negative findings are retained; all paper gates remain
open.

## Focused revision: preparation, compact release and the closest constructions

This revision follows citations into nine additional primary PDFs, with
targeted construction/definition reading as stated below. They are hash-pinned
in `../research-data/literature-plan-revision-20260930` (workspace path relative
to the repository). No full proof audit, new external run or first-of-its-kind
claim follows. In particular, the new sources substantially narrow any claim
based on compression plus verification.

| Primary source and reading scope | Established construction / relevant boundary | Consequence for the proposed work |
|---|---|---|
| **Verifiable Fully Homomorphic Encryption**, Viand–Knabenhans–Hithnawi, [2301.07041v2](https://arxiv.org/html/2301.07041v2), §§III–IV, especially IV-D/E | Explicit malicious-security definitions address reaction/decryption oracles; generic constructions combine circuit correctness with input admissibility. | A generic verify-before-decrypt wrapper, an input-validity predicate, or the key-recovery motivation is not ours. Any safe-release theorem must identify its narrower new transformation or improved cost. |
| **HELIOPOLIS**, Aranha et al., [2023/1949](https://eprint.iacr.org/2023/1949.pdf), §§1.1, 3.1, 6.5 and Appendix D context | HE-IOPs move checks to the plaintext layer. Terminal extraction, key-switch repacking and decomposition/recomposition reduce verifier decryption overhead. §3.1 explicitly excludes verification feedback and subsequent-output oracles from its verifier-privacy definition and discusses those risks. | **Required comparator for E66.** Smaller verified outputs and decoupled terminal parameters are established. Its oracle contract differs from our intended observable-abort service; this is a stated boundary, not a vulnerability discovered here. Its artifact has not been run. |
| **Leveraging Linear Decryption: Rate-1 FHE**, Brakerski et al., [2019/720](https://eprint.iacr.org/2019/720.pdf), §§1.3, 4.1–4.2 | Defines compression with a separate decoder and combines linear decryption with high-rate LHE; terminal homomorphic capabilities and assumptions matter. | Neither a dedicated compressed decoder nor asymptotically compact post-evaluation responses is new. Distinguish concrete costs, valid-ciphertext prerequisites and malicious release from the rate statement. |
| **HE is all you need / ZipPIR**, Akhavan Mahdavi–Diaa–Kerschbaum, [2303.09043v2](https://arxiv.org/html/2303.09043v2), §§3–4, 6.1 | Encrypts an LWE/RLWE key under a separate additive scheme; the server evaluates linear decryption, with packing, key-size and rescaling tradeoffs. Its compression propositions concern semantic security/correctness; the PIR database is server-held. | **Required terminal baseline**, including an honest independent-key Paillier implementation/control. Charge compression key, exponentiations, output decryptions and matching malicious integrity. Replacing one key by another does not automatically protect observable rejection. |
| **Downlink (T)FHE ciphertexts compression**, Bondarchuk et al., [SAC 2025 preproceedings](https://sacworkshop.org/SAC25/preproceedings/sac2025-2-paper3.pdf), §§1–2, 4–6 | Studies terminal coefficient truncation, compact LHE conversion and combinations; explicitly prices decryption-error probability and output count. Includes compressed Paillier-ElGamal. | Our precision/packing sweep must beat applicable combined controls. A small observed error or tiny output context does not justify deterministic exactness or a new security parameter. Paper timings are not local baselines. |
| **Efficient PCGs from Ring-LPN**, Boyle et al., [2022/1035](https://eprint.iacr.org/2022/1035.pdf), overview and §7.4–7.5 | Programmable correlations support matrix products and circuit-dependent preprocessing; matrix-triple generation is already studied. Its discussion distinguishes correlation size and practical expansion cost. | E69 needs a fixed-private-M, fresh-encryption, recipient-specific, full-Q authentication conversion. Generic matrix triples and short seeds alone cannot be its contribution. Read the exact setup/security theorem before selecting parameters. |
| **Efficient PCGs for Any Finite Field**, Li et al., [2025/169](https://eprint.iacr.org/2025/169.pdf), introduction and targeted §7.2 matrix/triple reading | Provides any-field programmable OLE and authenticated-triple/matrix applications, with separate setup and parameter analyses. | Small field support is not an unoccupied gap. Full construction/proof-level §5–9 review remains required; E69 is an ideal arithmetic conversion control, not its PCG instantiation or inherited assurance. |
| **SIMD-Aware Homomorphic Compression**, Cheon et al., [2408.17063v1](https://arxiv.org/html/2408.17063v1), §§I-B, III and V | Sparse index and payload compression uses power sums, a matching index indicator and SIMD matrix multiplication; terminal ring switching is explicit. | E46 must produce and certify sparse winners first. Encoding IDs, using moments, applying SIMD or switching rings afterward cannot be claimed as new. Compare threshold ties and payload recovery, not only digest size. |
| **SophOMR**, Lee–Yeo, [USENIX Security 2026 prepublication](https://www.usenix.org/system/files/conference/usenixsecurity26/sec26_prepub_lee.pdf), §§1.3, 2.4, 4.1–4.2 | Extends SIMD sparse compression to multi-slot payloads using precomputation/stacking and terminal ring switching. It requires a sparsity bound; detection precedes compression. | Stronger E46 compression control than a naive per-slot scheme. Any new claim must address winner discovery/coverage, not reinvent efficient packing of an already sparse vector. We pin this prepublication version, not an assumed final artifact match. |

The any-field PCG reading is deliberately shallower than the other new
construction readings. The full reductions and concrete attacks for its
assumptions are still a task. Primary-source sections supporting each claim,
retrieval/hash records and the distinction between old and new caches are in
the registry. No changed parameter/security labels have been approved.

### Contract matrix: what is actually comparable

“Required baseline” means align or adapt the contract and charge the adaptation;
it does not mean every row is an interchangeable production protocol.

| Family | Server's logical database | Client result / preparation | Integrity and local reproduction status |
|---|---|---|---|
| Current direct-fresh BGV | Owner-encrypted columns | All scores; fresh answer tokens plus private maps/check state | Conditional private full-field gate; local implementation and timings, full reviewed protocol open |
| General homemade BFV/BGV / Paillier | Owner-encrypted index | Exact scores; scheme-specific keys and encoding | Company baselines; compare each actual verifier/TEE mode separately |
| Original EMVP | Encoded hidden matrix | Exact product via response shares; cached/key-only client modes | Original CPU reproduction plus separately added private gate; strongest paper/parameter assurance not reproduced |
| BNTM | Masked/encoded matrix | Delegated linear algebra; recursive mode changes client costs | Unified simple mode only; per-answer integrity must be distinguished from its detection policy |
| vReinsPIRe | Server-plaintext matrix; may be our ciphertext operator in a proposed composition | Private linear result; server preprocessing | Full theorem/experimental admissibility differ;59 upstream cases and one native PIR pilot now run, no matched Hamming composition |
| Small-state vPIR/vLHE | Server-plaintext matrix with extractable binding | Private linear result; reusable proof plus query material | Protocol explicitly handles selective failure in its own auxiliary-key setting; no local reproduction yet |
| HELIOPOLIS | Encrypted inputs / HE proof computation | Private verification uses decrypted proof material; compact terminal ciphertexts | Different oracle definition above; no local run |
| ZipPIR / terminal LHE conversion | Plaintext PIR database, or generic input ciphertexts to compress | Compact linear-decryption output under another key | Compression semantic security is not our complete malicious service guarantee; no local run |
| PCG/MPC correlations | Distributed shares under the selected setup model | Correlated random shares/triples | A building block, not an encrypted-search protocol or a reproduced token factory |
| BioZKFHE | Committed encrypted gallery | Similarity evaluation with threshold/proof pipeline | Public/threshold trust and proof scope need their own comparison; no local run |
| SIMD compression / SophOMR | Ciphertexts with a sparse indicator after matching/detection | Sparse IDs/payloads | Useful terminal component, not full exact top-k or our owner-epoch service; no local run |
| Authenticated local cache | Server stores/transmits an owner-authenticated cache packet | Client obtains owned data and computes exact results locally | Locally measured acquisition/search control; permitted by the user |

### The distinctions that still deserve experiments

The following are **our inferences and proposed research questions**, not
absence-of-prior-art claims:

1. **Structure through the entire verifier.** E47's implicit operator could
   save storage while outer admissibility and extraction force expansion
   elsewhere. E68 should test a norm-aware structured construction end to end.
   ReinsPIRe already compiles polynomial sums to matrices, so a matrix view
   or faster convolution is insufficient. The new step must preserve proof
   premises while changing a complete resource bound.
2. **Exact fixed-index correlation conversion.** Existing PCGs do not by name
   supply our full recipient/distribution contract. E69 should either give
   that conversion with a benefit or exhibit its precise obstruction. A
   privacy test against a public linear mask bank is only a negative control.
3. **Compact release with reactions.** Generic vFHE already supplies the
   framework. A useful specialized transformation would have to preserve
   owner binding, carries and seed/key provenance at substantially lower cost;
   neither plaintext verification nor extraction alone proves this.
4. **Certified sparse winners.** New work, if any, lies in exact selection and
   complete omitted-row/tie coverage. Existing SIMD compression supplies a
   strong way to ship the winner vector once that problem is solved.

These questions are prioritized and falsified in the
[mechanism agenda](publication-mechanism-agenda.md). The strongest unresolved
baseline reproductions remain part of the next tasks. We have enough evidence
to reject several weak claims, but not to certify that the remaining ideas
are original or that any will produce a publishable positive result.

## Execution supplement: ring verification and known-control discriminators

[Huang et al., *Fully Homomorphic Encryption with Efficient Public Verification*,
2024/1764](https://eprint.iacr.org/2024/1764.pdf), targeted §§1.1–1.3/2.1 reading,
is a strong additional comparator for E70/E71. It expresses FHEW computation,
including gadget/modulus operations, in ring R1CS and uses sum-check with ring
polynomial commitments; its stated proof/preprocessing efficiency question
includes improving the quadratic bound. Thus “verify ciphertext arithmetic
before decryption” and a ring-native proof are already established directions.
A specialized linear/CRT construction needs a new complete cost or theorem.
The full reduction and an artifact have not been reviewed/executed. Our
split-field nonconstant-idempotent example is not an attack on its different
ring/domain instantiation. The25th cached primary PDF is hash-pinned separately
in the [source registry](publication-literature-sources.json).

The [baseline cards](protocol-baseline-cards.md) now give fields, owner binding,
admissible extraction, setup and reaction boundaries. Unchanged pinned author
vReinsPIRe passes59 unit cases and a4 MiB/kappa40 native PIR pilot. Its
formula byte/state values, three means and first-record correctness are not
same-contract Hamming measurements. Small-state vLHE was inspected only.
Original recursive BNTM and optimized terminal compression remain explicit
reproduction gaps.

New E66–E71 controls are documented in the [execution review](publication-mechanism-review-20260930.md).
They reject elementary digit wire, universal per-limb factoring, raw integer
phase packing, generic triples as free fixed-M preprocessing and the literal
encrypted-query/full-quotient system. Known recipe/support composition works;
quotient batching has only a conditional many-output payload niche. The
true-output/bad-quotient feedback example changes the **required protocol
argument**, not the list of claimed prior-art vulnerabilities. No current
survivor has established originality or useful outsourcing. The
[handoff](mechanism-execution-handoff-20260930.md) gives precise next mechanisms
and stronger controls rather than treating these ingredients as a contribution.

## 2026-10-01 supplement: packed input and programmed masks

Three additional primary PDFs/text are version/hash pinned in the registry;
28 sources now have targeted reading/cache identity. Old25 hashes stay intact.
This is not an exhaustive novelty search, proof audit or a new external artifact
reproduction. Source attribution separates known primitives from our controls.

| Closest primary work / targeted reading | Known ingredient relevant here | Executed consequence / still missing discriminator |
|---|---|---|
| Angel–Chen–Laine–Setty, [SealPIR](https://eprint.iacr.org/2017/1142.pdf),§3.3/Appendix A | Automorphism/key-switch based coefficient query expansion | E73 is a homemade partial CRT control, not invented packing. Full key/noise/expansion work and original-query binding must be priced |
| Ali–Lepoint–Patel–Raykova, [MulPIR](https://www.usenix.org/system/files/sec21-ali.pdf),§3.1–3.2 | Packed query expansion, preprocessing normalization and optimized HE PIR arithmetic | E73 predivides by H in the score field; a smaller query alone is not a smaller complete service. Publisher PDF is the cached version; do not equate its bytes to ePrint2019/1483 |
| Vaikuntanathan–Zamir, [Improving Algorithmic Efficiency using Cryptography,v2](https://arxiv.org/abs/2502.13065v2),§3.1–3.2 | Finite-field Bernoulli LPN and structured/recursive trapdoored matrix algorithms | E74's fixed-weight public-code mask is a different unreviewed recipe. Actual row-local F32/F23 beats that literal screen; no refutation of the cited secret/recursive construction or all PCGs follows |

E72 uses known complete projected linear fingerprints. E77 conditions the
E73 circuit on public C1 and hoists its affine C0 selector into those
fingerprints. That exact control shrinks the online vector; it **does not**
remove the trusted seed factory. Affine hoisting, adjoints and Freivalds are
known ingredients. A contribution must give a new certified/generation step,
not relabel the state moved to a helper as system compression.

E75/E76 supply actual same-harness returning-client HE/cache requests, distinct
from author PIR formulas. Their complete strong HE profiles still lose to
permitted caching on two finite fixtures. Private bootstrap, independent
resources and a useful different regime remain gaps. Prior-art differences
and experimental negatives do not themselves establish a publishable thesis.
The [current review](publication-mechanism-review-20261001.md) and
[handoff](mechanism-execution-handoff-20261001.md) record the next construction
cards before new proof-system or native work.
