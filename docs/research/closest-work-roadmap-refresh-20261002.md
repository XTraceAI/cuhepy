# Closest work and contribution audit after E99

2026-10-02. Evidence checkpoint: `8e7cd6b61839907c181fddd8dd0860532470323c`
(`checkpoint/gadget-dependency-controls-2026-10-02`). This is a planning review,
not an experiment or an originality certificate. It supersedes the **next-task
priority**, but preserves the results in the [earlier comparison](closest-work-comparison-20261002.md),
[E99 review](gadget-dependency-closest-work-20261002.md), and
[selection history](construction-selection-20261002.md). The accompanying
[execution plan](contribution-roadmap-refresh-20261002.md) states the proposed
mechanisms, full costs, and stop conditions.

## 1. Decision supported by the evidence

The company has useful homemade Paillier, BFV, BGV, native, and CUDA code.
The current evidence supports substantial improvements in arithmetic and
communication. It does **not** yet establish a novel, useful, complete,
malicious-server protocol with justified parameters. Arithmetic speed,
verification soundness, noise correctness, and lattice hardness are different
claims. Combining them requires new evidence.

The most credible immediate research target is **verification of the complete
native encrypted search without repeating the whole search in a trusted
server**. A proposed mechanism must improve the authenticated boundary, not
just make the unchecked evaluator faster. A second route targets a **finite
adaptive-lifetime correctness bound for a restricted reused-key BGV circuit**.
A third, separate-functionality route tests **exact owner-summary-assisted
retrieval**. No route below is declared original or selected as the paper's
main construction.

## 2. Comparison contract

The client owns its data and may retain all plaintext. The primary output is
all exact `(stable ID, Hamming distance)` pairs; stable top-three selection
happens locally. An exact-top-three-only protocol is a separate mode.
The primary adversary controls one compute server, may replace replies,
and observes accept/abort and declared traffic metadata. Owner-authenticated
registration is the first enrollment mode. TEE assistance is permitted, but
its secrets, work, rollback assumptions, and compromise consequences are paid.

Use the [contract](exact-search-contract.md) and
[security game](exact-search-security-game.md) when adapting a paper. Match
functionality, ownership, leakage, parties, starting state, hardware, and
parameter assumptions before comparing numbers. A single-server semi-honest
scheme or a two-server scheme can be a valuable control without satisfying
our primary contract. An unavailable adaptation is an open comparison, never
an assumed slow competitor.

## 3. Closest complete mechanisms for verification

| Primary work and reading scope | Established mechanism / important contract | Required distinction for our research |
| --- | --- | --- |
| [Slalom](https://arxiv.org/abs/1806.03287v2), §3.2, Lemma 3.1, Table 2, §3.3; newly archived v2 | Fixed linear operators have precomputed secret adjoint checks; an enclave delegates linear work to an untrusted accelerator. Preprocessing and protected state are explicit. | Freivalds checks, secret hints, convolution adjoints, or TEE/GPU partitioning alone are known. Give this control the same fusion and native arithmetic. |
| [DataSeal](https://arxiv.org/abs/2410.15215v1), §4.3–4.5, Algorithms 1–6; newly archived | Encrypted checksum rows and golden outputs support matrix-operation integrity checks. The displayed verification decrypts before checking; the paper describes one-operation encoding limits. | Our observable-feedback contract needs a complete safe-release argument. This order difference is an adaptation obligation, **not** a demonstrated attack on the paper. Do not claim encrypted checksums as new. |
| [CHEX-MIX](https://eprint.iacr.org/2021/1603), §3/3.1 and introductory protocol; newly archived latest revision | Combines HE and TEEs for cloud inference, with distinct model/client ownership and a rational-model-provider correctness assumption. | HE plus TEE is known. Specify a malicious compute host, an owner-approved circuit, and whether the checker ever has the HE secret or plaintext. |
| [Verifiable FHE via lattice SNARKs](https://eprint.iacr.org/2024/032), §§1.2, 3.2–3.3, Appendix A; retained targeted review | Exploits double CRT and handles maintenance operations; its rotation/switch scheduling is a strong structural control. | RNS-native proofs and delayed switching are known. Compare whole original-query-to-response statements and canonical digit constraints, not an isolated multiplication proof. |
| [Approximate HE verification](https://eprint.iacr.org/2025/286), §§3.4, 4, 6; retained targeted review | Proof-oriented ring arithmetic and range checks allow controlled relaxed maintenance relations. | State exactly which relaxed relation preserves exact scores. Charge its extra noise, range proof, original input binding, and decoder support. |
| [Efficient public vFHE](https://eprint.iacr.org/2024/1764), retained construction passages | Specialized ring-based public verification is a control for avoiding generic coefficient circuits. | Ring arithmetic or a quotient identity is not itself a gap. A new witness representation must improve a matched complete statement. |
| [HasteBoots](https://www.usenix.org/conference/usenixsecurity26/presentation/liu-fengrun), retained quotient-ring/PBS construction passages | Specialized proof machinery verifies TFHE evaluation including programmable bootstrapping, with batching. | Do not compare against a deliberately naive general proof of PBS. It becomes mandatory if our mode needs PBS. |
| [Small-prime SNARKs](https://eprint.iacr.org/2025/719), current §H overview/§H.1, pp.71–72; newly archived | Packed sumcheck amplifies small-field checking; its TFHE application includes NTT, Hadamard, decomposition lookup, and modulus-switch checks. | Small-prime proof arithmetic and shared lookup/range witnesses are occupied territory. The current revision uses common moduli in its displayed TFHE instantiation; those choices do not automatically fit our BGV transcript. |
| [BioZKFHE](https://arxiv.org/abs/2607.22065v1), retained biometric-score/proof/opening passages | Encrypted biometric similarity with decomposed verification and committee opening is a close application competitor. | A Hamming application with verification is insufficient novelty. Separate its opening/trust model from a single owner keeping its secret key. |
| [Verifiable FHE security model](https://arxiv.org/abs/2301.07041v2), retained definitions/reaction discussion | Computation integrity and malicious-decryption feedback are explicit vFHE concerns. | Verify-before-secret-use and the reaction-attack motivation are known. Prove the actual release composition; do not present discovering the general problem as new. |
| [HELIOPOLIS](https://eprint.iacr.org/2023/1949), retained IOP/oracle passages | Moves checks to the plaintext space under its stated oracle/composition scope. | Our feedback interface may require a different composition. An out-of-model requirement is not a vulnerability claim. |

**Local strongest controls:** [E13](bgv-checked-product.md) already fuses
product and canonical relinearization, eliminates C0/C1 intermediate witnesses,
checks full polynomials in each limb, and includes a native recomputation
competitor. [E72](encrypted-query-gate-control.md) already removes fresh trusted
index products using once-compiled private adjoints. [E73](packed-query-expansion-control.md)
already packs original queries and pays expansion/key costs; [E77](seed-affine-gate-control.md)
already prices factoring plus the trusted factory. A proposed fused check that
merely rediscovers any of these is an engineering control.

## 4. Closest work for communication, reusable setup, and updates

| Work | Existing result / contract distinction | Consequence |
| --- | --- | --- |
| [EMVP](https://eprint.iacr.org/2025/858), retained latest §§2/4/7 and artifact controls | Compressed additive-HE matrix-vector postprocessing; original and unified artifact executions are partial, separately scoped. | A small encrypted response is already possible by known postprocessing. Compare complete setup/private work and a fully specified integrity adaptation. |
| [Maverick](https://arxiv.org/abs/2609.10264v1), including retained private-matrix Appendices C/D | Private and verified matvec with preprocessing; the private-matrix extension matters. | Do not weaken the competitor to a public matrix. A trapdoor mask plus output code is known. |
| [BNTM](https://arxiv.org/abs/2502.13060v3) and [trapdoored matrices](https://arxiv.org/abs/2502.13065v2) | Structured/recursive delegated linear algebra, not just a one-level matrix example. | Full recursive controls remain missing. Literal small controls cannot close this comparison. |
| [ReinsPIRe](https://eprint.iacr.org/2026/1934), [small-state vPIR](https://eprint.iacr.org/2025/1714), [VeriSimplePIR](https://www.usenix.org/system/files/sec24summer-prepub-480-de-castro.pdf) | Verified LHE/PIR with different hint, digest, and key-lifetime contracts. The retained ReinsPIRe pilot is bounded PIR, not our Hamming adaptation. | Compact state or safe release through ephemeral keys is known. Price honest-digest, preprocessing, and answer-packing assumptions. |
| [Structured public matvec verification](https://arxiv.org/abs/1704.02768v1) | Dense and structured verification already exploit matrix structure. | A geometric challenge, polynomial identity test, sparse matrix, or structured opening is a control unless there is a distinct theorem or algorithm. |
| [Rate-1 HE](https://eprint.iacr.org/2019/720), [ZipPIR](https://arxiv.org/abs/2303.09043v2), retained downlink/SIMD/SophOMR sources | Terminal compression and sparse-output retrieval have substantial prior constructions. | Count conversion, predicates, overflow, masks, and metadata. Reduced bytes alone do not demonstrate a new mechanism. |
| [Ring-LWR PCFs](https://eprint.iacr.org/2025/1637), retained secret-replication PCFs and PCGs | Correlations, authenticated/threshold HE uses, and small-domain constructions raise the preprocessing novelty bar. | E82 stopped specific literal recipes, not every PCF. A later route needs an explicit different distribution/construction, not generic composition. |
| [Rogue](https://eprint.iacr.org/2026/1890), [authenticated incremental PIR](https://eprint.iacr.org/2026/1077) | Committed lookup and authenticated updates are close mutable-index controls. | Registration, row coverage, update authentication, and epoch invalidation must all be in the cost and proof. |

These rows use the retained targeted reviews. This tranche does not execute
their author artifacts or audit all proofs. The [registry](publication-literature-sources.json)
retains exact reading and execution scopes; the [archive](prior-work-archive.md)
preserves original versions.

## 5. Closest work for a finite reused-key noise theorem

| Primary source / scope | What it supplies | Gap to test, with limits |
| --- | --- | --- |
| [Accurate BGV dependency analysis](https://arxiv.org/abs/2504.18597v3), retained §§4–5 | Formal same-secret/public-key moment corrections and distribution analysis. | Dependency tracking and a variance compiler are known. A proposed theorem must give a valid finite tail for its actual distributions and reuse graph. |
| [Average-case critique](https://eprint.iacr.org/2025/1036), retained §§5–6/8 | Demonstrates dependency problems and discusses quantiles/compiler integration. | Another covariance calculation is insufficient. The finite lifetime loss and the restricted applicability must be explicit. |
| [Composable CKKS estimates](https://eprint.iacr.org/2024/853), newly pinned current revision, §§1.1/1.2.3/5.4 | Component-wise estimates and exact-CKKS applications; the current text explicitly withholds a full IND-CPA-D proof because distribution/independence heuristics leave a tail gap. | This is a concrete motivation for a restricted finite theorem, **not** evidence that our BGV model closes it. A generic MGF bound or union bound alone is not the proposed contribution. |
| [Central-limit Ring-LWE analysis](https://eprint.iacr.org/2019/452), newly pinned current revision, pp.4/20 | BGV average-case analysis and a broader CLT framework with explicit independence/convergence premises. | An asymptotic Gaussian approximation is not automatically a finite security-tail certificate for reused keys. Keep this strong model as a quantitative control. |
| Retained [drift](https://eprint.iacr.org/2024/1718), [FHEW](https://eprint.iacr.org/2014/816), [FINALLY](https://eprint.iacr.org/2024/1505), [gadget toolkit](https://eprint.iacr.org/2018/946) | Existing worst-case/conditional bounds, randomized rounding, and gadget basis tools. | E94/E97/E99 already implement useful known controls. A new result must handle an additional real dependence/lifecycle case with a quantitative consequence. |

**Version warning:** searching the older title of ePrint 2024/853 returned
earlier security language. The downloaded current PDF has 49 pages and its
qualified claim above; the web PDF cache exposed an older 66-page rendering.
Use the newly recorded local PDF/text hashes. Similarly, ePrint 2025/719 now
has a different title and an 82-page PDF; an earlier indexed title is not the
reviewed revision. The Slalom acquisition receipt contains a mistaken v2 date;
the append-only review records the correct **2019-02-27** date. No earlier
receipt is overwritten.

## 6. Closest work for owner-summary-assisted exact retrieval

| Work / scope | Existing result / model | Our required distinction |
| --- | --- | --- |
| [PANTHER](https://eprint.iacr.org/2024/1774), newly pinned current §§3.2/4.1 | Cluster selection followed by private candidate retrieval and within-candidate ranking, in a single-server semi-honest ANNS model with server-database privacy. | Clustering plus PIR is known. Exact omitted-row coverage, stable ties, malicious-server release, and our owner-retention contract need separate treatment. |
| Retained [SANNS](https://www.microsoft.com/en-us/research/wp-content/uploads/2019/04/sanns.pdf), [Tiptoe](https://eprint.iacr.org/2023/1438), [HERS](https://arxiv.org/abs/2003.12197v3), NIST biometric work | Private approximate retrieval and encrypted exact similarity/search provide application and layout controls. | Do not mix exact/approximate utility or server-owned/owner-owned data when claiming a win. |
| [Pirex](https://petsymposium.org/popets/2025/popets-2025-0095.php), newly pinned §2 | Client-efficient online/offline PIR uses two semi-honest noncolluding servers. | Its attractive state/online cost cannot be transferred to our one-malicious-server model. A separate two-server mode would need explicit approval of that contract and its own comparisons. |
| Retained [counting-sort private kNN](https://petsymposium.org/popets/2025/popets-2025-0093.pdf), [NOMOS](https://eprint.iacr.org/2026/2262), authenticated PIR/update papers | Known exact selection versus approximate ranking, and separate integrity/update mechanisms. | A triangle-inequality bound or a local top-k sorter is not new. Query-dependent fetch count/early stopping can reveal information even when each address is private. |

Owner-built summaries are allowed, but so are full raw/compressed caches.
The interesting question is a measured resource frontier, not a prohibition
on what the owner keeps. A certificate that authenticates fetched rows does
not by itself certify that all unfetched rows lose.

## 7. Native/GPU novelty boundary

[Libra](https://www.usenix.org/conference/usenixsecurity26/presentation/bian-song),
newly pinned §4, includes cross-scheme cost models, partition/rewrite rules,
hardware scheduling, and a nearest-distance example. Retained Fhelipe and
Porcupine already address packing/compilation. Fused NTTs, batching, lookup
tables, RNS, asynchronous transfers, and ordinary GPU profiling are valuable
implementation methods; they should support a surviving mechanism rather
than be relabeled a new cryptographic construction. Libra's program model is
also a mandatory control if the claim becomes joint scheme/layout scheduling.
No Libra performance was reproduced here.

## 8. What the accumulated results actually justify

| Evidence | Positive result | Limitation governing the new plan |
| --- | --- | --- |
| Monitored matched 8,192×512 BFV/Paillier block | BFV CUDA reply 204,900 B versus lookup hybrid 4,226,953 B: **20.63×** reduction; query plus reply **4.49×** | Prepared local elapsed **395.213 vs 344.524 ms**, so BFV is **14.71% slower** in this block. No measured WAN, complete authentication, setup, or equal-security comparison. |
| Separate 8k BGV/BFV panel | BGV **60.047 ms / 102,488 B**, BFV **396.411 ms** | Different fixture from the Paillier hybrid block. Do not invent a paired BGV/hybrid ratio. |
| Revalidated E26/E27 | Large CPU improvements survive | Small CUDA stage-sum ratios **1.00153 / 1.00075** have intervals crossing 1; not robust GPU wins. |
| E49/E57/E77 and acquisition controls | Some structural/native improvements remain useful | Strong vectorized preparation and caches overturn literal winners; E77 client plus factory is about **5.3–6.6% slower** in its repeats. |
| E79 isolated small acquisition/service cases | Actual private transport and resources are measured locally | Cache **0.708 / 0.141 ms** versus fresh HE **47.288 / 17.349 ms** on two fixtures, including cold-client comparisons. No general cache-free outsourcing advantage. |
| E85–E99 exact/count controls | Correct modular bridge, signed LUT/orbit interfaces, conditional owner coins, exact setup/dependency laws | Standard controls contain generic mechanisms. E99's 720 cards retain the same target precision and full-N costs. None supplies a complete compact source-to-release proof. |
| E96/E98/E99 assurance screens | Real sample law, sample-budget qualification, hidden-support distinction | Some proposed public-prefix profiles fail named cost screens; high estimates do not approve other profiles. Old prefix estimates are **inapplicable** to hidden positions. |
| Correctness and instrumented checks | 1,965 unique historical/revalidation cases and 448 later scoped CPU tests | Overlapping, differently scoped counts; neither is a constant-time proof, security reduction, or parameter approval. |

Source: [revalidation](measurement-revalidation-20261001.md), its frozen
linked synthesis, and the named execution reports. No new timing, security
cost, private-key recovery, or HE author artifact was run for this review.

## 9. Originality obligations

For each proposed route, write a one-page claim with: exact functionality,
two closest **complete** controls, a precise new algorithm/restricted theorem,
assumptions, a decisive falsifier, and the complete resource boundary.
Advance only if an informed reviewer can identify a difference after giving
the competitors the same elementary rewrites, representations, and hardware.

The review is broad and targeted, not exhaustive. Follow citation chains and
current versions around the surviving mechanism before asserting priority.
Reviewing 77 archived papers is not 77 full proof audits. A negative screen
or integration artifact may be useful; it is not automatically a noteworthy
conference contribution. The next plan explicitly allows all three routes to
stop, while retaining the company code and accurate evidence.
