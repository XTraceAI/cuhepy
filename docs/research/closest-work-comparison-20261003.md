> Latest bounded return2026-10-03: [E115/E117–E119](seeded-correctness-return-20261003.md)
> and [machine queue](publication-work-packages.json). The unit-free fixed-prefix
> ideal consequence now has independent public oracles; the squarefree extension
> uses prime-limb bounds. Protected-checker costs are explicitly paid.
> [Q46/E120](multilimb-owner-consequence-plan-20261003.md) is proposed, not executed.
> No new timing, original-main selection, actual cryptographic/parameter approval
> or production change. Earlier amendment/body below remains historical.

> Current execution amendment2026-10-03: see the
> [E109–E115 return](verification-aware-screens-return-20261003.md) and
> [queue](publication-work-packages.json). E109–E114 bounded components now have
> actual/scoped results; E115 remains partial. The planning/reassessment body
> below is preserved historical evidence, not current execution status. No new
> timing, original-main selection or parameter approval occurred.

# Closest work: what remains a plausible contribution after E108

2026-10-03. Planning/evidence review at
`8fdc431aa480634cd26bee8e3f73a53ef41b6d4c`. Read alongside the
[results reassessment](results-reassessment-20261003.md) and
[new contribution plan](contribution-plan-20261003.md). This comparison updates
priorities and novelty obligations; it does not overwrite previous source
versions, measurements or decisions. It is a broad targeted review, not a
complete literature search, full proof audit or originality certificate.

## 1. Main revision to the earlier comparison

The company arithmetic/communication work remains valuable. Three earlier
leads now have particularly strong direct controls:

1. **One shared bit oracle for binary ranges and odd-ring arithmetic:** BitZ
   explicitly commits packed binary representations and proves claims in
   arbitrary rings through ring homomorphisms. This directly occupies the broad
   shared-oracle idea retained after E108. LaBinius, BrakingBase and Binius64
   supply additional range/representation controls. Do not promote this idea
   based on the older same-characteristic Binius comparison alone.
2. **Exact semantic release with bounded noncanonical traces:** corrected
   ePrint2025/286 permits bounded alternative decomposition, vCCA explicitly
   formulates semantic extraction, and Fherret targets safe exact decryption
   against reaction/correctness-oracle attacks. Ciphertext-byte equality is not
   the only known route to safe release. Generic semantic relaxation is stopped
   as a novelty claim; a genuinely different complete theorem remains possible.
3. **Move canonical cuts into prepared index material:** matrix-RGSW/GGSW
   external products and precomputed encrypted linear algebra already provide
   the core identity. A partially prepared native graph is worth a bounded
   complete-cost discriminator, but compiled-index encryption itself is known.

The recommended research question is consequently narrower: can a **specific
new graph/representation algorithm or certified dependent-noise algorithm**
change the complete verification/evaluation frontier under the actual contract?
The [plan](contribution-plan-20261003.md) gives four bounded proposals and
explicit stops. None is currently an accepted main result.

## 2. Match contracts before claims or numbers

Our primary mode has an owner-private index, adaptive owner-private queries,
one malicious server, observable acceptance/rejection, owner-authenticated
registration, exact distances/stable IDs and permitted full plaintext caching.
All-score output and exact-top-three-only output are distinct contracts.
Our current N8 fixture and Q120/Q180 measurements are not parameter approval.

For every adapted competitor record: who owns plaintext and HE keys; whether
the matrix is private; setup/hint/auxiliary-key distribution; verifier state;
one-use versus reused keys; correctness versus computational soundness; accepted
witness semantics; feedback oracle; rounds; updates; and trusted parties.
Published times from different circuits, parameters and machines are not
matched baselines. Missing adaptations are unknown, not presumed inefficient.

## 3. Complete proofs, ranges and native arithmetic

| Closest primary work | What it establishes / relevant premises | Consequence for our candidate | Local comparison status |
| --- | --- | --- | --- |
| [BitZ,2026/2141](https://eprint.iacr.org/2026/2141), §§2.4,4.3,4.6 | Packed binary commitment, arbitrary-ring linear claims via integer lifts, exponent/GKR bridge; bit-size checking is inherent. Construction4.4 and Remark4.14 matter for arbitrary adjoint weights. | Direct shared-bit/odd-ring control. Exact `c<Q`, common lifts, exponent wrap, tensor structure and concrete lifetime soundness still need the matching relation. Not our new PCS. | New pinned PDF/text and targeted full math pages; no artifact execution or reproduced timing. |
| [LaBinius,2026/2103](https://eprint.iacr.org/2026/2103), definitions20–24,Thm1 | Lattice binary PCS separates a fully splitting commitment modulus from the binary evaluation field, with short-cross-product/SIS and relaxed rational extraction premises. | Separating native/commitment/evaluation moduli is known. Its extraction is not automatically canonical odd-integer equality; pay norms/slack and the conversion relation. | Newly pinned targeted full math pages; no adaptation executed. |
| [BrakingBase,2024/1825](https://eprint.iacr.org/2024/1825), Algorithm1,Thm3.1 | Linear commitment, BaseFold opening machinery and sparse parity-check/Spartan argument over a chosen sufficiently large field. | Small openings and sparse/preprocessed linear proving are controls. Field-agnostic does not mean integer equality across fields; code/matrix/opening costs remain paid. | Newly pinned targeted full math page; no adaptation executed. |
| [Binius64 Blueprint](https://www.binius.xyz/spec.pdf) | Word-oriented binary proof representation and arithmetic design, with128-bit IntMul and an exponent-wrap guard. | Native word operations and bit packing are established controls; arbitrary cross-ring consistency still requires its actual protocol. | New versioned blueprint PDF/text; publication/implementation scope differs from a theorem paper. |
| [Corrected approximate-HE verification,2025/286](https://eprint.iacr.org/2025/286), §§3.4,4.3,AppendixC | Bounded alternative decompositions; corrected auxiliary-field/common-integer CMC; VerDec composition under stated premises. Remark4.12 identifies the older CRT-alignment issue. | Common CRT source linkage and bounded semantic maintenance are mandatory controls. We did not discover the paper's corrected flaw. Its old range/application estimates are not automatically timings for the correction. | Old and corrected versions retained; targeted full pages, no proof backend reproduction. |
| [GlueLUT,2026/494](https://eprint.iacr.org/2026/494), Thm6 and §§6–7 | Residue-ring lookup/range proofs, Four-Squares and common-modulus consistency; auxiliary-prime bounds depend on dimensions and Q. | Range work cannot be priced as free; root/oracle/CMC costs and prime applicability are checked. Published prototype figures omit commitments/PCS opening verification. | Pinned targeted math pages; no matching artifact run. |
| [Batch,Pack,andProve official2026 talk](https://fhe.org/conferences/conference-2026/resources/slides/1440_Guimaraes.pdf) | Virtual oracle packing, BatchFold/SparsePack, and almost-splitting CKKS ring premises. | Packing linear witnesses is known; our fully split60-bit limbs are not automatically its extension-ring instantiation. | Official slides retained; full referenced CCC+26 paper not located in the earlier bounded search. |
| [Spartan,2019/550](https://eprint.iacr.org/2019/550) | General sparse R1CS argument over the actual scalar field, with computation commitments, padding and transcript assumptions. | E108's transparent relation can export here; actual backend costs are unknown. Use scalar ell, not Curve25519's base field. This is a known control, not our HE implementation. | Pinned paper and read-only source head; no build/prove/verify executed. |
| [Lattice-SNARK vFHE,2024/032](https://eprint.iacr.org/2024/032), §§3/5,AppendixA | Double-CRT arithmetic and maintenance checks; delayed rotation/switch scheduling. | Native RNS proof and delayed normalization are known. Bind the original request and full terminal statement, not isolated products. | Retained targeted audit; no complete matching adaptation. |
| [Public ring vFHE,2024/1764](https://eprint.iacr.org/2024/1764) | Specialized ring-based public verification. | Ring quotients and coefficient-packing identities are controls; the whole statement and costs decide usefulness. | Retained targeted construction reading; no matching adaptation. |
| [Small-prime SNARKs,2025/719](https://eprint.iacr.org/2025/719), current §H | Packed small-field proof with a TFHE application including maintenance/NTT checks. | Native small-prime proof arithmetic is established. Concrete repetition/lifetime and actual modulus compatibility are required. | Current82-page revision retained; targeted TFHE pages, no artifact reproduction. |
| [HasteBoots](https://www.usenix.org/conference/usenixsecurity26/presentation/liu-fengrun) | Specialized verification of TFHE programmable bootstrapping. | Mandatory if a top-k/bridge candidate needs PBS. Never compare only with a naive generic PBS circuit. | Retained construction reading; no matching runtime. |

BitZ's generic verifier/proof cost is not automatically polylogarithmic in the
bit witness; its favorable tensor split need not match arbitrary native adjoint
weights. Its bit-size checks do not alone prove exact Q-range or our full graph.
Exponent periodicity and the concrete challenge field need explicit integer
bounds/projections. Published100/114-bit experimental configurations are not a
128-bit lifetime claim for this protocol. These are adaptation obligations, not
evidence that BitZ fails or that our unimplemented method is faster.

The strongest local frontend already eliminates full C0/C1 products before
canonical relin checks (E13), derives once-compiled adjoints (E72), binds packed
original queries (E73), and applies generic C/quotient folding (E108). Every
competitor receives those elementary optimizations. E108's candidate/control
constraint ratio is1; no original proof saving has been established.

## 4. Feedback security and TEE composition

| Primary work | Relevant security/trust scope | Required difference / caution |
| --- | --- | --- |
| [Verifiable FHE,2301.07041v2](https://arxiv.org/abs/2301.07041v2) | Formal vFHE/reaction concerns and admissibility/correctness conditions | Verify-before-secret-use and discovering a response-oracle risk are known motivations. Prove the actual complete composition. |
| [Fherret,2025/700](https://eprint.iacr.org/2025/700) | Correct-and-honest evaluation with circuit privacy; public simulation of verification/correctness feedback under its FHE/function premises | Strong exact-safe-release comparator. Its sequential/parallel overhead, function-space communication and maintenance treatment differ from our native proof; do not transfer its times or dismiss it without adaptation. |
| [vCCA,2024/202](https://eprint.iacr.org/2024/202), Definition5 | Verifiable CCA-style security with semantic plaintext-equivalent extraction | Exact ciphertext equality is not a necessary novelty gap. A new relation must satisfy its actual extraction/adversary premises. |
| [Exact CPAD attacks,2024/127](https://eprint.iacr.org/2024/127) | Correctness/decryption-feedback risks for exact HE | Success/failure feedback and noise assurance belong in the protocol theorem. This review executes no attack on our code or a third party. |
| [Phalanx,2025/302](https://eprint.iacr.org/2025/302), current AppendixA.2 | FHE-friendly SNARK; current analysis warns that knowledge soundness/client privacy alone can permit a one-bit reaction; stronger statement has a one-time verification-oracle premise | Reused-key/query lifetimes require an explicit extension or a separate proven protocol. The current title/authors differ from the older preprint. |
| [HELIOPOLIS,2023/1949](https://eprint.iacr.org/2023/1949) | Plaintext-space proof design under its own oracle/composition scope | Different oracle scope is an adaptation question, not a demonstrated vulnerability. |
| [Slalom,1806.03287v2](https://arxiv.org/abs/1806.03287v2) | Trusted enclave delegates fixed linear operators using secret precomputed adjoints/Freivalds checks | TEE/GPU partition, fixed-operator checking and protected hints are known. Same fusion/preprocessing must be granted to the control. |
| [DataSeal,2410.15215v1](https://arxiv.org/abs/2410.15215v1) | Encrypted checksums/golden outputs; displayed verification decrypts before checking | Our release/feedback model needs a matching ordering theorem. Order difference is not an executed attack on DataSeal. |
| [CHEX-MIX,2021/1603](https://eprint.iacr.org/2021/1603) | HE plus TEE inference with distinct ownership/rational-provider premises | State exactly who owns data/model/key and who is malicious. Combining HE and a TEE is not new. |

The corrected2025/286 review explicitly allows a malicious prover to choose
bounded alternative digits/remainders with controlled noise inflation. Thus the
prior plan's semantic-release lead should not be pursued as a broad original
claim. A TEE checking canonical cuts may still be a useful implementation, but
must bind the exact committed oracle consumed by the remaining proof, price
its construction, and beat a strong full-replay/hybrid partition control.

## 5. Reusable encrypted operators, communication and graph choices

| Primary work | Established mechanism / model | Required comparison |
| --- | --- | --- |
| [Bae et al.,Fast Homomorphic Linear Algebra with BLAS,current2503.16080v2](https://arxiv.org/abs/2503.16080v2), §§3.4,5.4–5.5; exactv1 also retained | Matrix-RGSW formats, external-product encrypted matvec, precomputation/format changes and BLAS reductions; v2 adds explicit two-key/two-degree ★GSW and slot-matrix/coefficient-query integration | Direct control for compiled-index/query-digit cut migration. Include noise amplification, auxiliary modulus/division, key size, small dimensions, coefficient/slot conversions and the matching exact-HE adaptation. |
| [EMVP,2025/858](https://eprint.iacr.org/2025/858) | Compressed encrypted matvec from secret dual codes with preprocessing | Strong communication/operator control; private work, t/Q lifts and integrity adaptation remain paid. Partial original/unified artifacts were executed earlier, not a complete new comparison. |
| [Maverick,2609.10264v1](https://arxiv.org/abs/2609.10264v1), private-M AppendicesC/D | Private/verified matvec with preprocessing | Do not weaken to a public matrix. Full private-M control remains relevant and incompletely adapted locally. |
| [BNTM,2502.13060v3](https://arxiv.org/abs/2502.13060v3), [trapdoored matrices,2502.13065v2](https://arxiv.org/abs/2502.13065v2) | Structured and recursive delegated linear algebra | Full recursive baselines remain open; a literal one-level failure cannot rule them out. |
| [ReinsPIRe,2026/1934](https://eprint.iacr.org/2026/1934), [small-state vPIR,2025/1714](https://eprint.iacr.org/2025/1714), [VeriSimplePIR](https://www.usenix.org/system/files/sec24summer-prepub-480-de-castro.pdf) | Verified LHE/PIR with distinct hint, digest and key-lifetime contracts | Low client state/ephemeral-key safe release are known. Compare original-query binding, honest-digest and private provisioning. Earlier bounded PIR pilots are not an exact Hamming adaptation. |
| [Rate-1 HE,2019/720](https://eprint.iacr.org/2019/720), [ZipPIR,2303.09043v2](https://arxiv.org/abs/2303.09043v2), retained SIMD/downlink/SophOMR papers | Linear-decryption terminal compression and sparse retrieval | Count conversion, overflow, masks and winner discovery; downlink compaction alone is not original. |
| [Ring-LWR PCFs,2025/1637](https://eprint.iacr.org/2025/1637), [secret-replication PCFs](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.ITC.2026.7) | Reusable correlation families with precise distributions/security premises | E82's literal negatives do not rule out PCFs. A new fixed-private-M construction needs a concrete different distribution and complete costs. |
| [Libra](https://www.usenix.org/conference/usenixsecurity26/presentation/bian-song), [Fhelipe](https://people.csail.mit.edu/devadas/pubs/pldi24_fhelipe.pdf), [Porcupine](https://cs.stanford.edu/~trippel/pubs/porcupine-pldi-21.pdf) | Cross-scheme scheduling, packing/compilation and hardware cost optimization | Joint proof/evaluation graph search needs a new rewrite, sufficient state or frontier result beyond existing compilers; ordinary DP/min-cut and CUDA fusion are not enough. |

Local controls include E07 feature-major queries, E29 fresh one-use prepared
answers, E72 once-compiled private adjoints, E77 seed-affine factoring and the
full cache/delta controls. A proposed mixed functional-key graph must pay every
owner key family and rotation orbit. Product-only preparation leaves the
rotation cuts; fully prepared query-public graphs are a stronger control.
Uniform coefficients multiplying fresh encryption noise can destroy an assumed
bound. Extra secret/data-dependent key messages require their own security
premise, even if the owner's plaintext is already known to that owner.

## 6. Finite dependent noise and alternative retrieval

| Closest work / family | What is already covered | Possible restricted question still worth a bounded screen |
| --- | --- | --- |
| [BGV dependencies,2504.18597v3](https://arxiv.org/abs/2504.18597v3), [average-case critique,2025/1036](https://eprint.iacr.org/2025/1036) | Same-secret/public-key dependencies, moments, quantiles and critique of simplifying assumptions | Certified full decoder-event bounds for an actual nonlinear maintenance graph, without independent digits; generic covariance/variance compilers are controls. |
| [Composable CKKS estimates,2024/853](https://eprint.iacr.org/2024/853), [CLT Ring-LWE,2019/452](https://eprint.iacr.org/2019/452) | Component analysis, asymptotic/heuristic premises and explicit current tail/security qualifications | A finite restricted certificate with valid conditioning and actual lifetime loss; no unquantified Gaussian approximation. |
| [Drift,2024/1718](https://eprint.iacr.org/2024/1718), [FHEW,2014/816](https://eprint.iacr.org/2014/816), [FINALLY,2024/1505](https://eprint.iacr.org/2024/1505), [gadget toolkit,2018/946](https://eprint.iacr.org/2018/946) | Randomized rounding, gadget basis and existing conditional/worst-case bounds | A new certified event representation must beat equally optimized generic bounds/branch-and-bound, not restate a union/MGF calculation. |
| [BioZKFHE,2607.22065v1](https://arxiv.org/abs/2607.22065v1), retained §§III,V-C,VII-D/E | Committed gallery, BGV similarity, decomposed proof families and threshold opening; complete coverage requires every gallery block. Recorded prototype scope excludes operations outside its compiled trace. | Closest application/integrity comparator suggested by Liwen. Match metric, full coverage, proof/setup/release and opening trust; structure footprints are not automatically serialized network bytes. No local author artifact run. |
| [PANTHER,2024/1774](https://eprint.iacr.org/2024/1774), retained SANNS/Tiptoe/HERS/NIST biometric work | Private approximate candidate retrieval and encrypted similarity/packing | Exact omitted-row coverage, ties and traffic leakage are extra obligations. E103's oracle does not supply PIR. |
| [Private counting sort](https://petsymposium.org/popets/2025/popets-2025-0093.pdf), [NOMOS,2026/2262](https://eprint.iacr.org/2026/2262) | Exact/approximate private ranking and separate encrypted top-k contracts | Top-three-only needs complete conversion/selection/ID coverage. It cannot be compared with all-score output without stating the change. |
| [Rogue,2026/1890](https://eprint.iacr.org/2026/1890), [authenticated incremental PIR,2026/1077](https://eprint.iacr.org/2026/1077) | Authenticated lookup/update mechanisms | Epoch invalidation and exact current coverage are part of the system, not free deployment details. |
| [Pirex](https://petsymposium.org/popets/2025/popets-2025-0095.php) | Two noncolluding semi-honest servers with online/offline savings | A distinct mode; no transfer of its cost/security to one malicious server. |

The closest-work gap is a **hypothesis**: E105's distinct complete states might
still admit a compact certified decoder-event partition. An event certificate
must preserve the exact same random atoms through digit/carry and phase terms,
charge unresolved mass, and compare with optimized generic interval trees.
It may fail because public uniform masks create dense carry boundaries. No
projected compression, useful tail or parameter improvement is already known.

## 7. Paper claims we can and cannot make now

The [company's Paillier paper](https://arxiv.org/abs/2609.21364v1) is prior work,
not an unpublished new contribution of this plan. Its carry-separated encoding,
lookup/reduced-exponent arithmetic and CUDA batching remain required controls.
The [earlier closest-work review](closest-work-comparison-20260930.md) records
the reading scope; this planning revision does not reproduce its artifact or
replace the historical benchmark identities.

| Claim | Present status | Requirement before promotion |
| --- | --- | --- |
| Homemade native/CUDA exact-HE implementation substantially improves selected arithmetic/payload stages | Supported in recorded scopes | Disclose hardware/parameters, stage versus whole elapsed and preserved source/runtime identity |
| BFV is faster than strongest Paillier on the matched local8k fixture | **False for the retained comparison** | BFV395.213 ms versus lookup hybrid344.524 ms; payload advantage is separate |
| BGV is faster than that same hybrid on the same fixture | **Unknown** | One matched monitored cohort; no cross-fixture ratio |
| Our exact search has an original compact proof system | **Not established** | Strong BitZ/ring/lookup/specialized controls, actual complete costs and an uncontained construction |
| Semantic bounded release closes an unexplored problem | **Too broad / contained by direct priors** | A precise new restricted theorem or protocol consequence, full feedback composition |
| Selective offline graph preparation gives a new useful frontier | **Proposed E110** | Fresh-key/noise/full-rotation oracle, complete paid ledger, difference from GGSW/BLAS/functional controls and compiler prior |
| Certified event cells give a scalable dependent-noise method | **Proposed E111** | Independently checked certificates, exhaustive tiny event comparison, generic bound/tree controls and a quantitative consequence |
| Boundary-only TEE checking is cheaper and safe | **Proposed E112** | Exact oracle binding, cost advantage over strong hybrid/full replay, reviewed lifecycle/composition and real attestation |
| One-prime co-design improves complete exact verification | **Proposed E113** | Complete feasible margin, repetition/terminal/parameter assurance and an effect beyond ordinary tuning |
| Production-ready malicious-server security /128-bit parameters | **Not established** | Matching reviewed reduction, real lifecycle, private side-channel assurance and independent parameter review |

## 8. Source retention and review discipline

The [registry](publication-literature-sources.json) preserves the earlier81
entries exactly and appends ten new PDF/text pairs in this review, including
current revised papers and a blueprint. The [archive index](prior-work-archive.md)
links them. Exact downloads, text hashes, selected full-page rendering and
targeted reading records live in
`../research-data/contribution-reassessment-20261003/`. This is91 retained
PDF/text pairs, **not91 full audited proofs or reproduced benchmarks**.

New bounded targeted reviews cover BitZ/LaBinius/BrakingBase/Binius64/Bae v1/v2 and
Fherret/currentPhalanx/vCCA/exact-CPAD. Older sources use the retained E01–E108
reading records and their recorded versions. The ePrint2026/2141 official page
records receipt2026-09-21 and a last-history revision2026-10-01, while its v7
changelog says2/10/26; use the retained PDF hash, not an inferred date. Current
Phalanx is the CCS2025 major revision of2025/302 with updated title/authors.
Old indexed titles and performance claims are not the newly inspected version.
Bae's currentv2 (2026-04-27) preserves the main Algorithm9/Theorem9–10 product,
noise and operation controls and strengthens the representation comparison.
The targeted review found output-dimension notation inconsistencies: derive
dimensions from the actual matrix products rather than copying a displayed
shape/corollary. These observations do not demonstrate an implementation flaw.

No new author artifact, HE/native/GPU evaluation, proof, benchmark or estimator
was executed in this review. Current-work containment decisions are stronger
than the older broad leads, but still scoped: follow citation chains around any
surviving specific algorithm and seek an independent expert review before
asserting priority. The plan makes an unavailable control a named open task,
rather than assuming it slow.
