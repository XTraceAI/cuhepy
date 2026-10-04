> Execution return, 2026-10-04: [Q74/Q75 results](shared-query-gates-20261004.md) and the [current ledger](research-contribution-progress-20261004.json) now complete the two bounded preliminary gates. Shared-query exact semantics passed; the Q120 derived/public-index variants failed their public bounds, and one paid Q180 rescue was screened. The strongest known composition contains the new algebra. The next selected build is owner canonical Q120 shared-query native admission versus equally prepared replay, with permitted cache/acquisition and all lifetime costs. No new service speedup, original main claim, security/parameter approval or production change is established. This supersedes earlier next-task/selection pointers for future work; the complete earlier document below is byte exact.

# Closest work and the contribution we still need to establish

2026-10-04. Review through commit `4bbd55056d14405b617ae0c251b1f2bacc71e74c`.
Read the [results assessment](research-results-assessment-20261004.md),
[executable plan](research-contribution-plan-20261004.md), and
[reading receipt](research-contribution-review-20261004.json).
This is a targeted primary-source comparison, not exhaustive priority clearance.
Earlier negative decisions remain in force.

## What this review changes

The most direct mathematical predecessor is the corrected
[Cascudo et al. paper](https://eprint.iacr.org/2025/286.pdf), §3.4 and §4.1:
its CKKS relation accepts bounded alternative decompositions and relaxed
rescaling representatives to simplify verification while controlling extra
noise. Remark 4.1 also covers automorphisms through key switching. The current
2026-10-01 revision repairs the range protocol; some application estimates
still describe its earlier version. We inspected the rendered relevant pages
and retain both revisions separately. Consequently, neither using spare noise
to simplify a verified HE relation nor verifying rotations is a new claim.

We also downloaded [PEEV](https://doi.org/10.1109/ACCESS.2024.3424420), a 2024
framework connecting a high-level program, BGV evaluation, and ring-based
proofs. Its paper explicitly includes small Hamming-distance benchmarks.
Homemade arithmetic is a company priority and useful artifact, but it does
not make encrypted Hamming search or a verifiable HE compiler new.

The remaining question concerns a **complete system frontier**: can one
compiler jointly choose the search layout, bounded ciphertext-maintenance
relation, verification work, and retained state so that a fully admitted query
costs materially less in a useful deployment? We must test that question
against the strongest compatible combinations below. Familiar techniques
with a new name are insufficient.

## Five closest comparisons

| Work and inspected scope | Existing capability | Required distinction / fair control |
| --- | --- | --- |
| [Cascudo et al., corrected CRYPTO 2025 revision](https://eprint.iacr.org/2025/286.pdf), §§3.4, 4.1, Remark 4.1; corrected-range review retained | Ring proofs, maintenance relations, bounded noncanonical witnesses, controlled noise relaxation. | Adapt the permitted relaxation to our exact BGV graph. Charge corrected common-integer/range checks. Our possible distinction is a complete compilation/runtime result with original-query, terminal, and lifecycle binding and a useful paid frontier; priority remains unestablished. |
| [Viand et al., vFHE](https://arxiv.org/html/2301.07041v2), §V-B and Appendix D, refreshed primary text | Malicious-server integrity analysis and TEE-assisted tensor-product delegation to untrusted accelerators with lightweight equality checks. | Compare our complete maintained graph with matched checked-product/trusted-suffix and equally prepared replay. TEE plus FHE and randomized product checks are known. The [FHE-in-TEE artifact](https://github.com/zkFHE/FHE-in-TEE) was inspected, not reproduced. |
| [BioZKFHE](https://arxiv.org/html/2607.22065v1), §§IV, V-C, VII and concrete formulation, targeted retained/refreshed reading | Encrypted similarity search, packing, blockwise BGV proofs, snapshot/query binding, gallery coverage, committee-governed release. Its prototype proof domain excludes rotations, modulus switching, bootstrapping, and encrypted top-k. | Adapt its rotation-free per-feature organization, initially without extra base-T binding, to exact binary scores and delayed maintenance. Our single-owner TEE contract differs from its committee/public-proof contract. A cheaper service under stronger trust is not cryptographic dominance. |
| [HERS](https://arxiv.org/abs/2003.12197v3), §3.2 and Appendix B Algorithm 7; rendered pages 4 and 15 plus adjacent text | Transposed feature packing, encrypted representation matching, client score decryption/nearest selection. Its basic query carries one ciphertext per feature. | Give the exact binary adaptation the same query expansion and lazy maintenance. Exclude optional lossy dimensionality reduction from an exact-distance comparison. The layout itself is known. |
| [PEEV](https://doi.org/10.1109/ACCESS.2024.3424420), §§IV–V/start of VI; rendered pages 6, 8, 11; pinned author interface | CirC/YAP operation-list translation, SEAL BGV, Rinocchio verification, verify-before-decrypt protocol description, small Hamming workloads. | Determine the complete applicable maintenance adapter before timing. Our possible distinction is a verified-cost objective and complete GPU/native exact-search deployment with common-Q/lifecycle assurance. No reproduction, priority clearance, or production assurance is inferred from reading its interface. |

An unimplemented author adapter is **unknown**, never an infinite cost or
evidence that our code wins. Cross-paper timings on different hardware,
profiles, circuits, trust boundaries, and output contracts are not speed ratios.

## Mechanism-level controls

| Primary source / reviewed scope | Known mechanism | Consequence |
| --- | --- | --- |
| [SealPIR](https://eprint.iacr.org/2017/1142.pdf), expansion passages and pinned original client/server source | Automorphism-based coefficient expansion and client pre-normalization by an inverse power of two. | Once-per-query expansion is credited. Every expanded query must be linked to the owner's original ciphertext. |
| [Ali et al., MulPIR](https://www.usenix.org/system/files/sec21-ali.pdf), §§3.1–3.2, retained reading | Communication/computation tradeoffs, seeded symmetric queries, optimized oblivious expansion. | Include keys, expansion work/noise, and encryption mode; query compression alone is not new. |
| [Homomorphic gadget decomposition](https://eprint.iacr.org/2022/347.pdf), §§4.1–4.2, 6.2–6.3; page 9 refreshed visually | Bounded gadget preimages replace canonical inverses; additive propagation is generic. Multiplicative componentwise propagation needs a special gadget. | Our radix representation retains every convolution cross term. Give the control the same propagation/composite-key rewrites. Larger Q is a separately matched profile. |
| [Bivariate decomposition](https://eprint.iacr.org/2023/771.pdf), §3/Algorithm 1, retained reading | Decomposed arithmetic, precision separation, explicit carry/norm costs. | Unnormalized public digit products are known; count bounds, state, transforms, and normalization. |
| [BGV matrix triples](https://eprint.iacr.org/2023/593.pdf), §4.4, retained reading | Product accumulation before switching, hoisting, state/work tradeoffs. | One relinearization after a feature sum is a mandatory control. |
| [Lattice-based verifiable FHE](https://eprint.iacr.org/2024/032), retained double-CRT/maintenance reading and refreshed abstract | Ring-aware verification and maintenance scheduling. | Scalar-only or product-only proofs are insufficient sole comparators. Align full relations. |
| [GlueLUT](https://eprint.iacr.org/2026/494), retained common-integer interface | Explicit CRT alignment/range obligations. | Independent prime-limb membership does not prove one integer. Our common-Q parser is a correctness baseline. |
| [Slalom](https://arxiv.org/abs/1806.03287v2), §§3.2–3.3, retained reading | Trusted preprocessing and randomized delegated-linear checks. | Grant structured adjoints, batching, caching, and explicit challenge lifetime; avoid a dense/unprepared straw control. |
| [Fhelipe](https://people.csail.mit.edu/devadas/pubs/pldi24_fhelipe.pdf), retained layout reading; [CiFlow](https://arxiv.org/abs/2311.01598v4), retained dataflow reading | Packing and key-switch/dataflow optimization. | A layout, ordinary DP, or moving a switch is not new. Test the additional verified-cost objective and certificate invariant. |
| [Chen](https://arxiv.org/abs/1711.06319v1), retained relinearization reading; [KeyMemRT](https://arxiv.org/abs/2601.18445v1), retained lifetime reading | Maintenance scheduling, key reuse, memory-aware execution. | Grant kernel pairing, streaming, and lifetime repairs. Our sufficient schedules are not lower bounds. |
| [vCCA](https://eprint.iacr.org/2024/202), [Fherret](https://eprint.iacr.org/2025/700), [exact-FHE CPAD attacks](https://eprint.iacr.org/2024/127), retained security reading | Integrity and correct-and-honest evaluation address malicious response/reaction risks. | Prove composition for the actual sampler, allowed relation, protected release, and leakage. Admission before private decode is assurance, not standalone novelty. |

The [earlier larger comparison](closest-work-system-blueprint-20261003.md)
retains retrieval, selection, proof, update, and compiler controls, including
SANNS/PANTHER/Tiptoe, Spiral/YPIR, binary/ring proof backends, and authenticated
updates. Their approximation, retrieval, trust, and output contracts remain
separate. This review does not newly audit all those proofs.

## The strongest combined counterfactual

A known-method baseline receives all compatible advantages:

1. Transposed feature storage and signed query features.
2. One compressed pre-normalized query expanded for all gallery groups.
3. Three-component accumulation and one relinearization per group.
4. Generic bounded gadget propagation and canonical affine elimination.
5. Structured checks, fusion/streaming, shared setup, and full common-integer,
   coverage, and terminal checks.
6. Equally prepared full replay and the permitted plaintext cache.

This baseline already receives the prospective O(D + G) source inventory in
the [plan](research-contribution-plan-20261004.md). That inventory is **not a
novel asymptotic result**. The research question concerns a complete
noise-admitted relation/compiler and a useful prior-separated systems result.

If a generic adaptation gives identical equations, bounds, and resources,
reject a new algebraic/algorithmic claim. A systems paper remains possible only
with a separately defensible design result, complete implementation, useful
evaluation, and precise closest-system distinction. A larger benchmark alone
does not meet that requirement.

## Claim status

| Statement | Current status / falsifier |
| --- | --- |
| Homemade BGV/CUDA is a useful foundation | Supported engineering result under recorded experimental profiles; production security parameters unapproved. |
| Propagation can remove witness cuts | Scoped mathematical and small encrypted/native evidence; primitive identities are known. |
| Latest cut policy makes a complete service faster | **Unmeasured.** Producer, transfer, verification, setup, or updates may erase the advantage. |
| Shared query maintenance changes full checked-search cost | **Unexecuted hypothesis.** Public guards or the strongest known combination may eliminate the useful distinction. |
| Our compiler/system supports an original main paper | **Unaccepted.** Needs claim cards, applicable prior adapters, and complete useful results. |
| Admission prevents adaptive private-key reactions | Conditional proof objective; full controller, parameter/origin, leakage, and deployment assurance remain open. |

The archive preserves **109 earlier source records unchanged**, adds the PEEV
PDF/text pair, and therefore contains **110 source records**, not 110 newly read
or fully audited papers. Two repositories are pinned at exact commits.
Relevant retained papers were copied byte exactly into the new evidence bundle.
No HE experiment, timing panel, proof reproduction, or author-artifact
execution occurred in this planning review. Hashes, inspected pages, scope,
and retrieval qualifications are in the reading receipt and literature registry.
