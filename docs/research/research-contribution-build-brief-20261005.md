# Research contribution and system build brief

2026-10-05. Read this first, then the [detailed decision plan](research-system-decision-plan-20261005.md), [closest-work matrix](closest-work-contract-matrix-20261004.md), and [progress ledger](research-contribution-progress-20261004.json). This brief consolidates the decisions; the ledger controls actual completion and the committed experiment contracts control execution. It adds no parameter search, workload sweep, or encrypted experiment reservation.

## Decision and present evidence

Build the exact owner-data search service on the homemade BGV implementation. Retain homemade BFV, Paillier, CUDA/native arithmetic, and the optional SEAL sanity examples. The research prototype is under `experiments/bfv_search_lab`; it is not yet a complete production service. Our own implementation is the foundation, while originality must come from an additional substantive mechanism or systems finding.

The paper question is: **how should an exact encrypted-search service construct, admit, retain, and refresh encrypted representations when it must check complete authorized execution before private decoding?** The candidate contribution is a particular safe execution that removes measured paid work and changes a useful operating region after the strongest compatible known construction receives the same ordinary optimizations.

No original main result is accepted yet. Generic caching, base-plus-delta storage, feature packing, TEE verification, random product checks, and cost-aware graph partitioning are established techniques. Their implementation can be valuable without being a new algorithm. The plain immutable-base plus owner replacement template is already constructively contained by a compatible known composition. A stronger execution or substantive assurance result must survive that objection.

The storage dependency is resolved: unchanged pure preflight passed with approximately 68 GiB available, above the existing 20 GiB floor. The separately registered comparison launched at 21:04:18 UTC on 2026-10-05, from source checkpoint `c92c1f3ee560023a6faae4bf149777c260cf9821`. Its complete return remains pending. Earlier failed/interrupted attempts remain retained and excluded from its selection. See the [actual start receipt](native-shared-query-complete-cost-separate-start-return-20261005.json).

| Retained finding | What it supports | What it does not establish |
| --- | --- | --- |
| Earlier 32,768 × 512 BGV CUDA: 117.298 ms local median; 204,895 B first reply. Paillier lookup CUDA: 2,599.103 ms; 16,908,071 B. | Reuse compact BGV engineering and evaluate the complete admitted service. | A secure end-to-end speedup: profiles are unequal/unapproved; this old local panel excludes networking and complete admission. |
| Earlier BGV 32-row update: 7.2788 s, of which 7.1466 s rebuilt resident preparation; compact packet already 491,721 B. | Investigate avoiding repeated preparation, rather than rediscovering compact uploads. | That prior work intrinsically requires the rebuild, or that base-plus-delta is novel. |
| Earlier returning authenticated raw cache: 4.384 ms local median and zero returning-query download. | A returning cache is a serious control; permitted partial caching may also beat encrypted overlays. | That every fresh-client or larger-capacity regime favors caching. Acquisition and maintenance must be paid. |
| Original EMVP artifact with our bounded complete gate beat old CPU BGV controls on the retained Mushroom/Semeion fixtures; BNTM had smaller reply bodies. | Keep alternative schemes in the publication comparison. | Matched final-service superiority or a fully reproduced strongest BNTM protocol. |
| Full internal witness 127,057,920 B versus 1,474,560 B aggregate at two groups; aggregate checker still recomputes products. | Verification placement and formats have material costs. | An 86-fold client-download reduction or an arithmetic advantage over protected replay. |
| Public/native origin, lifecycle, complete-frame and noise gates; twelve model lemmas and four new integer assertions. | Concrete support for building and refining the service. | Native correctness, a completed privacy reduction, approved parameters, real attestation or end-to-end side-channel assurance. |

The old 32k panel has five measured queries in one key/index/process block per variant, not five independent replicas. Its complete qualified table and the 160-record alternate-scheme reanalysis are in the detailed plan. CPU and GPU improvements must be reported separately. Preserve the revalidation and contamination records; counts of receipts, queries, distances, test cases and source records are different units.

## Functionality and trust that every comparison must preserve

The honest client owns the data and may retain all or any subset of its plaintext. The main functionality returns every exact Hamming distance and top3 ordered by `(distance, original ordinal)` for one authorized snapshot. The cloud may substitute, omit, replay, reorder, or mix results and observe public acceptance/rejection. Denial of service is allowed.

The protected verifier is trusted for the stated computation integrity and authorization; it receives no HE decryption key. The owner checks complete public admission before consuming any private response. An ordinary process signer is a prototype authority, not hardware attestation. Hidden random-check state, signing-key custody, and HE-key custody have different requirements and must not be conflated.

Declare shape/length, changed-row identities, message sizes, timing, policy/compaction choices and public feedback leakage. Do not restrict owner caching to manufacture a win. Approximate ANN, top-k-only release, public databases, committee decryption, noncolluding servers, and plaintext-in-TEE execution belong to explicitly different contract rows.

## Closest work and the precise obligation it creates

The [archive index](prior-work-archive.md) and [source registry](publication-literature-sources.json) retain 138 versioned source records and local primary papers/text. A record is not necessarily a distinct paper or a completed proof audit. This review rechecked the primary pages below; it did not execute their artifacts or import their published runtimes into our tables. Detailed version, correction, artifact and adapter limits remain in the comparison matrix.

| Predecessor | Established result to credit | Required control or surviving distinction |
| --- | --- | --- |
| [HERS v3](https://arxiv.org/abs/2003.12197v3) | Packed encrypted representation search and client score recovery. | Grant compatible exact binary packing and delayed maintenance. Our implementation language is not the new result. |
| [PPMI v3](https://arxiv.org/html/2506.17336v3), §4.3/A.1/A.2 | Dynamic encrypted vector operations, precomputation, and transform placement that limits cache invalidation. | Grant compact updates, selective refreshed preparation and unchanged-state reuse. A new lifetime proposal must change additional necessary work or a guarantee. |
| [Argos](https://petsymposium.org/popets/2025/popets-2025-0099.php) | Trusted integrity-only FHE execution, with attestation secrets isolated from the evaluator CPU. | Compare equally optimized protected replay and actual attested authority. A local CPU signer does not inherit its hardware/side-channel assurance. |
| [vFHE](https://arxiv.org/html/2301.07041v2), §III/§V-B/Appendix D | Malicious-response/input analysis and trusted checking of tensor products delegated to untrusted hardware. | Build its real randomized maintained-graph adapter before claiming broad delegation superiority. Component-polynomial checking is different from sampling one NTT coordinate. |
| [Slalom](https://arxiv.org/html/1806.03287v2) | Fixed-operator preprocessing and inexpensive randomized online linear checks. | Pay preparation, retained verifier state, maintenance and adaptive challenge lifetime. Do not compare only with an artificially uncached checker. |
| [BioZKFHE v1](https://arxiv.org/html/2607.22065v1) | Packed BGV similarity, structured trace proofs, session/snapshot coverage and committee-governed release. | State its distinct metric and committee trust; pay the common-Q, maintenance and release adaptation. Verified similarity and complete snapshot binding are prior work. |
| [ILA v1](https://arxiv.org/html/2509.11559v1) | Noise/value types and conditional functional correctness for FHE circuits. | Instantiate honest input origin and actual native arithmetic/terminal behavior. A scoped model proof or ordinary type adaptation is supporting assurance, not automatic theorem novelty. |
| [IntegriDB](https://integridb.github.io/IntegriDB.pdf); incremental authentication/verification records in our archive | Authenticated dynamic queries and fresh owner digests; related work supports incremental maintenance. | Grant the same current recipe, replacement map and reusable base. Signatures alone establish neither currentness nor arithmetic correctness. |
| [EMVP](https://eprint.iacr.org/2025/858) | Repeated encrypted matrix-vector products with short owner secrets and code-based assumptions. | Compare original fast code, full reply checks and paid safe dynamic masking. Our update counterexample is not an attack on its static author protocol. |
| [Braverman–Newman v3](https://arxiv.org/html/2502.13060v3) | Trapdoored linear algebra, exact cancellation and recursive reductions; distinct dishonest-execution detection guarantees. | Supply the strongest applicable preprocessing/verification adapter. Detecting some dishonest calls is not the same as authorizing each private response. |
| [Fast HE Linear Algebra with BLAS v2](https://arxiv.org/html/2503.16080v2) | Format conversions and reductions to fast ordinary linear algebra. | Credit compatible BGV/BFV specializations and pay origin/noise/conversion/admission costs. Matrix hardware and gadget rewrites alone are not the contribution. |
| [Silph](https://eprint.iacr.org/2023/060), [CirC](https://eprint.iacr.org/2020/1586), packing/dataflow predecessors in the matrix | Conversion-aware protocol assignment, multiple representations and compiler optimization. | Give the generic reference the same legal choices, information, reuse and horizons. A better label for its objective is not a new optimizer. |
| Corrected Cascudo/Laminate, VERITAS, PEEV and WAHC vFHE in the matrix | Ring/range-aware verification, maintenance, plaintext authentication and program-to-proof pipelines under their stated feedback contracts. | Credit corrected versions and align input validity, verdict exposure, full frames and terminal conversion before comparison. Missing adapters remain unknown, not infinitely expensive. |
| Permitted full/partial owner cache | Authenticated acquisition/patches, local exact search and overlap with remote first answers. | Returning, fresh, racing and changed-row-only controls receive the same owner permissions. A surviving outsourcing region must be demonstrated. |

The strongest compatible reference is a construction, not one isolated weak paper: known packed search + valid noise/origin model + optimized protected replay or properly maintained randomized delegation + dynamic authenticated state + conversion-aware placement + permitted caches. If it reproduces the whole proposed execution, record containment and keep the useful company code.

## Select one substantive mechanism from the completed comparison

R3 is the discovery/selection study. Wait for its complete return before treating a bottleneck as established. Its query-latency objective excludes cold setup and updates: report those separately and explicitly name the lifecycle objective of the prospective extension. A large update time alone cannot demonstrate a gain in the frozen query-only primary metric.

The eligible contribution must have two literal source-to-release graphs, a necessary invariant, a paid incremental resource vector, a strongest compatible reference, a same-output causal ablation and a falsifier. Describe the exact operations/bytes/live state removed. A smaller witness, faster kernel, or passed oracle is insufficient by itself.

| Completed R3 points to | Mechanism question to resolve | Required distinction | Close the claim if |
| --- | --- | --- | --- |
| Paid update/refresh costs | Which prepared/admitted physical state can remain valid while current logical authority changes? | An additional concrete HE admission/state mechanism or substantive refinement beyond the already-contained base-plus-replacement template. | Selective refresh and permitted owner correction reproduce the entire execution or eliminate its useful region. |
| Paid construction/admission | Can one different contiguous common-Q segment avoid unnecessary protected transformations or witness materialization without weakening complete admission? | Name its actual source/transform/maintenance boundary and bind every ancestor, limb and terminal output. Whole protected-prefix placement is already a control. | The existing aggregate/replay graph or known compatible specialization performs the same work, or the remaining work/traffic removes the gain. |
| Protected-state capacity | Can one snapshot be checked with a bounded live working set while preserving reuse and exact all-row coverage? | Demonstrate a paid capacity consequence beyond equally streamed replay, with exact lifetime and coverage bounds. | Ordinary streaming yields the same state/work, or the claimed scale/capacity condition is unmeasured. |

These are conditional alternatives for **one extension**, not three new experiment queues. The most promising historical trigger is refresh; the actual complete comparison may change that ranking. A candidate remains experimental until its eligibility return passes.

### Refresh route: cheapest decisive reference first

Implement the owner-held current replacement layer and selective-refresh reference before an encrypted tile. For 32 changed 512-bit rows, the plaintext value body is 2,048 B plus paid authentication/IDs/delivery. The owner can compute 32 ordinary popcounts and replace the corresponding base distances.

The proposed encrypted tile requires a 245,760 B update coefficient body, an extra HE product/relinearization and a 102,400 B terminal body on each query. These are analytic counts, not measured timings. If the tile removes no necessary cost under the actual owner contract, stop it before a cohort. Do not rescue it by forbidding partial owner storage.

The prospective invariant binds the immutable base, ordered IDs, key/profile, original query/nonce, current replacement recipe and logical revision before any private work. Each ordinal gets exactly its latest value; compaction/overwrite/crash publication is atomic; old base admission is only a component of the current answer. An old signature cannot establish freshness.

Expected implementation: additive `authenticated_replacement_layer.py`, independent full-distance/transition tests, and one study adapter under `experiments/bfv_search_lab`. An encrypted variant additionally needs its own native relation and decoder. The baseline grammar and production fallback remain available.

### Construction or capacity route: make the new execution literal

For a construction cut, list the exact transforms, CRT/digit/range checks, products, canonicalization and terminal work on each side. Grant applicable known rewrites to the reference. Fresh query-dependent expansion cannot reuse another query's certificate. A public-after-commit challenge is a known possible control; freshness and irrevocable whole-claim binding must be paid.

For a capacity route, bound live groups and transient staging in the actual implementation, not only allocated coefficient arrays. Charge streaming/repeated I/O and prove all IDs/groups are covered exactly once. A larger scale or GPU/attestation path needs its own justified frozen registration; it is not activated by this brief.

## Finite execution tickets and exact exits

| Ticket | Required work/artifact | Completion and next action |
| --- | --- | --- |
| R2c — complete | Public launcher gate and exact committed comparison freeze. | Preserve 446 source/716 dependency pins and unchanged guards. No repetition merely to increase case counts. |
| R3 — running | `benchmarks/complete_cost_owner_study.py`, launched through the additive detached helper; six calibration blocks then twelve held-out blocks. | Actual complete terminal return, full independent oracle, immutable policy freeze, paid traces, paired block analysis and contamination report. Then R4 eligibility. |
| R4a — pending | One mechanism/containment card, invariant, resource prediction, named lifecycle objective and compatible reference. | Identify an actual surviving distinction; otherwise close that positive claim. Do not run a contained variant simply to populate a table. |
| R4b — pending | Actual additive mechanism, independent oracle/fault gate, strongest reference and same-output ablation. | Commit exact interface/bounds/codec and a separately scoped experiment registration. Then R4c. |
| R4c — proposed, not activated | One matched extension cohort: two keys × two process blocks × eight queries = 32 measured requests per retained variant. | Freeze choices before held-out; charge auxiliary attempts; report useful and losing regimes, or retain a negative result. |
| Q78 — partial support complete | Native/refinement, conditional security argument, approved parameter/sampler/private-leakage review, real attestation and nonrollback/current authority. | Identify every proved premise and trusted assumption. A secure-service or attested GPU claim needs its actual deployment evidence. |
| Q79 — pending | Final justified workloads/replication, strongest compatible alternate schemes, external originality/security review, artifact and manuscript. | One defensible mechanism or generalizable finding; no fastest-system or conference-readiness conclusion from selection data alone. |

Thus the remaining preliminary timing work is the running complete selection study and one eligible prospective extension study. Assurance and publication evaluation remain separate substantial packages. Randomized vFHE is additionally required for a broad delegation claim and is not already inside either timing reservation. The existing native prototype means system construction has begun; there is no need to reopen an unlimited preliminary portfolio.

R3 uses two fresh HE keys, three sizes (8,224/16,384/32,768), three process blocks per key/size and eight queries. Six trajectories produce 864 measured requests: 288 calibration and 576 held-out. These are clustered observations, not 864 independent key/index experiments. Warmups/post-update checks are separate. Earlier partial data cannot enter new policy selection or substitute for missing rows.

Use actual owner completion minus causal arrival as the frozen primary mean. Also report tenant setup, first answer from lifetime start, existing-tenant/fresh-device acquisition, update-to-next-answer, both links, protected/producer/private work, persistent/transient state and cleanup. Join and charge racing-cache losers. Attributed native intervals are not a separately measured bare evaluator. Do not sum overlapping stage medians into end-to-end latency.

After R3, run the retained read-only complete-return analyzer and paired pooled analysis against the new addendum. The output must answer H1 (does complete-cost selection differ from evaluator-only selection?), H2 (what boundary explains the cost?), and H3 (does any outsourcing region survive permitted caches?). Then return to R4a; avoid selecting a new extension from a convenient incomplete prefix.

For the extension, freeze a causal crossover prediction on discovery/calibration evidence and test it on independent held-out traces. Refresh savings must pay extra queries, layer preparation/acquisition, verification and compaction. The ablation disables exactly the mechanism while preserving rows/IDs/output/arrival law. It is distinct from the strongest competitor. If candidate/reference graphs coincide, document one implementation serving both aliases rather than manufacturing duplicate novelty rows.

## Security argument to develop alongside the selected mechanism

Define the ideal snapshot functionality and adaptive public feedback. The supporting proof has four explicit obligations:

1. Public authorization/admission failure never invokes the private callback.
2. Accepted native arithmetic and complete canonical frames refine the authorized original-query graph, including all common-Q limbs, maintenance and terminal rounding.
3. Honest origin/encoding/noise plus the current recipe imply exact full distances and stable top3; freshness and at-most-once consumption survive the specified crash/multi-device model.
4. Outside explicitly defined signature/hash/admission/freshness failures, the server view reduces to the actual augmented HE and delivery assumptions under the declared leakage/private-execution premise.

Write games, simulators and named bad events with multi-key/adaptive-attempt factors. IND-CPA alone is not CCA security; output checking after private decryption is not the oracle defense. The current local at-most-once state is not durable nonrollback state.

The four new kernel-checked integer facts support terminal reasoning only. Unwrapped rounding preserves the plaintext residue; a canonical component modulo P need not. Full paired Q/P phase wraps and centered private decoding must justify the final message. These facts and the twelve older model lemmas do not prove the C++ implementation, honest distributions, privacy or side-channel behavior.

The real AWS adapter must bind measured code and result-signing authority to the owner-verified attested channel, supply currentness/nonrollback/revocation, and pay transport/provisioning. The HE secret remains with the owner. A GPU may be an untrusted producer whose work is actually checked; GPU attestation is an optional distinct trust adapter. Require a matched admitted GPU execution before advertising the earlier CUDA timings as this system's performance.

Parameter/security review and the complete private path remain open. Fixed-work private NTT code does not cover Python key handling, query encryption, parsing or end-to-end leakage. These are explicit assurance tasks, not claims made by the present prototype.

## Paper claim and artifact checklist

The manuscript's central statement should name **one execution change, the invariant that permits it, the necessary paid work it removes, and the useful/losing regimes against the strongest compatible reference**. Known cryptography can support a systems contribution; a substantive and generalizable finding still has to be earned. A security theorem is a main contribution only if its guarantee/refinement is non-routine and survives the prior-work comparison.

Required evidence includes the actual mechanism, proof-premise table, independent all-output oracle/adversarial transitions, causal ablation, matched references, frozen held-out traces, honest cache wins, justified final workloads/independent replication, approved parameters and deployment evidence for every advertised assurance. Missing author adapters are disclosed, not scored as failures. Use earlier negative/contained experiments to explain design choices.

Keep raw failures and interrupted prefixes, source/binary/dependency pins, attempt accounting, telemetry and receipts. The compressed/source checkpoints and versioned primary-paper archive remain part of the reproduction path. Current main and staging and company-delivered crypto are unchanged by this plan.

After every ticket: record its scoped return, update the existing ledger, and resume its first unmet dependency. Observe the original host PID birth/boot and actual terminal result; a lost tool handle alone is not a scientific failure. No automatic resume, block replacement, secret restoration or extra cohort follows a failed action.
