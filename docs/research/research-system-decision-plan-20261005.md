# Build decision and research contribution plan

2026-10-05. Current implementation: `73b552f2cbcc7a4b0add092c41d0171d236a826a`,
branch `experiment/native-shared-query-service-20261004`. Its owner-trajectory
checkpoint is remotely verified. This plan replaces the earlier decision text;
the preceding version remains in Git and the planning evidence archive.
The [progress ledger](research-contribution-progress-20261004.json) controls
execution status. The [closest-work matrix](closest-work-contract-matrix-20261004.md)
retains the detailed comparisons and version qualifications. The
[current review receipt](research-paper-design-audit-20261005.json) pins this
review, the public algebra calculation and retained measurements.

## Decision and prospective contribution

Build one exact owner-data search service using our homemade BGV arithmetic.
Reuse the existing native/RNS/CUDA engineering; retain Paillier, BFV and the
optional SEAL sanity controls. The selected complete-admission graph currently
has a CPU native prototype. The earlier fast CUDA graph is different; its
timings cannot be advertised as the selected protected service's performance.

The **conditional system candidate** is an authenticated composite index:
retain a densely packed base across updates, represent current replacements
separately, and authorize their combination as one current answer. Because the
owner may retain plaintext, its strongest update path may compute replacement
distances locally. The encrypted row-tile variant below is subordinate to that
mandatory control, not the expected winner. Study the useful verification/reuse
execution and its crossover. If the complete-cost study identifies construction/
admission or protected-state capacity as the limiting cost, select one of the
two existing alternatives below.

The intended contribution is a specific useful execution with a necessary
invariant, an actual mechanism ablation and an explained crossover. Packing,
query expansion, cached representations, log-structured updates, TEEs and
generic cost assignment are known. Their composition is not automatically
original. **No original main result has yet been accepted.** The company
implementation remains valuable if a stronger known construction contains the
whole result.

## Contract and architecture

The honest client owns its data and may retain all plaintext. The cloud is
malicious and may change, omit, replay or substitute ciphertexts and observe
public acceptance/rejection. The protected verifier is trusted for execution
integrity and current authorization; it has no HE decryption key. Availability
against a malicious cloud is not promised. The owner receives every exact
Hamming distance and top3 ordered by `(distance, original row ordinal)` with
authenticated UInt64 IDs. Content retrieval is outside this selected search
measurement and must be separately paid if added to the final system.

The owner signs the original encrypted query and pins the authorized snapshot.
A public evaluator produces the ciphertexts and required intermediate claims.
The protected role admits the complete computation and signs the bound result.
The owner authenticates and consumes that result **before private decoding**.
Authenticated plaintext acquisition and compact cache patches provide a
separate permitted local-search path, including acquisition racing with remote
search on the same client link.

```mermaid
flowchart LR
    O[Owner: query, private key, current snapshot] --> L[Shared client link]
    L --> E[Encrypted evaluator: native or future matched GPU]
    E --> V[Protected computation admission]
    V --> R[Bound complete result receipt]
    R --> L
    L --> D[Owner: verify, consume, decode, select]
    L --> C[Authenticated cache and compact patches]
    C --> S[Owner: publish current cache and scan]
```

The current process signer is a local prototype. It is not deployed attestation.
The integrity-only HE contract above is the comparison contract, not a claim
that customers forbid plaintext inside a TEE. A protected plaintext-search
service is a separate useful control if its stronger key-custody trust is
acceptable; report its assumptions and costs explicitly. Do not introduce a
client memory restriction or forbid retention to create an HE advantage.

## What the accumulated results support

The retained matched local panel used 32,768 vectors of 512 bits, one
process/key/index block per variant, five measured queries, one excluded warmup
and one post-update check. This review recalculated its 25 measured samples;
it did not generate new timing observations.

| Variant | Local median ms | First reply B | One 32-row update s |
| --- | ---: | ---: | ---: |
| Earlier public-index BGV CUDA | 117.298 | 204,895 | 7.2788 |
| Prepared BFV CUDA | 892.813 | 409,770 | 0.7243 |
| Paillier lookup CUDA | 2,599.103 | 16,908,071 | 0.0052 |
| Paillier lookup hybrid | 1,418.960 | 16,907,985 | 0.0055 |
| Returning authenticated raw cache | 4.384 | 0 per returning query | 0.0269 |

These are swap/setup-qualified, unequal unapproved profiles and unverified
local paths, excluding networking and complete protected admission. All 35
searches, 1,146,880 distances and five update checks matched. Repetition within
one key/index block does not provide population confidence. The earlier BGV
update already used a compact 491,721-byte packet; 7.1466 seconds of its update
was resident-state re-preparation. This is evidence to investigate refresh,
not evidence that the new mechanism uniquely invents compact uploads.

The selected canonical graph has separate bounded source correctness evidence:
one key, six searches and 114,752 distances. Q76's prototype, replay, aggregate,
mutable cache and static certificate gates are complete in their recorded
scopes. Q77 retains **376 distinct public cases across component invocations**;
the latest 66-case invocation comprised 24 new and 42 repeated cases. Private
HE/native arithmetic was stubbed in that invocation. Honest tenant provisioning,
the full cohort launch and the exact pre-HE freeze remain unfinished. Q77 has
consumed **zero** HE keys, complete-cost blocks or timing observations.

At two groups/32k rows, retained interface accounting gives 127,057,920 bytes
of full internal witness, 1,474,560 bytes of aggregate claim, an earlier
204,895-byte client frame, a 263,206-byte descriptor and 2,359,635-byte cache
acquisition. Query-expansion sources contribute 125,583,360 witness bytes.
The approximately 86-fold aggregate reduction is on the internal link;
deterministic aggregate admission still recomputes the products. Prepared RNS
rows alone consume 826,277,888 bytes, not full process RSS. These counts motivate
a placement question, not a secure-service speedup.

| Experiment family | Carry into the system | Claim or task closed by its evidence |
| --- | --- | --- |
| Homemade BFV/BGV, native/RNS/CUDA, compact formats and prepared transforms | Arithmetic, codecs, resident workspaces, exact oracles and fallback schemes. | A language/backend optimization alone does not establish a new algorithm. |
| CPU/GPU measurement revalidation and equal-capacity controls | Paired blocks, complete costs, actual setup and contamination records. | Large CPU gains do not imply equal GPU gains; some small complete GPU differences are ties. |
| Low-rank, dictionaries, query spaces and correlation experiments | Data-specific and changed-preprocessing alternatives with their exact contracts. | Unstructured-data losses, reusable-mask leakage and unpaid token/state costs remain negative. |
| Output summaries, filters and two-round refinement | Coverage/ID counterexamples and exact-selection oracles. | Top-k-only, approximate or candidate-only outputs cannot replace all-distance exact search. |
| E101/E110, Q57/Q59 and Q74/Q75 | Exact relations and strong ordinary algebraic controls. | Contained affine sharing, gadget propagation, expansion and generic optimization claims stay closed. |
| Q65–Q73 semantic cuts and bounds | Scoped feasibility/counterexamples, complete integer/noise obligations and useful implementation ideas. | Partial-body models and known semantic rewrites are not complete latency or accepted originality. |
| Q76 and partial Q77 | Admission, lifecycle, independent metadata checks, owner path, shared traffic and public orchestration. | Local tests/model lemmas do not prove production security or replace the unexecuted cohort. |

The [portfolio review](research-evidence-review-20261003.md),
[detailed build plan](paper-system-build-plan-after-roles-20261004.md) and raw
reports preserve narrower qualifications. The 272 revalidation receipts,
290 normalized observations and 297 historical/fresh pairs are different units;
do not sum them into independent experiments.

## Closest work and the obligation it creates

The comparison must survive a compatible composition of the strongest prior
methods. A missing adapter has unknown cost; it is not an infinitely slow
baseline. The detailed matrix and archived primary sources contain the passages.

| Work | Ingredient already established | Required control or remaining question |
| --- | --- | --- |
| [HERS](https://arxiv.org/abs/2003.12197v3), [SealPIR](https://eprint.iacr.org/2017/1142), [MulPIR](https://www.usenix.org/system/files/sec21-ali.pdf) | Packed encrypted search, expansion and communication/computation tradeoffs. | Identical exact graph, once-per-request expansion, delayed maintenance and equal native/GPU optimizations. Our existing algebra is contained. |
| [PPMI v3](https://arxiv.org/html/2506.17336v3), §4/Appendix A | Decomposed queries, cached encrypted key representations, dynamic operations and cache-invalidation-aware transform placement. | Strong compact row upload and selective cache refresh, including its exact binary specialization where valid. Freshness/admission adaptation and its actual cost must be supplied. |
| [Argos](https://petsymposium.org/popets/2025/popets-2025-0099.php) | Hardware-backed integrity-only FHE and verification before decryption. | Equally optimized protected execution. Our CPU signer does not inherit its isolated attestation-secret custody or side-channel argument. |
| [vFHE](https://arxiv.org/html/2301.07041v2), Appendix D | Malicious-server analysis and randomized ring-polynomial checking of delegated products. | Actual aggregate adapter with committed claims, fresh challenges, complete maintenance and adaptive lifetime soundness. Required before broad superiority over delegation. |
| [ILA](https://arxiv.org/html/2509.11559v1), [PEEV](https://doi.org/10.1109/ACCESS.2024.3424420), [WAHC vFHE](https://cknabs.github.io/assets/pdf/vfhe.pdf) | Valid-model/noise reasoning and program-to-verification pipelines. | Concrete origin/common-Q/native/terminal/release refinement. No first compiler, typing or verifiable-HE claim. |
| [Silph](https://eprint.iacr.org/2023/060), [CirC](https://eprint.iacr.org/2020/1586), [FlowCert](https://www.contrib.andrew.cmu.edu/~bparno/papers/flowcert.pdf) | Conversion-aware multiple representations, scheduling and validation. | Equal legal plans, reuse, information and horizons. Generic solver agreement is expected and closes a superior generic-optimizer claim. |
| [Corrected Cascudo](https://eprint.iacr.org/2025/286), [corrected Laminate](https://eprint.iacr.org/2025/2285), [BioZKFHE](https://arxiv.org/html/2607.22065v1) | Ring verification or verified encrypted computation/matching under distinct contracts. | Pay well-formedness, common-integer/range, release and feedback adapters. No cross-contract runtime ratio. |
| [Authenticated incremental PIR](https://eprint.iacr.org/2026/1077) | Authenticated retrieval with immediate updates and periodic row aggregation. | Credit incremental authenticated databases; entry retrieval does not directly instantiate complete encrypted distance evaluation. |
| [CSSC](https://arxiv.org/html/2603.04742v1), §§3–4/6 | Sparse encrypted matrix-vector packing and a stated semi-honest model; static-pattern recompression is an open extension in that paper. | Compare compact changed-row/sparse-value controls with explicit structural leakage. Its BFV SIMD profile is not our coefficient ring, and that open extension is not priority clearance. |
| [Engorgio](https://www.usenix.org/conference/usenixsecurity25/presentation/bian), §§3–4 | Quantized CKKS hybrid queries, encrypted ordering/permutation and top-k. | If changing output to encrypted top-k, pay comparisons, exactness/ties and malicious-result verification. This is not a free substitute for the current contract. |
| [Compact Storage for HE](https://eprint.iacr.org/2022/273) | Two-server compact storage and dynamic retrieval packing. | Credit late construction of HE representations; state its extra trust/service and reconstruction costs if adopted. |
| [PRAG v2](https://arxiv.org/html/2604.26525v2), [Lin et al.](https://iqua.ece.utoronto.ca/papers/wlin-tpds21.pdf) | Dynamic encrypted ANN or private similarity updates with different trust/search laws. | Approximate/candidate and semi-honest/two-server premises remain separate. No imported performance ratio. |
| Permitted owner cache and protected plaintext search | Local scans, compact authenticated patches and acquisition overlap; alternative key-custody choices. | Returning/fresh/racing full cache and a partial owner replacement layer are mandatory. Trust-changing plaintext-in-TEE execution is reported separately. |

Three further primary PDF/text pairs are retained by this review, bringing the
registry from 128 to **131 source records**, preserving every earlier record.
These are versioned reading records, not 131 fully audited distinct papers.
The new PDFs are CSSC v1, the Engorgio publisher edition and a hash-pinned
Compact Storage ePrint mirror copy; the official download's 403 is retained.
No author implementation or published speedup was reproduced.

The strongest objection to the leading candidate is already concrete:
**dynamic packed search plus cached representations is known**. The experiment
must show that a particular authenticated version split changes paid execution
after a strong specialization has the same upload and reuse opportunities.

## One conditional extension: authenticated composite snapshot reuse

**Trigger:** R3 attributes a limiting paid cost to refresh or update-to-next-answer,
and calibration predicts a useful benefit after extra response/query costs.
The old rebuild time does not satisfy this trigger for the selected graph.

Keep the feature-major encrypted base immutable. Represent current values of
changed rows in a separate owner-authenticated layer. A signed descriptor binds
`(base root, ordered IDs, overlay root, latest-row map, key/profile, epoch)`.
The latest map assigns each ordinal exactly one authoritative value: its current
replacement row or its base row. Bind evaluation to the **same original query**
and complete current recipe. Authorize the old base as its component; never
relabel old ciphertexts as freshly encrypted current inputs.

### Mandatory partial-owner control, before choosing encrypted tiles

For a replacement map `U`, verify/decrypt the canonical base distances `h`,
then set `h_current[r]=HD(q,U[r])` for replaced ordinals and leave all others
unchanged. This is exactly the composite snapshot's full distance vector;
compute stable top3 afterwards. Only changed rows need to be retained. For 32
rows of 512 bits their value body is 2,048 bytes, plus actual authenticated
delivery, mapping, version and framing. A returning owner already has its
updates; a fresh device must acquire/provision this partial layer. Charge both.

This removes new HE products on the changed rows and the extra tile response.
The current full-cache patch API cannot be assumed to implement a partial
cache: build its actual adapter and complete recipe/frame binding. Both local
and encrypted replacement variants require freshness, complete coverage and
authorization before private base decoding. There is no reason under the
current owner contract to prohibit local popcounts on those rows.

The encrypted-tile variant therefore must survive **partial-owner replacement**
as well as selective server refresh and full-cache/prefetch controls. If it
does not, choose the useful local layer for the company system and close the
encrypted-update headline. Ordinary client correction/base-plus-delta storage
is also known; its usefulness does not by itself establish a new paper main.

### Revised coefficient layout and public feasibility

Let `u[j]=1-2*q[j]`, `v[r,j]=1-2*x[r,j]`, `d=beta=512` and `t=1031`.
The existing query is `A(X)=beta^-1*sum_j u[j]*X^j`. For at most 32 rows use

```text
B(X) = sum_(r=0..31) sum_(j=0..511) v[r,j]*X^(512*r+511-j)
[X^(512*r+511)] A(X)B(X) = beta^-1*sum_j u[j]*v[r,j] (mod t).
```

The preceding plan's spacing 1024 was sufficient but unnecessary. Spacing 512
allows adjacent product supports to overlap, but they miss each other's
selected middle coefficients. The maximum degree is 16,894; negacyclic wrap
affects coefficients 0..510, whereas selected exponents are 511,1023,...,16383.
The bounded public screen checks every basis contribution for both layouts
and all 513 possible distances. Multiplying the selected coefficient by beta
modulo t and centering recovers the unique score in `[-512,512]`, then distance
`(512-score)/2`. This is known convolution packing, already present in our
homemade shallow reference, not a new identity.

Using retained owner-sampler boxes and one canonical30 relinearization gives
conditional Q/P bounds for the direct tile product; the public terminal bound
is 8,446,469, below `P/2`. This does not admit a future native graph, establish
its representation refinement or approve cryptographic parameters.

| Exactly 32 changed rows | Seeded coefficient body B | Added terminal body B | Extra product/relinearization |
| --- | ---: | ---: | ---: |
| Direct replacement of 512 feature columns | 125,829,120 | 0 relative to base | Existing graph |
| Earlier guarded proposal, two tiles | 491,520 | 204,800 | 2 |
| Revised contiguous proposal, one tile | 245,760 | 102,400 | 1 |

Headers, seeds, manifests and protocol traffic are additional. The 512-fold
body ratio compares only the direct feature-replacement protocol. The strongest
dynamic baseline already receives compact row uploads. No speedup follows
from that ratio. With the literal terminal codec, the 32k base response body
grows from 204,800 to **307,200 bytes**. The extension trades update/state work
for more query/download work. Auxiliary plaintext correlations and wrap are
authorized owner data; they require an explicit overlay decoder grammar,
rather than the existing base-only zero-tail predicate. Selecting a few
ciphertext coefficients before decryption is not a valid free response codec.

### Implementation, invariant and strongest control

First specify the composite-snapshot authority and implement its partial-owner
replacement adapter; leave the canonical baseline intact. Add the encrypted
tile/native admission/owner decoder only if its public discriminator shows a
credible benefit against that control. Reuse the existing relin key where its
relation applies and add no query expansion for a tile. Bind actual common-Q
sources, all maintenance, full terminal frames and latest-row coverage.
Updates replace the current entry rather than adding unbounded delta chains.
Freeze one cap and compaction law before timing; charge compaction.

The server-refresh control gets compact row uploads, valid public transposition/
cached refresh, unchanged-group reuse and the best applicable PPMI specialization. If it
requires different evaluation keys, noise bounds or input origin, supply and
pay that adapter; do not mark it impossible merely because our current code
lacks it. The permitted owner cache gets the same compact patch.

Freeze the new frame and public bounds, then register one future cohort. The
existing proposal is two fresh keys × two process blocks × eight post-update
queries, **32 observations per variant**, with separately budgeted warmups,
update checks and every encryption/preparation/signing attempt. These are
proposed slots, not current Q77 consumption. Fix actual variants after the
public invariant gate: strong immediate refresh, partial-owner replacements,
one surviving composite variant, its same-output base-rebuild ablation and the
full-cache control. Do not reserve a timing row for a stopped encrypted variant.
Use repeat-overwrite/stale-map/omission/swapped-ID/mixed-epoch/late-substitution/
wrap/codec faults as correctness obligations under a separate bounded gate.

The serial predictor is `saved refresh > queries*extra query cost + extra tile
preparation`. Use calibration to freeze its crossover/compaction decision;
held-out whole traces with actual overlap decide whether it is useful. Require
a useful region against the strong dynamic and partial-owner controls, an
explanation of the losing regimes, and the base-reuse ablation. If ordinary known
specialization obtains the same result, close the proposed new-algorithm claim.

### Alternatives selected by R3, not additional experiment queues

If construction/admission dominates, choose **one mixed common-Q boundary**:
move one contiguous expansion or maintenance segment, bind its original-query
ancestors and verify all downstream coordinates. Predict and then ablate the
transforms, CRT/digit work, witness traffic and state removed. Grant the same
boundary and reuse freedoms to replay/delegation. A generic cut or signed
unchecked root is not the result.

If protected-state capacity at a justified scale dominates, choose **one streamed
snapshot** with the same streaming/prefix reuse for controls. Larger scale
requires a separately frozen registration. The list does not authorize three
parallel extensions, a parameter search or a proof-backend grid.

## Finite build and evaluation sequence

| Step | Deliverable and location | Exit condition / next decision |
| --- | --- | --- |
| R2, current implementation | Finish `complete_cost_tenant.py` and `complete_cost_owner_study.py` using the existing owner/coordinator/relay/supervisor modules; complete honest provisioning, independent sessions and guards. | One runnable cohort action, meaningful bounded public integration gate, exact execution addendum committed before HE work. |
| R3, reserved selection study | Two keys × sizes 8224/16384/32768 × three fresh process blocks × eight queries: 18 blocks/144 observations per trajectory. First six blocks/48 queries calibrate; twelve/96 are held out. | Freeze policies before held-out. Return actual complete costs and bottleneck, including failures and cache utility. |
| R4, one creative extension | The one mechanism selected above, admitted graph, strongest adaptation, whole-execution ablation and new finite registration. | Useful held-out region and surviving prior-work distinction, or close the claim and preserve the engineering artifact. |
| Q78, assurance/deployment | Conditional reduction, native refinement, parameter/private-leakage review, real attested authority and rollback/revocation tests; matched GPU path if used in the final claim. | Complete premises and real deployment evidence before a secure-service or GPU-service performance claim. |
| Q79, final paper/artifact | Additional justified workloads/deployment evaluation, strongest counterconstruction, external originality/security review, reproducible artifact and paper. | One precise defensible finding with winning and losing regimes. |

R2 is partially implemented: actual trajectories, HE-independent cache/races
and compact public update assembly pass their public gate. Honest tenant
provisioning and the full launch are absent. Complete these rather than creating
another instrumentation-only milestone. The new launcher registration reserves
eight further public cases within the parent cap; no actual HE work has run.

R3 compares three independently prepared remote modes, returning/fresh cache
and racing acquisition. For each mode, charge actual provisioning, setup,
initial upload, query/receipt traffic, verification, private decoding, updates,
retained state and cleanup. Shared client directions must account for contention
between search and acquisition. Join/charge losing work. Prefetch closes remote
use before its cache-only update. No forced HE download on a cache path.

Use equally weighted paired process-block results and actual owner
completion-minus-arrival as the primary metric. Report cold/first answer,
steady queries, update-to-next-answer, CPU/GPU work, both link directions and
peak live state separately. Do not sum stage medians to fabricate overlap.
Keep failures, timeouts and contaminated blocks without replacements. Native
clock projections are attributed intervals, not a separately measured bare
evaluator baseline. The two-key synthetic cohort is a selection study, not
the paper's entire workload or population-confidence argument.

Historical caps remain unchanged and unconsumed. The pending exact-addendum
proposal is 702 fresh query encryptions, 72 protected signer contexts, 31,744
feature encryptions and two HE keys; it does not activate those budgets here.
Retain the 8 GiB additional-artifact ceiling, source/binary/dependency pins,
attempt-before-work accounting, <=1 s public telemetry, owned process custody,
deadline/memory guards and the granted idle-window discipline. Cooperative
guards are not hard instantaneous memory limits.

Policy selection gets only calibration information available to a deployable
policy. Grant the generic selector the same legal choices, horizons and data;
report a retrospective minimum as an oracle diagnostic. The 20% remote-policy
project threshold is separate from cache utility and research originality.
A complete randomized vFHE adapter remains mandatory before broad superiority
over delegated verification; otherwise explicitly limit the claim to the
deterministic paths actually run.

## Supporting security and deployment work

Specify an ideal functionality for the owner's current snapshot, exact full
distances, stable ordinal top3 and abort. Declare public shape, sizes, changed
ordinals, scheduling/compaction and feedback leakage. Overlay row identities
must not silently be assumed private; hiding them would be a different paid
protocol. No malicious client/data-origin claim is included in the honest-owner
contract.

Build the argument in four layers:

1. **Refinement:** accepted complete common-Q arithmetic/maintenance equals the
   authorized graph's canonical evaluation, including actual limbs and terminal
   parsing. For overlays prove selected-coefficient correctness and one latest
   value per ordinal, even though an older base is reused.
2. **Correctness:** honest origin, exact encoding and public noise/terminal
   bounds imply every accepted private decode is an exact permitted output.
   Previously successful decryption and server metadata do not prove this.
3. **Authorization:** snapshot/request/IDs/code/frame binding, freshness,
   at-most-once consumption and crash/rollback behavior restrict private work to
   the currently authorized result. The whole base-plus-overlay recipe advances
   atomically; mixed epochs and delayed old replies cannot reach private work.
4. **Privacy:** public rejection paths are independent of the HE secret and
   accepted private operations only process authorized outputs. Condition the
   hybrid/reduction on the actual augmented RLWE/evaluation-key assumptions,
   seeded sampling, signature/hash security, admitted execution and leakage
   model. Explicitly account for adaptive attempts and multi-key lifetimes.

This is a prospective conditional argument, not a finished reduction. IND-CPA
alone is not CCA security, and post-decryption result checking is not the
oracle defense. The twelve existing Lean model lemmas do not prove C++ or
private side-channel behavior. Validate actual distributions/parameters and
private sampler/arithmetic access before production use. For randomized
admission derive its concrete actual-prime lifetime failure probability; do
not transfer a single-check bound to an adaptive service unchanged.

AWS deployment must bind measured code and the result-signing key to an
owner-verified attested channel with currentness/revocation and a nonrollback
authority. [Nitro's documented isolation and lack of persistent storage](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html)
mean an ordinary parent SQLite file is not trusted durable enclave state.
Owner-maintained monotone version/consumption state is one candidate; define
multi-device synchronization and crash semantics before selecting it.
Charge actual enclave transport/provisioning. A GPU producer may remain
untrusted and have its outputs checked; trustworthy GPU attestation is a
separate optional trust adapter, not assumed by the current prototype.

## What will make the paper ready

The prospective headline is a substantive authenticated version/reuse execution
that improves complete exact search after compact upload, selective refresh and
partial-owner correction are already granted to the baseline. This distinction
is unestablished. Fill a claim card with the actual change,
its invariant, prior construction extended, displaced work/bytes/state,
held-out regions, ablation and strongest objection survived. Finding no
identical paper in this targeted search is not an originality proof.

The final artifact needs multiple justified workloads/update distributions,
real attested deployment, matched GPU evidence if claimed, all complete costs,
and an external cryptography/systems review. Avoid a new result for each
kernel optimization. Use figures for the execution dependency graph,
update/query crossover, first-answer/cache frontier, work/traffic/state and
assumption map. If cache or the compatible prior composition absorbs the
whole result, keep the company system and close the positive research headline.
A negative paper needs a generalizable new explanation, not just a slow
prototype. Do not promise conference acceptance from implementation success.

The remaining packages are **Q77 evaluation/one extension, Q78 assurance and
deployment, Q79 paper**. There is no remaining broad preliminary portfolio.
After each task, preserve inputs/commands/failures/scope/checkpoint in the ledger
and return here. **Next implementation: finish R2's honest tenant and full
cohort launch, then commit its exact pre-HE freeze.** This planning review does
not complete that dependency or reserve additional encrypted experiments.
