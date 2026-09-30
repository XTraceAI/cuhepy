# From the experiment portfolio to a system and a paper

2026-09-30, `experiment/creative-search-algebra`. This consolidates E01–E40;
the individual reports and raw observations remain the evidence. The latest
[E36–E40 report](verification-frontier-results.md) supplies paired measurements
and mathematical controls. The company implementation and earlier checkpoints
remain available.

## Decision supported by the evidence

Build two explicitly selected paths around our homemade arithmetic. Retain the
general BGV/CUDA circuit for workloads without useful structure or trusted
correlations. Develop the response-transposed, one-use query-space circuit as
an experimental option when its preprocessing, retained plaintext coordinates,
client disclosure and epoch lifetime are acceptable. Select a representation
using complete cost and contract checks, rather than choosing it solely by
rank, server kernel time or response size.

The best paper candidate is the **joint representation/verification/lifetime
frontier for exact outsourced search**. A possible contribution is a useful
algorithm and analysis for choosing private query spaces, final CRT geometry,
plaintext/ciphertext fields and complete verification together. The known
ingredients and a fast implementation do not establish originality. A second
candidate is a narrowly stated set of obstructions and constructive alternatives
for authenticated correlations and output summaries. These need comparison with
the closest work before becoming contribution claims.

“All possible hypotheses” is not a finite scientific objective. This document
closes the current portfolio's inexpensive discriminating tests where possible,
records unresolved tracks, and specifies the evidence that would advance or
abandon them. It does not label unimplemented CKKS, TFHE, MPC, correlation
generators, full GPU verification or real AWS deployment as completed work.

## What the accumulated experiments establish

`Measured` below means a retained encrypted comparison within its report's
stated contract. `Oracle/model` means exact small arithmetic or accounting,
not production latency. A negative result applies to the tested construction,
not every possible algorithm in that area.

| IDs | Hypothesis and evidence | Consequence for the system / research |
|---|---|---|
| E01 | Partial encrypted reductions spend spare response capacity to remove switches; homemade CPU/CUDA measurements exist. | Keep as a planner choice. Charge extra reply coefficients and owner work. |
| E02 | Native/private-owner references, seeded queries and one-use offline work reduce client cost. | Preserve fresh errors and token lifetime. Small seeded packets are computational encodings, not information-theoretic pads. |
| E03 | Cached transform representations remove repeated index transforms. | Useful for immutable/resident indices; memory and update preparation belong in setup. |
| E04 | Persistent workspaces, GPU terminal output, fusion and batches have measured gains and losses. | Retain the winning measured modes and single-query controls. Throughput does not imply lower request latency. |
| E05 | Narrow-limb NTT comparison is implemented; wholesale alternative switching is not justified by that microbenchmark. | Keep standalone arithmetic evidence; require a complete circuit before adopting new limb/key formats. |
| E06 | Coefficient correlations and trace/butterfly collection are implemented through homemade BGV. | Established packing ingredients; useful general-data baseline. |
| E07 | Feature-major encrypted reference and delayed accumulation are implemented. | Extra encrypted query/key representations must pay for themselves; ordinary deferral alone is insufficient. |
| E08 | Shallow BGV avoids the BFV scale-and-round circuit; complete native/CUDA comparisons exist. | Retain BGV as the fast general circuit, with independent correctness and security review. |
| E09 / E18 | Stable selection and sparse encodings have exact oracles. Complete RLWE-to-Boolean selection is unimplemented. | Output-only top-k remains a separate protocol track. Include conversion, comparisons, IDs, ties and authentication. |
| E10 | Exact lower-bound filtering and whole-tile refinement work locally. | Certification, poor bounds, access patterns and dependent rounds can cancel pruning. |
| E11 | Measured layout/precision planners exist; E39 adds explicit contract and pool gates. | Choose only among compatible measured candidates. Model extrapolations separately. |
| E12 | Exact factorization/folding is tested; unrestricted approximate sketches/CKKS remain proposals. | A fast approximate shortlist is not exact unless every omitted candidate is covered. |
| E13 | Full tensor-product/switch subcircuit checks and direct-RNS GPU boundary measurements exist. | This is not complete GPU authentication; remaining reduction/rounding relations must also be checked. |
| E14 | Arithmetic relations, scalar/CRT complete linear checks and E37 known fingerprint alternatives are implemented. | Co-designing the circuit can eliminate difficult verification boundaries; trusted preprocessing remains essential. |
| E15 | Coefficient-specific support models justify deterministic precision choices. | Preserve the complete bound and negative dependency controls; observed small noise is not a certificate. |
| E16 | Balanced/direct-distance radix, joint precision and word codecs have complete measurements. | More useful scores per reply can win; larger fields, conversion and setup can also lose. |
| E17 | Owner-prepared gadget and restricted masked-query conversion have tiny encrypted references. | The most promising form is conversion directly into the required query space; literal source/key growth is retained. |
| E19 | Syndrome/weight and certified low-rank lookups have exact controls; literal encrypted lookup remains expensive. | Keep as a coverage research track. Selectivity alone is not a server-work or privacy win. |
| E20 | Secret-expression and encrypted deferral experiments show ordinary deferral saves no switches here. | Do not optimize an invalid projection schedule or ignore transformed secrets. |
| E21 | Literal answer-polynomial circuits lose to packed scores; rank/tie controls are retained. | Require a different output construction before further optimization of this circuit. |
| E22 | Redundant-coordinate folding and index-specific dictionaries win on favorable data, fail on unstructured controls. | Use index-only proposals and charge per-row exception/state costs. |
| E23 | Trusted interval discovery and complete native/CUDA two-round refinement are implemented; charged subset work loses. | Extra RTT and subset preparation must be included. Revisit only with a new cheap coverage/refinement mechanism. |
| E24 | Exact witnesses can share otherwise unused response support. | A useful circuit ingredient; it does not authenticate omitted rows or create free output capacity. |
| E25 | Owner residuals reduce server work; compressed hints can approach compressed full-data size. | Always retain full-cache/local-scan controls. Encrypted residual lookup is only a costly scalar control. |
| E26 | Local affine maps and full-ring CRT multiplexing improve CPU time; GPU totals improve much less. | Map density, padding and client transforms explain limits. Different block queries need not mean different ciphertexts. |
| E27 | Rank-boundary repair, unequal CRT capacity, full affine caching and one-row update controls are implemented. | Good data-specific representation; an insertion can double fixed-layout work. Capacity and update cost matter alongside rank. |
| E28 | Homemade matrix-BGV/noncommutative secret-source oracles and 148 state/count models are retained. | Native matrix CUDA remains unjustified without a favorable source/key/capacity inequality. |
| E29 | Reply-transposed encrypted columns plus fresh one-use encrypted answers remove online ciphertext products/switches. | This changes the preprocessing/state contract. Complete full-Q checking becomes linear; index/token authenticity is not supplied by that equation. |
| E30 | Common/residual query directions trade client/check state against encrypted index size. | Simple sharing is useful in some regimes. Public linear mask-bank expansion leaks joint query relations. |
| E31 | Hierarchical sharing reduces query coordinates but increases state/latency on measured data. | Query-only savings are tiny when the response dominates. Keep equal-form merging as a strong control. |
| E32 | Exact CBD finite-batch bound enables q32 with 20% smaller bodies. | Restricted to queries fixed before enrollment; the separate type prevents silently granting adaptive correctness. |
| E33 | Correlation functionality and two-field carry/false-accept controls are specified. A secure generator is unimplemented. | No drop-in PCG/VOLE shortcut. Account for fresh encryption, private matrix handling, authentication and field conversion. |
| E34 | Fresh ideal pads give exact independence; reuse, early disclosure and mask selection break it. | Real encrypted-transcript privacy is a proof obligation. The deterministic E35 correctness bound does not need ideal error independence. |
| E35 | Private rank discovery separated from final CRT roots permits independently refitted smaller fields and deterministic adaptive q32. | Same 20% body reduction with a broader query schedule. Full frontier work, unused tokens and a larger checker are charged. |
| E36 | Exact/projective Lee-norm bounds and expectation/witness lower limits are implemented. Real layouts show small or no improvement and no new byte boundary. | Stop relying on norm tightening alone for the next IO jump. The obstruction concerns one bounding method, not actual HE noise. |
| E37 | Exact native control, GMP/native polynomial fingerprints and lossless Q-bit bodies have full-size paired searches. | Recover the verifier bottleneck while measuring the known-family alternative fairly. No secret HE key enters the new C++ code. |
| E38 | Valid one-hot schema diameter is smaller than bit dimension; query violations and CRT-root limits are tested. | Range and slot geometry must be chosen together. Smaller scalar fields can require a much larger index. |
| E39 | Valid Hamming moment/histogram counterexamples, exact coverage tests and contract-filtered cost models are implemented. | Distance-only summaries cannot generally recover exact stable IDs/top-k. The planner cannot substitute a different trust/output contract. |
| E40 | Fixed certified maps are reallocated across ring degrees; exact plaintext embedding and body models retain rejected small leaves. | Smaller N can require more replies and leave traffic unchanged. Changed-N candidates need fresh parameter assurance and actual encrypted measurements. |

The first sixteen directions' reports are linked from the
[sandbox README](../../experiments/bfv_search_lab/README.md). Later cycles have
individual reports in this directory. This ledger distinguishes experiments
from unsolved scheme-conversion and protocol questions.

## Measurements that can be combined, and those that cannot

The [earlier general-data GPU study](bgv-compute-followup.md) used 8,192 vectors
of 512 bits, N=16,384 and its depth-one Q120 circuit. Its paired compute total
fell from 66.92 to 46.76 ms. A later owner-index precision study measured
47.22 ms locally and 198,863 framed query-plus-response bytes. These are
historical measurements within those studies, not fresh E37 measurements.

E29–E39 use a different circuit and state contract. E37 uses 7,996 Mushroom
rows at 126 bits or 1,465 Semeion rows at 256 bits, two held-out splits, full
N=16,384, fixed eta=21, three Q/field profiles, and complete checking before
decryption. Its local totals are paired sums of measured stages. A table
putting those times beside the 8,192×512 GPU study without this distinction
would not be a speedup comparison.

The [new report](verification-frontier-results.md) compares, on the same
queries, old GMP checking, the same check in C++, GMP polynomial hashing,
native polynomial hashing, old byte bodies and exact bit bodies. The native
control is necessary: an implementation-language gain is not evidence that
the alternative hash family is intrinsically better. Four gates in the
experiment check one response; a deployed candidate would run one gate.

The E39 link/pool planner uses recorded stage medians and exact body counts.
It pays for all nine prepared tokens at utilization 1/9, 4/9 and 9/9 and
refuses extrapolation beyond that pool. The 1/10/100/1,000 Mbps link scenarios
are serial models, not measured networks or pipelined throughput. Actual
framing, authenticated provisioning, persistent journals, memory allocation,
key delivery and service scheduling need separate measurements. Canonical
state bodies are not Python or native resident memory.

## Proposed system architecture

The current modules stay independent until their contracts and format are
reviewed. Package BFV/Paillier remain the company fallback; the general BGV
research path remains an independent homemade reference.

| Component | Existing implementation / next concrete interface | Required invariant |
|---|---|---|
| General encrypted evaluator | `shallow_bgv.py`, `native_bgv.py`, `_native`, `owner_bgv.py`; later opt-in package adapter | Exact full scan, fresh query encryption, compatible parameter/context binding; no unchecked GPU receipt |
| Representation compiler | `affine_dictionary.py`, `rank_partition.py`, `field_frontier.py`, optional shared/hierarchical bases | Index-only proposals; every enrolled row certified in the chosen field; roots required only by final CRT cover |
| Reply-column evaluator | `crt_masked_bgv.py`, `crt_native_bgv.py`, `_subring` | Canonical full-Q output, pinned schedule, same GMP/native coefficients, absolute honest-circuit phase bound |
| Offline token producer | Current trusted owner `prepare`; future authenticated owner service | Independent fresh answer encryption, epoch binding, hidden seeds/tags, no future-query inspection |
| Complete response check | Existing `EpochCheck`, E37 native same-family control, explicit polynomial alternative | Trusted columns/tokens, hidden independent check key, fixed reply shape, total attempt budget, check before decryption |
| Public body codec | E37 `coefficient_body.py`, independent GMP reference | Exact Q bits, pinned count/Q, zero padding and every residue checked; no unauthenticated new remote API |
| Contract/cost selector | E39 `portfolio_costs.py` plus existing measured layout planner | Match output/trust/state/epoch requirements before ranking; production-ineligible profiles rejected by default |
| Lifecycle store | New isolated persistent epoch/token/attempt store after protocol review | Durable consume before releasing delta; crash, retry and rollback cannot restore a released mask |

For each index epoch, enumerate a bounded set of raw/global/local/shared
representations. Fit and certify maps afresh per field; do not reduce a map
from another field and call it a certificate. Allocate final factors and reply
capacity. Derive an honest-circuit phase certificate and complete-check policy.
Measure enrollment, resident state, token work, complete online stages and
updates. Cache the selected immutable plan under an owner-authorized epoch.
Retain a compatible full-scan plan when compression or state budgets fail.

Offline plaintext coordinates are real owner/service state. Moving that state
off the online device does not make it disappear. A full plaintext cache may
already answer the small public workloads in milliseconds; any outsourced
system must explain why that cache is disallowed, too large, undesirable or
outside the intended device/service separation.

## Attested correlation factory: the most concrete protocol experiment

The current owner computes `M*r` and freshly encrypts it. A proposed factory
can move **this offline matrix computation** into an owner-approved enclave,
without duplicating every online query. It is a separate trusted service,
not a verifier that repeats the server search on each request.

Proposed boundary: the factory is authorized to hold private coordinates `M`
and generate fresh `r` before a query exists. It sends the bound plaintext
`M*r` and private token seed to the owner over an attested authenticated
channel. The owner freshly encrypts the result and prepares its hidden check
material. The untrusted search server receives only the encrypted answer,
delta and public schedule. This keeps the owner's HE secret outside the
factory, but trusts the factory with coordinates and masks. A factory that
later exposes masks to the search server exposes transformed queries.

AWS documents measurement-based identity and optional nonce/public-key/user
data fields; those identify a running enclave and support a protocol, rather
than proving an arbitrary GPU result correct. Our epoch, session, channel and
token binding would still need implementation and review.
[AWS attestation validation](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html).

First local experiment: authenticated factory/owner/server messages with epoch
and token digests, a durable consumed-state journal, and malicious substitution,
stale token, concurrent consume, crash-before-send, crash-after-send and rollback
controls. Measure producer work, owner encryption/checking, token packets,
unused pool storage and one-row epoch changes. Synthetic local attestation
must remain labeled synthetic. The next hardware experiment uses a reviewed
AWS image and measured provisioning; none has been launched by this cycle.

In parallel, retain the E33 two-helper/PCG and rerandomized-encrypted-index
alternatives. They need a complete share-to-fresh-BGV-token construction and
field/carry checks; the factory is a pragmatic baseline, not a proof that these
alternatives cannot work. See the
[authenticated correlation contract](authenticated-correlation-contract.md).

## Candidate proof structure, with unresolved premises

This is a proof agenda, not a claimed reviewed security theorem.

1. **Representation exactness.** Prove affine enrollment reconstruction, query
   contraction/anchor identity, full CRT embedding and all-row coverage. These
   identities have independent oracles and full encrypted agreement tests.
2. **Adaptive honest correctness.** E35's absolute phase bound holds for every
   centered correction in the declared public space, regardless of how the
   query was selected. It does not require E32 independence/concentration.
   This is correctness for the honest prescribed circuit, not authentication
   of a malicious server's bound or parameter-security assurance.
3. **First false acceptance.** Condition on trusted preprocessing, hidden
   independently selected check key, canonical fixed-shape responses and a
   bounded verification-only transcript. Prove the complete relation's error
   vector is nonzero for an incorrect response. Use either ideal-vector
   `B/Q^r` plus the seeded-challenge PRG hybrid, or the irreducible-polynomial
   factor count `B*floor((L-1)/d)/I_Q(d)`. Private timing and public tags are
   excluded premises, not consequences of that bound.
4. **Replace secret decryption by ideal scores.** Until the first false
   acceptance, accepted responses equal the intended complete ciphertext;
   the deterministic correctness certificate then gives the exact scores.
   Rejected responses use no HE secret. A game replacement could simulate
   subsequent query policy from ideal scores rather than expose a challenge
   decryption oracle. This step must specify which outputs/failures the server
   observes, including subsequent retrieval IDs and legitimate output leakage.
5. **Encrypted-transcript privacy.** Attempt a multi-message IND-CPA hybrid
   replacing independently encrypted offline answers with encryptions of zero,
   followed by fresh-pad independence in the hybrid. The simulator needs the
   prescribed owner input/ideal functionality and all trusted setup bindings.
   Current query selection must not inspect its mask seed or reuse/select masks.
   Explain correlated encrypted columns, adaptive earlier outputs, private
   transforms and token consumption. A uniform-delta marginal alone is not
   this argument. An ordinary IND-CPA statement does not certify the homemade
   parameters or private implementation.

Explicitly test proof assumptions: public polynomial keys admit a constructed
collision; repeated/randomly mixed public pad banks leak relations; tags or
current-mask-dependent query selection defeat the intended model; unreviewed
malicious preprocessing invalidates the complete-check premises. Limit the
theorem to the implemented transcript and disclose approved leakage. Do not
present tests, conditional integrity, attestation or a candidate hybrid as a
complete privacy/CCA/side-channel theorem.

## Contribution ledger and closest work

| Candidate claim | Known ingredients / closest reading | Evidence we have | Missing acceptance gate |
|---|---|---|---|
| Joint private query space, CRT occupancy, fields and verification planner for exact search | HE SIMD/CRT, affine factorization, Slalom preprocessing, existing HE compilers | E26–E39 identities, failures, full-size comparisons and contract models | Closest-work reproduction, precise algorithm/objective, larger data/scaling, complete trust/leakage model |
| Lifetime-aware authenticated reply-column protocol | One-use blinding, secret Freivalds/Rabin hashing, outsourced linear algebra | Independent whole-coefficient checks, forged/replayed/stale controls, E34 ideal failures | Reviewed transcript proof, authenticated setup, durable state, malicious-preprocessing argument, private timing/parameters |
| Search-specific obstruction/control suite | Classical Lee metric, Prouhet partitions, finite-field factor counts, public linear-kernel leakage | Exact finite counterexamples and quantitative real-layout limits | Identify a nontrivial new restricted theorem or useful sharp frontier; avoid claiming classical lemmas as new |
| Homemade GPU/native system artifact | Many prior GPU HE systems and packing implementations | Existing exact CPU/CUDA comparisons, Nsight profiles and retained sanitizer controls | Same-workload/security comparisons against current external systems, complete authorized request timings |

[Slalom](https://arxiv.org/html/1806.03287v2), Sections 3.2–3.3 and Appendix B,
is the closest preprocessing/integrity context; its neural-network setting
does not itself prove our encrypted-index protocol. Merely adding HE to a
known masked linear check is not an originality argument.

[SANNS](https://www.microsoft.com/en-us/research/wp-content/uploads/2019/04/SANNS-Scaling-Up-Secure-Approximate.pdf),
Sections I, III-C and IV-B, gives an especially useful comparison: coefficient
dot products avoid batching-root constraints, and selection uses a mixed
protocol. Its semi-honest, approximate Euclidean-search and server-held-data
contract differs from our exact owner-encrypted search. We read these portions;
we have not reproduced its performance or malicious-security properties.

The E36 objective is a maximum Lee weight of a linear image. The centered-lift
metric is classical; see Definition 2.1 in
[Verma and Singh](https://arxiv.org/html/2507.17654v1). Their function-correcting
coding problem is different; neither their minimum-distance results nor our
average-weight calculation establish a new cryptographic lower bound.

The E37 families and E39 equal-power-sum construction are identified in the
new results report. Novelty search still needs complete comparison against
authenticated outsourced linear algebra, preprocessing PIR/correlation
generators, search-specific packing, and output-private secure selection.
Abstract-only leads in the [literature agenda](encrypted-search-literature-agenda.md)
remain leads, not reviewed constructions.

## Prioritized unresolved experiments and stopping rules

| Order | Discriminating experiment | Advance if | Abandon / retain as negative if |
|---|---|---|---|
| 1 | Complete E34 transcript/game specification and E33 attested-factory local lifecycle prototype | Proof premises map to actual messages/state and crash tests preserve one-use semantics | Simulation needs a forbidden decryption oracle, public tags, current-mask selection or unpriced trusted online search |
| 2 | Same-data general BGV/CUDA vs reply-column CPU/GPU, with one chosen complete checker and real state measurements | A compatible verified request wins after token utilization, setup and owner-cache controls | A fast kernel loses on owner/check work or the changed-state deployment is unjustified |
| 3 | Representation compiler with exact small optima and larger index-only trajectories | A new greedy/DP/relaxation approach improves the joint frontier or has a useful guarantee | Benefits are explained entirely by existing merging/rank/padding controls |
| 4 | Update-stable correction layers or bounded exception classes | One/few insertions avoid global rank/padding/token invalidation while preserving bindings | Selector cost, map disclosure or token migration cancels the gain; keep E27 update control |
| 5 | Output-private selection: exact Boolean/MPC/attested stable top-k with full coverage | Conversion/selection/proof total beats full-score transfer under its stated contract | Only approximate recall, unpriced comparisons, omitted IDs/ties or trusted access leakage produce the apparent win |
| 6 | Genuine two-field/correlation generator | Small complete authenticated share-to-token oracle succeeds with fresh errors and declared collusion | Missing carry/centering/rerandomization or public mask-bank leakage remains |
| 7 | Matrix HE / CKKS certified refinement / alternate exact modulus arithmetic | A proved identity and matched full cost crosses a current frontier | Literal key growth, unbounded error or recall-only evidence; no native backend before the oracle survives |

CPU native verification makes another public server speedup less dominant:
owner decryption/transforms and complete checking now matter. GPU work is
justified when it tests a new representation, verified relation or larger
throughput regime. It must retain an equally optimized native control and
charge transfer/initialization; a faster untrusted kernel cannot be signed
unchecked by the existing CPU Nitro path.

## Paper evaluation and outline

Use a single declared workload/configuration ledger. Include encrypted owner
data vs server plaintext, exact vs approximate output, full scores vs only
top-k, trusted preprocessing vs none, owner coordinate/cache state, query
adaptivity, access leakage, verifier transcript budget and update frequency.
Compare only within compatible groups; display changed contracts separately.

Evaluation grid: the pinned public datasets plus redundant and random controls;
held-out index/query splits and independent repetitions; 1k/8k/32k/128k or
larger rows where memory permits; dimensions 128/256/512; small rank-boundary
and update adversaries; several token utilizations and directional links.
Keep full-distance/stable-ID exactness, entire-coefficient GMP/native agreement,
warm/cold setup, p50/p95, owner/server stages, live memory, complete packet
sizes, error certificates and proof/attestation traffic. Larger scales and WAN
numbers are future measurements, not implied by today's small public data.

Baselines: matched homemade Paillier CPU/CUDA/lookup, package BFV, general BGV,
GMP/native reply columns, full plaintext cache where allowed, and explicitly
labeled SEAL/other external references. Add closest packing/search/protocol
artifacts after reproducing their intended contracts. Implementation ownership
does not remove the obligation to compare with strong external work.

Suggested manuscript structure:

1. Problem, owner/client/server contract and why verified end-to-end IO matters.
2. Closest work and the exact proposed difference; known ingredients credited.
3. Joint representation and response-column algorithm, with small worked example.
4. Exactness/phase/conditional integrity analysis and complete transcript theorem
   if reviewed; otherwise scope the paper to a systems/algorithm result.
5. Compiler/frontier and state/lifetime/update tradeoffs, including obstructions.
6. Same-workload CPU/GPU/IO evaluation, full setup, negative controls and artifact.
7. Limits: data dependence, caching alternatives, unresolved protocol/private
   assurance, parameter review and hardware-specific behavior.

Submission gate: at least one precise claim survives closest-work comparison;
the main claimed benefit holds with strong compatible baselines and full cost;
all theorem assumptions match the code/artifact. If novelty is only faster
Python-to-C++ arithmetic, retain the company optimization and choose another
paper question. Do not force a cryptographic primitive claim from useful
engineering progress.
