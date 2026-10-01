# Research plan: structured verified encrypted search

Revision: 2026-10-01, contribution reassessment after E77. Read the new
[closest-construction comparison](contribution-reassessment-20261001.md) and
[finite construction packets](construction-hypotheses-20261001.md) first.
This revision is planning only: no E78–E81 experiment has run, no protocol is
selected as a paper winner, and no security gate has passed.
The protected E01–E65 evidence remains frozen at `6207455`, tag
`checkpoint/publication-controls-2026-09-30`; the initial planning revision is
retained at `b60a715`. New bounded R0–R4/E70–E77 controls are recorded in the
[progress log](publication-progress.md) and
[preceding review](publication-mechanism-review-20260930.md) and
[E77 selection review](publication-mechanism-review-20261001.md).
These are executed oracles/pilots, not a new complete cryptographic protocol
or security approval.
The [preceding plan, through E65](publication-research-plan-through-e65.md)
retains the original hypotheses, gates and execution amendments unchanged.

## 1. Decision and intended contribution

Prioritize **exact, owner-private linear search whose structure survives the
complete verification protocol**. The first construction screen is now
**H1 / E80: subring-preserving outer verification**. It makes the E47/E68 idea
specific: choose a common query subring, express the operator and outer CRS as
module matrices, and investigate whether registration, admissible bounds and
finalization can retain that representation. The query width and complete
packing cost must remain paid. Scalar-coordinate layouts receive no such gain.

Use owner-generated registration as the first deployment mode: the owner
authenticates the index/digest and provisions private checking material once.
The construction packet includes a retained-digest outer-LHE control, with
verification before both decryption layers and explicit rounding-remainder
costs. Outsourcing this registration to an untrusted server is a separate mode;
its extraction/binding assumptions are not imposed on every owner-built setup.

The competing **H2 / E78** screen proves the composed original-query-to-answer
relation using E77's affine decomposition. Prior work already proves key
switching, uses ring proofs and batches their arithmetic; the new experiment
must eliminate work beyond those controls. **H3 / E81**, conditional on a range
proof bottleneck, asks whether bounded noncanonical traces can retain exact BGV
decoding. Existing relaxed CKKS proofs are its direct originality control.
These are hypotheses, not established constructions or announced contributions.

Do not build a bigger representation/lifetime optimizer as the next project.
Its current static and causal variants failed strong simple controls. Existing
affine/CRT layouts, native/CUDA evaluators, complete checks, decoders and
update controls remain valuable components and company results. A future
optimizer is justified only after we discover two useful, safely composable
protocol choices that create a real decision problem.

The paper should ultimately support one coherent statement of the form:

> For an explicitly defined class of encrypted linear operators, a new
> construction reduces a specified preparation, state or communication cost
> while preserving exact outputs and confidentiality under observable rejection;
> a homemade implementation demonstrates the resulting system tradeoff.

The missing words in that statement—operator class, construction, reduction and
measured effect—are deliverables. They must not be filled with an attractive
name or an isolated speedup. The system should select local caching when it
wins; a useful remote mode needs its own evidence. No current result establishes
a publishable novelty claim or an outsourced deployment advantage.

The [new construction packets](construction-hypotheses-20261001.md) specialize
the broader tracks in the [original agenda](publication-mechanism-agenda.md):

| Priority | Track | Cost it attempts to remove | Research discriminator |
|---|---|---|---|
| 1 | **H1: subring/module verified evaluation**, E47 → E68 → proposed E80 | Literal registration material and per-query trusted preparation | Closure through query, digest, admissibility and finalization; a new complete construction consequence beyond the module rewrite |
| 2, competing construction | **H2: composed expansion/answer certificate**, proposed E78 | Duplicate canonical expansion and private seed-factory work | An actual elimination of complete proof/state cost versus specialized ring/maintenance/batch proofs |
| Conditional mathematical screen | **H3: exact bounded trace freedom**, proposed E81 | Canonicalization/range proof overhead | Exact outputs for every admitted trace, with a new bound/representation consequence beyond published relaxed-maintenance proofs |
| Alternative | **B: authenticated correlation generation**, E69 | Per-query owner computation/provisioning for the existing fast online circuit | A complete fixed-private-matrix conversion with fresh ciphertexts and full-field authentication, beyond invoking a generic PCG |
| Alternative, explicit output change | **C: exact top-k with complete coverage**, E46 continuation | Sending every score | A cheaper way to produce and certify sparse winners, beyond known sparse-result compression or a standard selection network |

Safe response compaction, E66, is a required control and a shared protocol
obligation. It becomes a standalone research track only if it yields a new
constructive result beyond existing verifiable/compressed HE. E44 heterogeneous
contexts and E45 certified approximation remain bounded fallbacks. These
original experiment IDs retain their meanings.

## Current execution decision

The [bounded construction cards](protocol-baseline-cards.md) close R0's premise
mapping; the selected author client/server targets pass 59 unit cases and a
bounded native PIR control runs. That is not a matched malicious Hamming
reproduction. R1's recipe/decoder control and R2's real cache transfer pilot
have executed. E75/E76 now measure same-harness enrolled HE/cache RPC;
full private bootstrap, independent resources and optimized terminal compression
remain open.

R3's [operator](structured-operator-results.md) and
[registration](structured-registration-results.md) oracles preserve exact
structure, but elementary digit bodies lose and a universal gadget-limb
factorization fails. R4's [ideal random-triple control](fixed-matrix-correlation-reduction.md)
still needs the dense owner correction. Stop those specific shortcuts.

The bounded R3 alternative [E70](convolution-certificate-results.md) screens
public ciphertext-arithmetic certificates. Its known quotient/batching primitives expose
state/wire/RTT tradeoffs and unsafe NTT/point/domain/challenge-order shortcuts;
they do **not** remove the masked scheme's factory or pass Gates B/C.

[E71](encrypted-query-certificate-control.md) now instantiates actual encrypted
CRT queries, three-component evaluation and one-use private-point release.
All112 toy searches are exact, but the literal full-query/full-quotient variant
fails its wire screen:5.68–28.37× the old linear public body, before separate
private hint/ticket provision. A true output with one corrupted quotient also
exposes a single point's predicate; a wrong-output repetition bound does not
justify arbitrary verifier-point reuse under reactions.

The next bounded tranche has executed and changed the discriminator:

| Completed finite task | Result | Return decision |
|---|---|---|
| [E72 dense projected encrypted-query gate](encrypted-query-gate-control.md) |112 exact searches, no per-query owner answers/point hints, but large once-per-index private vectors | Strong known control; literal version stopped as a paper candidate |
| [E73 packed query expansion](packed-query-expansion-control.md) |112 packed +112 unpacked exact searches; actual query packets924→231 B; untrusted expansion does not bind original query | Keep canonical client-expansion control; keys/noise/duplicate work paid. Literal combined variant stopped |
| [E74 public-code programmed masks](programmed-mask-block-results.md) |81 products/42 CRT checks; surviving incomplete trial/entropy filters cost1.645x/1.727x actual block products | Stop this one-level public-code recipe before enabling it in HE; no security/impossibility claim |
| [E75/E76 actual enrolled service](enrolled-global-service-control.md) |112 mode queries across legacy/strong global panels; best HE returning medians46.79/15.78 ms still lose to permitted caches | Finite returning-client negative. Cold/new-client provisioning, separate endpoint resources and other regimes remain open |
| [E77 seed-conditioned affine gate](seed-affine-gate-control.md) |112 exact searches; online vectors4,096→512 B in toys, but factory retains old vectors/full fresh expansion; client+factory4.7–7.8% slower | Keep factoring identity/control; stop literal trusted-helper version as a whole-system winner |

Next R3 work is **E80's module closure/norm/full-cost card**, then **E78's
composed-relation card**, with a return to R6 after each. E77 makes the second
interface concrete: a public proof of an offset does not automatically supply
the receiver's private beta. A new construction must solve that interface or
retain/pay the factory. Both cards have an initial two-session allocation;
do not port a proof system before identifying the new step. E81 is conditional.
R4 correlations and R5 selection remain bounded alternatives.

R6 has no selected paper winner. The [current handoff](mechanism-execution-handoff-20261001.md)
defines finite next subcomponents, strongest controls and falsifiers; the
[previous handoff](mechanism-execution-handoff-20260930.md) remains historical.
No acceleration or production promotion follows from these controls.

## 2. Fixed contract and deployment questions

The [exact-search contract](exact-search-contract.md) remains authoritative.
The owner and querying client may retain all owned plaintext. The compute
server learns the declared public geometry, epochs, traffic and accept/abort
events; it must not learn the index or query values beyond that leakage.
The primary output is every exact Hamming score with stable IDs and local
top-3 selection. A returned item must belong to the pinned owner-approved epoch.

No query-dependent routing, extra noncollusion assumption, approximate answer,
server-visible candidate set or output-only selection is silently added. An
alternative gets a separate contract row before it gets a timing comparison.
Owner/client compromise and implementation side channels require separate
analysis. Availability cannot be guaranteed against a malicious server.

Treat client storage as a measured resource axis, not a fabricated restriction.
Compare three distinct starting states:

1. **Cold owner and client:** include representation discovery, keys, index
   creation/upload, private provisioning, authentication and first query.
2. **Enrolled server, new online client:** amortized enrollment is reported;
   charge every private map, ID table, verifier hint and token the client must
   acquire. Include an authenticated download-once cache from the same state.
3. **Returning client:** charge retained state, updates, token production and
   repeated queries. Include raw/compressed/mutable local caches.

Measure the resource frontier before claiming a customer need. A deployment
trace can later justify device memory, session duration, churn and link rates.
Absence of such a trace does not block algebraic research, but does block a
claim that the measured resource limit describes production. The existing
Paillier API establishes owner access; it does not establish a memory cap.

## 3. What the accumulated results say

These anchors were checked against retained reports and selected raw JSONs.
They use different workloads/profiles; **do not combine their speedups**.
The [E01–E40 synthesis](research-synthesis-and-system-roadmap.md),
[execution log](publication-progress.md) and
[claims ledger](paper-claims.md) retain the full chronology.

| Experiment family | Strongest relevant observation | Planning consequence |
|---|---|---|
| E01–E08, E26/E27 | Homemade CPU/CUDA and shallow BGV are strong foundations. Mushroom CPU roughly 639–640 → 206–214 ms, CUDA roughly 53.5–54.3 → 50.9–51.1 ms on the historical paired scope | Preserve the fast backend; a CPU algebra gain may leave GPU, client and wire costs dominant |
| E10/E19–E25/E39 | Lookup, filtering, moments and residual hints expose coverage, selection, extra-round or local-state costs; complete two-round refinement lost | A new selection proposal must solve the previously measured bottleneck, not repeat a filter-count argument |
| E29–E37 | Trusted fresh correlations make the online ciphertext circuit linear; field/geometry choices and native checking help | The main unresolved cost is the entire preparation/release protocol; hiding it in an offline column is not a contribution |
| E30/E31 | About 69–71% query-body reduction becomes only about 0.4–0.5% less total online traffic, with worse CPU/state | Optimize the actual dominant term |
| E43/E49 with stronger controls | Sparse repair costs 9.25%/7.88% more than vectorized fresh preparation; the initial factory speed advantage also reverses | Close these general speed claims; do not resuscitate a weak baseline |
| E54/E56/E59 | Private deltas save about 36–62%; selected tiles save about 28% only for localized edits; mutable cache still dominates its matched lifecycle | Keep these known controls in the system; they do not establish a new update algorithm |
| E57 | All 16 causal decisions choose ordinary deltas, adding policy/training cost | Defer further learned reserve/rebase policy work until a competing useful action exists |
| E61, 32,768 distinct Connect-4 rows | Affine BGV: 102.46 ms online CPU + 71.16 ms fresh answer/check, 262,144 B reply. Local cache: about 3 ms/query; zlib1 packet 305,261 B once, zlib9 247,388 B once | A whole cache can be smaller than a single reply here. Eliminate hidden preparation and measure cold acquisition before another remote-speed claim |
| Original author EMVP, E42 supplement | Added-gate cached CPU about 5.94 ms Mushroom / 1.36 ms Semeion, but replies 1,471,264 / 205,100 B | Serious CPU/communication competitor; same data alone does not align its assumptions or gate with our protocol |
| E47 | Literal full-Q outer matrix expands the index 32–64× in the reproduced layouts | Structure must survive the outer protocol; a literal wrapper is not the proposed innovation |
| E48/E53 | Public C1 reconstruction trades wire for client work; publishing related factory randomness can expose masks under a precise rank condition | Recipe provenance and seed visibility are protocol constraints, not interchangeable serialization choices |
| E62–E64 | Dedicated selected-phase decoding works in stated scopes; 112 split/legacy toy encrypted searches pass. C1/carry controls prohibit naive deletion/reduction | Reuse the correctness oracles; do not claim generic optimal compression or a reviewed protocol |
| E65 | Balancing plus one-row refinement recovers every tested static frontier | Stop the static optimizer as a leading contribution; preserve the negative result |

Sources: [affine/dyadic results](dyadic-rank-results.md),
[vectorized controls](vectorized-update-controls.md),
[larger real control](connect4-encrypted-controls.md),
[original EMVP](original-emvp-results.md),
[operator screen](backend-frontier-results.md),
[decoder](supported-decoder-results.md),
[static stronger controls](support-planner-results.md).
E61 is one warmup and three timed queries per HE profile, CPU only, research
parameters. It is not a service p95, a GPU comparison or parameter assurance.

## 4. Closest work determines the novelty boundary

The [current comparison](contribution-reassessment-20261001.md) adds construction
and proof-optimization controls to the [earlier comparison](closest-work-comparison-20260930.md).
It includes 18 comparison rows and separates executed author artifacts from
targeted reading, source-reported performance and missing adaptations.
The [source registry](publication-literature-sources.json) records versions,
targeted reading depth, hashes and actual reproduction status.

The essential comparisons are:

- **Hidden-matrix evaluation:** original EMVP and recursive BNTM, including
  client state, field/code dimensions and verification semantics.
- **Reusable verified linear evaluation:** ReinsPIRe/vReinsPIRe and small-state
  vPIR/vLHE, including the admissible database, extraction/norm assumptions and
  auxiliary-key lifecycle. Their plaintext server matrix could be our public
  ciphertext operator; that composition must be analyzed, not dismissed.
- **Safe/compact decryption:** maliciously secure vFHE, HELIOPOLIS,
  linear-decryption rate-1 HE, ZipPIR/additive-HE compression and downlink TFHE
  compression. Byte savings and verification alone are already occupied.
- **Correlation generation:** Slalom and programmable PCGs for matrix products
  and authenticated triples. A generator for random shares is not automatically
  our fixed private index, fresh encryption and two-field checker functionality.
- **Selection and packing:** SIMD-aware compression/SophOMR, SANNS, BioZKFHE,
  biometric lookup search, Fhelipe/Porcupine and recent polynomial compilers.
  Sparse compression begins after the hard predicate/coverage problem.
- **Proof construction and scheduling:** VeriSimplePIR's extraction/reuse,
  lattice-SNARK vFHE's delayed-switch schedule, approximate-HE ring/range proofs,
  and HasteBoots' batched arithmetic. These newly pinned controls narrow H1–H3;
  ordinary proof decomposition, batching and relaxed maintenance are already known.

Do not claim a missing feature from an unread proof. In particular, HELIOPOLIS
is a strong compression/verifier comparator with a different reaction-oracle
contract; its stated limitation is not a newly discovered vulnerability here.
The bounded unchanged vReinsPIRe author pilot now has local timings and59 unit
cases in the [baseline cards](protocol-baseline-cards.md). It uses random-byte
PIR, kappa40 and formula bytes; it is not a matched Hamming/full-paper result.

## 5. Execution sequence and bounded decision gates

Use the decision-task IDs R0–R7 in the
[work packages](publication-work-packages.json). They route work through the
existing P00–P12 packages; they do not mark unfinished packages complete.
An effort cap is a research allocation, not a promise of elapsed completion.
When exhausted, record the unresolved issue and revisit this plan.

| Order / task | Concrete output | Initial effort cap | Advance condition / stop rule |
|---|---|---|---|
| **R0: baseline contract closure** (P00/P01/P07) | Construction-level cards for strongest vLHE, recursive BNTM and relevant compression modes: owners, feedback, norm/field/key assumptions and all paid state. Pin/reproduce the selected baseline or document exactly what cannot run | 2–3 focused sessions | No matched malicious-security comparison until premises align; an unavailable baseline remains a gap, not a zero-cost or slow comparator |
| **R1: close compaction controls**, E66 (P03/P07/P10) | Recipe + supported-decoder reference; priced extraction/repacking and independent-key terminal compression controls; carry/verification dependencies | 2–3 sessions | Known combinations are controls. Stop expansion if saved bytes are repaid in private state, client reconstruction or verification |
| **R2: useful full-cost frontier**, E67/E75/E76 (P01/P06) | Enrolled returning socket control complete in two geometries; finish cold/new-client private provisioning and independent CPU/peak resources; retain CPU/cache and relevant GPU controls | 2–3 sessions for next finite screen | Measured nondominated operating point or documented negative. A model only screens; do not build a large optimizer on a dominated profile |
| **R3: constructive screens**, proposed E80, then E78; conditional E81 (P02/P03/P07) | Module closure/norm/query/packing ledger; composed seed/answer proof card; optional exact admissible-trace bound | 2 sessions per initial card; 1 conditional mathematical screen | New protocol consequence + plausible full-cost margin against the new comparison; stop if only one object shrinks or missing material recreates the old cost |
| **R4: correlation alternative**, E69/E74 (P03/P07/P10) | Generic triples/public-code recipe stopped; price secret/recursive/block-preserving programmed conversion before a new generator | 2 sessions before a PCG implementation | All outputs/fields under declared trust; no public mask bank, dropped carry or undeclared helper; actual small block F is the comparator |
| **R5: exact selection alternative**, E46 (P02/P10) | Full stable-ID/coverage circuit or certificate; conversion, predicate, compression, proofs and rounds | 2 sessions before native code | Useful complete bound against all-score download and strongest selection controls; dense ties/adverse inputs included |
| **R6: selection review** (P04/P06/P07/P12) | One selected mechanism, discarded alternatives, theorem statements, held-out preregistration and integration design | 1 session | Gates A/B pass with credible path to C/D; otherwise narrow the question or preserve a negative report |
| **R7: develop and evaluate survivor** (P05–P12, scope-dependent) | Homemade reference → native implementation → optional CUDA; proof, parameter/implementation review and artifact | Scope after R6 | Gates C/D and claim-to-source evidence, not number of experiments completed |

R0–R2 close controls; R3 is the first substantial new-mechanism priority.
The bounded R0 card remains complete; stronger matching proofs/artifacts remain
open in P01/P07. An R6 construction decision may occur while R2's independent
resource work is open; a deployment or final Gate C claim may not. Do not let
an unfinished broad control package block a useful finite algebra screen.
R4/R5 are alternatives, not mandatory prerequisites for every paper. Run their
bounded screens if R3 fails or they target an independently demonstrated cost.
Mathematical screening can precede complete service measurements; expensive
acceleration cannot. Do not spend months completing every literature artifact
before testing the central algebraic obstruction.

**Gate A — contract/viability:** same outputs, permitted leakage, trust and
paid resources; cache remains a feasible action. State any changed contract.

**Gate B — mechanism/originality:** a new construction, algorithm or restricted
theorem survives the strongest simple control and targeted citation review.

**Gate C — useful effect:** preregister a primary resource objective. Initial
project targets are at least 20% lower complete cost, or a factor-of-two
reduction in a genuinely binding state/preparation resource with declared
latency limits. These are decision thresholds, not conference standards or
promised gains. Include uncertainty and regressions. A new asymptotic
result without a practical win must be presented as such, not a fast system.

**Gate D — assurance/artifact:** matching proof, justified parameters, private
implementation review, durable protocol state where required and reproducible
same-contract evidence. Correctness tests cannot substitute for this gate.

## 6. Evaluation that can support a paper

Retain the frozen59-run/181-source artifact. New files use new run IDs and
hashes and the [separate mechanism manifest](publication-mechanism-execution-manifest.json).
The [evaluation inventory](publication-evaluation.md) lists runners; the
205-test receipt is historical. New scoped validation records90 CPU tests in
12 files, explicit lint on28 Python paths and25 cached primary PDF hashes.
Neither receipt claims whole-repository CI or security assurance.

The E72–E77 [separate query manifest](publication-query-execution-manifest-20261001.json)
retains75 tracked raws and248 source versions (164 historical Git/84 workspace
dependencies). [Current scoped validation](publication-query-validation-20261001.json)
passes129 CPU tests in8 files and16 explicit Ruff paths;28 source PDFs/text and
updated task/document identities are checked. Counts overlap historical control
sets; do not add them as whole-repository totals. The [current handoff](mechanism-execution-handoff-20261001.md)
and verified adjacent checkpoint archive retain this tranche separately.
Those are historical execution receipts. This planning revision adds four
primary PDFs (32 total) and separate documentation/source validation; it does
not rerun or enlarge the historical test totals.

Evaluate along independent axes: rows, bit dimension, exact rank/structure,
reply occupancy, number of queries, token utilization, update locality, client
state, link/RTT, concurrent clients and CPU/GPU residency. Use Mushroom/Semeion
as small explanatory cases, distinct Connect-4 rows as an adverse larger case,
and justified additional real binary workloads. Synthetic low-rank, uniform,
boundary-rank and dense-tie data diagnose mechanisms; they do not stand in for
customer distributions. Never duplicate rows merely to claim real-data scale.

Keep paired exact outputs and stable tie rules. Separate owner setup, server
setup, offline generation/checking, client preparation, server compute,
serialization, actual transfer, verification, decoding and selection. Charge
all created/invalidated tokens and query-independent verifier setup. Private
provisioning counts even when performed over a separate channel.

For U queries and P prepared tokens, report at least:

```
total work = enrollment + calibration + P * preparation
             + sum(query + server + check + decode + selection + updates)
total bytes = index + public keys + private provisioning + P * token packets
              + sum(query + reply + proof + framing + updates + retries)
```

Do not equate summed work with wall-clock latency. Measure pipelines, queueing,
producer throughput and peak resident memory separately. A steady producer
slower than consumption cannot sustain the quoted online throughput.
For a first warm-client model only, if cache acquisition costs A, remote costs
r/query and local cache costs l/query, the crossover is A/(r−l) when r>l.
Derive these terms from the same starting state; update churn changes it.

Required panels: latency versus total communication, client state versus
latency, cold-to-repeated-query cost, preparation throughput and update cost.
Use measured confidence intervals after pilot-based sample sizing, independent
process runs and disjoint tuning/test splits. Do not report p95 from three
samples. Quote each security/profile tuple beside its point.

Baseline ladder: (1) raw/compressed authenticated cache and ordinary deltas;
(2) Paillier CPU/lookup/CUDA and homemade general BFV/BGV CPU/CUDA;
(3) strongest direct-fresh BGV/full gate and E48/E64 controls;
(4) original EMVP and compatible recursive/vLHE constructions;
(5) relevant terminal compression or exact-selection construction.
HBC, conditional private-gate, full malicious-proof and actual-attested modes
receive separate panels. An author-reported number is never a local point.

## 7. Security argument to develop with the selected mechanism

Use [the security game](exact-search-security-game.md),
[direct-fresh draft](direct-fresh-conditional-security.md) and
[supported relation](supported-decoder-relation.md) as scoped starting points.
These are not independent reviews or ready-made reductions for E68–E71.

1. Define owner enrollment, approved operator/release relation, adaptive query,
   update and corruption interfaces, public plan leakage and observable abort.
   Specify whether successful application outputs are later exposed.
2. Prove exact functionality over actual integer lifts, ciphertext fields,
   CRT decoder and stable IDs. Bound every allowed query, not just test noise.
3. Bind verification to the owner's operator, epoch, parameters and request.
   Extractability of some server database is not automatically owner binding.
4. Prove first-false-acceptance soundness across the actual lifetime. Replace
   accepted secret decoding by the authorized ideal result before privacy
   hybrids. Include rejected/malformed trials, concurrency and key/epoch changes.
5. Discharge the selected construction's seeded/related-encryption, RLWE/LSN/
   SIS/PCG and commitment assumptions. A published public seed is not justified
   by a hidden-seed PRG hybrid. Independent-key conversions need a directed
   key-dependency argument; ephemeral keys do not generically cure leakage.
6. Validate the implementation boundary: no long-lived-key operation before its
   matching gate, authenticated private setup, durable token/attempt accounting
   if used, private timing/access review and explicit parameter assurance.

For the existing ideal full-vector check, a bounded union/first-failure term
such as sum_e B_e/Q_e^c_e belongs only to its stated challenge distribution.
It is not a universal security formula for outer vLHE, ring hashes, compressed
relations or a resettable service. A mechanized small-model check is useful
support; the computational reduction and independent review remain necessary.

## 8. System and paper deliverables

The intended system has an owner enrollment layer, a chosen execution backend,
a separately specified authenticated release layer and an owner-authorized
client cache/buffer. Keep full-score and exact-top-k profiles explicit. A small
measured policy chooses among surviving modes; it need not be a novel compiler.
An optional TEE is a separate assurance/cost mode, not a proof of the
cryptographic protocol or a substitute for real hardware attestation.

Implement first in `experiments/bfv_search_lab/`, benchmark in `benchmarks/`,
record results here, and use established native/CUDA subdirectories only after
gates. Promote to `src/cuhepy/` only after review in a separate change. Existing
production/fallback paths and Microsoft/author reference examples are preserved.
External artifacts supply baselines; our deliverable stays homemade.

Potential publication outcomes, each conditional:

- **Protocol/system paper:** a new structured verified evaluation or correlation
  construction, matching reduction, and useful complete measured frontier.
- **Security-focused paper:** a substantive safe-release/composition result with
  a constructive efficient instantiation and a clear separation from vFHE and
  HELIOPOLIS—not merely our own bug fixes or a restated generic wrapper.
- **Exact-selection paper:** a new complete winner-selection/coverage mechanism
  under an explicit output contract, with compression as an attributed component.
- **If none survives:** retain company improvements and rigorous negative
  results; do not retrofit a novelty claim onto a benchmark collection.

Every completed subtask appends to [progress](publication-progress.md), updates
its R/P task and claims, records immutable source/raw hashes, then returns to
the earliest unmet applicable gate. A handoff includes the contract, hypothesis,
closest competitor, falsifier, exact paths/command, result classification and
next decision. Venue choice follows the result; a presentation opportunity
and an archival conference paper are different deliverables.
