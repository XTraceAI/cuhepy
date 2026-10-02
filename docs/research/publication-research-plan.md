# Research plan: compact, verified owner-private search

Revision: **2026-10-02, after measurement revalidation and a refreshed closest-work
review**. Start with the [detailed execution plan](contribution-plan-20261002.md)
and [closest-work comparison](closest-work-comparison-20261002.md). The
[machine work packages](publication-work-packages.json) and
[progress log](publication-progress.md) govern execution and return decisions.

**Current status:** planning complete for the next finite tranche. E82, E83 and
E84 are proposals; none is implemented. No original complete protocol has been
selected and no production/security gate has passed. The useful company
BFV/BGV/Paillier implementations and SEAL reference remain preserved.

## 1. Decision

Pursue a construction that amortizes privacy and verification for a fixed,
owner-private linear operator, removing repeated trusted matrix work or reducing
binding verifier state without merely moving that cost to another party.
Exact Hamming scores and stable IDs remain the primary application.

The new comparison adds **Maverick, including its private-matrix extension**,
new PCF constructions, structured verification, exact counting-sort selection
and authenticated updates. These raise the novelty bar. A generic private,
verified matvec, PCF-plus-EMVP composition or histogram selector is a control.
The new step must have a precise algorithm/distribution/bound consequence.

| Priority | Proposed experiment | Concrete question |
|---|---|---|
| First | **E82: fixed-function correlations**, token route and direct field-output route | Can programming/projection and authentication share work for the actual thin/block M, beyond strong secret-code/recursive/private-M controls? A non-HE survivor need not manufacture a BGV token |
| Competing bounded screen | **E83: code and operator structure through verification** | Can the complete authenticated check retain compact signed-shift/subring generators, with a full-error bound, instead of large dense hints or paid per-query row downloads? |
| Conditional fallback | **E84: exact bucket-to-top-3 release** | Can packed carry/conversion/coverage work be shared enough to beat complete known key-value selection? Exact IDs, ties and omitted rows must be covered |

The [detailed plan](contribution-plan-20261002.md) specifies algebra, candidate
representations, proposed paths, controls, stop conditions, phase budgets and
security obligations. Do not infer a new protocol from these sketches.
No larger representation optimizer or new GPU kernel is the immediate task.

## 2. Evidence governing the decision

Use the [revalidation report](measurement-revalidation-20261001.md) and
[frozen final synthesis](../../../research-data/revalidation-20261001/analysis-final-followups-04.md).
The audit covers current-source confirmations, recorded historical nonbinary
source closures rebuilt with new tools, deterministic counts/models and scoped
instrumented tests. It does not prove historical contention caused a difference.
Two dirty historical source closures remain unavailable.

- Strong CPU and native/CUDA gains remain valuable. E27's two matching-block
  allocated/repair32 complete CUDA intervals include a tie.
- In the matched 8k BFV/Paillier study, prepared BFV CUDA has 20.63× smaller
  replies but 395.213 ms local elapsed versus 344.524 ms for the lookup hybrid.
  BGV's 60.047 ms result belongs to a **different** 8k fixture. No combined paired
  BGV/hybrid ratio or equal-security ranking follows.
- Vectorized owner preparation defeats several earlier speed hypotheses.
  Counting client plus trusted helper defeats the literal E77 state trade.
- Actual enrolled/isolated service and acquisition controls favor permitted
  caches on the measured small datasets. A remote operating point needs evidence.
- The fresh layout models change 25/63 choices at 8k and 17/63 at 32k, mainly
  precision. Use their matching inputs for later research routing; no production
  consumer or measured WAN/security winner exists.
- The 1,965 unique passing tests and scoped tool checks are correctness evidence,
  not security or parameter assurance.

Do not multiply ratios across studies or treat stage sums as observed elapsed.
Keep failed/qualified attempts, negative results and source/runtime distinctions.
The [new plan's evidence table](contribution-plan-20261002.md) states each scope.

## 3. Contract and controls

The [exact-search contract](exact-search-contract.md) remains authoritative:
one malicious compute server; owner-private index and adaptive private queries;
owner-approved epoch; exact scores and stable IDs; observable accept/abort.
The owner/client may retain **all** plaintext. No storage restriction is inferred
from the Paillier API. Full-score, exact-top-3, approximate, helper/noncollusion
and TEE modes have separate output/trust/leakage contracts.

Owner-built authenticated registration is the first mode. Malicious outsourced
registration needs additional binding/extraction arguments. Every use of a
long-lived secret on a remote response follows its matching complete check,
unless a different complete reviewed protocol establishes its own safe order.

Mandatory controls:

1. Raw/compressed authenticated caches and ordinary mutable deltas.
2. Paillier CPU, lookup CPU, CUDA and CPU-server/GPU-client lookup hybrid;
   homemade BFV/BGV CPU/CUDA with state and hardware disclosed.
3. Strong direct-fresh, token, supported-decoder and full-check controls.
4. The two closest complete construction competitors for the selected idea,
   including compressed EMVP/private-M/recursive or small-state verified modes
   where applicable. Unavailable adaptations stay open, not assumed slow.
5. Strong exact selection and output-compaction controls for E84.

Cold owner enrollment, enrolled-server/new-client and returning-client sessions
are distinct starting states. Charge every owner/helper operation, setup/key/
private provisioning packet, unused token, update, proof, retry and retained
state. Measure full elapsed, endpoint work and memory separately.

## 4. Execution queue and gates

**Next:** Q0, refresh the two closest construction cards at actual matrix shapes;
then Q1/Q2, E82 contract/count and independent oracle. Q3 screens E83 before Q4
selects one main mechanism. Q5/E84 is conditional. Q6 reference, Q7 native/CUDA,
Q8 security, Q9 matched evaluation and Q10 paper/artifact follow only a survivor.
The detailed queue and per-packet acceptance tests are in
[plan §7](contribution-plan-20261002.md#7-execution-order-and-the-return-to-plan-rule)
and `current_packet_queue` in the machine tasks.

After **each** packet: log hypothesis, result classification, source/evidence,
closest-work difference, pass/stop and next action; update the queue; return to
the earliest unmet applicable gate. A finite screen does not complete a broad
P package. Keep prior E IDs and stopped recipes unchanged.

- **A — contract/viability:** exact functionality, leakage, parties and all costs
  specified; actual implementation interface is possible.
- **B — mechanism:** a concrete new algorithm/construction/restricted theorem
  survives strong controls and targeted citation review.
- **C — useful effect:** initial target ≥20% complete-cost improvement, or ≥2×
  binding state/preparation reduction with declared latency/traffic limits.
  For a state claim, initial limits are 10% extra elapsed and 10% extra per-query
  traffic versus the strong matched control; report the full Pareto curve.
  These are project screening targets, not conference criteria.
- **D — assurance/artifact:** actual transcript reduction, justified parameters,
  private implementation/lifecycle review and reproducible matched evidence.

The primary research question can survive a failed recipe. A generic composition
or a faster known implementation remains useful engineering, without passing B.

## 5. Development, evaluation and proof

Implement a surviving reference in `experiments/bfv_search_lab/`, runners in
`benchmarks/`, reports here. External libraries/artifacts are differential
controls; the deliverable remains homemade. Native/CUDA work follows profiling
of the complete valid protocol. Promotion into `src/cuhepy/` is separate.

The [evaluation preregistration](contribution-plan-20261002.md#8-evaluation-preregistration-to-complete-after-selection)
requires matching corpora/queries/contracts, independent process blocks,
monitored serial runs, measured transport for network claims, distinct larger
records, cache/lifecycle controls and complete ablations. First match BGV and
Paillier lookup hybrid in one larger fixture; no extrapolated comparison.

Start correctness, binding and feedback lemmas during construction. Use the
[existing game](exact-search-security-game.md),
[direct-fresh draft](direct-fresh-conditional-security.md) and
[supported-decoder relation](supported-decoder-relation.md) only within their
stated premises. Prove accepted release is correct before HE/privacy hybrids;
include original-query binding, failures, epochs, state reuse, public seeds,
auxiliary keys and full integer/RNS semantics. A conditional oracle or passing
taint test is not a computational reduction or constant-time proof.

The paper should have one defensible mechanism and theorem, with complete
system evidence. CSF requires a substantive foundational contribution; an
FHE.org talk/poster has a different submission format. Venue fit and policies
are linked in the detailed plan; no deadline supplies missing evidence.

## 6. Preserved history and checkpoints

The prior active plan is retained exactly at `f1b7552`; the
[E01–E65 plan](publication-research-plan-through-e65.md),
[construction hypotheses through E81](construction-hypotheses-20261001.md),
[E81 selection return](construction-selection-20261001.md), and all old raw
reports remain historical records. E80 retained-H, E78 generic fusion and
E74 public-code recipes remain stopped in their tested scopes; E81 remains a
conditional exactness building block. E79's finite isolated endpoint scope is
complete, with WAN/scale/update/security work still open.

Company checkpoint: `checkpoint/verification-frontier-2026-09-30`.
E01–E65: `checkpoint/publication-controls-2026-09-30`.
Construction controls: `checkpoint/construction-screens-2026-10-01`.
Revalidation: `checkpoint/measurement-revalidation-2026-10-01` (`f1b7552`).
The full measurement archive and all-ref bundle are retained outside Git under
`../checkpoints/measurement-revalidation-2026-10-01/`. The planning revision
changes documentation/task routing only; production crypto and measurements stay
unchanged.
