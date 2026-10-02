# Research plan: compact, verified owner-private search

Revision: **2026-10-02, after Q0–Q5/Q11–Q22 bounded execution**. Start with the
[latest return decision](construction-selection-20261002.md) and
[next bounded control](owner-bound-rounding-plan-20261002.md). The
[original detailed plan](contribution-plan-20261002.md) and
[closest-work comparison](closest-work-comparison-20261002.md) retain the
pre-execution strategy. The
[machine work packages](publication-work-packages.json) and
[progress log](publication-progress.md) govern execution and return decisions.

**Current status:** E82–E96 bounded arithmetic/count and limited estimator
screens are implemented; **365 scoped tests** pass across sixteen CPU files.
E94 restores the modeled source headroom; E95 supplies a true-uniform rounding
law for any fixed target key and stops generic shared rerandomization as original.
E96's exact independent sample subset exposes sub128 classical estimates for
all registered p512/p1024 target contexts. Larger supports are repriced but not
security approved. These are arithmetic/count/heuristic results, not measured
speed or an attack execution. No original complete main protocol or broad
production/security gate is selected. **Next Q23/E97** is the missing complete
owner-bound stochastic-rounding strong control, followed by R6 before a new
score/proof/compressed-query construction. Company homemade BFV/BGV/Paillier,
SEAL references, production sources, frozen measurements and main/staging remain
preserved. Original-score/PBS authentication and private assurance stay open.

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

| Packet | Executed/proposed experiment | Current return |
|---|---|---|
| Q1/Q2 | [E82 fixed-function correlations](fixed-function-correlation-screen.md) | Stop shared/noiseless masks and common-slope bit-line recipe; exact projection simulates, minimal-support key work loses |
| Q3 | [E83 code/operator structure](coded-operator-screen.md) | Known structure survives; literal row fetch costs 54.15–233.99× entire baseline public body even under optimistic bounds |
| Q5 | [E84 bucket/coverage](exact-bucket-release-screen.md) | Small-field multiplicity collision and coefficient/slot mismatch reject shortcuts; extension challenge is not original-score/ID binding |
| Q11 | [E85 phase interface](score-phase-bridge-screen.md) | Known BFV extraction works; two naive BGV maps fail; C2, rounding, LUT and coverage costs remain explicit |
| Q12 | [E86 modular-unit BGV bridge](bgv-unit-bridge-screen.md) | Correct cheap known conversion advances; private carry witnesses are unnecessary for this map alone |
| Q13 | [E87 batch switching](batched-score-bridge-screen.md) | Exact scalar/convolution and once-packed controls; compact digit/input/PBS/coverage proof does not follow |
| Q14 | [E88 orbit common masks](orbit-common-mask-screen.md) | Block/key reuse and public support trimming work; independent-key and one-ring diagonal shortcuts stop |
| Q15 | [E89 odd-domain LUT/precision](odd-domain-lut-screen.md) | Full odd-domain signed LUT works; final MS margin is paid, standard small-degree worst-case bound fails |
| Q16 | [E90 shared orbit remainder](orbit-remainder-trace-screen.md) | Full signed carry/phase and sharp odd-grid count controls survive; generic hoisting gives equal or less division work |
| Q17 | [E91 dependent-secret drift certificate](quadratic-drift-screen.md) | Sound all-secret integer certificate; 46/96 synthetic bounds improve, no original-q sufficient lookup margin passes; canonical control is tighter |
| Q18 | [E92 partial packed switching](partial-packed-switch-screen.md) | Exact mixed-key control survives; candidate is contained in ordinary approximate switching; inherited quarter-domain source budget is already negative |
| Q19 | [E93 source/fresh-key family/degree controls](committed-precision-epoch-screen.md) | Correct restricted law; posterior negative and shared known control stop generic original composition |
| Q20 | [E94 conditional adaptive-query source phase](committed-precision-epoch-screen.md) | All40 source margins restored, no new Q needed in that model; reusable target precision and complete proof remain open |
| Q21/E95 | [Late owner zero, fixed-key precision](late-owner-precision-screen.md) | Exact law/receiver survives; known shared control contains generic mechanism, tiny target costs qualified by E96 |
| Q22/E96 | [Known-prefix security and coupled precision](late-owner-precision-screen.md) | Exact independent public LWE rows; all p512/p1024 profiles sub128 in named model; larger supports repriced, unapproved |
| **Next: Q23** | [**E97 owner-bound stochastic rounding**](owner-bound-rounding-plan-20261002.md) | Missing strong known baseline before original proof/query construction; proposed, unimplemented |

The [detailed plan](contribution-plan-20261002.md) specifies algebra, candidate
representations, proposed paths, controls, stop conditions, phase budgets and
security obligations. Do not infer a new protocol from these sketches.
No larger representation optimizer or new GPU kernel is the immediate research task.

The new BGV control multiplies all components by `t^{-1} mod Q`, then accounts
for a known plaintext permutation. It adds no secret material or body bytes
for that map alone. It does **not** supply TFHE keys/PBS, sufficient rounding
noise, arbitrary LUT support or an authenticated exact stable-ID winner.
Do not weaken the closest baseline by repeating E85's failed maps.

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
- This tranche adds exhaustive finite arithmetic and deterministic counts,
  not new timing panels. E86, E87, E91 and E92 also check actual local homemade BGV products. E89 corrects the scope of the earlier even-domain LUT negative; its odd-domain control is known prior work.
  Frozen revalidation is unchanged; background load cannot contaminate exact
  finite distributions/counts, while those counts imply no speedup.

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

**Next:** Q23/E97, primary randomized-rounding review/preregistration, exact
fixed-input coin/order law, full diagnostic subrelation and paid strongest
shared-control comparison. Return to Q4/R6 after each component. Q0–Q5 and
Q11–Q22 have completed bounded scopes; no original main mechanism is selected.
Q6 reference, Q7 native/CUDA, Q8 security, Q9 matched evaluation and Q10 paper/
artifact remain conditional on unmet selection/assurance gates. The detailed
queue and acceptance tests are in [plan §7](contribution-plan-20261002.md#7-execution-order-and-the-return-to-plan-rule)
and `current_packet_queue` in the machine tasks. Larger target support and
precision must be coupled; a p512 arithmetic win is not an equal-security result.

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

The [latest execution receipt](late-owner-execution-validation-20261002.json)
and [identity manifest](publication-late-owner-execution-manifest-20261002.json)
record seven E95/E96 raw results and exact sources. Earlier source-lifetime,
partial-switch, orbit-precision, fixed-function and batched-score receipts retain
their historical scopes. The [paper archive](prior-work-archive.md) links
**62 hash-pinned PDF/text pairs**, with reading and artifact status. The pinned
external estimator source is archived separately; its execution is not an HE
protocol/performance reproduction. Targeted reading is not a full proof audit.

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

## 7. Latest execution return and paper controls

Q13–Q15 completed their finite sessions with [validation](batched-score-execution-validation-20261002.json) and [source/result manifest](publication-batched-score-execution-manifest-20261002.json), which pin the then-53 PDF/text pairs. Q16/Q17's [checkpoint receipt](orbit-precision-execution-validation-20261002.json) pins 56 pairs. The [primary archive](prior-work-archive.md) now retains **62 pairs**, including source/dependency and HE security controls; each earlier receipt retains its own archive count. Targeted reading, complete proof audits and reproduced author artifacts are separate statuses.

E88's exact signed orbit view is a useful interface: block masks reuse canonical slot-key rows and a public partial-key support union. It does not turn slot-diagonal/nonlinear operators into ring multipliers. E89 supplies a full odd-domain test vector, with a stricter margin. Increasing Q does not remove the final componentwise rounding floor. Reviewed probabilistic/high-precision methods can beat the worst-case control; the next candidate must include their actual key, noise, packing and proof premises.

Q16/E90 completes the full public remainder subrelation and a restricted exact
odd-grid half-count proof. Distinct dyadic stages have disjoint half sets;
public corrections preserve unreduced integer phases. The strong hoisted
control gets identical reuse. Keep this company/reference interface.
Q17 then tested a dependent-secret deterministic certificate without assuming
Gaussian or independent-key failure estimates. No complete new selector is
supplied by the arithmetic alone.

Q17/E91's all-k matrix identity and exact moment certificate pass independent
finite controls. Dense uniform synthetic cards tighten the strong box bound
by 12.24–32.98×; this is **bound tightening**, not measured performance.
Canonical norms remain stronger. The modeled original-q margins do not pass,
and complete score/PBS/ID authentication is still missing. The source S-squared
must remain its actual derived secret, not an independent ternary key.

Q18 tested a more concrete consequence: switching only upper C2 levels,
certifying the remaining source-secret term, and safely releasing a rounded
target-key result. B64/q64 makes any nonzero omitted residual impossible under
the proposed zero-mask condition; smaller precision has a paid noise/PBS
tradeoff. E92 finds identical outputs already supplied by ordinary approximate
switching; stop this zero-mask mechanism and keep the exact company control.
The inherited source bound itself exhausts the chosen quarter-domain budget,
so the larger zero-pass cards cannot rank switching methods. All 2,430 small
mixed-key cases and one fresh trusted BGV differential pass their exact checks.

Q19/E93 completed that source-budget prerequisite, then investigated a
committed finite precision family before a fresh target-key epoch. Its first
question is an actual dependency/order proof for statistical bounds under
malicious postselection and feedback. A Gaussian substitution or a standard
fresh-key composition alone is not a contribution. Every epoch, extra RTT,
owner key preparation, complete proof and permitted cache is paid. Keep useful
company interfaces while returning to R6 after each result; Q6 is conditional.

E93 stops generic fresh-epoch originality, while E94's conditional fixed-index/
fresh-query source law restores all40 original modeled-Q margins. E95 then
proves a restricted all-fixed-target precision law using a late true-uniform
owner zero; an equally shared standard adapter has the same resources, so the
generic mechanism is stopped as original. Colocated fresh-key and zero routes
both avoid extra RTT; older separate-provisioning counts remain conditional.

E96's exact disjoint-row argument makes known zero suffixes relevant to the
unknown LWE dimension. All12 small-prefix profiles are below128 in the named
classical model at4096 published zeros. Larger supports have only limited
positive estimates and materially larger modeled lookup degrees. Neither an
executed attack nor production-key compromise is inferred. Seven immutable
results preserve the soft-timer exception and two hard-isolated repeats.

Next is [Q23/E97](owner-bound-rounding-plan-20261002.md), a complete standard
stochastic-rounding competitor. Its potential owner-product saving is worth
testing, but is not originality. Preserve exact laws and negative boundaries;
a main paper result must still supply a genuinely new complete proof/binding or
correlated-query consequence with approved parameters and useful matched costs.
