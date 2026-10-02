# A research program for compact, verified owner-private search

2026-10-02. Status: **plan ready for bounded execution; no new experiment run,
construction selected, reduction proved or production assurance granted**.
This supersedes next-task priorities in the
[E81 return](construction-selection-20261001.md), preserving its findings.
Use the [closest-work review](closest-work-comparison-20261002.md),
[machine tasks](publication-work-packages.json) and
[progress log](publication-progress.md). Frozen evidence is commit `f1b7552`
and `checkpoint/measurement-revalidation-2026-10-01`.

## 1. The result we should try to earn

Investigate **how to amortize privacy and verification together for a fixed,
owner-private linear search operator, without another full trusted computation
per query or a verifier state approaching the cost of retaining the data**.
Exact Hamming search is the motivating application and evaluation; a useful
restricted operator theorem could be more general. We should not promise a
general replacement for HE or a win over an owner who already has a fast cache.

The desired paper has one main mechanism, one precise correctness/security
argument, and a complete homemade system showing a useful resource frontier.
CPU/CUDA optimizations support that mechanism. A collection of backend speedups,
a generic verification wrapper, or a benchmark survey is not the selected thesis.

Select the **research question** now, not an untested construction. E82 remains
the first screen, with a direct non-HE exit route. E83 competes on verification
state. E84 is a separately specified exact-top-3 fallback. After their bounded
algebra/count screens, choose at most one main construction for full development.

The strongest new literature changes the tests: Maverick's private-M mode is
a required control; PCF-to-EMVP composition is known; RevoLUT supplies a serious
non-comparison selector. See the comparison for actual models and reading
limits. These findings prevent us from spending an implementation cycle on a
generic composition and later discovering that it was already published.

## 2. What the evidence can support

These are **separate studies**, not rows of a matched all-scheme leaderboard.
The [final revalidation analysis](../../../research-data/revalidation-20261001/analysis-final-followups-04.md)
contains the source/runtime and timing boundaries; its raw identities and
failed/qualified attempts are retained. The audit cannot attribute a historical
timing difference specifically to background contention.

| Evidence | Revalidated or retained finding | Decision |
|---|---|---|
| Matched 8,192 × 512 BFV/Paillier block | Prepared BFV CUDA: **395.213 ms**, **204,900 B** reply; Paillier lookup hybrid: **344.524 ms**, **4,226,953 B** reply. BFV has **20.63×** less reply and **4.49×** less query-plus-reply, but **14.71%** longer local elapsed | Keep the hybrid CPU-server/GPU-client control. IO and compute are separate objectives. One process, three warm calls, no network/setup/authentication, no equal-security claim |
| Separate 8k BGV block | Owner BGV CUDA: **60.047 ms**, **102,488 B** reply; prepared BFV CUDA: **396.411 ms** in that same block | Strong engineering foundation. Different fixture from the hybrid panel; do not manufacture a paired BGV/hybrid ratio. One process/five warm calls; no authenticated service claim |
| E26/E27, five matching process blocks | Large CPU gains survive. Allocated/repair32 complete CUDA stage-sum ratios **1.00153** and **1.00075**, both provisional block intervals cross one | No material complete-GPU preference. A new kernel is lower research priority than removing a protocol cost |
| Factory, updates, E77 | Vectorized owner work reverses the factory/sparse-update speed claims; seed-affine client plus paid helper stays about **5.3–6.6% slower** | A smaller online device is not free total work. Use vectorized NumPy and all helper costs |
| E79 independent endpoints | Fresh loopback returning HE means **47.288/17.349 ms**, versus raw cache **0.708/0.141 ms** on the two small fixtures; cache wins cold/new-client controls too | Keep owned-data caching. Find and measure a relevant remote operating regime; do not invent a storage prohibition |
| E80/E78/E81 | Module setup savings bring larger replies; generic relation fusion supplies no new step; bounded alternative traces preserve exactness in the tested domain | Retain exactness/structure oracles. These screens do not establish a winning protocol or succinct proof |
| Layout-model refresh | **25/63** 8k and **17/63** 32k modeled choices change, mainly terminal precision | Use matching fresh reports for later experiments. They are nominal-link models, with no production routing consumer or WAN/security winner |

The audit's **1,965 unique passing tests** and scoped sanitizer/taint checks
support implementation regressions. They are not a security proof. Two dirty
historical source closures remain unavailable; replacement/current-source and
new-toolchain observations must retain their labels. The protected company
baseline is independent of whether this research succeeds.

## 3. Functionality, mathematical objects and cost objective

Let `X ∈ {0,1}^{m×d}` be the owner index and `x ∈ {0,1}^d` a query. The reference
function is

```
h_i = weight(X_i) + weight(x) - 2 <X_i,x>,   0 <= h_i <= d.
```

The primary mode returns all exact `(ID_i,h_i)`, ordered by the approved ID
table, with stable `(h_i,ID_i)` top-3 computed locally. Its field representation
uses a proven score range, not a guess from observed noise. Denote the actual
private coordinate matrix by M over `F_t`; legacy row widths 32/23 and strong
global widths 85/256 are distinct baselines. A large concatenated query vector
does not make every row dense.

The public ciphertext-coefficient operator D over `Z_Q` is a **different
object**. Its products include CRT/subring embedding, signed convolution,
multiple ciphertext components and approved output projection. Neither reducing
D modulo t nor using independent unchecked RNS digits preserves the release
relation automatically.

Owner and online client may coincide; a separate owner is charged, not treated
as free infrastructure. Compare cold enrollment, enrolled-server/new-client,
and returning-client sessions. Dataset ownership permits every cache baseline.
Memory, links, session length and updates are measured axes, not restrictions
inferred from the production API.

For each candidate record a vector of costs rather than a hidden weighted score:

```
enrollment: owner/server CPU, bytes, retained/peak memory, keys and commitments
per query: client + server + any helper work; measured critical-path latency
traffic: upload + reply + proof + private provisioning + retries + updates
lifetime: paid setup + all generated tokens + all actual queries and updates
```

The **primary screening objective** is eliminating repeated trusted matrix work
or reducing genuinely binding client/verifier state by at least 2×, with total
query traffic and elapsed time explicitly constrained. Alternatively accept a
≥20% complete-cost improvement at matched state. For the state objective use an
initial ceiling of 10% extra complete latency and 10% extra per-query traffic
against the relevant strong control, then report the full Pareto curve. These
are preregistration defaults, not promised gains or conference requirements.
A scientifically valuable theorem can be assessed separately from this systems
threshold. Unknown proof/adapter costs are **unknown**, never zero.

## 4. E82 — make fixed-function correlations useful, or change the backend

**Priority 1; proposed, unimplemented.** Retain the original
[token contract](authenticated-correlation-contract.md) and
[E82 negative controls](construction-selection-20261001.md). Budget: one
contract/count session, one mathematical oracle session; return to R6 before
any large primitive implementation. Do not reopen E69/E74's stopped literal
recipes without a specific different construction step.

### E82-T: compatible token path

The client obtains a fresh private r; the existing server receives a bound
fresh encryption of the required `M r`, with private check material sufficient
to authenticate its complete subsequent full-Q result. Specify every recipient,
sampler, field lift, key dependency, token ID, refresh and failure transition.
Freshly encrypting a correct value with a server-known or correlated error law
is not this functionality.

Try **joint programming across the actual block operator**, rather than one
security-sized seed expansion per tiny block. Start with a concrete secret-code
or programmable-correlation construction and a linear projection P_j for each
local query space. Ask whether the one shared secret correlation can provide
the joint distribution of `(P_j r, M_j P_j r)_j` without a dense correction per
row, and without exposing cross-block or cross-query linear relations. Price
the projected distributions and all dimension/security floors. The new step
would be a valid fixed-function programming/projection rule with a complete
advantage; “use one PRG seed for everything” is not that step.

A useful restricted target is a family of block operators with a proved common
factorization and small private correction. Compare against ordinary shared-form
merging and E30/E31 before claiming that sharing itself is new. If a correction
touches every row/form at each query, compare its **actual vectorized cost** to
direct `M r`, including private-index gathers and their side-channel treatment.

### E82-D: direct authenticated field-output path

Do not force a non-HE protocol to manufacture BGV ciphertexts. Specify
`Enroll → Query → Evaluate → Verify → Release` directly for M, with authenticated
field outputs or shares converted privately into exact Hamming scores. The
server must still learn neither operand beyond declared leakage. This uses the
same full-score functionality with a different cryptographic assumption set.

The design question is whether fixed-function correction and authentication
can **share setup/representation** so that their combined cost is below running
the best private-matrix protocol plus its independent check. Compare EMVP's
compressed mode, full recursive BNTM and the private-M control identified in the
new review. A stock composition is a baseline, not our contribution.

Explore a precise small-domain projection only if it maintains full joint
mask entropy and adequate authentication: multiple correlated coordinates plus
local recombination instead of one full-field scalar per primitive. Write the
recipient simulation and count every component. Query bits being binary does
not imply that the random masks, field outputs or authentication key may be
binary. The PCF review supplies both a related open question and already-known
EMVP composition; either must be credited.

### First executable packet

Create only after the contract/count review:

- `experiments/bfv_search_lab/secret_code_mask_oracle.py` and its test: independent
  tiny-field oracle for repeated-query span leakage, projection correctness,
  sparse-error corrections and all recipient views. Enumerate unknown offsets
  as well as known-query differences. A counterexample is not a cryptanalysis
  of a published construction unless that construction is actually instantiated.
- `benchmarks/secret_code_mask_lab.py`: count/state/traffic ledger over actual
  F32/F23 and global 85/256 profiles, plus public uniform/high-rank controls.
  Compare full field widths, code entropy, all owner/helper work and safe gathers.
- `docs/research/fixed-function-correlation-screen.md`: target functionality,
  closest construction, one proposed new step, conditional claims and decision.

Tests must include exposed/reused r, public mask coefficients, low-dimensional
noiseless spans, bogus authenticated setup, t/Q carries, missing RNS links,
incorrect initial encrypted answers, stale epochs and duplicate consumption.
For E82-D add malicious share/MAC substitution and adaptive failures. Tiny
entropy or information-set filters cannot certify 128-bit security.

**Stop** a literal variant when it needs the original dense trusted product,
relies on an invalid distribution, or loses its full-cost screen. **Advance**
only with a specified primitive/adapter, conditional proof obligations and
one resource improvement unexplained by a standard competitor. If the direct
route survives but token conversion fails, retain that result and proceed
without BGV conversion. Failure of both routes is a valid R6 return.

## 5. E83 — preserve operator structure through fresh verification

**Competing screen; proposed, unimplemented.** Motivation: E72 removes trusted
fresh answers but pays large hints; E78 does not remove that cost; E80 loses on
strong scalar layouts. Seek a check representation that avoids dense client
hints and hidden reusable challenges. Begin with a known authenticated-access
control before claiming any new verifier construction.

For one **prime-field limb**, write `y=D u`, with output dimension L and input
width W. Let `E : F_q^L → F_q^n_c` be a linear error-detecting code, and let
`V=E D`. An owner-pinned commitment to V allows a client to retrieve authenticated
rows of V after the **entire y is fixed**. The client tests

```
(E y)[j] = V[j,:] u
```

at fresh uniformly sampled positions j. With a proved relative distance δ,
checking s independent positions individually misses a fixed nonzero error
with probability at most `(1-δ)^s`; add commitment/setup failure and lifetime
losses. This elementary coded-check bound is a **known control**, not a theorem
we claim to have invented. A vector of independent RNS checks needs a sound
bound for an error occurring in only one limb, not a product across all limbs.

Literal Merkle row fetches pay roughly `s W ceil(log2(q)/8)` row bytes, paths
or multiproofs, code evaluation and an extra round. If they simply turn a
once-downloaded hint into a similar-size download **every** query, stop that
variant. A commitment to a server-chosen V does not prove `V=E D`; initial V
must be owner-generated/checked or accompanied by a fully paid setup proof.

The research attempt is to choose **E and the representation of V together**:

1. Test whether signed-shift/subring generators admit compact derivation and
   authentication of coded rows or their evaluated linear forms. Ordinary
   row hashing and generic polynomial openings are strong controls. Account
   for the cost of proving a value from a row, not only membership of that row.
2. Test a block/tensor code compatible with mixed subrings and selected output
   support. Prove distance for **every nonzero admissible error**, including
   one coefficient, one block and one RNS limb. An invertible NTT on its own
   is not a redundant code with constant relative distance.
3. If authentication uses an existing succinct opening, compare the strongest
   complete structured verifier and matrix-lookup primitive. The new result
   must be a representation/bound consequence reducing paid work/state, not
   merely adding Merkle paths or porting a known commitment.

Use E72's direct fresh encrypted-query relation first so removal of trusted
preparation is real. E73 expansion remains canonical locally until its entire
original-query relation is proved. Apply the mechanism to E29's token path only
as a separately paid control; improving its checker alone does not remove its
factory. Protect every C1/C2 dependency of the supported decoder.

Proposed files: `experiments/bfv_search_lab/coded_operator_oracle.py`, its test,
`benchmarks/coded_operator_lab.py`, and
`docs/research/coded-operator-screen.md`. First enumerate all tiny nonzero error
vectors, not just basis errors; verify independently expanded D, E, ED and
decoder support. Negative cases: wrong code distance, challenge-before-output,
two different outputs, malicious V, bad row opening on a true answer, wrong
limb/modulus, dropped secret-dependent coefficient and rollback/epoch mismatch.

Budget one algebra session and one full-ledger session, then R6. A survivor
needs a new structured encoding/authentication step, a valid full-error bound,
and a state/latency/traffic point beyond generic coded checking, E72, vLHE and
permitted cache controls. If the new step is absent, record a useful adapter
or a negative, not an original protocol. Keep E81's exactness lemma available
only if a later proof actually benefits from its relaxed relation.

## 6. E84 — exact top-3 through shared conversion and complete coverage

**Conditional fallback; proposed, unimplemented.** Activate if E82/E83 stop,
or a surviving system's measured dominant term is the all-score reply. Define
a separate output contract: the exact three lexicographically smallest
`(distance,stable ID)` pairs, including exact handling of ties and fewer than
three live rows. Keep the all-score mode as the primary comparison.

The creative question is whether a packed **score-to-bucket-to-winner** relation
can share expensive carry/decomposition/verification work across many scores,
so that output selection need not convert every score independently into a
general comparison circuit. Hamming's finite alphabet `0..d` is useful
structure, but a histogram by itself loses IDs and does not identify winners.

Start from the complete relation:

- Every approved row contributes exactly once to its exact distance bucket.
- The returned threshold is the first cumulative bucket with at least k rows.
- All smaller buckets are included; the threshold bucket uses the approved
  stable-ID order. No omitted smaller ID may win a tie.
- The result binds the original encrypted query, index/ID epoch, bucket counts,
  threshold and output; neither a server-chosen candidate set nor a valid proof
  of the wrong computation qualifies.

Investigate joint radix/carry constraints for packed scores, with an independent
integer oracle before any HE/Boolean implementation. If aggregate constraints
cannot recover the required winner/coverage witnesses without per-row nonlinear
work, state that cost rather than assuming it away. Compare RevoLUT key-value
selection, a strongest tournament/network, full-score download/local top-3,
and SophOMR **after** the match predicate exists. CKKS/NOMOS is a separate
approximate control unless a proved exact margin/tie mechanism is added.

Proposed files: `experiments/bfv_search_lab/exact_bucket_release_oracle.py`, its
test, `benchmarks/exact_bucket_release_lab.py`, and
`docs/research/exact-bucket-release-screen.md`. Reuse E19/E21/E23/E39 negatives:
all equal distances, duplicate rows, IDs near tie boundaries, every row near
threshold, bucket overflow, missing/duplicated rows, wrong carry, forged
threshold and mismatched originals. Report worst-case behavior and number of
rounds; a favorable shortlist is not a complete win.

Budget two mathematical/count sessions before any TFHE port. The new step
would be a demonstrably cheaper exact conversion/coverage construction, not
counting sort, histogramming, range proofs or sparse compression in isolation.

## 7. Execution order and the return-to-plan rule

The following is the current queue. It refines existing R/P packages without
marking their broad unfinished scopes complete. Session caps are allocations,
not elapsed-time promises. A missing implementation is a gap, not an indefinite
block on independent algebra/count work.

| Packet | Deliverable | Dependency and exit |
|---|---|---|
| Q0 — comparison/contract refresh | E82/E83 cards for the two closest controls, actual matrix shapes, all recipient objects and assumptions | Next executable task. Include private-M and strongest compressed corrections. No need to reproduce the entire literature first |
| Q1 — E82 contract/count | Separate T/D interfaces, one proposed distribution/projection step, complete lifecycle ledger | Q0. Stop if the only step is a known composition or dense correction |
| Q2 — E82 oracle/decision | Independent finite-field counterexamples and any surviving exact identities; reviewed count card | Q1 plausibility. Return to R6 even if unsuccessful |
| Q3 — E83 oracle/count | Complete coded operator and authenticated-access control; all-error and full-RNS negatives | Q0. Run after the first E82 return, before selecting a winner |
| Q4 — R6 selection | One mechanism statement, closest-work delta, missing lemmas, primary metric and preregistered ablations | Q2/Q3 returns. No survivor: Q5 or a documented new question; no automatic new CUDA project |
| Q5 — E84 fallback | Exact bucket/tie/coverage relation and counts | Conditional activation in §6; then return to Q4 |
| Q6 — complete reference | Homemade enrollment/query/evaluate/verify/release with bounded serialization and independent oracle | Selected viable mechanism, conditional proof outline and concrete primitives; no mock proof represented as security |
| Q7 — implementation | C++/RNS only where profiling the complete reference justifies it; CUDA after native agreement | Q6 correctness and relation binding. Preserve CPU fallback and separate experimental package |
| Q8 — security closure | Formal games/reductions, concrete parameter review, feedback/lifecycle and private implementation audit | Begin lemmas in Q1/Q3; finish alongside Q6/Q7, not after paper writing |
| Q9 — matched evaluation | Same corpus/query/security-contract panels, independent repetitions, scale/cache/updates/concurrency/network | Preregister after pilot; preserve all blocks and telemetry. Q6 required for system claims |
| Q10 — paper/artifact | One claim/evidence matrix, theorem appendix, all losses, reproducible source and raw checkpoint | Q8/Q9 satisfy relevant gates; honest narrow result if the main hypothesis fails |

At every completed packet, append **hypothesis → result classification →
evidence/source hashes → closest-work difference → pass/stop → next packet** to
progress; update the machine queue and revisit Gate A (contract), B (mechanism),
C (useful effect), D (assurance). Do not mark an entire P package complete
because one finite screen returned. Stopped recipes stay stopped unless the
new mathematical step is recorded first.

## 8. Evaluation preregistration to complete after selection

Preserve Mushroom/Semeion explanatory cases and distinct Connect-4 rows as
adverse controls. Add at least one justified larger **distinct-record** binary
workload before a scale claim. Synthetic uniform/low-rank data are labeled
diagnostics. Discover shapes from owner index only; reserve held-out queries
and datasets for final selection. Run a bounded pilot before sizing repetitions.

Match source, compiler/runtime, parameters, workload, client/server hardware,
thread count, warmup, retained state and trust mode. Required baselines are
raw/compressed authenticated caches plus ordinary deltas; Paillier CPU/lookup/
CUDA and lookup hybrid; homemade BFV/BGV; strongest compatible fresh-query/
verified/token controls; and the two closest construction competitors.
Keep honest-but-curious, conditional private-gate, proof-verified and actually
attested modes separate. An author number or optimistic count is not a local
measurement. First match BGV and the lookup hybrid in the same larger fixture.

Explore rows/dimension, rank and block widths, client state, session length,
update churn/locality, owner provisioning, concurrency and residency. For a
bounded initial screen use session lengths 1/10/100/1,000, several state budgets
including full cache, and unchanged plus sparse/dense updates. Select final
ranges from a pilot and a plausible deployment trace; do not claim they describe
customers without evidence. Link models can screen 1/10/100/1,000 Mbps and
0/20/80 ms RTT, but final latency claims require actual measured/emulated
transport with its implementation and limits disclosed.

Measure complete elapsed to first authorized result, endpoint CPU and peak
RSS/device memory, actual serialized bytes, setup/registration time, unused
tokens, epoch updates, failures/retries, throughput and first-request latency.
Report producer saturation if correlations are consumed. Count all provisioning
channels and replies. Do not add stage medians or overlapped CPU times and call
the sum a measured wall clock. Do not infer p95 from three calls.

Use serial locked benchmark blocks, idle preflight and resource monitoring from
the audit. Pilot at least five independent process blocks per paired contrast;
size the final study from block variance and the preregistered meaningful effect.
Randomize/alternate variant order, separate tuning data, and record all rejected
resource blocks with a speed-independent rule. Query repeats within one process
are not independent hardware runs. If the interval includes the material-effect
threshold, report inconclusive rather than selecting the smallest median.

Required ablations: proposed step off; strongest known composition; fresh work
fully charged; equal retained-state bound; equal query/output/trust; serialization
and complete release enabled; cold/new/returning clients; low/high rank; dense
ties; updates; reference/native/CUDA on the same accepted relation. Four main
figures should show complete latency versus traffic, client state versus paid
work, lifetime break-even including updates, and full protocol cost breakdown.

## 9. Security analysis as a construction constraint

Develop the reduction for the **selected transcript**, starting with the
[existing game](exact-search-security-game.md). State which assumptions are
standard, heuristic, new or merely unreviewed. A security target and a lattice
estimator output are not parameter assurance.

1. Prove integer/field/CRT correctness and stable-ID coverage for all admitted
   inputs and traces. Establish uniform noise/rounding bounds where needed.
2. Bind initial operator, code/commitment, IDs, keys, epoch and query. Owner-built
   registration is the first mode; malicious outsourced setup is separate.
3. Prove that accepted incorrect release requires a named bad event. For a
   supported full-Q relation, identify every component used by private decoding.
   For a code check, prove distance and challenge order; for shares, prove the
   actual MAC/opening theorem. Never transplant a field bound to a composite ring.
4. Analyze adaptive accept/reject, malformed-but-correct-output proofs,
   concurrent sessions, repeated challenges, retries and epochs. Replace accepted
   private decryption with the authorized ideal output before privacy hybrids.
   Failure feedback cannot be ignored merely because scores are returned locally.
5. Prove privacy of the chosen mask/programmed correlation or direct backend,
   including joint repeated transcripts, published seeds, key dependencies,
   projection, auxiliary ciphertexts and allowed output/access leakage.
6. Review private timing/access, samplers, zeroization, durable one-use accounting
   and rollback. Fresh public checks can change lifetime requirements, but do
   not erase key secrecy, replay/epoch binding or implementation obligations.

A useful target statement is a bound separating binding/code/verification
failure, HE or correlation distinguishing advantage, honest decoding failure
and authenticated-channel/epoch failures. Exact terms depend on the accepted
construction. Write no combined theorem until each hybrid is justified.
Use exhaustive tiny oracles and reduction-oriented negative tests as evidence,
then obtain independent cryptographic and private-implementation review.

TEE deployment remains an allowed company mode. A genuine attested baseline
must measure provisioning and execution within its real boundary; a signature
or CPU enclave does not attest an unchecked external GPU. Do not spend this
research cycle on a new hardware integration unless it is part of the selected
contribution or a necessary measured baseline.

## 10. System integration and publication outcome

Keep the existing homemade code and independent SEAL/author controls intact.
Start new protocols under `experiments/bfv_search_lab/`, runners in
`benchmarks/`, reports in `docs/research/`. A shared harness should distinguish
full-score and top-3 outputs and make setup/release/trust explicit. Introduce
only the small interface needed by the survivor; avoid another generic planner.
Production promotion into `src/cuhepy/` is a separate reviewed change.

The paper skeleton is: precise problem/threat model; closest constructions and
their actual limitations for our workload; one new algorithm/protocol; exactness
and security argument; implementation; matched evaluation/ablation; limitations
and retained negative results. Maintain a claim-to-source/lemma/raw table as
the implementation develops. No claim may cite only an author-reported ratio
or an unexecuted optimistic model as our system evidence.

Potential outcomes are a new fixed-function protocol, a restricted verified
operator construction, or a genuinely new exact selection/coverage mechanism.
A strong negative result needs a theorem or new general insight beyond a list
of failed optimizations. If no candidate meets that standard, retain company
improvements and revise the research question rather than declare success.

Venue is secondary. [CSF 2027](https://csf2027.ieee-security.org/cfp.html) emphasizes
foundational security results; this program would need its model/reduction or
principled analysis to be substantive. [FHE.org 2027](https://fhe.org/conferences/conference-2027/call-for-presentations)
is a call for talks/posters spanning theory and practice, distinct from an
archival-paper acceptance. Human authors should review every theorem, source
and number; track AI assistance for the applicable submission policy. Recheck
requirements when a real submission is ready, rather than let dates weaken the
construction or evidence gates.
