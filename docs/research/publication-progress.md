# Publication research execution log

The [publication plan](publication-research-plan.md) governs task order. This
log records evidence and decisions; [work-package statuses](publication-work-packages.json)
are updated only when their acceptance conditions are met. The protected
E01–E40 implementation remains available at `02e06c0`, and planning at `00a6362`.

## 2026-09-30: first execution tranche

| Package | Status | Evidence / next action |
|---|---|---|
| P00 | Contract frozen; viability open | [Exact-search contract](exact-search-contract.md); state-budget/usefulness evidence still required. |
| P01 | Preliminary reproduction done; package open | [Matched author results](baseline-reproduction.md); 78 external tests, two public exact fixtures, own native anchors. Stronger low-state variants and publication-size evaluation remain. |
| P02/P04 | Static finite oracle/DP implemented; novelty gate open | [Planner analysis](representation-planner-analysis.md); exhaustive binary and resource-vector references, equal-form/raw/global/beam controls. Gains explained by known ingredients do not count as new contributions. |
| P03 | Algebra/count screening implemented | [Backend results](backend-frontier-results.md); actual code-dimension floors, full-Q matrix/carry oracle and expansion costs. Outer protocol and assurance unresolved. |
| P05/P06 | Frozen-map encrypted repair pilot implemented/measured | [Update results](representation-update-results.md); 29.3% complete-update gain at larger rank, regression at smaller rank; about 15% initial+update gain, below full-lifetime Gate C. |
| P07 | Conditional game/reduction agenda written | [Security game](exact-search-security-game.md); no completed reviewed theorem or parameter/private-timing assurance. |
| P08/P09/P10/P12 | Planned, subject to gates | Durable authenticated migration, new GPU mechanisms, alternate exact circuits and paper claims require the corresponding protocol/practical evidence. |
| P11 | Partial artifact retention | Raw runs, input/source/compiler/lock/binary hashes and tests retained; final evaluation/artifact gate remains open. |

Initial environment: native research extension imports successfully. The
current restricted process has no `/dev/nvidia*` device and `nvidia-smi` cannot
contact a GPU. An approved check outside that process confirmed the RTX 3080
with driver 595.91.07 is available. No new GPU measurements are implied.
Rust toolchain 1.98.1 is installed; the external artifact requests 1.95.0, so
record the compiler override rather than pretending to reproduce its compiler.

Venue scope was checked at the user-supplied official sites and is recorded
in the contract. No submission or external message is authorized by this log.

## Decisions after returning to the plan

1. **P01:** Preserve contrary results. BNTM's native verified mode is faster
   and communicates less on Semeion, but retains full plaintext/verification
   matrices. Next compare recursive/low-state versions and compressed local
   caching; do not use an artificial memory budget to exclude the best control.
2. **P02/P04:** The complete oracle shows rank/check/state tradeoffs. Equality
   merging explains the strongest tiny gain; originality Gate B remains open.
   Continue toward lifetime/noise/dependency choices rather than naming known
   affine/packing algebra as novel.
3. **P03:** A naive outer vLHE has a 32–64x literal matrix expansion and needs
   full inner Q arithmetic. Retain the oracle; do not implement that naive
   route without actual structured-operator/parameter support.
4. **P05/P06:** Sparse unused-pad repair helps only beyond a cost crossover.
   Both the larger positive and smaller negative encrypted experiments are
   retained. Repeated edits, utilization, rebasing and real-data fit failures
   are the next discriminators. New GPU kernels have not passed their gate.
5. **P07:** Owner-local plaintext/plan hashes must not become public epoch
   commitments. New repair epochs are random. Seeded encryption with published
   seeds requires an explicit random-oracle/seeded-IND-CPA premise; ordinary
   secret-seed PRG security does not justify that hybrid.
6. **Closest work:** Incremental PIR and authenticated incremental PIR already
   preserve preprocessing across updates. Four primary papers were located;
   direct local PDF download returned HTTP 403, so full-text/hash reconciliation
   is still pending rather than represented as a completed proof reading.

All implementations here are separate research modules. The protected
E01–E40 checkpoint, current company/native/GPU schemes and production branches
remain available. An expensive benchmark reporting bug was fixed; subsequent
update runs checkpoint completed cases before final report generation.

## Result recording rules

Each entry gives a hypothesis, source/context, command, raw artifact, result
class (`proved`, `measured`, `model`, `counterexample`, `unresolved`) and next
decision. Tests and count oracles are not security proofs or network timings.
Failed candidates and changed contracts remain visible. A partial external
reproduction does not complete P01. Follow-on tasks may make independent
progress while another package still has unresolved subcomponents.

## 2026-09-30: repeated lifecycle, stronger controls and return to the algorithm

First execution checkpoint: `e52df4b`, tag
`checkpoint/publication-execution-pilot-2026-09-30`. Later immutable checkpoints
retain E48 at `d2c198d`/`7f2962b`, initial repeated lifecycle at `f8a8290`,
the enrollment-cost correction at `cf88c1b`, and complete eight-edit work/E49 at
`4cff0ed`. Source hashes in each raw run identify exact source content;
recorded Git HEAD may precede uncommitted experiment files. Later reports
correct scope without rewriting historical observations.

Second source/results checkpoint: `7058a47` (cache/factory controls, parameter
screening, full-ring layout and E52 lifetime model). Follow-on global controls
and E53's composition regression are retained separately.

| Completed subcomponent | Result class / evidence | Return-to-plan decision |
|---|---|---|
| E43 eight edits / all 32 tokens | **Measured:** 115.478 vs 135.963 s including discovery, 15.07% paired saving; [report](representation-update-results.md) | P05/P06 open. Earlier four-edit 18.6% excluded discovery. Test real-data failures/reserve/rebase and vectorized controls. |
| E48 public component recipe | **Measured/model:** 128→64 KiB; more cached CPU/state, modeled crossover ~43–46 Mbps; [report](component-recipe-results.md) | Optional priced recomputation; fixed fresh index only, no new primitive/service/GPU promotion. |
| E49 encrypted-index factory | **Measured/counterexample:** original 3.34x gain fails stronger control: plaintext 38.136 ms vs encrypted 53.900 ms; exposed zero seed recovers pad/query; [report](ciphertext-factory-results.md) | Retain conditional route; do not promote as speed contribution. Keep vectorized plaintext baseline. |
| E50 cache controls | **Measured:** raw/zlib/one-bit-coordinate exact search on three workloads; Semeion maps exceed raw corpus; [report](coordinate-cache-results.md) | Gate A open; actual retention/resource limits need evidence. |
| P07 parameter screening | **Heuristic:** N1024 rejected; N2048 returned classical/quantum-sensitivity costs above target, additional failures retained; [report](parameter-frontier-results.md) | No parameter assurance. Arora-GB, seeded/transcript premises, timing and review remain open. |
| E51 ring/output capacity | **Measured/exact:** Semeion 128→16 KiB / ~57→19 ms; Mushroom seven replies, 128→112 KiB / ~10% work gain | Gain is full-N choice. Preserve adverse occupancy and correctness/phase checks. |
| E52 lifetime DP | **Exact within model:** exhaustive schedule agreement; equal-rank/equal-static-cost maps have different future span feasibility; real encrypted reserved-zero-column repairs pass; [analysis](lifetime-planner-analysis.md) | Calibrate and assess a held-out policy. Hindsight counts are not runtime gains or an originality proof. |

The company checkpoint and homemade arithmetic remain retained. External
author code and the estimator are pinned baselines/tools. No new GPU
measurement or hardware-attestation deployment was performed. P08/P09 remain
behind Gate C; no full package is declared accepted from these pilots.

Stronger [global controls](global-representation-controls.md) subsequently reach
25.933 ms/64 KiB on Mushroom and 9.826 ms/16 KiB on Semeion at N2048. Their
larger F/index state and vectorized preparation are charged. These replace
partitioned layouts as the stronger online comparator, while raw/zlib caches
still dominate when allowed. [E53](seed-composition-obstruction.md) generalizes
the hypothetical public-zero-seed failure to multiple coordinates and fixes
an intermediate-subring spacing bug in the E47 **research matrix oracle**.
The genuine factory still keeps that seed private; production arithmetic was
unaffected. The [claims ledger](paper-claims.md) records all promotion limits.

### Next executable sequence

1. **P01/P00:** Reproduce the strongest usable recursive/low-state code-based
   verifier and a larger justified corpus/retention scenario. Native author
   BNTM uses its plaintext matrix online for `M*T`; dropping an array is not
   the stronger low-state protocol. Keep raw/zlib/coordinate cache controls.
2. **P05:** Measure real/synthetic span failures, reserves, sparse/full/delta
   crossovers and noise-forced refresh. Charge vectorized owner preparation,
   every token, mapping/key/state change and compiler work. Define stable-ID
   insertion/deletion semantics before implementing those transitions.
3. **P04/P06:** Calibrate E52 prices from complete native traces, preregister an
   objective, train a bounded reserve/rebase policy and evaluate held-out
   traces against hindsight. Extend sharing/alignment/capacity boundaries only
   with exact successor semantics.
4. **P07/P12:** Complete the surviving mechanism's transcript argument and
   forward/backward closest-work audit: dynamic HE/compiler planning,
   incremental PIR, masking and code-based preprocessing. Keep proved,
   conditional, modeled, measured and unresolved claims distinct.
5. **Gate review:** A usefulness, B originality, C complete practical effect
   and D defensible paper all remain open. Advance durable service/new GPU
   kernels on the stated evidence. If a cache or existing protocol dominates,
   retain company improvements and pivot the paper question.

## 2026-09-30: stronger update control and next baseline

Returned to P05/P06. Recorded the
[experiment specification](lifetime-policy-preregistration.md) before new
measurements. Owner-private batch products are implemented, with atomic-edit,
negative-delta, failed-token-budget and encrypted lifecycle regressions.
Matched rank32 and the prior rank128 lifecycles both finish and pass every
encrypted diagnostic. [Latest results](vectorized-update-controls.md) reverse
the earlier win: sparse repair costs 9.25% and 7.88% more than vectorized fresh
reencryption. This is a measured negative, not a reason to delete E43.

Returned to the plan: E54's ordinary private client delta ledger is implemented
and its exact/encrypted base tests pass; complete-cost measurement is next.
The EMVP authors' original Go/C++ artifact was found via the pinned paper and
cloned at `856762f5925fe873bb5cbc0401ceb5a44568efa9`. It is not yet built or
measured. Production/company source and earlier checkpoints remain intact.

## 2026-09-30: private deltas, base identity and original author control

| Completed subcomponent | Result class / evidence | Return-to-plan decision |
|---|---|---|
| E54 fixed-base private corrections | **Measured/exact:** 61.60% / 36.15% complete-cost savings on two synthetic sizes; all encrypted diagnostics pass; [report](client-delta-results.md) | Ordinary delta caching is the stronger control, not a novelty claim. Private authorized snapshot delivery, insert/delete and real workloads remain. |
| E55 checkpoint/exception frontier | **Exact within count model:** exhaustive schedules agree; base identity affects future cancellation despite identical current counts/costs; [analysis](overlay-lifetime-analysis.md) | Calibrate prices and a causal policy; no measured algorithmic gain follows yet. |
| Original EMVP Go/C++ artifact | **Measured:** complete gated cached scans 5.942 / 1.363 ms, substantially larger replies; [report](original-emvp-results.md) | Keep original low-persistent-state control and its transient regeneration cost. Parameter/entropy and recursive BNTM gaps remain. |
| Original adapter affinity failure | **Counterexample/fix:** unpinned key-only Semeion failed exact scores; pinned OS-thread sequences pass both datasets and forced-GC regeneration tests | Preserve failed raw and source/binary versions; passing upstream tests alone was insufficient. Author source unchanged. |
| Static-code edit with reused mask | **Exact negative:** a systematic encoded-column difference exposes a binary toggle | Do not count a reused-mask static code edit as a privacy-preserving cheap update. Track mask provenance in future planner states. |
| Replacement span screen | **Exact algebra/measured fits:** learned reserves offer zero Semeion acceptance and small Mushroom gains; global/schema controls accept all tested rows; [report](span-reserve-results.md) | No learned-reserve promotion. Next price selective encrypted tile rebuilding and bounded causal delta/rebase controls. |

These are completed subcomponents, not acceptance of their enclosing P00–P12
packages. This entry predates the user's clarification permitting all data
retention. Complete protocol/parameter assurance and all paper gates remain open.

## 2026-09-30: permitted caches, causal negatives and decoder-aware alternatives

The user clarified that the client queries its own data and may keep/access
any part of it. Inspected deployed Paillier/lookup client interfaces: plaintext
encryption inputs and owner keys are present and no input-retention ban exists.
The contract now explicitly permits caching. These interfaces do not establish
customer memory/device/session limits; no artificial restriction is assumed.

| Completed subcomponent | Result class / evidence | Return-to-plan decision |
|---|---|---|
| E56 selective encrypted tiles | **Measured:** localized complete lifetime7.651→5.495 s; spread7.478→7.498 s; ordinary private deltas cheaper in both; [report](tile-update-controls.md) | Known partial rebuild is a stronger control, not a novel-policy pass. |
| E57 prices and causal rule | **Measured negative:** good refresh predictions, all16 unseen-trace choices keep deltas; policy adds execution and full34.029 s training cost; [report](lifetime-price-policy-results.md) | Reject planner speed claim on this domain; preserve exact hindsight oracles and stop enlarging a losing rule. |
| Shared attempt allowance | **Implemented/tested:** volatile global guard burns before checker calls across fresh epochs, malformed/rejected/exceptional trials included | P07 correspondence improves; no durable receiver/rollback claim. |
| E58 encrypted cache acquisition | **Measured:**144 then432 exact local queries, actual AES-GCM packets/owner+client acquisition at four compression efforts; real67,429-row Connect-4 cache; [report](cache-acquisition-results.md) | Full authorized caching is mandatory and fast; maximum compression can waste cold CPU time. |
| E59 arbitrary private inserts/deletes/edits | **Measured/exact:**96 full-current results agree; buffer4.059 s vs authenticated cache0.02659 s complete compute; [report](client-buffer-results.md) | Functionality control implemented; no encrypted-base migration/erasure/durability, no novelty claim. |
| E60 cold-link screen | **Model:** cold cache favorable37/40 cells; prepaid-owner-cache38/40; narrow single-query slow-link Semeion BGV cells remain | Usefulness unresolved; remote omits provisioning and uses fastest gated sample. Real network/device/assurance data needed. |
| E61 larger real encrypted control | **Measured:**32,768 distinct Connect-4 prefix, rank126→82; online111→102 ms, cache~3 ms; all HE/cache score hashes agree; [report](connect4-encrypted-controls.md) | Larger corpus still favors local reuse. Known affine reduction does not establish outsourcing advantage. |
| P07 direct-fresh draft/oracle | **Conditional argument/exact oracle:** explicit advantages/authentic state/leakage;684 ideal rejection paths; reset/conditional-probability negatives; [draft](direct-fresh-conditional-security.md) | Formal environment, assumption discharge, private timing and independent review remain. |
| E62 dedicated projection | **Measured/exact:**14.23% smaller Semeion2048 body, only1.20% Mushroom2048; all16 public encrypted queries pass; C1/mod-t negatives; [report](decryption-projection-results.md) | Separate changed relation/decoder and Python checker; no native speed or assurance claim; ordinary sample extraction credited. |
| E63 decoder support | **Exact:** eight complete tiny decoder matrices agree with analytical support; equal old resource vectors give192 vs224 B projected models | Price support/alignment in a protocol-aware hypothesis; split-CRT projected gate and originality still unimplemented/unestablished. |

Reports retain raw filenames, exact executed source hashes and recovery notes.
The seed57001 encrypted run completed before a reporting-only path failure;
its cases were recovered and revalidated without changing their timings. The
next seed completed directly. E58 maximum-effort and subsequent effort-sweep
runs, initial/expanded E60 screens and all adverse cases remain distinct.

Returned to the plan after each component. The primary calibrated lifetime
rule has **not** passed Gate C. The new sequence prioritizes a scoped proof and
exact decoder-support grammar before another native/GPU implementation. Full
retention permission is settled; actual resource/cold-session usefulness and
paper originality are not. P08/new GPU work remains gated. P01 strongest
recursive/vLHE, P07 reviewed seeded privacy/parameters/timing and publication-
size uncertainty remain open. No full P00–P12 package is falsely marked accepted.
