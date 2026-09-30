# E57: bounded calibration and a causal policy that loses to ordinary deltas

2026-09-30. Returned to P04/P06 after E55/E56. The purpose was to test whether
complete measured prices make lifetime choices useful, rather than crediting
a hindsight count oracle with a runtime gain. Sources are
`experiments/bfv_search_lab/lifetime_prices.py`, `verification_lifetime.py`
and `benchmarks/lifetime_price_lab.py`, `client_delta_lifecycle_lab.py`.

Only repetition0 of the localized/dispersed E56 runs trains the nonnegative
affine models. Repetition1 checks prediction error. These are separate timing
repetitions of already designed traces, not new unseen update traces. Geometry
is fixed: m8192/d128/rank32, N2048/t1153/Q40/eta21, 24 original tokens,
four128-row edits. Prices reject unknown geometry and out-of-domain features.
Tile prices exist only for one and four dirty tiles; other counts are omitted,
not extrapolated. The fitting implementation checks identifiable feature data
and solves the two-parameter nonnegative problem over its active sets.

| Predicted operation | Held-out mean relative error | Mean absolute error |
|---|---:|---:|
| Complete full refresh/check/native preparation | 0.81% | See raw samples |
| Complete selected-tile refresh/check/native preparation | 1.31% | See raw samples |
| Trusted private delta edit | 9.73% | ~37 μs |
| Per-query private correction | 2.05% | ~20 μs |

Training acquisition is **34.029 s**, plus the recorded fit cost. This is a
cost, even though the data already exist. Every policy case charges it once in
`complete_lifetime_s`; `native_execution_lifetime_s_without_training` is
explicitly separate. Shared calibration could later be amortized across many
sessions, but that is another declared model, not this cold result.

The causal rule observes current exceptions, dirty tiles and remaining unused
tokens and uses a one-query horizon. It sees no future edit or query trace.
Private edit work is sunk for every candidate, and actual residual rebase,
refresh, full checker/native preparation and decision work are timed. A trusted
partial rebase installs only current authorized rows, preserves untouched
base values/residuals, and rejects changed maps/profile/IDs. This does not
authenticate an external base. A single volatile `AttemptBudget` is shared
across all refreshed verification epochs and burns before every checker call,
including malformed/rejected/exceptional calls. It requires trusted retention
of that object and is not a durable network receiver.

Two new random edit traces use seeds57001/58001, independent of calibration
trace selection. They are synthetic same-geometry tests, not blinded real-data
holdouts. Each trace has two rotating repetitions of full reencryption,
ordinary private deltas and the priced policy; every original token is used.

| Edit-trace seed / method | Pair mean execution | Pair mean with calibration |
|---|---:|---:|
| 57001 / full refresh | 7.610 s | 7.610 s |
| 57001 / ordinary deltas | 2.895 s | 2.895 s |
| 57001 / priced rule | 2.932 s | 36.963 s |
| 58001 / full refresh | 7.472 s | 7.472 s |
| 58001 / ordinary deltas | 2.804 s | 2.804 s |
| 58001 / priced rule | 2.846 s | 36.877 s |

All16 policy decisions retain private deltas. Ordinary deltas save61.96% and
62.48% against full refresh; the policy adds about1.3–1.5% execution cost to
the already winning simple choice. All288 encrypted queries pass full
pre-decryption gates, complete score/stable-top3 checks and once-per-revision
native/GMP/integer-phase diagnostics. Each case records24 global attempts.

The seed57001 encrypted cases finished before a **final-report path bug**.
Completed partial cases were retained, their cross-method score/top3 hashes
rechecked, and the report recovered without rerunning or changing their
timings. The raw artifact records that recovery and the exact pre-fix source
hash. Seed58001 completed directly after resolving the price path for metadata.
Both source versions remain committed.

Raw artifacts:

- `publication-lifetime-prices-20260930.json`
- `publication-causal-policy-seed57001-20260930.json`
- `publication-causal-policy-seed58001-20260930.json`

Return to the plan: **reject an optimizer speed claim for this rule/domain**.
Prediction quality does not imply a useful decision problem. E52/E55 remain
exact finite-model references. A new policy needs a justified workload where
different safe actions actually compete, and must beat deltas and permitted
cache controls after training/state/updates are charged. Gate C and originality
Gate B remain open. Do not promote new GPU kernels for this losing rule.
