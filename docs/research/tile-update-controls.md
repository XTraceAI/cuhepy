# E56: selective encrypted tile rebuild versus private deltas

2026-09-30. This is a stronger P05/P06 control after the vectorized and private
delta results. `RepairPool.edit(method="tile_reencrypt")` refreshes all columns
and never-exposed mask answers at selected public reply positions, preserving
the ciphertext objects of other replies. The private maps, IDs, key and
geometry are fixed. An edited row in a CRT leaf of degree L affects reply
floor(local_row/L); all component/column encryptions in that reply are fresh,
including zero values. This reveals affected reply locations, not private
mask-dependent sparsity. That update schedule belongs in leakage.

Every reply's phase is checked before mutation, including unchanged aged
replies. Refreshing tile0 cannot reset tile1's old noise. All index/cache/answer
replacements commit after preparation; consumed pads remain consumed. New
tests check full native/GMP coefficients, every score, integer phases, stale
requests, unchanged ciphertext identity, failed atomic updates, canonical
selection and a high-phase unchanged-tile negative.

No incremental verifier reuse is assumed. The benchmark charges a new full
hidden checker, pending-answer hints and native index at every encrypted edit.
The private-delta arm keeps its complete frozen-base gate. Both arms pay the
same complete initial discovery, keys, index/pool setup and every original
token, plus all edits and adaptive queries. Local volatile execution and
unreviewed parameters remain; no network timing or production assurance.

Two paired rotating repetitions: 8,192 synthetic rows, d128/rank32, N2048,
t1153/Q40/eta21, 24 original tokens, four batches of 128 approved edits. Two
queries on each nonfinal revision, final revision consumes the remaining16.
Localized edits stay in reply0; a fixed coprime spread visits all four replies.
The edit count, row values and query policy match between methods within each
trace. These are designed adverse controls, not observed workload frequencies.

| Trace / method | Complete lifecycle, pair mean | Paired median saving vs full |
|---|---:|---:|
| Localized / full fresh rebuild | 7.651 s | reference |
| Localized / selective tile rebuild | 5.495 s | 28.17% |
| Localized / private client deltas | 3.038 s | 60.29% |
| Spread / full fresh rebuild | 7.478 s | reference |
| Spread / selective tile rebuild | 7.498 s | −0.27% |
| Spread / private client deltas | 2.863 s | 61.72% |

Localized encrypted update packets fall 8,440,704→2,110,176 B. Dispersed edits
refresh every reply and retain the original packet count. Client deltas need
20,736 B total private update bodies and at most20,544 B additional private
snapshot body in either trace, with no server ciphertext edits. Body models
exclude transport authentication/framing and RSS. All 288 encrypted queries
across the two complete runs pass full score/stable-top3 and pre-decryption
gates; independent native/GMP/integer diagnostics pass once per revision.

Raw/source identity:

- `benchmarks/results/publication-tile-delta-localized-20260930.json`
- `benchmarks/results/publication-tile-delta-spread-20260930.json`
- `benchmarks/client_delta_lifecycle_lab.py` with `--methods full_reencrypt tile_reencrypt private_client_delta`

Return to the plan: location/dependency scope has a real cost effect, but
ordinary client deltas still win. The 28% is a company optimization/control,
not Gate C evidence for a novel planner. Next calibrate predictions with
held-out repetitions and test a causal decision rule. A selective verifier
would need independently versioned challenge/hint semantics and a global
attempt budget; a fresh epoch is not permission to reset security accounting.
