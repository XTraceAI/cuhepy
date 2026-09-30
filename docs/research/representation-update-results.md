# E43: repairing never-exposed pending work in a frozen representation

2026-09-30. New encrypted prototype in
[`representation_updates.py`](../../experiments/bfv_search_lab/representation_updates.py).
This is an owner-local research experiment, not durable or remotely authenticated
token migration. The company's BFV/BGV/TEE baseline remains unchanged.

**Latest control:** [vectorized matched lifecycles](vectorized-update-controls.md)
reverse the earlier positive result. Sparse repair costs ~9.25% more at rank32
and ~7.88% more on the old eight-edit rank128 workload. The tables below retain
the original Python-control measurements; they are not the current strongest
full-reencryption comparison.

## Hypothesis, mechanism and strong control

For fixed approved maps/geometry/IDs, an edit within each map's old affine space
changes coordinates by Delta M. An unused pad r can retain its value: update
its answer by adding fresh `Enc(Phi(Delta M*r))`. This evaluates only edited-row
dot products per pending token. It also adds fresh encrypted column differences.
Every column and every pending reply is encrypted, including zero patches, so
public packet counts do not disclose secret-pad-dependent zero tests.

The control uses the same frozen maps, geometry, keys, padding and unused-pad
semantics, but independently reencrypts the complete new index and every full
new `M*r`. It does not discard all tokens, refit maps or rederive masks just to
make the control slower. Initial unused-pool preparation is charged equally.
Full checker/answer-check preparation and native index preparation are included.

Maps reject out-of-space edits. Stable IDs and positions are fixed. Pads are
burned before query release; consumed tokens stay consumed, even after edits.
Private row-derived digests remain local; public epoch handles are random.
The entire phase budget is checked before changing the local target. Repeated
additions accumulate noise and eventually require a fresh rebase.

## Retained positive and negative results

All runs use full encryption N=16,384 and eta=21, homemade GMP encryption and
existing native public evaluation/full-vector checking. Synthetic rows duplicate
private pivot bits across coordinates, deliberately creating a known exact
affine structure. They are not a representative real-workload claim.

| Fixture | Pending pool | Sparse complete update | Full reencryption control | Initial setup + pool + update |
|---|---:|---:|---:|---|
| 8,192 rows, d=32, rank=8, t=193, Q32; 3 paired repetitions | 12 | median 0.967 s | median 0.904 s | 1.719 vs 1.654 s; sparse loses |
| 16,384 rows, d=512, rank=128, t=1153, Q40; 2 paired repetitions | 32 | 8.508 s | 12.032 s | 18.927 vs 22.249 s; about 15% less work |

The larger update stage improves by about **29.3% (1.41x)**, while the smaller
case regresses about 7%. The sparse row dot product count is much lower, but
fresh encryption, ciphertext addition, verification setup and index setup still
cost time. This explains why an arithmetic-count speedup alone is misleading.
These are local measured CPU stage sums, not network request latency. Paired
arms alternate order, use the same public workload/edit/query policy and fresh
independent private randomness. The sample is too small for publication p95 or
confidence claims.

All validation requests passed the full gate before secret decryption, matched
every current Hamming distance/stable top-3, and matched native/GMP ciphertext
coefficients. Tiny regressions also exercise three successive edits, stale
responses, consumed-pad rejection, out-of-space changes and phase exhaustion.
The initially failed report-generation call was corrected; subsequent completed
runs are retained incrementally so reporting failure cannot lose costly work.

Raw results:
[`publication-pending-repair-8192-20260930.json`](../../benchmarks/results/publication-pending-repair-8192-20260930.json),
[`publication-pending-repair-rank128-20260930.json`](../../benchmarks/results/publication-pending-repair-rank128-20260930.json).

## Originality boundary and next discriminating experiments

### Repeated-update execution, complete setup and utilization

The follow-on [lifecycle harness](../../benchmarks/representation_lifecycle_lab.py)
interleaves two adaptive queries with each approved edit and drains all
remaining prepared tokens at the last revision. Every token is used exactly
once. Both arms use the identical edit/query trace and stable IDs; previous
authorized results drive later queries. Full checks precede secret decryption.
Each revision also receives an untimed GMP/independent unreduced-phase audit.

The complete larger run has eight edits, 32 prepared/consumed tokens per arm,
two paired repetitions (128 accepted exact queries across four arms), N=16,384,
rank=128, d=512, t=1153 and Q40. Affine discovery costs **29.868 s** and
compilation/certification **11.118 s**; neither is amortized away.

| Complete measured CPU stage sum | Sparse repair | Full reencryption |
|---|---:|---:|
| All setup + preparation + eight updates + all token uses | 115.478 s | 135.963 s |
| Eight update stages | 62.348 s | 82.954 s |
| All online stages | 2.211 s | 2.210 s |

Complete paired savings are **15.22% and 14.92%**, median **15.07%**; update
stages alone improve about **24.84%**. Thus the larger update gain survives
full utilization but still misses the plan's initial 20% complete-cost target.
Small-rank repeated repair remains a regression. Gate C stays open.

Earlier four-edit lifecycle files have a misleading
`full_lifetime_stage_sum_s` name: they include compilation but **exclude affine
discovery**, so the larger 18.6% number is not a complete enrollment-lifetime
claim. They remain immutable historical evidence, superseded for complete-cost
claims by the eight-edit run. The harness was corrected before that run.

Accumulated patches also require a larger independent integer audit modulus
than fresh-only ciphertexts. `integer_phase_audit.Audit` now accepts a declared
maximum answer bound and checks it before measurement; a three-edit regression
tests the diagnostic itself. This corrects the audit, not the encryption ring.

Raw: [complete eight-edit run](../../benchmarks/results/publication-pending-lifecycle-rank128-20260930-complete.json),
[earlier four-edit larger run](../../benchmarks/results/publication-pending-lifecycle-rank128-20260930.json),
[earlier four-edit smaller negative](../../benchmarks/results/publication-pending-lifecycle-rank8-20260930.json).

Updating preprocessed private-retrieval state is established prior work.
[Incremental Offline/Online PIR](https://eprint.iacr.org/2021/1438) preserves
preprocessing across changes; [Single Pass Client-Preprocessing PIR](https://eprint.iacr.org/2024/303)
has dynamic hint updates. More directly,
[Incremental Single-Server PIR](https://eprint.iacr.org/2026/030) and
[Authenticated and Incremental Single-Server PIR](https://eprint.iacr.org/2026/1077)
study entry-level/aggregated updates to LWE-based preprocessing, including
authenticated variants. Merely calling our repair incremental is not a novel
contribution. Their public-database PIR contracts differ from our private-index,
full-score, full-Q pre-decryption verification and owner-secret pad lifecycle;
that difference needs an actual construction/proof/evaluation, not a name.

The next tasks are repeated approved edits interleaved with queries, complete
pool utilization and producer saturation, public real-data frozen-map failures,
ordinary delta indexing, reserved capacity/insertion/deletion and rebasing.
Fit a cost rule on training traces and evaluate it on held-out traces. Include
all initial/unspent/invalidated tokens and update/ciphertext noise costs.
Joint representation/sharing/pad/noise planning remains the candidate research
contribution. The current full-cycle improvement is below the initial 20% Gate C
target, and originality Gate B is open; no new GPU kernel is justified yet.

P07 specifies the conditional hybrid and missing review. P08 must atomically
bind durable pad state to the authenticated ciphertext/plan revision before
this prototype can become a network migration protocol. Tests alone do not
establish either property.
