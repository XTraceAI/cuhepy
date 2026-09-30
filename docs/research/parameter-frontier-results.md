# P03/P07: full-ring parameter screening and E51 capacity controls

2026-09-30. New profiles are **research-only**. No allowlist, company default,
production branch or encryption scheme is changed by this experiment.

## Estimation method and unresolved attacks

The [Sage runner](../../benchmarks/bgv_parameter_estimation.py) pins the
[lattice estimator](https://github.com/malb/lattice-estimator) to
`53da5982597709ba0fdf94ea37a84d822310fd84` and verifies tracked sources. It
records Sage 10.9, Python, model/configuration, the actual NTT prime Q, attack
cost details and failures. It uses full encryption dimension N, uniform
ternary secrets, CBD_21 errors (variance 10.5), GSA and unlimited independent
samples. For a known message, normalize `(c0-m,c1)` by `t^-1 mod Q`; this leaves
CBD_21 error, **not t times its standard deviation**. Public correction
subring degree is not the secret-key dimension.

The updated [HE security guidelines](https://eprint.iacr.org/2024/463.pdf)
use contemporary attack models; their tables are not a certificate for this
custom protocol. The estimator itself labels its outputs heuristic and warns
that `rough` uses a different cost model. We call the individual full-API
attacks with explicit MATZOV-classical/GSA settings. Quantum ADPS16 is a cost
sensitivity model, not complete quantum assurance.

| Full N | Q bits / actual Q | Minimum returned cost, four primary MATZOV attacks | Four primary ADPS16 quantum sensitivity attacks |
|---|---|---:|---:|
| 1,024 | 32 / 4,294,957,057 | 106.48 bits | Not run |
| 1,024 | 40 / 1,099,511,592,961 | 84.98 bits | Not run |
| 2,048 | 32 / 4,294,955,009 | 219.09 bits | 178.08 bits |
| 2,048 | 40 / 1,099,511,590,913 | 173.07 bits | 133.90 bits |

Primary attacks: primal uSVP, primal BDD, dual and dual hybrid. Additional
classical calls evaluate BKW, primal hybrid with/without MITM and Arora-GB.
The first additional run returns no lower finite cost, but N=2,048/Q32 MITM
and both Arora-GB calls time out at 45 s; Q40 BKW hits a read-only Maxima
configuration path. These are recorded as **unresolved**, never infinity or a
successful assurance result. A separate 60-second-target retry redirects
Maxima configuration to `/tmp`: Q32 MITM returns 333.20 bits and Q40 BKW/MITM
380.86/257.60 bits; both Arora-GB calls still time out. None lowers the primary
minimum. Sage/Maxima swallowed one alarm during object cleanup, so Q40 BKW
ran 110 seconds despite the 60-second target; actual elapsed times are retained.
The signal-based timeout is best effort, not process isolation.

An initial monolithic full-API call was stopped because it saved no
intermediate estimates. The current runner checkpoints every attack and
profile. Per-attack time limits are not mathematical attack exclusions.
RLWE structure/correlations, published-seed SHAKE, adaptive transcript
reductions, multi-message concrete losses, implementation timing and independent
review remain open even when returned costs exceed 128 bits. In particular,
the Q40 quantum margin is modest and not a deployment recommendation.

N=1,024 fails even this preliminary target and is excluded from performance
pilots. N=2,048/Q32 is screened for **local correctness/performance only**.
Fingerprint collision targets are recomputed for the actual prime and a
1,024-attempt lifetime; they do not certify encryption hardness.

## E51: feature columns are not input-vector packing

[The output-only layout](../../experiments/bfv_search_lab/score_layout.py)
distinguishes E29's transposed columns from E27's input-packed multiplication.
E29 separately encrypts one coordinate column in every final score position.
Constant CRT query corrections multiply those positions directly. Each leaf
therefore holds degree-many row scores, even if F exceeds its degree; F still
costs columns, owner work, native state and phase growth.

The new interface has `padded=1`, a distinct binding and zero legacy butterfly
switches. Legacy input-query/index packing explicitly rejects it. Exhaustive
tiny-field schoolbook multiplication, whole-row capacity tests and encrypted
native/GMP/unreduced-phase regressions cover F larger than a leaf and even N.
Ordinary CRT algebra explains this interface; it is not a novel primitive.

## Measured public fixtures, including the adverse occupancy case

Same E37 private maps, field, IDs, held-out queries and complete all-score
output; three timed samples plus a warmup per profile. Full serialization,
parsing, verification, secret decryption and stable selection are included.
Every complete gate passes before secret decryption; native/GMP coefficients,
every Hamming distance and unreduced integer phases are checked independently.
Setup/discovery, offline production and diagnostics are recorded separately.

| Fixture / full ring | Replies | Response coefficient body | Legacy-layout online stage sum | Output-only online stage sum |
|---|---:|---:|---:|---:|
| Semeion / N=16,384 | 1 | 131,072 B | 56.881 ms | 56.595 ms |
| Semeion / N=2,048 | 1 | **16,384 B** | 19.479 ms | 19.408 ms |
| Mushroom / N=16,384 | 1 | 131,072 B | 51.122 ms | 50.952 ms |
| Mushroom / N=2,048 | 7 | **114,688 B** | 46.169 ms | 45.147 ms |

Semeion saves 8x in reply bodies and about 2.9x in complete local online work.
Mushroom saves only 12.5% in reply bodies and about 10% in online work because
its map occupancy needs seven replies. Neither workload distinguishes the two
layouts materially: the observed gain comes from **full N**, not removing the
legacy feature-width restriction. Do not attribute it to a new mechanism.
These are paired-scope CPU stage sums, not network latency, lifetime totals,
GPU results or publication confidence intervals.

The parameter/layout domain is now ready for reserve/noise-planner screening.
Return to P04/P05: use exact identity/capacity and accumulated phase state;
smaller static rank alone cannot choose a safe dynamic plan. Larger public
corpora, justified retention constraints and stronger low-state baselines
remain necessary to pass viability and research gates.

Raw [classical primary](../../benchmarks/results/publication-bgv-estimator-classical-20260930.json),
[quantum sensitivity](../../benchmarks/results/publication-bgv-estimator-quantum-sensitivity-20260930.json),
[additional attacks](../../benchmarks/results/publication-bgv-estimator-additional-20260930.json),
[bounded retry](../../benchmarks/results/publication-bgv-estimator-retry-20260930.json),
[Semeion](../../benchmarks/results/publication-score-layout-semeion-20260930.json),
[Mushroom](../../benchmarks/results/publication-score-layout-mushroom-20260930.json).

Runner example: `DOT_SAGE=/tmp/cuhepy-sage MAXIMA_USERDIR=/tmp/cuhepy-maxima
/opt/sage/bin/python benchmarks/bgv_parameter_estimation.py --estimator
../research-data/reference-artifacts-20260930/lattice-estimator --n 2048
--q-bits 32 --json-out /tmp/estimates.json`. This environment's `sage` wrapper
does not support the traditional `sage -python` invocation.
For the encrypted pilot use `.venv/bin/python benchmarks/score_layout_lab.py
--dataset semeion --cache-dir ../research-data/uci-20260927 --json-out /tmp/layout.json`.
