# Certified filters and coordinate folding: second creative cycle

2026-09-27, on `experiment/creative-search-algebra`. The previous baseline is
preserved by `checkpoint/creative-algebra-2026-09-27` (`db21633`). This cycle
adds experiments outside the production package; Paillier/BFV/BGV arithmetic
and authenticated clients are unchanged. All HE execution uses our homemade
BGV, including its existing C++/RNS and CUDA implementations. NumPy SVD only
proposes a public, offline approximation in one experiment.

**Outcome:** exact folding of redundant database coordinates improves measured
server computation on a deliberately structured 8,192-vector fixture. A noisy
version gives certified lower bounds, with substantial query-dependent costs
for exact refinement. The competing compressed syndrome lookup loses its
useful selectivity after certification. These results select the next research
questions; they establish neither novelty nor production security.

## 1. E22: fold coordinates, retain an exact error allowance

Implementation: [`folded_filter.py`](../../experiments/bfv_search_lab/folded_filter.py).

Think of the database as a binary matrix with one vector per row. The owner
groups columns that are equal, complementary, or close across the index. Each
group has a representative coordinate. Expanding a row's representative bits,
with the recorded complements, produces a template `z_i`. The owner computes
the exact residual `e_i = Hamming(x_i, z_i)` over the **entire** stored row.

For every possible query, the triangle inequality gives

```text
Hamming(q, z_i) - e_i <= Hamming(q, x_i).

s_j(q) = 2*q_j - 1
w_g(q) = sum_{j in group g} sign_j * s_j(q)
v_ig   = 2*x_i[representative_g] - 1

sum_g w_g(q)*v_ig = d - 2*Hamming(q, z_i).
```

The owner encrypts the folded query weights; the index encrypts the
representative signs. If errors exist, one extra feature encrypts `2*e_i`
against a query coefficient of one. The resulting dot product yields
`Hamming(q,z_i)-e_i`. The owner can clamp a negative final bound to zero.
With zero residual, every output is the **exact original distance**, so there
is no refinement stage or accuracy tradeoff, even for unrelated queries.

The map is learned from the index, while the inequality holds for all queries.
The greedy column threshold affects quality, not correctness. This differs
from assuming that an average approximation error bounds each individual row.
New index rows must have their residuals recomputed; the current code rejects
rows exceeding the plan's certified maximum. It does not implement incremental
index updates or remote enrollment.

Only the feature layout shrinks. The cryptographic ring degree stays fixed.
Weighted query coefficients and the residual feature use the **generic BGV
correctness bound**, without the binary-only E15 shortcut. Decoding first
computes `(d-dot)/2` modulo `t`, then unwraps the interval `[-max_error,d]`.
It requires odd `t > d+max_error`. A centered-dot interpretation can fail even
when this interval fits; a regression covers that wraparound case.

### Full-size paired native measurement

[`folded_bgv_native.py`](../../benchmarks/folded_bgv_native.py) uses 8,192
**distinct** 512-bit vectors generated from 48 latent bits, with repeated and
complemented coordinates. This is deliberately favorable column structure;
row deduplication does not explain the improvement. Uniform queries alternate
with near-row queries. Seven paired measured rounds follow one warmup, and
execution order is shuffled.

Same owner key, `N=16384`, `t=1031`, 120-bit RNS `Q`, `eta=21`, 30-bit gadget
digits, owner-encrypted index, and 32-bit terminal precision for both layouts.
Hardware: Ryzen 7 5800X, RTX 3080 10 GiB, NVIDIA driver 580.173.02;
`OMP_NUM_THREADS=8`. This uses the ordinary `NativeServer.search_compact` API
and its generic bounds. The separately optimized packed workspace/codec path
is a different benchmark. Setup, network and authentication are outside the
online timings; setup is recorded separately in the artifact.

| Measured median | Original 512 features | Folded 48 features, padded to 64 | Ratio |
|---|---:|---:|---:|
| CPU server | 2,484.45 ms | 319.33 ms | 7.78× faster |
| CUDA server | 38.03 ms | 18.43 ms | 2.06× faster |
| CPU local request, including owner work/codecs | 2,518.10 ms | 352.91 ms | 7.14× faster |
| CUDA local request, including owner work/codecs | 72.54 ms | 51.93 ms | 1.40× faster |
| Index ciphertexts | 256 | 32 | 8× fewer |
| Full index coefficient bytes | 125,829,120 | 15,728,640 | 8× smaller |
| Evaluation-key coefficient bytes | 19,660,800 | 13,762,560 | 1.43× smaller |
| Query upload | 245,866 bytes | 245,866 bytes | unchanged |
| Response download | 131,164 bytes | 131,164 bytes | unchanged |

Every distance and stable top-three result matches the independent integer
Hamming oracle. Complete CPU/CUDA ciphertext envelopes also agree byte for
byte within each layout. Index byte counts exclude framing; online byte counts
use the existing seeded-query and compact-response envelopes. Folding setup
took 1.32 s. The measured CUDA gain is smaller than the operation-count gain;
the unchanged full-ring query, response and API work still costs time. No
profiling claim assigns that difference to a particular kernel.

The exact folded index can replace the full HE search index in this mathematical
model. Keeping both representations for experiments/fallback consumes their
combined storage. The approximate path below **requires both indexes** in its
current implementation.

## 2. Refinement must discover its threshold and fetch whole tiles

[`adaptive_refinement.py`](../../experiments/bfv_search_lab/adaptive_refinement.py)
starts without a kth distance. It requests promising original ciphertext tiles,
uses every returned score, caches visited tiles, and updates the kth known
`(distance, original ID)` pair. It stops only when every remaining bound pair
is worse. Equal-distance candidates with smaller IDs remain eligible.

The original 512-feature layout holds 32 rows per ciphertext at `N=16384`.
Selecting one candidate therefore charges a whole tile. We do not assume
that ciphertexts holding scattered candidates can be repacked for free.
Batching tile requests trades extra evaluation against dependent rounds.

The three data seeds preserve 48 groups with 2, 8, or 16 deliberately placed
bit flips per row. Near-row queries are favorable; unrelated uniform queries
are additional controls. Simple coordinate sampling at the same padded feature
budget is also measured. Results and the fixed-radius counts are in
[`certified_filter_lab_20260927.json`](../../benchmarks/results/certified_filter_lab_20260927.json).
The adaptive algorithm itself never receives the oracle kth radius.

For seed 2701, near-row query and eight tiles per refinement batch:

| Perturbation per row | Exact residual maximum | Filter products | Original tiles refined | Total products | Dependent rounds / response ciphertexts |
|---|---:|---:|---:|---:|---:|
| 2 flips | 20 | 32 | 8 | 40 | 2 / 2 |
| 8 flips | 58 | 32 | 8 | 40 | 2 / 2 |
| 16 flips | 68 | 32 | 47 | 79 | 7 / 7 |
| Full distance scan | — | — | 256 | 256 | 1 / 1 |

These are **circuit counts**, not measured full-size adaptive runtimes. One
perturbed representative can affect several reconstructed coordinates, which
explains why the certified residual exceeds the injected flips. The approximate
index adds 32 tiles to the retained 256-tile exact index: 288 total, rather than
an index-storage saving. Two different query encodings are needed. No protected
tile-request protocol, response-size padding or authentication cost is included.

The unrelated-query and overcompression controls are essential: weaker bounds
can touch almost every original tile and lose to the full scan. Uniform random
database columns do not compress under exact folding (512 groups). Forcing them
into one group is mathematically safe but retains all 8,192 candidates at the
oracle radius. Zero-error plans directly return exact scores; their recorded
forced-refinement model is only a control and is unnecessary in actual use.

For **unrelated uniform queries**, the three seeds require 184–199 original
tiles at eight flips per row, giving 216–231 total products and 24–26 rounds
with eight tiles per batch. At sixteen flips, all three seeds touch all 256
original tiles: 288 products and 33 rounds versus the scan's 256 products and
one round. The survivor counts are only 1,692–3,900 in the latter case, yet
scattering them across ciphertext tiles destroys the apparent pruning benefit.

A separate **tiny encrypted CPU reference** runs all stages, including actual
selection of existing encrypted tiles, at `N=128`, `d=32`, `M=257`, `t=257`,
180-bit `Q`, `eta=1`. It verifies every stable top-three answer. Median product
counts fall from 65 to 29, while response ciphertexts grow from 3 to 6 and
dependent rounds from 1 to 4. Median local CPU reference time is 447.73 ms for
the scan and 301.42 ms for refinement. Its timings and all samples are in the artifact;
they do not predict optimized GPU latency or a protected network deployment.

## 3. Certified low-rank lookup: safe, but unsuccessful here

[`certified_lookup.py`](../../experiments/bfv_search_lab/certified_lookup.py)
tests whether the previous coupled syndrome/weight lookup can become cheaper
through approximation. SVD proposes integer factors `U,V` after quantization.
The public small table is then enumerated exhaustively with Python integers:

```text
A[q,b] = exact coupled lower bound for query q and reachable bucket b
S      = quantization^2
b[b]   = min_q (S*A[q,b] - U[q] dot V[b] - initial_a[q])
a[q]   = initial_a[q] + min_b remaining_slack[q,b]

U[q] dot V[b] + a[q] + b[b] <= S*A[q,b]   for every q,b.
```

Column corrections are one extra encrypted feature across all blocks; the
owner adds its query-specific row correction after decryption. There is one
final integer division after summation. A separate exact checker rejects
corrupted certificates, and a large-integer test crosses machine-word limits.
No safety argument depends on floating-point accuracy or sampled residuals.

For 64 eight-bit blocks and quantization 32:

| Per-block rank | Features including correction | Padded features | Filter products | Required `t` strictly greater than |
|---|---:|---:|---:|---:|
| 1 | 65 | 128 | 64 | 585,608 |
| 3 | 193 | 256 | 128 | 571,310 |
| 7 | 449 | 512 | 256 | 565,920 |

The larger plaintext requirement comes from the corrected integer numerator;
the operation counts alone do not establish equal ciphertext parameters or
noise costs. On all three balanced fixtures, every tested rank retains all
8,192 candidates, while the previous exact coupled bound retained 26/74/54.
The simple seven-of-eight coordinate control retains just three on those
fixtures, although its padded circuit already costs as much as a full score.
On planted close neighbors, cheap coordinate sampling already matches the
compressed lookup's pruning. We retain this construction as a correctness
reference and negative result, without pursuing kernel optimization for it.

## 4. Prior work and security contract

These are familiar ingredients with an experimental composition. Binary matrix
factorization already studies compact representations over several arithmetic
domains; see [Kumar et al., ICML 2019](https://proceedings.mlr.press/v97/kumar19a.html).
Our restricted signed column dictionary and triangle-inequality residual are
not claimed as new factorization or metric theorems. The comparison question
is whether a dictionary chosen for **HE padding, residual certification and
tile refinement together** gives a useful complete-search tradeoff. This
targeted reading has not established an original contribution.

The client here is the data owner and can learn all scores. The coordinate map
depends on private index contents and stays on that owner. Publishing it to
third-party clients changes the privacy contract. Layout/key sizes can also
disclose compression structure. Epoch, row count, original ID ordering, map,
error bounds, query, and complete output must be bound by any future protected
protocol. A bound certificate proves an inequality about a local representation;
it does not prove that a remote server evaluated the committed index correctly.

The adaptive oracle exposes tile IDs, timing and round counts. Even hiding IDs
with PIR would leave schedule leakage and response authentication to solve.
[Authenticated PIR](https://www.usenix.org/system/files/usenixsecurity23-colombo.pdf)
explicitly treats selective-failure privacy: adding a signature/MAC to retrieved
records alone does not prevent leakage through an observed accept/reject bit.
The same issue rules out treating AEAD checks on privately fetched encrypted
vectors as a complete fix for our active-server threat model.

[SimplePIR/DoublePIR](https://eprint.iacr.org/2022/949) and
[Piano's author artifact](https://github.com/wuwuz/Piano-PIR-new) are alternatives
for a separately budgeted refinement experiment, with preprocessing/client
state charged. [Distributional PIR](https://eprint.iacr.org/2025/132.pdf)
also studies RLWE-to-LWE conversion for faster SimplePIR preprocessing and
queries. That conversion is relevant prior work for E17. Its distributional
retrieval relaxation cannot silently replace our exact top-k contract. We
have not implemented these schemes in this cycle or imported their code.

Private arithmetic and parameter assurance remain at the existing research
baseline. The raw GPU is not attested; these tests add no new production
decryption authority.

## 5. Reproduce and choose the next experiment

```bash
OPENBLAS_NUM_THREADS=1 .venv/bin/python benchmarks/certified_filter_lab.py \
  --json-out /tmp/certified-filter-lab.json
OMP_NUM_THREADS=8 OPENBLAS_NUM_THREADS=1 .venv/bin/python benchmarks/folded_bgv_native.py \
  --json-out /tmp/folded-bgv-native.json
```

Sources are checkpointed in `b5f5825` (models/reference/tests), `6beacea`
(native measurement), and `b2937b8` (unrelated-query/overcompression controls).
Artifacts record their exact source commit and hashes; the native measurement
predates the added model controls, without a change to its fixture generator.
See [validation](../../benchmarks/results/certified_filter_validation.md),
[native samples](../../benchmarks/results/folded_bgv_native_20260927.json), and
[model/reference samples](../../benchmarks/results/certified_filter_lab_20260927.json).
There are 150 passing focused regressions, including 49 new tests; Ruff and
Mypy pass. No full production/security-suite rerun is claimed for this sandbox
change.

The next discriminating experiments, before ordinary CUDA tuning, are:

1. **Padding-aware dictionary design.** Compare the current threshold/first
   representative rule with a fixed budget of 63 representatives plus one
   residual feature. Optimize per-row error tails, not only average column
   error. Measure whether extra representatives reduce whole-tile refinements
   enough to pay for them; test all grouping choices on held-out queries.
2. **Exact residual correction without adaptive routing.** Ask whether a sparse
   exception representation can evaluate the correction with less work than
   the original dense score. Count encrypted support lookup and conversion;
   plaintext sparsity is not automatically cheap under HE.
3. **Dictionary and physical-tile layout together.** Compare owner-committed
   reorderings and per-tile dictionaries while preserving original stable IDs.
   Charge duplicated keys, query encodings and layout metadata. The target is
   fewer fetched ciphertexts, not merely fewer surviving plaintext records.
4. **Private refinement across schemes.** Compare authenticated/padded tile
   evaluation with PIR of owner-encrypted raw records and local rescoring.
   Include hint size, preprocessing, index updates and fixed-schedule padding;
   keep the full scan as the fallback and performance control.
5. **Real distribution gate.** Add licensed binary data and independently
   chosen queries before treating the synthetic exact-folding gain as useful
   beyond a proof of concept. Report compression, residual tails, deduplication
   controls and complete compute/traffic under the same contract.
