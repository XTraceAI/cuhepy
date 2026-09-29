# Common and local query directions: state, index and correlation costs

Research cycle eight, 2026-09-29, on `experiment/creative-search-algebra`.
Implementation: `fc5aa84`; encrypted benchmark source: `185ffc7` after correcting
the separate original-cache accounting label. The preceding E29 checkpoint,
`checkpoint/crt-response-transpose-2026-09-28` (`15c6737`), remains intact.

**Result:** an exact common-plus-local affine representation offers a measurable
index/state tradeoff. At unchanged encrypted index size, it reduces query
coordinates by 12–16% and private map-plus-checking state by 7–12%. A more
aggressive point saves about 41% of that state, with 41–44% more index storage.
Complete native online time is about 75–78 ms. This is primarily a state and
representation result, not a large latency improvement.

A single global affine map is an important simpler control. Relative to raw
bit columns, it uses 32.5% less encrypted index storage and about 19% less native
server time on the measured public dataset. The mixed representation does not
dominate it on every metric. A second dataset and explicit algebraic
counterexamples retain cases where sharing loses.

Everything here uses our homemade BGV, Python/GMP and the existing standalone
C++ subring arithmetic. Encryption retains degree **16,384**. No SEAL, CUDA,
production client or Nitro authorization path was changed. Fresh trusted token
preprocessing, parameter review, durable one-use state and private arithmetic
assurance remain unresolved deployment requirements.

## 1. Prior work and the question

Shared and individual subspaces are established mathematical tools. The
[JIVE paper by Lock et al.](https://pubmed.ncbi.nlm.nih.gov/23745156/) decomposes
multi-source variation into joint, individual and residual terms. Its abstract
and model motivate a comparison; our exact finite-field decomposition is not
its approximate statistical algorithm.

[Oraqle, Vos et al.](https://eprint.iacr.org/2024/1409.pdf), Section 5, explicitly
uses semantic common-subexpression elimination in HE compilation. Reusing
equivalent query forms is therefore not, by itself, a novelty claim.
[cFHE, Schoinianakis and Sabzevari](https://eprint.iacr.org/2026/845), inspected
at abstract/metadata level, jointly treats low-rank factorization error and
CKKS precision. This is another relevant precedent for representation/parameter
co-design; no implementation or performance comparison with it was performed.

The experiment asks a narrower question: **can shared private query directions
reduce both masked-query dimension and exact response-checking state without
giving up the small CRT-transposed index?** The distinguishing cost is the sum
of the correction subring degrees, together with encrypted columns, complete
client state and per-token work. Whether that combination supports an original
contribution remains open; the literature search is not exhaustive.

## 2. Exact decomposition and public correction degrees

E29 represents a row in block `g` as `x = a_g + u B_g (mod t)`. Choose a common
direction basis `C` of rank `K`, put it in reduced row-echelon form, and project
each `B_g` into the quotient by `C`. Row reduction there gives a residual basis
`R_g` of rank `r_g`, zero at every pivot of `C`. Every enrolled row then has

```text
x = a_g + c C + v R_g                         (mod t)
H(q,x) = H(q,a_g) + c·[C(1-2q)] + v·[R_g(1-2q)] (mod t).
```

First take `c` from the differences at the common pivots. Subtract `c C`, then
take `v` at the residual pivots. Enrollment reconstructs every original bit;
`t > dimension` makes the final Hamming distances unambiguous. Anchors and both
bases remain private owner state. No future query is used to fit them.

Common query forms are identical across all CRT components. Their corrections
are **scalar** polynomials. Local forms still require the degree-`S` subring
interpolation from E29. The full-degree ciphertexts and output positions are
unchanged. Apart from the explicit dummy feature for a constant map at `K=0`,

```text
query mask dimension h = K + sum_g r_g
encrypted column count F = K + max_g r_g
correction coefficient count W = K + S * max_g r_g.
```

This separates three quantities that a plain rank count conflates. At fixed
reply count, index bytes scale with `F`, upload bytes with `h`, and retained
checking hints with `W`. For `rounds` hidden checks, the seed-and-hint body is
`rounds * (32 + W * coefficient_width)` bytes. With fresh phase bound `B0`,

```text
B_worst = B0 * (1 + floor(t/2) * W) < Q/2.
```

The implementation also derives the actual bound from the centered correction
coefficients for each request. Centered mod-`t` lifts are not linear over `Q`;
the checker uses the actual lifts, just as E29 does. Its scalar columns need
only zero-shift fingerprints; local columns retain all required shifts.

The GMP evaluator independently uses scalar or full-ring multiplication per
column. The C++ adapter prepares separate scalar and short-NTT column groups,
chaining raw native result buffers without converting intermediate sums to
Python integers. It reuses the unchanged E29 C++ binary. The zero-shared mode
preserves E29's original space/epoch/mask binding bytes.

## 3. A bounded heuristic, with an explicit failure case

Starting from `C=0`, the overlap heuristic considers current residual RREF rows.
For each candidate direction it checks membership in **every** residual space,
not only equality with another basis row. Adding a direction decreases `r_g`
exactly when that direction belongs to that quotient space. The greedy score
first minimizes the next maximum residual rank, then their sum, then the number
of nonzero coefficients. The complete index-only trajectory is retained.

A raw-coordinate control instead offers standard coordinate directions. This
tests the originally proposed mixed raw/affine construction. On correlated
bits, a shared non-coordinate direction can remove a whole residual dimension
when deleting a raw coordinate cannot.

The candidate pool is not a subspace optimizer. Over `F_7`, consider

```text
A = span{(1,0,1), (0,1,1)}
B = span{(1,0,2), (0,1,3)}.
```

Their shared direction `(1,3,4)` is not a basis row in either pool. Choosing it
gives two total columns and three mask coordinates; this heuristic instead
uses three columns and four coordinates after one step. A regression retains
that counterexample. Pairwise/multiway intersections and hierarchical sharing
are motivated next experiments, not optimizations already implemented here.

## 4. Encrypted experiment and state measurements

Two independently shuffled public Mushroom splits each contain **7,996 index
rows**, dimension 126, with labels removed and 128 held-out queries. We reuse
E29's holdout positions 112–115 for a paired diagnostic: one warmup and three
measured queries per representation. The same source query IDs are used across
all six variants. No held-out query selects maps, directions or curve points.

Parameters are `N=16384, t=1153, eta=21`. Each candidate uses the smallest of
the already-tested 32/40-bit prime profiles satisfying its worst-case bound;
these are correctness profiles, not reviewed security estimates. Checking uses
five rounds at 32 bits or four at 40 bits. All cases produce one complete,
unrounded response ciphertext and use freshly encrypted one-use offline answers.

Measured points are selected before timing: the local endpoint; minimum
map-plus-check state within its index-byte budget; 32 common directions;
minimum index bytes among feasible 32-bit mixed points; and global/raw controls.
The mixed-case order reverses across splits, and GMP/native evaluation order
alternates per query. These small samples do not establish tail latency or
statistical significance for small differences.

Mask seeds use a fixed PRNG only as a reproducible public benchmark fixture.
HE keys, encryption seeds/errors and hidden checking challenges use fresh OS
randomness. These public-fixture runs are not a query-secrecy demonstration.

| Representation | Common directions, splits 3001 / 3002 | Columns | Query coordinates | Q bits | Expanded encrypted index bytes | Private maps + epoch checking body bytes |
|---|---:|---:|---:|---:|---:|---:|
| E29 local affine | 0 / 0 | 32 / 32 | 523 / 596 | 40 | 5,242,880 / 5,242,880 | 30,150 / 31,994 |
| Same index budget | 4 / 6 | 32 / 32 | 459 / 500 | 40 | 5,242,880 / 5,242,880 | 27,898 / 28,130 |
| 32 common directions | 32 / 32 | 46 / 45 | 222 / 235 | 40 | 7,536,640 / 7,372,800 | 17,863 / 18,930 |
| Mixed, smaller word | 77 / 76 | 79 / 78 | 89 / 93 | 32 | 10,354,688 / 10,223,616 | 9,556 / 10,796 |
| One global affine map | — | 85 | 85 | 32 | 11,141,120 | 2,612 |
| Public raw columns | — | 126 | 126 | 32 | 16,515,072 | 2,680 |

The final column is **not total client memory**. Each JSON also includes an
explicit wider owner-state body model: full provided public/secret key
coefficients, an ordered stable-ID array, canonical public geometry, map/check
state, column bounds, digests and counters. It excludes Python/GMP objects,
compiled-map duplicates, transient buffers, authentication credentials and a
durable journal; it is not a network serializer or measured RSS.

For split 3001 that wider epoch model is 294,691 bytes for local affine,
292,439 for the same-index choice, 282,517 for 32 shared directions, 225,323 for
the smaller-word mixture, 216,177 for global affine and 216,575 for raw columns.
Thus a 41% saving in map/check bodies is only about **4%** of this wider model.
Comparisons across word sizes also include a change in key coefficient widths.
An unimplemented compressed secret-key format is not credited as a saving.
Pending tokens add 72/76 modeled bytes at 40/32 bits, plus spent-token state.

The offline owner/service still needs plaintext index coordinates. Their
uncompressed `u16` body count is recorded separately; it grows when more common
directions increase the feature count per row. Moving that state to a trusted
service does not eliminate its cost or establish a deployment protocol.

## 5. Timings, communication and preprocessing

The following are medians in milliseconds, split 3001 / split 3002. Complete
online time includes local request creation, native server evaluation, reply
body packing, verification, HE decryption, decoding and stable top-three
selection. It excludes network latency and all offline preparation.

| Representation | GMP server | C++ server | Full conditional check | Decrypt + decode/select | Complete native online |
|---|---:|---:|---:|---:|---:|
| Local affine | 858.1 / 857.4 | 12.2 / 12.4 | 34.8 / 35.0 | 24.0 / 23.8 | 75.8 / 76.5 |
| Same index budget | 799.1 / 769.8 | 12.2 / 12.2 | 34.5 / 34.6 | 23.9 / 24.0 | 75.8 / 75.9 |
| 32 common directions | 743.1 / 732.2 | 12.3 / 12.7 | 33.7 / 35.2 | 24.0 / 25.1 | 74.7 / 78.1 |
| Mixed, smaller word | 933.4 / 919.5 | 14.4 / 14.3 | 40.1 / 39.9 | 23.5 / 23.2 | 82.2 / 81.6 |
| Global affine | 973.1 / 961.6 | 13.7 / 13.7 | 39.4 / 39.3 | 23.1 / 23.0 | 80.2 / 80.1 |
| Raw columns | 1442.2 / 1438.3 | 17.0 / 16.8 | 39.7 / 39.6 | 23.0 / 23.0 | 83.7 / 83.7 |

Scalar corrections help the GMP reference by replacing expensive generic ring
products. The prepared C++ path already contracts short NTT fibers, so that
replacement has much less impact there; more encrypted columns also add work.
Reading and checking all reply coefficients remains a major online cost. At
32 bits the extra checking round partly offsets the smaller response body.

| Representation | Query body bytes, splits 3001 / 3002 | Reply body bytes | Offline seeded answer packet per token | Offline + online bytes per completed query, every token used |
|---|---:|---:|---:|---:|
| Local affine | 1,046 / 1,192 | 163,840 | 82,026 | 246,912 / 247,058 |
| Same index budget | 918 / 1,000 | 163,840 | 82,026 | 246,784 / 246,866 |
| 32 common directions | 444 / 470 | 163,840 | 82,026 | 246,310 / 246,336 |
| Mixed, smaller word | 178 / 186 | 131,072 | 65,642 | 196,892 / 196,900 |
| Global affine | 170 | 131,072 | 65,642 | 196,884 |
| Raw columns | 252 | 131,072 | 65,642 | 196,966 |

Query-coordinate savings alone barely affect total traffic because replies and
offline answer uploads dominate. The larger mixed choice crosses the existing
32-bit correctness boundary and reduces the full reply by 20%, but roughly
doubles the local-affine encrypted index. Raw columns already had that reply
size in E29. These counts omit new authentication/transport framing, setup keys
and one-time enrollment. Expired tokens still cost work, upload and storage:
the retained 100%, 50% and 10% utilization models apply unchanged.

For split 3001, the offline timings are:

| Representation | Index encryption (s) | Native preparation (s) | Epoch checker preparation (s) | Fresh token answer (ms) | Trusted answer fingerprint (ms) |
|---|---:|---:|---:|---:|---:|
| Local affine | 0.93 | 0.17 | 3.62 | 45.0 | 33.2 |
| Same index budget | 0.88 | 0.17 | 3.23 | 46.0 | 32.9 |
| 32 common directions | 1.31 | 0.22 | 1.96 | 51.9 | 32.4 |
| Mixed, smaller word | 2.17 | 0.38 | 1.39 | 68.7 | 39.6 |
| Global affine | 2.17 | 0.39 | 1.22 | 70.8 | 39.8 |
| Raw columns | 3.26 | 0.60 | 1.79 | 89.8 | 39.7 |

Basis fitting, coordinate enrollment and owner query compilation are separately
recorded. Smaller checking hints make **epoch setup** cheaper; they do not avoid
hashing each fresh token's complete ciphertext. Ordinary local plaintext search
remains about 2.7–2.9 ms with a 127,936-byte uncompressed row cache, under its
different client-storage/trust contract. No new GPU comparison was performed.

## 6. Negative controls and preprocessing obstruction

Semeion has 1,465 index rows, dimension 256, and 64 local maps in both splits.
Only index-only curves were run there, not encrypted timing comparisons. At
32 shared directions, the overlap heuristic leaves the query dimension at
**1,401** while increasing encrypted columns from 23 to 55/54. Its map-plus-check
body grows from 581,028/579,246 bytes to 699,791/733,506. The raw-coordinate
control instead reaches 1,433 query coordinates and 55 columns, although its
maps become smaller. Neither gives a universal win. Single full-rank groups
and the missed-intersection example provide independent algebraic controls.

Two shortcuts for cheaper preprocessing are also rejected:

1. **Mask only in the private query image.** If a private transform has image
   `(a,b,a+b)`, every visible difference obeys the same private relation when
   its mask is sampled from that image. Full declared-coordinate masks avoid
   this particular relation. A tiny exhaustive test compares both distributions.
2. **Expand a small encrypted mask bank by public linear mixing.** Let prepared
   masks form rows of `R`, let public mixing weights be `L`, and send
   `Delta = W - L R`. Any public `z` with `z^T L=0` gives
   `z^T Delta = z^T W`: a relation among private queries. Three combinations of
   two masks can have perfectly uniform *individual* differences while leaking
   a joint relation. Independently encrypting or re-randomizing the answer
   ciphertexts does not remove information already present in `Delta`.

Two additional exhaustive pool tests show the distinction between invertibly
reparameterizing two masks and expanding them to three requests. This is an
ordinary rank obstruction for **public linear mixing**, not an impossibility
result for computational correlation generators. These are rejected designs,
not vulnerabilities introduced into the existing one-use token API.

[Boyle et al., Efficient Pseudorandom Correlation Generators](https://eprint.iacr.org/2019/448),
read at abstract/overview level, is a relevant next lead for succinct
correlations with computational security and setup assumptions. It is not a
drop-in implementation of our encrypted matrix/answer functionality. The next
protocol study must specify who learns the matrix, masks, output shares and
authentication material, and price maliciously secure setup and conversion to
the exact BGV response/checking format. No cheaper trusted token protocol is
claimed by this cycle.

## 7. Validation and retained artifacts

The expanded regression suite passed **355 tests**, including 19 new cases for
common/local algebra, all binary queries on tiny fixtures, complete plaintext
polynomials, independent schoolbook phase bounds, empty and multiple replies,
replicated maps, context substitution, mixed fingerprint shifts and native/GMP
equality. Two separate mask-pool tests also passed: **357 tests in total**.
Ruff passed for changed Python files; Mypy passed for the five changed/new
arithmetic modules. The C++ source/binary is unchanged from E29; no new native
sanitizer claim is added.

All **48 full-degree encrypted searches** agree on every distance and stable
top-three result. Native and independent GMP ciphertexts match in every
coefficient, and the conditional checker runs before HE decryption. The
existing poisoned-trusted-state and one-use rollback limitations remain.

- [Shared-basis implementation](../../experiments/bfv_search_lab/shared_query_basis.py)
  and [tests](../../experiments/bfv_search_lab/test_shared_query_basis.py).
- [Public linear-pool limit tests](../../experiments/bfv_search_lab/test_correlation_pool_limits.py).
- [Benchmark](../../benchmarks/shared_query_basis_lab.py), sharing the
  [E29 measurement harness](../../benchmarks/crt_masked_bgv_lab.py).
- [Mushroom 3001](../../benchmarks/results/shared_query_basis_mushroom_3001_20260929.json)
  and [3002](../../benchmarks/results/shared_query_basis_mushroom_3002_20260929.json).
- [Semeion 3001 curves](../../benchmarks/results/shared_query_basis_semeion_3001_20260929.json)
  and [3002 curves](../../benchmarks/results/shared_query_basis_semeion_3002_20260929.json).
- [Validation and manifest](../../benchmarks/results/shared_basis_validation.md),
  including source/artifact hashes and complete-query comparisons.

Commands:

```bash
.venv/bin/python benchmarks/shared_query_basis_lab.py \
  --cache-dir /home/pete/yavor-projects/xtrace-work/research-data/uci-20260927 \
  --seed 3001 --repeats 3 --json-out /tmp/shared-mushroom-3001.json
.venv/bin/python benchmarks/shared_query_basis_lab.py \
  --cache-dir /home/pete/yavor-projects/xtrace-work/research-data/uci-20260927 \
  --dataset semeion --seed 3001 --curves-only --limit 32 \
  --json-out /tmp/shared-semeion-3001.json
```

Repeat with seed 3002. The optional C++ extension is built with
`make -C experiments/bfv_search_lab/_subring PYTHON=../../../.venv/bin/python`.

## 8. Next discriminating experiments

1. **Hierarchical sharing across CRT subtrees.** Instead of a direction shared
   globally or only within one map, permit directions shared within selected
   subtrees. Derive per-column correction degrees `S_j` and optimize the triple
   `(F, h, sum_j S_j)`, including private maps and changed geometry leakage.
   Start with exact two-/four-block oracles and exhaustive tiny optima; test
   whether intermediate degrees improve the current frontier.
2. **Discover intersections that basis-row candidates miss.** Compare exact
   pairwise intersections, combinations and raw/global controls. Charge dense
   maps and fit time. Stop if all useful improvements merely move toward the
   global map or another complete client cache.
3. **Specify a correlation functionality before implementing a PCG backend.**
   Retain both public-linear mask recovery controls. Separate fresh blinding
   from correct offline-answer authentication. Compare a trusted service,
   verified encrypted preprocessing and appropriate computational correlations,
   including epoch updates, unused pools and crash-safe consumption.
4. **Measure lifetime break-even, not only one query.** Fit/enroll/check setup,
   per-token work and expiry can dominate short epochs. Keep the global affine
   control and ordinary seeded BGV under their distinct state/trust contracts.

Further GPU tuning is conditional on a representation/protocol improvement
that survives these comparisons. The earlier production-oriented CPU/CUDA and
authentication work remains available independently.
