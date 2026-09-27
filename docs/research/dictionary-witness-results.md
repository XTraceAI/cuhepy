# Dictionaries, owner hints, mixed score packing and exact residual correction

Follow-up: [exact affine dictionaries inside one BGV query](affine-component-results.md)
implements block maps without per-row residual arrays, shared queries through
polynomial CRT, and an encrypted hidden-position lookup control. It keeps this
cycle's results/checkpoint intact and compares the new state/compute tradeoff
with full-data retention.

2026-09-27, `experiment/creative-search-algebra`. This extends the
[certified folding experiments](certified-folding-results.md), preserving the
earlier company and research checkpoints. All encrypted arithmetic here is our
own Python/GMP, C++/RNS and CUDA BGV. NumPy is used for dictionary preprocessing;
Microsoft SEAL is not imported by these experiments.

The useful new result is a **client-state/server-work tradeoff**: keeping sparse
exact residuals with the index owner makes approximate coordinate folding exact
in one response. On a public categorical fixture, CPU local time improves
3.31× and CUDA local time improves only 1.09× through the ordinary native API.
This is not a stateless-client improvement, a production security claim, or an
established novel cryptographic construction. The complete compressed plaintext
database is nearly as small as the compressed residual hint on that fixture
and supports much faster local search.

Three other hypotheses have informative limits. Reordering rows helps pruning,
but simple signature ordering often beats the metric partition. Reducing worst
reconstruction error does not reliably reduce search work. Packing exact
witnesses into spare response coefficients works algebraically, but its extra
work and queries usually outweigh its pruning improvement.

## 1. Mechanisms and exactness

### E22: a fixed budget and stable physical layout

[`folded_dictionary.py`](../../experiments/bfv_search_lab/folded_dictionary.py)
selects column representatives by complement-invariant farthest-first distance.
It optionally replaces a representative within each fixed group, accepting
only a lexicographic improvement in `(max row error, sum error², sum error)`.
This is a heuristic, not an optimum. Every row's residual is recomputed with
independent integer XOR/popcount.

Three orders are compared: shuffled input, representative-bit signature, and
balanced partitions by distance difference to two far pivots. Queries never
guide the dictionary, layout or witness sample. Source line IDs remain the
stable tie-breaker after physical reordering. Refinement evaluates complete
original ciphertext tiles, including unselected neighboring rows.

### E23: owner radius hints give both bounds before refinement

For row `x_i`, let `z_i` be its template and `e_i = H(x_i,z_i)`. The server
computes encrypted template distances `s_i = H(q,z_i)`. The owner retains `e_i`:

```text
L_i = max(0, s_i - e_i) <= H(q,x_i) <= min(d, s_i + e_i) = U_i.
```

The kth smallest `(U_i, original_ID_i)` bounds the true kth pair from above.
Every possible winner has `(L_i, original_ID_i)` no greater than this bound.
[`interval_filter.py`](../../experiments/bfv_search_lab/interval_filter.py)
therefore requests all qualifying original tiles in one batch. Exact point
intervals need no fetch. This replaces many threshold-discovery rounds with at
most two rounds, while often fetching more tiles. The owner-held radius also
removes the encrypted residual feature: 32 representatives fit 32 padded
features, whereas 32 plus one encrypted error feature would pad to 64.

### E24: spare coefficients carry exact threshold witnesses

An index-only fixed sample of 128 or 256 rows is separately packed offline.
Its exact scores tighten the kth upper bound without assuming an oracle
nearest-neighbor radius. They cover individual sampled rows, **not** all rows
in those witnesses' original tiles. The full-dimension query is reused for
subsequent refinement.

For a butterfly response with ring degree `N` and padded dimension `D`, useful
row `i` appears at `(i mod (N/D))*D + floor(i/(N/D))`. Honest outputs are zero
modulo the plaintext modulus outside this support.
[`witness_packing.py`](../../experiments/bfv_search_lab/witness_packing.py)
finds a non-wrapping monomial shift of the witness output with disjoint support.
It adds the ciphertexts and decodes each region with its own inverse trace
scale. The phase bounds ADD.

At `N=16384`, 7,996 template scores with `D=32` leave room for 128 full scores
with `D=128`, shifted by 16. One first-stage ciphertext carries both. This saves
one response compared with **separate template and witness replies**, not with
the existing full scan's already single response. Both evaluations, a second
query, the extra witness index, conversion, addition and compaction are charged.
Placement can fail even when enough coefficients are nominally free; the model
charges a separate reply then. No arbitrary free scatter is assumed.

### E25: exact sparse residuals replace remote refinement

The elementary coordinate identity is:

```text
H(q,x_i) - H(q,z_i)
  = sum over j where x_ij != z_ij of (1 - 2*q_j)*(2*x_ij - 1).
```

[`owner_residuals.py`](../../experiments/bfv_search_lab/owner_residuals.py)
keeps these positions and original bits with the owner. A canonical sparse
encoding stores sorted `(position << 1 | original_bit)` entries and per-row
offsets. Enrollment compiles them into positive/negative masks; each online
correction uses two AND/popcounts. Corrected distances are exact for every
query when the template response and hints are correct. There is one query,
one response, no adaptive tile schedule, and only the folded encrypted index is
needed for this mode. The full index remains a comparison/fallback.

This changes state/privacy. Residual locations and values are private data,
not public helper information or a read-only-user credential. Their holder
must be the authorized index owner. Python correction is variable-time and has
no private side-channel assurance. Hints/maps must be pinned with the index
epoch and refreshed on updates. Small hints do not imply a quantified small
information leak.

## 2. Public data and cost-model findings

Both UCI datasets are labeled CC BY 4.0 by their repositories:

* **Semeion Handwritten Digit [Dataset] (1998), UCI**, DOI
  [10.24432/C5SC8V](https://doi.org/10.24432/C5SC8V): 1,593 binarized 16×16
  handwriting images. Use supplied pixel bits; discard class labels.
* **Mushroom [Dataset] (1981), UCI**, DOI
  [10.24432/C5959T](https://doi.org/10.24432/C5959T): 8,124 **hypothetical**
  samples with 22 categorical attributes. Encode the published category schema
  as 126 indicator bits, including `?`; discard the edible/poisonous label. A
  differing attribute contributes two Hamming bits.

These adaptations benchmark exact search, not classification or field
observations. [`binary_fixtures.py`](../../experiments/bfv_search_lab/binary_fixtures.py)
pins archive/body hashes and validates the schema. Raw datasets stay outside
Git; use [`fetch_binary_fixtures.py`](../../benchmarks/fetch_binary_fixtures.py).

Seeds 2901 and 2902 independently hold out 128 source rows. Remaining indexes
contain 1,465 and 7,996 distinct rows; no reported public query equals an index
row. Fitting sees only the index. Model queries use holdout positions 32:64,
following a separate 0:16 exploratory pilot. Native measurement uses 96:104
with position 95 as warmup. This is a small research split, not a dataset-wide
or writer-disjoint generalization claim.

The [model artifact](../../benchmarks/results/dictionary_layout_lab_20260927.json)
retains all 75 dictionary/layout configurations, 2,400 configuration–query cases
and five methods' exact top-3 checks (12,000 searches). Controls include noisy
foldable 8,192×512-bit data with near/unrelated queries and a uniform random
index/query case. Counts are circuit models, **not HE timings**. Native subset
preparation, authentication and hidden routing remain unpriced here.

Mean ciphertext-product counts across both public splits:

| Fixture / representation | Full scan | Adaptive, input | Adaptive, signature | Adaptive, metric | Radius hints, metric | 256 witnesses, metric |
|---|---:|---:|---:|---:|---:|---:|
| Semeion, 127 groups, two tail passes | 23 | 25.00 | 20.86 | 20.13 | 29.58 | 29.69 |
| Mushroom, 31 groups, no tail passes | 63 | 50.91 | 24.02 | 26.47 | 41.81 | 38.81 |
| Mushroom, 32 groups, two tail passes | 63 | 66.70 | 40.64 | 42.98 | 42.30 | 39.23 |
| Mushroom, 64 groups, two tail passes | 63 | 69.31 | 67.06 | 67.22 | 34.89 | 36.34 |
| Uniform random, 64 groups, no tail passes | 256 | 320 | 320 | 320 | 288 | 296 |

Adaptive methods include an encrypted residual feature and fetch up to four
tiles per round; other methods keep radii on the owner. Thus 32 and 64 groups
double padding for the adaptive column, not the hint column. Switches and
replies matter too: Semeion's metric adaptive 20.13 products need 126.66 switches
and 3.33 replies versus 23 products, 123 switches and one reply for full scan.
On Mushroom, changing 31-group metric dictionaries from zero to two tail passes
lowers max error from 18 to 17 but raises adaptive work from 26.47 to 27.41
products. That objective is insufficient for search.

E25 moves work/information to owner state. Canonical array sizes below exclude
map/IDs/epoch/framing; public cases use split 2901:

| Fixture | Groups | Residual body | Raw full rows | Coarse / full products |
|---|---:|---:|---:|---:|
| Semeion, two tail passes | 64 | 97,336 B | 46,880 B | 6 / 23 |
| Mushroom, two tail passes | 32 | 60,514 B | 127,936 B | 16 / 63 |
| Noisy foldable synthetic, two tail passes | 64 | 83,658 B | 524,288 B | 32 / 256 |
| Uniform random synthetic | 64 | 3,594,962 B | 524,288 B | 32 / 256 |

For `M` rows and `w=ceil((ceil(log2(d))+1)/8)` entry bytes, this codec costs
`4*(M+1) + w*sum(e_i)`. It need not beat raw storage or a lossless compressor.
Expanded Python masks can exceed both.

## 3. Actual homemade CPU/CUDA results

The [native artifact](../../benchmarks/results/dictionary_bgv_native_20260927.json)
measures Mushroom split 2901: 7,996×126 bits, 32 groups, two tail passes, metric
layout and 128 fixed witnesses. One warmup plus eight fresh paired queries;
case order shuffled. Ryzen 7 5800X, eight OpenMP threads, RTX 3080 10 GiB.
All modes share a key/ring: `N=16384`, `t=1031`, approximately 120-bit RNS `Q`,
`eta=21`, 30-bit gadget digits and 32-bit terminal coefficients. Ordinary
conservative bounds apply; the binary-only shortcut is not used.

| Method | CPU server | CPU client | CPU local total | CUDA server | CUDA client | CUDA local total |
|---|---:|---:|---:|---:|---:|---:|
| Full scan | 620.90 ms | 26.56 ms | 647.50 ms | 27.81 ms | 26.01 ms | 53.95 ms |
| Radius hints, two rounds | 672.10 ms | 55.26 ms | 727.57 ms | 204.93 ms | 54.72 ms | 260.06 ms |
| Packed witnesses, two rounds | 670.19 ms | 58.87 ms | 731.61 ms | 213.85 ms | 58.14 ms | 272.83 ms |
| Exact owner residuals, one round | 167.59 ms | 27.79 ms | 195.61 ms | 21.77 ms | 27.61 ms | 49.65 ms |

Medians are per field and need not sum. Server includes query expansion,
evaluation, public conversion/fusion, selected-index preparation and response
packing. Client includes query preparation/encryption, decryption, decoding,
correction and stable selection. Local total excludes setup and network latency.
This measures the ordinary native API, not the separately optimized packed
workspace/codec path or attested service.

All distances, template/witness scores and stable top-3 results match plaintext
oracles. Complete CPU/CUDA response bytes agree for every mode and both rounds.
Eight samples support an exploratory median, not p95 or a robust claim about
the 8% CUDA local-time reduction on other hardware/data.

**Refinement's failure is concrete:** the current API prepares selected original
ciphertexts per query. Median CUDA subset preparation is 159.36 ms with radii
and 138.21 ms with witnesses. Witnesses reduce median fetched tiles from 25.5
to 22, but add a full-dimension evaluation and ~10.75 ms of Python public fusion,
plus compaction/conversion. A resident gather could remove a bottleneck; it
would not solve exposed routing. No CUDA kernels changed in this cycle.

**E25 changes the representation:** it evaluates 16 coarse ciphertexts instead
of 63 full ones. Raw index coefficient bodies fall from 30,965,760 to 7,864,320 B
(3.94×); evaluation-key bodies fall from 15,728,640 to 11,796,480 B if only this
mode is provisioned. Keeping a fallback incurs both indexes/key sets. E23/E24
need both; E24 adds a 491,520 B witness index. JSON records setup separately.

Full scan and E25 each use **245,866 B query + 131,162 B response = 377,028 B**.
The two-round methods use 491,732 B queries plus 262,324 B replies on these eight
queries, plus tiny MessagePack tile-ID requests. These local codec figures
exclude context/attestation/authenticated-routing framing. E24 saves a download
relative to separate filter/witness replies, not relative to E23 or full scan.

E25 correction takes ~1.57 ms. Its 60,514 B canonical hint expands to ~967.5 kB
of Python masks. The shared stable-ID/permutation array is another 15,992 B for
this layout; maps/context are additional. With zlib level 9 and the same row
order, the complete database is **23,466 B** and the hint is **21,319 B**, before
common IDs/metadata. The compiled hint uses more Python memory than all raw row
integers (410,600 B). Retaining all plaintext rows permits a **2.36 ms** local
search with no server, HE or network. The modest compressed-storage difference
does not currently justify E25 on this fixture; its value here is exposing the
exact state/compute tradeoff for further study.

## 4. Prior work, security and next discriminating experiments

Triangle bounds, clustering, residual coding, known-score thresholds and linear
ciphertext addition are established ingredients. The butterfly already cites
[Chen, Dai, Kim and Song, Algorithm 2](https://eprint.iacr.org/2020/015).
[Quantized sparse representations](https://arxiv.org/abs/1608.03308) treats coding
and memory as nearest-neighbor design variables; it is approximate search, not
our exact encrypted protocol. This limited review establishes no novelty claim.

[SimplePIR/DoublePIR](https://www.usenix.org/conference/usenixsecurity23/presentation/henzinger)
charges offline hints, and
[YPIR](https://www.usenix.org/conference/usenixsecurity24/presentation/menon)
studies removing offline communication. Those retrieval protocols have different
database/query contracts; their security/performance does not transfer to owner
residuals or encrypted nearest-neighbor search.

Range checks, sparse decoding and support/interval certificates **do not
authenticate an untrusted evaluator**. Adversarial tests demonstrate plausible
wrong scores and omitted winners from false bounds. The raw GPU remains
unauthenticated. Complete-response authentication before observable decrypt/
accept/refine behavior, parameter review and private side-channel obligations
still apply. E23/E24 expose tile IDs and schedules. E25 removes the adaptive
request but does not solve active-server attacks. Production clients are unchanged.

Prioritize these algorithm questions before kernel tuning:

1. **Encrypted exact residual evaluation with bounded owner state.** Can sparse
   corrections be evaluated without disclosing locations/values to ordinary
   query clients or publishing support? Charge support lookup, conversion,
   keys and worst-case work. Compare E25's changed-state reference and full scan.
2. **Block-dependent dictionaries and query sharing.** Test a small family of
   dictionaries with different tile assignments, charging every encoded query
   and key. Compare signature order first. Optimize padded work and residual
   state, preserve original IDs, and certify exactness with integer arithmetic.
3. **A state/epoch experiment.** Compare hints with compressed full data and
   local scan across entropy and update rates. Include resident/canonical sizes,
   maps/IDs, enrollment, private arithmetic and synchronization. Reject schemes
   that just cache most of the database less efficiently. A codec alone is no paper.
4. **Budgeted first-response side information.** E24 demonstrates mixed trace
   scales sharing honest support. Try other fixed exact summaries only if they
   repay query/index/evaluation costs. Retain uniform failures; empty coefficients
   do not imply free placement, and small summaries do not prove coverage.

## 5. Reproduction and preserved evidence

```bash
.venv/bin/python benchmarks/fetch_binary_fixtures.py \
  --cache-dir ../research-data/uci-20260927
OPENBLAS_NUM_THREADS=1 .venv/bin/python benchmarks/dictionary_layout_lab.py \
  --cache-dir ../research-data/uci-20260927 --json-out /tmp/dictionary-layout.json
OMP_NUM_THREADS=8 OPENBLAS_NUM_THREADS=1 .venv/bin/python benchmarks/dictionary_bgv_native.py \
  --cache-dir ../research-data/uci-20260927 --json-out /tmp/dictionary-native.json
```

Run timing experiments sequentially with native extensions from this worktree.
The model records source `f49b5f8`; native measurement records `21f598a`. Source/
binary hashes, samples and setup costs are pinned. See the
[validation log](../../benchmarks/results/dictionary_witness_validation.md).
The new modules have 31 focused tests; with prior algebra/folding controls,
**181 tests pass**. Prior research tags remain untouched.
