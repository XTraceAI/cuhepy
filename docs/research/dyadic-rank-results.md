# Rank-boundary repair, unequal CRT capacity and complete-cache controls

2026-09-27, `experiment/creative-search-algebra`. E27 extends the preserved
[affine-component checkpoint](affine-component-results.md). Encryption,
evaluation and decryption still use our homemade BGV, C++/RNS and CUDA code.
No Microsoft SEAL import, production-client change or new CUDA kernel is involved.

**Result:** index-only splits targeted at rank/padding boundaries reduce public
Mushroom CPU local time from the previous 347–348 ms to 206–214 ms. Relative to
the matched full scan, this is about 3.0–3.11×. CUDA local time improves only a
few percent, to about 51 ms. Unequal component capacity also rescues a deliberately
imbalanced synthetic layout, reducing its products from 128 to 34 and replies
from two to one. These are representation/state tradeoffs, not established novel
cryptographic primitives or production security claims.

The strengthened cache control is important: the same maps plus **all** rows'
packed pivot bits support roughly 2.5 ms local public-data search, including
decompression. Outsourcing is compelling only under an appropriate client-state,
data-scale or deployment constraint; a faster encrypted baseline alone does not
establish that constraint.

## 1. Unequal plaintext components, unchanged encryption ring

[`dyadic_crt.py`](../../experiments/bfv_search_lab/dyadic_crt.py) represents a
complete binary factor tree of `X^N+1`. At an internal node:

```text
X^(2m) - gamma² = (X^m - gamma)(X^m + gamma).
```

Given child polynomials `f+` and `f-`, degree below `m`, interpolate the parent:

```text
parent = (f+ + f-)/2 + X^m * (f+ - f-)/(2*gamma)      over F_t.
```

Projection evaluates the two halves as `low +/- gamma*high`. Stopping at
different depths gives pairwise-coprime factors `X^m_l-zeta_l` of unequal degree.
Leaves may themselves be reducible; these are grouped plaintext factors, not
smaller independently encrypted RLWE instances. Recursive CRT is standard
algebra. Its transform work is bounded by `O(N * maximum tree depth)`, rather
than the old dense `T×T` transform across all coefficient blocks.

Every leaf still uses a **common** power-of-two padded feature count `D`, with
`D | m_l`. This is not a mixed-rank trace implementation. The existing butterfly
generator `1+2N/D` is 1 modulo each leaf root's order `2N/m_l`, so it fixes the
leaf idempotents. The same monomial/trace schedule and inverse scale `D` recover
independent leaf scores. Products and replies are charged as:

```text
products = max_l ceil(M_l / (m_l/D))
replies  = max_l ceil(M_l / m_l).
```

The native API receives virtual count `max_l M_l*(N/m_l)`; this accounts for
unused capacity. No leaf's rows are silently omitted. The plaintext field stays
`t=1153`, supporting the required splits through depth six, and the encryption
degree stays `N=16384`. All comparisons use the same key/parameters per run.

Tests compare direct polynomial remainders, independent schoolbook products,
the old flat CRT after root permutation, and **whole** homemade-BGV output
polynomials. Empty leaves, partial tiles and multiple replies are included.
Incomplete/overlapping trees, incompatible fields, inconsistent roots, shape,
padding and plaintext bounds are rejected.

## 2. Repair the rank boundary before allocating capacity

[`rank_partition.py`](../../experiments/bfv_search_lab/rank_partition.py) starts
with index-only ordered blocks. Blocks already within a target rank are left
intact; only offending blocks split. Each split halves its parent's plaintext
capacity. A median-only control competes with a greedy hybrid that tries the
median, several balanced binary-coordinate cuts and one rare-coordinate cut.

A varying binary coordinate is a nonconstant linear functional on the parent
affine space. Fixing it to zero or one restricts each nonempty child to affine
dimension at most `rank(parent)-1`. We also recompute and certify every child
from all its rows; this dimension fact is not used as a substitute for checking.

The heuristic first reduces remaining rank violation, then prefers lower tile
occupancy and smaller map bodies. It is **not** a globally optimal partitioner.
It has a depth-six/64-leaf budget and fails explicitly if it cannot meet the
rank target. A byte cap is applied to completed candidates: splitting a dense
map can make it sparse, so prematurely pruning every temporary large map would
discard some possible solutions.

For fixed maps and common `D`, capacity allocation has a simple exact solution.
Divide the full ring into `S` elementary components, each holding `c=N/(S*D)`
rows per product. To finish group `i` in at most `L` products, it needs
`ceil(M_i/(L*c))` components. Therefore:

```text
L is feasible iff sum_i ceil(M_i/(L*c)) <= S.
```

Binary search finds the minimum feasible `L`. Contiguous same-map components
are coalesced into dyadic leaves; a group's encrypted coordinates can occupy
multiple leaves while the owner retains just one copy of its map/query transform.
All rows, unused tails and replicated public geometry are charged. Exhaustive
small integer allocations verify the optimum. The claim covers **fixed maps,
common D and fixed elementary granularity**, not joint optimal rank partitioning
or unrestricted homomorphic packing.

The selector compares only the declared candidates, with an explicit canonical
map-byte cap. It prioritizes reply count, products, switches, map bytes and leaf
count, in that order. It falls back to full scan unless the charged circuit cost
strictly improves. Compression, Python objects, common IDs and key material are
different budget categories and are not silently substituted for canonical maps.

## 3. Public data, failures and a third split

The [model artifact](../../benchmarks/results/dyadic_layout_lab_20260927.json)
retains **72 successful configurations**, **six rejected fits**, and **1,152
configuration–query cases** checking every distance and stable top-3. These are
exact arithmetic/count models, not HE latency. Queries never guide fitting.

Pinned CC BY 4.0 UCI data remains outside Git: Mushroom (1981),
[DOI 10.24432/C5959T](https://doi.org/10.24432/C5959T), has hypothetical samples
encoded with the fixed 126-bit categorical schema; Semeion Handwritten Digit
(1998), [DOI 10.24432/C5SC8V](https://doi.org/10.24432/C5SC8V), has supplied binary
256-pixel images. Labels are discarded. Mushroom splits 3001, 3002 and new 3101
leave 7,996 distinct index rows; Semeion split 3101 leaves 1,465. Model holdout
positions 80:96 are disjoint from native positions 120:128 (119 is warmup).
No reported public model query equals an index row.

| Mushroom split / method | Products | Switches | Leaves / unique maps | Canonical maps |
|---|---:|---:|---:|---:|
| Full scan, any split | 63 | 189 | — | No private dictionary |
| 3001, old equal-8 layout | 32 | 95 | 8 / 8 | 4,527 B |
| 3001, hybrid rank-32 repair | 19 | 50 | 20 / 20 | 9,542 B |
| 3001, repair + allocation | 18 | 49 | 35 / 20 | 9,542 B |
| 3002, old equal-8 layout | 63 | 189 | 8 / 8 | 4,848 B |
| 3002, old equal-16 layout | 32 | 95 | 16 / 16 | 8,271 B |
| 3002, repair only the rank-65 block | 32 | 95 | 9 / 9 | 5,419 B |
| 3002, hybrid rank-32 repair | 20 | 51 | 24 / 24 | 11,386 B |
| 3002, repair + allocation | 20 | 51 | 33 / 24 | 11,386 B |
| 3101, old equal-8 layout | 32 | 95 | 8 / 8 | 5,570 B |
| 3101, hybrid rank-32 repair | 18 | 49 | 27 / 27 | 13,983 B |

Targeting rank 32 with median-only splits fails at the depth/leaf limit on all
three public categorical splits. Hybrid splits in randomized input order also
fail that target; index-only physical order matters. Allocation saves one
product on split 3001 and none on the other two. It is not automatically a win.

At a 4 KiB canonical-map budget, all these workloads select full scan. At 8 KiB,
Mushroom selects 32-product layouts; at 16 KiB it selects 18/20/18 products.
Semeion's map-heavy reductions are rejected even at 32 KiB. The full-size
8,192×512 uniform-random control gets no work reduction and selects full scan.
The prior cycle's finer-partition random-data map blowup remains a separate
negative result, rather than rerunning that expensive search here.

The unequal synthetic control has 8,192 distinct 512-bit rows and eight **given
generative maps**, rank 48 each, with counts
`4096,2048,1024,512,256,128,64,64`. Equal-degree components use 128 products,
254 switches and two replies. Allocation uses 34 products, 97 switches and one
reply, retaining the same 19,904 B of private maps. Its 22 leaves share eight
maps. Given boundaries are deliberate favorable information, not a learned
clustering result or representative public distribution.

## 4. Paired native CPU/CUDA results and ablations

Ryzen 7 5800X, eight OpenMP threads, RTX 3080 10 GiB. Same full `N=16384`,
`t=1153`, 120-bit RNS `Q`, secret, `eta=21`, 30-bit gadget digits and 32-bit
terminal coefficients per comparison. Ordinary conservative bounds apply to
all inputs, including dense CRT polynomials. One warmup and eight fresh paired
queries; case order is shuffled. CPU/CUDA receive identical query ciphertexts
within each mode, and complete response bytes match for every pair.

Local totals include query transformation/encryption, expansion, server
evaluation, response packing, decryption, decoding and stable selection. Setup,
network and authentication are separate. These are ordinary native API calls,
not the separately optimized packed workspace or attested service. Medians per
field need not sum. All figures below are milliseconds.

| Fixture / method | CPU server | CPU client | CPU total | CUDA server | CUDA client | CUDA total |
|---|---:|---:|---:|---:|---:|---:|
| Mushroom 3001, full | 612.90 | 25.69 | 639.47 | 28.36 | 25.43 | 54.33 |
| 3001, previous flat-8 | 318.35 | 28.71 | 347.05 | 24.28 | 28.26 | 52.59 |
| 3001, rank-32 repair | 179.85 | 29.29 | 209.37 | 22.20 | 28.61 | 50.80 |
| 3001, repair + allocation | 175.81 | 29.32 | 205.55 | 22.05 | 28.85 | 50.93 |
| 3001, allocation with flat-64 codec | 175.34 | 32.68 | 207.95 | 22.11 | 32.30 | 54.36 |
| Mushroom 3002, full | 613.38 | 25.67 | 640.13 | 28.16 | 25.34 | 53.51 |
| 3002, previous flat-16 | 318.31 | 29.66 | 348.00 | 23.97 | 29.07 | 53.04 |
| 3002, same index, recursive codec | 318.80 | 29.13 | 347.93 | 24.05 | 28.65 | 52.67 |
| 3002, repair only rank-65 block | 318.45 | 28.90 | 347.47 | 23.98 | 28.33 | 52.21 |
| 3002, rank-32 repair | 183.91 | 29.45 | 213.79 | 22.25 | 28.75 | 51.04 |
| 3002, repair + allocation | 184.15 | 29.42 | 213.57 | 22.24 | 28.96 | 51.05 |
| 3002, allocation with flat-64 codec | 185.08 | 32.77 | 217.66 | 22.26 | 32.45 | 54.89 |
| Unequal synthetic, full | 2,437.46 | 25.57 | 2,464.21 | 42.47 | 25.30 | 67.79 |
| Unequal synthetic, flat-8 given maps | 894.73 | 38.32 | 933.04 | 39.14 | 38.26 | 77.47 |
| Unequal synthetic, allocation | 326.60 | 28.82 | 355.97 | 24.39 | 28.44 | 52.77 |
| Unequal synthetic, allocation with flat-64 codec | 326.86 | 32.22 | 359.09 | 24.27 | 32.11 | 56.41 |

Artifacts retain every mode/sample:
[split 3001](../../benchmarks/results/dyadic_bgv_mushroom_split1_20260927.json),
[split 3002](../../benchmarks/results/dyadic_bgv_mushroom_split2_20260927.json),
[unequal synthetic](../../benchmarks/results/dyadic_bgv_uneven_20260927.json).
All distances and stable winners match independent XOR/popcount oracles.

The recursive-codec-only control permutes component roots so that its **entire
index and query plaintext polynomials equal** the flat control; it shares the
same prepared encrypted index. That small codec change alone does not explain
the CPU improvement. The flat-64 allocation control has the same product count
and private maps as coalesced allocation, but slower owner transforms/decoding:
on split 3002, query transform is 5.41 versus 3.18 ms. That erases its CUDA gain.
The coalesced representation makes finer allocation practical in this prototype.

Choosing fewer products does not guarantee the best observed GPU latency:
split 3001's 19-product repair is slightly faster than its 18-product allocation
in this eight-sample run. The public-data GPU changes are exploratory, not p95
or robust hardware/general-data claims. Single-GPU and client fixed costs still
dominate. The synthetic allocated result is 6.92× CPU / 1.28× CUDA versus full
scan, or 2.62× / 1.47× versus the imbalanced flat-map baseline.

All public modes send **245,866 B query + 131,162 B reply = 377,028 B**. Synthetic
full/allocated modes send 245,866 + 131,164 B; the imbalanced given-map control
sends a 262,247 B two-ciphertext reply. Thus the response reduction is against
that imbalanced layout, not the already single-reply full scan. Public layout,
epoch and authentication framing is additional.

Index coefficient bodies fall from 30,965,760 B for full scan to 8,847,360 B
(18 products) or 9,830,400 B (20) on Mushroom. Rank-32 evaluation-key bodies are
11,796,480 B versus rank-64's 13,762,560 B and full scan's 15,728,640 B. Unequal
synthetic index bodies fall from 125,829,120 B full / 62,914,560 B flat-given to
16,711,680 B allocated. Native/object overhead is separate; provisioning a
fallback as well incurs its index/key material.

## 5. Stronger owner-state and update controls

The [state/epoch artifact](../../benchmarks/results/dyadic_state_epoch_lab_20260927.json)
implements a complete **plaintext owner cache**: canonical maps plus every row's
binary pivot bits. It reconstructs all rows, not just scores. Its query timing
includes unpacking or per-block zlib decompression, the same compiled private
map transforms, exact field scoring and stable top-3. No server or encryption
is needed under this changed state contract.

| Body/state category | Mushroom 3001 | Mushroom 3002 | Unequal synthetic |
|---|---:|---:|---:|
| Private maps only, canonical | 9,542 B | 11,386 B | 19,904 B |
| Private maps only, zlib 9 | 2,591 B | 2,959 B | 5,960 B |
| Additional packed pivot bits for **all rows** | 25,236 B | 24,395 B | 49,152 B |
| Additional per-block compressed pivot bodies | 20,026 B | 19,044 B | 49,394 B |
| Complete maps + pivot bodies, jointly zlib 9 | 22,532 B | 22,353 B | 55,984 B |
| Complete original rows, same layout, zlib 9 | 22,123 B | 22,213 B | 524,454 B |
| Local packed-cache query median | 2.35 ms | 2.41 ms | 2.18 ms |
| Local compressed-cache query median | 2.48 ms | 2.49 ms | 2.13 ms |

Body counts exclude common IDs/layout/framing. Stable-ID bodies add
15,992/15,992/16,384 B. Compressed map bytes are storage figures, **not online
working memory**. Compiled map object sums in the native allocated modes are
136,532/157,816/137,832 B, with common IDs, layout, crypto state and other objects
additional. The prepared local-cache object sum including Python IDs is about
458/478/490 kB. These are explicit object-category audits, not process RSS;
benchmark processes also retain dense enrollment models and plaintext oracles.

The compressed-cache control therefore gives a real choice: retaining another
19–20 kB of compressed per-row coordinates on these public fixtures avoids HE
and network. On synthetic nonadjacent-column structure, affine coding is a much
stronger complete-data comparator than generic compression of raw rows. Neither
case establishes that the complete cache fits a required deployment budget;
it establishes the competing cost that must be justified. Query time need not
improve just because a body compresses better.

For update sensitivity, eight synthetic blocks initially have affine rank 64.
Replacing one row introduces a 65th direction in one block. The old local epoch
checksum and old affine map reject it. Rebuilding the fixed eight-block layout
doubles work from **32 products / 95 switches** to **64 / 191**. Hybrid repair
splits only that block, returning to **32 / 95**, with nine maps: canonical state
grows 19,496→21,891 B. Every old/new score and stable winner is checked for 16
queries, including the changed and former row.

These are **full owner rebuilds**, not incremental index updates: old fitting
2.83 s, changed fixed fitting 2.94 s, repaired fitting/certification 3.50 s, and
separate allocation/certification 2.74 s. Public hybrid rank-32 fitting takes
about 1.05–1.53 s in the model. Re-encryption, native index replacement, any key
changes, transactional epoch binding and network are still additional. The
local checksum also rejects in-span modifications/reordering, but is not server
authentication and does not independently bind external stable IDs.

## 6. Research interpretation and next experiments

CRT, recursive transforms, affine subspaces and capacity feasibility are
established tools. [Smart and Vercauteren](https://eprint.iacr.org/2011/133) covers
homomorphic SIMD/lookup; the butterfly follows
[Chen, Dai, Kim and Song](https://eprint.iacr.org/2020/015). The tensor-ring matrix
framework of [Zheng, Li and Wang](https://eprint.iacr.org/2023/1649) remains relevant
packing prior art. This cycle does not claim an unpublished combination or a
reproduced comparison against those papers.

A targeted literature check also surfaced
[Bence Mali's Generalized BGV, BFV, and CKKS for Homomorphic Encryption over Matrix Rings](https://eprint.iacr.org/2025/972).
That preprint replaces scalar ring plaintext/ciphertext spaces with matrix
rings, uses a superoperator treatment of noncommutative relinearization, and
bases security on Module-LWE. It suggests an alternative arithmetic model to
study before further optimizing scalar-ring packing. Only its abstract and
available technical-overview excerpt were reviewed here; no implementation,
parameter assessment or performance transfer is claimed.

The online schedule here is fixed by an epoch. Data-derived maps/anchors/cuts
remain private owner information; public geometry, counts and padding are
metadata. There is no adaptive per-query tile routing. Exactness, range checks
and local hashes do **not** authenticate malicious server output. Reviewed
authorization, private side-channel assurance and parameter review remain open.
The experiments do not extend production decryption permissions or the GPU TEE
trust boundary. All distances still reach the owner.

Prioritize these next discriminating experiments:

1. **Memory/scale boundary, not just another kernel.** With genuinely distinct
   growing indexes and a fixed map/working-memory cap, compare this encrypted
   representation with the complete compressed-coordinate cache and streaming
   local scan. Include codec decode time, schema drift, IDs and update frequency.
   Establish where outsourcing earns its cost before selecting a paper claim.
2. **Stable dictionaries plus a bounded encrypted delta.** Keep an epoch's main
   maps stable and score a small changed-row buffer exactly. Test whether the
   delta can share one query/reply through reserved components; charge its
   capacity loss, extra key/circuit work, duplicate IDs and replacement semantics.
   Compare full rebuilds and reveal or hide update locations explicitly.
3. **Joint rank/capacity cuts.** Replace the greedy rank-first score with a small
   beam/Pareto search over map bytes, padding, allocation and rebuild cost. Keep
   exact fixed-map allocation as a subroutine and prove coverage. It must beat
   the existing hybrid under the same state cap, not just lower rank.
4. **Alternative matrix-valued HE (E28).** Read the complete generalized-BGV
   construction, then build a homemade tiny algebra/count oracle for exact
   Hamming matrix products. Charge ciphertext/key growth and noncommutative
   switching at matched lattice dimension; distinguish batch-one latency from
   throughput. No reduced polynomial degree is free security or performance.

Commands, source hashes and checkpoint information are in the
[validation record](../../benchmarks/results/dyadic_rank_validation.md).
