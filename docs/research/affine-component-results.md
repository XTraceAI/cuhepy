# Exact affine dictionaries inside one full-size BGV query

Follow-up: [rank-boundary repair and unequal component capacity](dyadic-rank-results.md)
implements the next cycle, preserves these controls, and adds a complete local
affine cache plus a one-row update experiment. Its full ring and parameter
profile match this cycle; the earlier artifacts remain unchanged.

2026-09-27, `experiment/creative-search-algebra`. E26 follows the
[dictionary/residual cycle](dictionary-witness-results.md). All encryption,
evaluation and decryption use our homemade Python/GMP, C++/RNS and CUDA BGV.
NumPy performs exact bounded-integer preprocessing/CRT transforms and independent
oracles; these experiments do not import Microsoft SEAL.

**Result:** several block-specific exact dictionaries can share one encrypted
query and reply. On 7,996 public categorical vectors, this reduces CPU local
time about 1.84–1.85× with a 4.5–8.3 kB canonical private map. CUDA local time is
nearly unchanged. On deliberately block-structured 8,192×512-bit data, CPU local
time improves 7.10× and CUDA local time 1.31×. The full encryption ring is retained.
Traffic matches the existing full scan; the saving is computation/index storage,
not a smaller response. This is a state/representation experiment, not a new
cryptographic primitive, established novelty or production assurance.

## 1. From private residuals to exact local affine spaces

E25 kept a private correction for every index row. Here the owner retains a
map for each of `T` blocks, without a per-index-row residual array. For binary
rows `x` of dimension `d`, choose one binary anchor `a` per block and compute a
row-reduced basis `B` for all differences `x-a` over the prime field F_t. With
pivot coordinates `P`, every enrolled row satisfies:

```text
u = x[P] - a[P]                           (entries -1, 0 or 1)
x = a + u B                              (mod t)
w(q) = B (1 - 2q)
H(q,x) = H(q,a) + u w(q)                  (mod t).
```

The anchor score is computed privately by the owner; the encrypted server
computes `u w(q)`. Since `t > d`, the residue identifies the exact distance in
`[0,d]` for every binary query. There is no approximation or learned-query
assumption. A constant block uses a dummy zero feature.

[`affine_dictionary.py`](../../experiments/bfv_search_lab/affine_dictionary.py)
certifies **every** enrollment row against the resulting basis, and rejects a
new row outside the pinned affine space. Basis identity/pivots, field, dimensions
and binary inputs are validated. Matrix products fit int64 under the explicit
research bounds; input reduction precedes CRT integer conversion.

For fixed `T,d`, basis storage is bounded by `O(T*d²)` field elements, independent
of the number of rows `M`. That is not a constant-size client claim: stable
IDs/permutations still take `O(M)` space, and increasing `T` can make maps larger
than the data. Anchors contain actual binary rows and relations reveal private
structure. These maps belong to the authorized index owner, not arbitrary
read-only search users or the evaluator.

### Binary-query contractions

A dense private matrix multiply and repeated map validation erased the CUDA
benefit in the first run. Enrollment now optionally groups equal nonzero field
coefficients of each basis row into bit masks. Using centered coefficients `c`,

```text
B_g (1 - 2q) = bias_g - 2 sum_c c * popcount(q AND mask_gc)     (mod t)
bias_g = sum_c c * popcount(mask_gc).
```

This is exact for arbitrary field coefficients, not just `+1/-1`. It validates
the map once, compiles an immutable local object, then contracts each binary
query without rereading the dense basis. It retains no row-specific residuals.
The canonical byte audit, dense Python object size and compiled Python object
size are reported separately. Python private arithmetic remains variable-time.

## 2. Different dictionaries, one ciphertext

Sending one encrypted query per dictionary loses much of the benefit. Let
`N = T*m` be the unchanged encryption degree and choose a prime with `2T | t-1`.
For the `T` odd powers `zeta_l` of a primitive `2T`-th root,

```text
X^N + 1 = product_l (X^m - zeta_l)                 over F_t.
F_t[X]/(X^N+1)  =  product_l F_t[X]/(X^m-zeta_l).
```

[`crt_multiplex.py`](../../experiments/bfv_search_lab/crt_multiplex.py) implements
this standard polynomial Chinese remainder transform directly. Each component
holds its own reversed query weights and rows of encrypted affine coordinates.
Component factors need not be irreducible for this ring decomposition.

All blocks use common power-of-two padding `D >= max(block ranks,1)`, with
`D | m`. Each input ciphertext then holds `m/D` rows **per component**. The
existing butterfly's automorphism generator `1+2N/D` fixes the component
idempotents: its exponent is 1 modulo `2T`. Thus the same trace/packing circuit
works componentwise, with trace scale `D`. Monomial shifts also act within each
component. The decoder CRT-projects the plaintext reply and reads each block's
score positions with that scale removed. Small encrypted tests independently
check the entire output polynomial, tails, empty components and multiple replies.

The full encryption degree remains `N=16384`; these are plaintext subalgebras,
not separate encryptions under smaller RLWE rings. The benchmark uses `t=1153`
for **all** comparison modes. The earlier `t=1031` does not admit this split
for `T>=2`, so this is a distinct, explicitly selected experimental parameter
profile. Retaining `N` does not replace a parameter/security review.

Uneven groups waste component capacity. Input products are
`ceil(max(block sizes)/(m/D))`, and replies are `ceil(max(block sizes)/m)`.
The model charges virtual row count `T*max(block sizes)` and common worst-block
padding. It does not assume free repacking or heterogeneous `D` within a trace.
For Mushroom seed 3001, full scan uses 63 products and 189 switches; CRT uses
32 and 95. Eight separate evaluations also use 32 products but 184 switches,
eight queries and eight replies. Sharing the trace therefore matters alongside
sharing communication; a product-only cost model misses that difference.

## 3. Exact hidden-position lookup: a retained expensive control

[`private_residual_lookup.py`](../../experiments/bfv_search_lab/private_residual_lookup.py)
also implements a tiny encrypted binary multiplexer tree for E25. Encrypted
address bits select an encrypted query bit; an encrypted sign forms
`sign*(1-2*q[address])`. Padded absent residuals have sign zero. Homemade encrypted
tests cover different addresses, signs and zero padding.

The **scalar reference** needs `d` ciphertext products per residual, including
the final sign product, and depth `log2(d)+1`. At `d=512`, `M=8192`, two padded
residuals per row, that is 8,388,608 products. It is a rejection of this literal
construction, not a lower bound for packed SIMD, optimized lookup, PIR, nonlinear
circuits or multiround protocols.

A narrower algebraic obstruction explains why a tiny exact linear lookup is
not automatic: the matrix `A[q,j]=q_j` contains `I_d` on singleton queries, so
an exact separated bilinear representation requires at least `d` features.
Allowing a free query-only affine offset saves one on the singleton-address
domain. This rank statement does not rule out packing several features into
one ciphertext or exploiting restricted/index-specific data.

## 4. Public distributions and rejection cases

The [model artifact](../../benchmarks/results/component_dictionary_lab_20260927.json)
retains **46 configurations × 16 queries = 736 cases**, each checking every
distance and stable top-3 against binary XOR/popcount. These are arithmetic/count
models, not encrypted timing measurements.

Pinned UCI **Mushroom** (1981), [DOI 10.24432/C5959T](https://doi.org/10.24432/C5959T),
contains hypothetical categorical samples; its fixed 22-attribute schema becomes
126 bits. **Semeion Handwritten Digit** (1998),
[DOI 10.24432/C5SC8V](https://doi.org/10.24432/C5SC8V), supplies binary 16×16 images.
Both repositories label their datasets CC BY 4.0. Labels are discarded; encoding
and archive/body hashes are pinned in
[`binary_fixtures.py`](../../experiments/bfv_search_lab/binary_fixtures.py).
Raw data stays outside Git. These are search adaptations, not classification
results or evidence on natural biometric/security deployments.

Each seed (3001, 3002) holds out 128 source rows, leaving 7,996 and 1,465 distinct
index rows. All fitting sees only index data. Model queries use holdout positions
64:80; native queries use 104:112, with 103 as warmup. Public query rows do not
equal index rows in the reported model. Randomized input order and balanced
metric order are both retained, with `T=1,4,8,16,32`.

| Fixture / layout | T | Max rank / padded D | Full / CRT products | Canonical maps | Interpretation |
|---|---:|---:|---:|---:|---|
| Mushroom seed 3001, global | 1 | 85 / 128 | 63 / 63 | 752 B | Global affine relations do not cross padding boundary |
| Mushroom seed 3001, metric | 8 | 58 / 64 | 63 / 32 | 4,527 B | Useful compact local maps |
| Mushroom seed 3002, metric | 8 | 65 / 128 | 63 / 63 | 4,848 B | A single excess direction removes saving |
| Mushroom seed 3002, metric | 16 | 58 / 64 | 63 / 32 | 8,271 B | More maps recover the boundary |
| Semeion seed 3001, metric | 16 | 91 / 128 | 23 / 12 | 691,554 B | Reject under a small-state contract |
| Semeion seed 3001, metric | 32 | 45 / 64 | 23 / 6 | 793,252 B | Fewer products, even more owner state |
| Piecewise synthetic, given block order | 8 | 48 / 64 | 256 / 32 | 19,904 B | Deliberately favorable structural control |
| Uniform synthetic, input order | 8 | 512 / 512 | 256 / 256 | 8,768 B | No work saving |
| Uniform synthetic, input order | 32 | 255 / 256 | 256 / 128 | 6,320,870 B | Map nearly caches small blocks; reject |

The Semeion full raw database is 46,880 B (about 25.7 kB with zlib); uniform
full raw rows occupy 524,288 B. Rank reduction alone is not useful compression.
Mushroom's randomized partitions do not cross the rank-64 boundary in the
tested configurations. Metric partitioning therefore matters here, unlike
several previous residual-pruning experiments where signature order won.

The positive synthetic fixture contains **8,192 distinct** 512-bit vectors,
eight given contiguous blocks, each generated from 48 independent binary
features with different coordinate maps. Its global affine rank is 384, padded
to 512. It deliberately supplies favorable block boundaries; it is not evidence
that a clustering algorithm discovers them on arbitrary data. Native queries
alternate fresh unrelated random bits and nearby perturbed index rows.

## 5. Paired homemade CPU/CUDA measurements

Ryzen 7 5800X, eight OpenMP threads, RTX 3080 10 GiB; one warmup and eight fresh
paired queries per run, with shuffled evaluation order. Same `N=16384`, `t=1153`,
120-bit RNS `Q`, secret, `eta=21`, 30-bit gadget digits and 32-bit terminal
coefficients within each comparison. Ordinary conservative bounds are used,
including for the denser CRT plaintexts. No binary-only noise shortcut is applied.

The four modes are full signed-coefficient scan, separate queries per dictionary,
one dense-map CRT query, and that same CRT index with compiled owner bit masks.
The last two reuse identical prepared index handles. CPU/CUDA receive identical
fresh query ciphertexts within each mode. Setup/enrollment is recorded separately.

Medians in milliseconds; local total includes client and server stages:

| Fixture / method | CPU server | CPU client | CPU total | CUDA server | CUDA client | CUDA total |
|---|---:|---:|---:|---:|---:|---:|
| Mushroom 3001, full | 614.54 | 25.65 | 640.23 | 28.22 | 25.38 | 53.55 |
| Mushroom 3001, 8 separate queries | 683.62 | 174.13 | 857.84 | 161.26 | 174.21 | 335.67 |
| Mushroom 3001, dense CRT | 319.12 | 36.28 | 355.36 | 24.08 | 35.84 | 60.15 |
| Mushroom 3001, CRT + masks | 318.37 | 28.21 | 346.98 | 23.97 | 28.05 | 52.12 |
| Mushroom 3002, full | 612.90 | 25.70 | 638.63 | 28.31 | 25.63 | 53.95 |
| Mushroom 3002, 16 separate queries | 896.27 | 343.74 | 1,239.81 | 313.44 | 343.68 | 658.76 |
| Mushroom 3002, dense CRT | 317.73 | 42.07 | 359.97 | 24.10 | 41.68 | 65.79 |
| Mushroom 3002, CRT + masks | 317.55 | 29.15 | 346.73 | 24.01 | 29.13 | 53.24 |
| Piecewise synthetic, full | 2,436.44 | 25.81 | 2,462.43 | 42.52 | 25.73 | 68.17 |
| Piecewise synthetic, 8 separate queries | 681.41 | 197.55 | 879.38 | 160.87 | 197.39 | 358.16 |
| Piecewise synthetic, dense CRT | 318.38 | 58.51 | 377.26 | 24.06 | 58.44 | 82.55 |
| Piecewise synthetic, CRT + masks | 318.35 | 28.21 | 346.80 | 24.13 | 27.99 | 52.19 |

Medians per field need not sum. Server includes query expansion, evaluation
and response packing; client includes query transform/encryption, decryption,
decode and stable selection. Network, setup and authentication are excluded.
This is the ordinary native API, not the separately optimized packed workspace
or an attested service. No CUDA kernel changed in this cycle.

Sources: [Mushroom 3001](../../benchmarks/results/component_bgv_mushroom_masks_20260927.json),
[Mushroom 3002](../../benchmarks/results/component_bgv_mushroom_split2_20260927.json),
[piecewise fixture](../../benchmarks/results/component_bgv_piecewise_20260927.json).
The [initial dense-only run](../../benchmarks/results/component_bgv_mushroom_20260927.json)
is also retained: CPU 640.66→355.57 ms; CUDA **53.93→60.50 ms**, a regression.
In the paired follow-up, binary-mask compilation reduces Mushroom 3001 query
transform from 7.32 to 2.72 ms and decode/selection from about 9.2 to 6.0 ms.
On the synthetic fixture those stages fall from 20.96/17.86 to 2.78/5.88 ms.

All distances and stable winners match the plaintext oracle. Complete serialized
CPU/CUDA response bytes match within each mode for every query. Eight measured
samples justify exploratory medians, not p95, general-data speedups or robust
claims about Mushroom's 1–3% CUDA local-time difference. The synthetic 1.31×
CUDA total improvement is much smaller than its 8× reduction in products because
fixed client, transfer, conversion and server costs remain.

### Communication, static storage and owner state

For Mushroom, full and CRT modes each send **245,866 B query + 131,162 B reply
= 377,028 B**. Separate dictionaries send 8× or 16× that. The synthetic reply
is 131,164 B because its metadata encoding is two bytes longer. Thus CRT saves
communication versus separate local queries, and preserves the full-scan
traffic. Context/epoch/attestation/authentication framing is not included.

Encrypted index coefficient bodies fall from 30,965,760 to 15,728,640 B on
Mushroom (63→32 ciphertexts), and 125,829,120 to 15,728,640 B on the synthetic
case (256→32). Evaluation-key bodies fall from 15,728,640 or 19,660,800 B to
13,762,560 B. These exclude object/native allocation overhead. Keeping the
full scan as a simultaneously provisioned fallback costs its index/key material
as well; the experiment does not count them as free.

| Owner/data body, excluding common IDs/context | Mushroom 3001 | Mushroom 3002 | Piecewise synthetic |
|---|---:|---:|---:|
| Canonical private maps | 4,527 B | 8,271 B | 19,904 B |
| Maps, zlib level 9 | 1,669 B | 2,545 B | 5,940 B |
| Dense map Python objects | 367,532 B | 598,172 B | 1,654,124 B |
| Compiled bit-map Python objects | 89,796 B | 145,028 B | 138,740 B |
| Complete raw binary rows | 127,936 B | 127,936 B | 524,288 B |
| Complete rows, zlib level 9, same order | 22,518 B | 22,698 B | 524,454 B |
| Modeled complete affine cache: maps + packed pivot bits | 45,012 B | 41,259 B | 69,056 B |
| Common stable-ID array | 15,992 B | 15,992 B | 16,384 B |

The last cache-body estimate is `map_bytes + sum_l ceil(M_l * rank_l / 8)`:
binary pivot bits plus the anchor/map reconstruct every row. It is an explicit
uncompressed storage model, not a measured cache codec or cache-query timing.
Generic byte compression misses the synthetic nonadjacent column structure;
the 69,056 B affine cache is a stronger control than comparing only with raw
or zlib data. Maps alone cannot generally reconstruct every row or perform a
full local scan without its encrypted coordinates, but their information leakage
is not quantified by byte count.

Measured local plaintext search with **all raw rows retained** takes 2.41, 2.43
and 2.29 ms respectively. It is far faster and avoids HE/network entirely, with
a different state contract. Compiled maps are smaller than the previous per-row
residual masks, but still larger than compressed full Mushroom data. Compression
is a storage comparison, not proof that the compressed representation supports
equally fast queries at that memory footprint. Both honest controls matter.

## 6. Prior work, protocol boundaries and next experiments

[Smart and Vercauteren, Fully Homomorphic SIMD Operations](https://eprint.iacr.org/2011/133)
already study homomorphic SIMD and encrypted lookup. Affine factorization and
polynomial CRT are established algebra. The existing butterfly cites
[Chen, Dai, Kim and Song](https://eprint.iacr.org/2020/015).
[Zheng, Li and Wang, A New Framework for Fast Homomorphic Matrix Multiplication](https://eprint.iacr.org/2023/1649)
is relevant tensor-ring encoding prior art: exploiting ring structure for fewer
matrix operations and switching keys. This cycle inspected its abstract and
metadata, not a reproduced implementation or full comparative proof. Our
candidate question is the joint index-specific rank/padding/state/update
tradeoff under exact encrypted search; this review does not establish novelty.

The online schedule is fixed for an index epoch and has no adaptive tile
requests. `T`, block counts and common padding are metadata; maps, anchors and
coordinate values are private. Owner-bound maps, ID order, roots, parameters
and index version must move together. One out-of-span row can change rank 64
to 65 and double padding; the regression rejects using the old map for it.
Measured static fitting/encoding/encryption is not an incremental-update system.

Local correctness/range checks do not authenticate a malicious server. A test
deliberately accepts plausible wrong field scores. The new format has no reviewed
remote authorization path, attested GPU execution, constant-time private map
implementation or parameter assurance. Production clients/TEE protocols are
unchanged; do not expose these raw decoders as a remote accept/reject oracle.
All scores reach the owner, preserving the current all-distance output contract.

Prioritize these discriminating algorithm/protocol experiments next:

1. **Padding-aware, bounded-state layout selection.** Fit from index data only;
   minimize complete products/switches under explicit map-byte and update budgets.
   Compare one global map, input/signature/metric order, learned splits and full
   scan. Add/remove outlier directions; charge rebuilds and stale-epoch rejection.
   A useful planner must reject the Semeion/uniform near-cache cases.
2. **Unequal component capacities or mixed ranks.** Model allocating more CRT
   components to large blocks, or separate rank classes with charged query/reply
   fusion. Find an algebraic schedule that avoids worst-block padding without
   free scatter, omitted switches or a smaller security ring. Include an index
   update that crosses a power-of-two boundary as a falsification case.
3. **Exact affine core plus encrypted exceptions.** Try structured residual
   support classes, factored/small-domain private lookups or another scheme;
   retain the scalar mux as a control, not a universal lower bound. Require a
   private fixed schedule, all-row coverage and bounded owner state. Charge
   exceptional-row index material and all query/conversion/depth costs.
4. **Query conversion fused with component statistics (E17).** Derive whether a
   short encrypted query can directly produce all `B_l(1-2q)` forms without
   materializing a large intermediate ciphertext. The private maps cannot be
   handed to the server silently; include their encrypted/trusted representation
   and conversion-key costs. Preserve existing full-query controls.

Validation/reproduction commands and checkpoint details are in the
[validation record](../../benchmarks/results/affine_component_validation.md).
