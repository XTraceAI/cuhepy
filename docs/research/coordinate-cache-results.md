# E50: strong local cache controls

2026-09-30. [Implementation](../../experiments/bfv_search_lab/coordinate_cache.py),
[benchmark](../../benchmarks/coordinate_cache_lab.py). This completes an
important P01/P06 subcomponent, not the usefulness or originality gates.

Affine pivots contain binary `x_j`, so one bit per row/pivot suffices; the
anchor recovers the signed coordinate `x_j-a_j`. A constant block needs zero
coordinate bits. The cache retains the same private maps and stable row/ID
interpretation as the encrypted representation. It contracts the query,
computes every field score, unwraps the exact Hamming distance and selects
stable top-three. No original full rows are consulted by that cache.

Two controls retain complete rows: Python integer/popcount search and a zlib-9
body decompressed/decoded on every query. Every variant materializes all scores
and selects by `(distance, ID)`. The same E49 public fixture split, maps and
held-out query prefix are used; eight timed samples plus a warmup, rotated arm
order. These pilots do not establish publication confidence intervals.

| Fixture | Packed coordinates | Expanded int8 coordinates | Raw row search | zlib row search |
|---|---:|---:|---:|---:|
| Mushroom, 7,996 rows / d=126 | 1.922 ms | 1.693 ms | 0.922 ms | 2.327 ms |
| Semeion, 1,465 rows | 2.655 ms | 2.282 ms | 0.180 ms | 0.598 ms |
| Synthetic rank-128, 16,384 rows / d=512 | 4.480 ms | 3.948 ms | 2.286 ms | 6.344 ms |

All full scores and stable ties match. Raw/zlib avoid affine discovery; the
coordinate-cache setup reports and pays discovery/certification separately.
The synthetic generator schema is explicitly known, not a free empirical fit.

| Fixture | Packed coordinate cache + maps + IDs/permutation | Raw rows + IDs | Compressed rows + IDs |
|---|---:|---:|---:|
| Mushroom | 129,215 B | 191,904 B | 92,857 B |
| Semeion | 573,092 B | 58,600 B | 37,709 B |
| Synthetic rank-128 | 461,000 B | 1,179,648 B | 417,810 B |

These are canonical bodies/size models, **not RSS**. ID/permutation modeling is
12 bytes per row for coordinates and 8 for raw rows. Map bodies are canonical
private sparse encodings; actual Python maps, compiled bit masks, index arrays
and NumPy temporary conversions add state. The raw control retains Python
integers, whose resident cost exceeds its packed-body model. zlib charges
decompression in its timer and reports the uncompressed scratch body; this is
not a measured peak-memory bound. None of these controls requires an HE key,
fingerprint, pending-token pool, encrypted index or network response.

The Semeion affine maps alone are 551,460 bytes: even highly compact coordinates
cannot compensate for that overhead. On these small public fixtures, local
caching is substantially faster than the roughly 50–57 ms E49 encrypted
online path. This is an explicit negative finding for unrestricted local
caching, not a reason to invent a budget that excludes it. The existing
full-score contract already notes that an authorized client can reconstruct
rows in d+1 chosen queries; these experiments claim compute-server privacy,
not database privacy from that client.

Return to the plan: justify an actual retention/resource constraint, evaluate
larger corpora with all state charged, and retain raw/compressed-coordinate
controls. The private factory dot-product control must also be vectorized
before attributing its speed difference to homomorphic rerandomization. No
new GPU deployment follows from this pilot.

Raw artifacts:
[Mushroom](../../benchmarks/results/publication-coordinate-cache-mushroom-20260930.json),
[Semeion](../../benchmarks/results/publication-coordinate-cache-semeion-20260930.json),
[synthetic rank-128](../../benchmarks/results/publication-coordinate-cache-synthetic128-20260930.json).

Reproduce with `.venv/bin/python benchmarks/coordinate_cache_lab.py --dataset
semeion --cache-dir ../research-data/uci-20260927 --json-out /tmp/cache.json`;
substitute Mushroom or `synthetic128` (the latter needs no cache directory).
