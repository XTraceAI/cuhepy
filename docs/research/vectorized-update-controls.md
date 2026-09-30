# Vectorized update control: the earlier repair win does not survive

2026-09-30. [Preregistered scope](lifetime-policy-preregistration.md),
[owner arithmetic](../../experiments/bfv_search_lab/coordinate_factory.py),
[repair implementation](../../experiments/bfv_search_lab/representation_updates.py),
[matched harness](../../benchmarks/representation_lifecycle_lab.py).

The full-reencryption arm of E43 previously evaluated every pending `M*r` with
Python loops. Both new arms use immutable owner-private int8 coordinates and
batched exact int64 products. Cache construction/replacement, fresh encryption,
all zero patches, complete checking, native preparation, initial discovery and
every original token are charged. The Python fallback is retained. Failed local
preparation now reserves/burns the token ID and lifetime allocation before
fallible encryption; encrypted update failures leave the old target unchanged.

| Synthetic workload | Complete sparse lifecycle | Vectorized fresh lifecycle | Paired median sparse cost change |
|---|---:|---:|---:|
| m4096, d128, rank32, N2048, pool16, four edits | 3.382 s | 3.096 s | **+9.25%** |
| m16384, d512, rank128, N16384, pool32, eight edits | 111.070 s | 102.960 s | **+7.88%** |

Two pairs per workload rotate arm order, with t1153/Q40/eta21. Two tokens are
used on nonfinal revisions; the final revision consumes the remaining pool.
Every accepted query matches every score and stable top-3 and passes the full
gate before secret decryption. Independent GMP coefficients and unreduced
integer phases agree once per revision. The new owner cache retains 128 KiB
and 2 MiB, respectively, in addition to the original owner Python/plan state;
these numbers are array bytes, not total RSS. All 192 queries across both runs
complete. No network or GPU timing is implied.

The larger workload's measured update stages are 63.524 versus 55.509 seconds.
The encrypted addition and fixed encryption/check/index schedule outweigh the
now-cheap owner dot products. This **rejects the present implementation's
general speed claim**, including the previous ~15% complete-lifetime pilot.
Earlier raw observations remain valid for their old Python control and are not
rewritten. Gate C remains open; no policy should train on the old inflated full
rebuild price.

Raw:
[rank32](../../benchmarks/results/publication-vectorized-lifecycle-rank32-20260930.json),
[rank128](../../benchmarks/results/publication-vectorized-lifecycle-rank128-20260930.json).

Return to P05/P06: add ordinary private client deltas and selective response-tile
rebuilds before pricing a reserve/rebase policy. The primary contract permits
private owner-to-client state, so withholding those controls would artificially
favor encrypted repair. Neither ordinary delta caching nor batched products
is itself a new research contribution.
