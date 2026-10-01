# E76: strongest retained global HE geometry through the same TCP harness

2026-10-01, R2 return after E75. Existing E51 global-affine/raw representations,
homemade HE/native evaluator, vectorized factory and full-Q checker; no new
cryptographic mechanism. [Preregistration](enrolled-global-preregistration-20261001.md).

```sh
.venv/bin/python benchmarks/enrolled_service_lab.py --cache-dir /home/pete/yavor-projects/xtrace-work/research-data/uci-20260927 --datasets mushroom semeion --repeats 3 --query-budget 1024 --profile global2048 --json-out benchmarks/results/publication-enrolled-global-service-control-20261001.json
```

[Raw](../../benchmarks/results/publication-enrolled-global-service-control-20261001.json)
and [runner](../../benchmarks/enrolled_service_lab.py). Same rows/IDs/query
prefix as E75, but cache timings are rerun rather than copied. **56 exact mode
queries** agree. Eight current E75/E76 tests pass, including global coverage
and stable-ID restoration, wire/GMP equality and release ordering. One warmup
and three measured queries per mode; no confidence/p95 claim.

## Returning-client observations

| Dataset / geometry | Complete HE query, median ms | Full reply body | Answer upload + query/reply application bytes | Already-retained owner raw, median ms | zlib1/raw-retained returning query, median ms |
|---|---:|---:|---:|---:|---:|
| Mushroom,7,996 rows,global affine rank85,N2048 | 46.79 | 65,536 B | 98,912 B/query | 0.887 | 0.710 |
| Semeion,1,465 rows,global raw rank256,N2048 | 15.78 | 16,384 B | 25,275 B/query | 0.182 | 0.146 |

Fresh vectorized owner preparation plus answer hashing takes median
14.41+3.43 ms / 3.90+0.96 ms. Server native evaluation is7.08 /3.85 ms,
complete private checking3.70 /1.88 ms, secret decryption7.71 /1.91 ms.
These are nested stages, **not additions to the complete query wall**.
The stronger geometry improves the finite service panel; comparing separate
E75/E76 runs is not a paired confidence interval or isolated causal speedup.

Mushroom's cache acquisition takes2.95–3.23 ms and packet49,901–191,996 B.
Semeion's takes0.82–0.89 ms and packet30,268–58,692 B. Compressed-retention
queries, including per-query decompression, remain3.48–3.52 ms /0.80–0.82 ms.
Cache packets are downloaded once; plaintext access/retention is authorized.
Original owned rows can also be retained with zero acquisition.

Actual seeded index uploads cost2,823,386 /2,125,850 application bytes, more
than E75's local columns despite smaller replies. Expanded HE index bodies
are5,570,560 /4,194,304 B. Full private checker preparation takes0.632 /0.480 s.
Owner coordinate arrays occupy679,660 /375,040 actual NumPy bytes, while
private map bodies shrink to565 /296 B. This distinction is why map bytes
alone are an inadequate retained-state claim.

## Decision and remaining boundary

**R6 negative for this regime:** even the stronger retained HE geometry loses
returning-query time to authorized caches in both pinned fixtures. The result
does not rule out other corpora, links, updates or a new protocol. Preserve the
fast company backend and return to R3's preparation/verification construction,
rather than accelerate an already dominated complete request.

Only the enrolled endpoint / returning-client subcomponent is measured.
HE context/keys/maps/IDs/fingerprints and cache keys/manifests are already
pinned; full cold/new-client private bootstrap remains open. Same-process TCP
threads share hardware/GIL. No independent endpoint RSS/CPU, WAN/TLS, GPU,
durability, private timing or parameter assurance is established. N2048/Q32
is the retained research candidate, not an approved production tuple. These
known controls close neither R2's full acceptance nor Gates B/C/D.
