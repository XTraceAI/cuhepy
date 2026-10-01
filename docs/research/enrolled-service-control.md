# E75: actual enrolled TCP HE/cache control

R2-C0 bounded subcomponent, preregistered on 2026-10-01. This is a measurement
control, not a new protocol, paper contribution or complete cold deployment.
All code is homemade; the public C++ NTT/checker backend is the retained code.

## Execution and exactness

```sh
.venv/bin/python benchmarks/enrolled_service_lab.py --cache-dir /home/pete/yavor-projects/xtrace-work/research-data/uci-20260927 --datasets mushroom semeion --repeats 3 --query-budget 1024 --json-out benchmarks/results/publication-enrolled-service-control-20261001.json
```

Raw: [enrolled panel](../../benchmarks/results/publication-enrolled-service-control-20261001.json).
Specification: [preregistration](enrolled-service-preregistration-20261001.md).
Source: [runner](../../benchmarks/enrolled_service_lab.py),
[public callback/wire helpers](../../experiments/bfv_search_lab/enrolled_rpc.py),
[TCP harness](../../experiments/bfv_search_lab/loopback_exchange.py).

The same pinned split3001 rows, IDs and four held-out queries feed seven modes
per dataset: masked HE, five snapshot/retention controls, and retained owner
raw rows. **56 mode queries** agree on every exact score and stable top-3.
One query per mode is warmup; three are measured. Seven scoped tests check
literal received coefficient equality against GMP, canonical framing/deltas,
duplicate/replay handling, actual TCP callbacks and reject-before-key ordering.
Both a changed ciphertext and a malformed body consume the shared volatile
verification budget before any secret decryption.

The server expands the actual uploaded seeded index/answer packets. Each HE
request includes fresh vectorized owner preparation, trusted answer-hash
registration, answer upload, correction/reply, parsing, complete native
full-Q checking, secret decryption, restoration and selection. The wall clock
contains the server/RPC work; those nested stages must **not** be added again.
Small byte-count and equality instrumentation is also inside the wall clock.
Score/reference comparisons are outside it.

## Measured finite panel

Median over the three measured queries; times are milliseconds. These are
same-process loopback pilots, not independent endpoint CPU or service p95.

| Dataset / full index | HE N16384/t/Q profile | Complete HE query | Server native arithmetic, nested | Fresh owner prepare + answer hash, nested medians | Owner already-retained raw query |
|---|---|---:|---:|---:|---:|
| Mushroom / 7,996 rows,126 bits | t193/Q32 | 97.25 | 12.64 | 29.32 + 6.91 | 0.879 |
| Semeion / 1,465 rows,256 bits | t257/Q32 | 109.12 | 12.74 | 34.36 + 7.64 | 0.177 |

| Dataset / cache delivery + retention | Snapshot packet bytes, paid once | Download + authentication/parse ms, paid once | Returning local query ms |
|---|---:|---:|---:|
| Mushroom raw/raw | 191,996 | 3.22 | 0.705 |
| Mushroom zlib1/raw | 63,064 | 2.96 | 0.697 |
| Mushroom zlib9/raw | 49,901 | 2.93 | 0.689 |
| Mushroom zlib1/compressed | 63,064 | 3.02 | 3.457 |
| Mushroom zlib9/compressed | 49,901 | 3.06 | 3.425 |
| Semeion raw/raw | 58,692 | 0.81 | 0.139 |
| Semeion zlib1/raw | 32,954 | 0.91 | 0.143 |
| Semeion zlib9/raw | 30,268 | 0.83 | 0.147 |
| Semeion zlib1/compressed | 32,954 | 0.88 | 0.807 |
| Semeion zlib9/compressed | 30,268 | 0.89 | 0.967 |

HE pays **197,320 / 199,599 application bytes per query**, including the fresh
answer upload, identifiers/length frames, correction and full131,072 B reply.
Its actual enrolled index upload is **2,100,826 / 1,509,976 application bytes**.
Every request and response has an eight-byte length frame. Cache upload and
download framing are also recorded separately. No private material travels on
the untrusted callback; the HE mask seed remains owner-local.

Owner map/coordinate/key construction and complete checker setup are recorded
separately. In particular checker preparation costs 4.40 / 3.18 seconds, and
Semeion private map bodies are551,460 B. Reported body models are **not RSS**.
The cache's256-bit key + pinned manifest is96 B already held by the client;
its transfer is not timed here. Long-lived clients can retain their original
owned data with zero acquisition, as the user-authorized raw control does.

## Scope and return to plan

This closes one **enrolled endpoint / returning-client** socket subcomponent.
It does not complete R2: context, private keys, maps, IDs, fingerprints and
cache manifests are already pinned. Full cold/new-client private bootstrap,
independent endpoint peak memory/CPU, multiple-process uncertainty, GPU and
WAN/TLS remain unmeasured. The volatile check and research HE parameters are
not durability, timing, reaction-privacy or parameter assurance.

**R6 decision:** no outsourcing win in these two literal profiles; caches win
even with compressed retention. But legacy N16384 is not our strongest HE
geometry. Before using this as a frontier conclusion, return to R2 and run the
same harness with the retained global-affine N2048 control. Then return to
R3/R6's new-mechanism questions; do not accelerate this dominated legacy panel.
