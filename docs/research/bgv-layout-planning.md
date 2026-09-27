# E16: choosing layout, precision and setup horizon together

The follow-up measures every available precision tradeoff for each existing
radix layout and adds a reporting planner. The main finding is conditional:
**three-vector packing wins locally, two-vector packing wins the tested links
at 32,768 vectors, and ordinary packing wins those links at 8,192 vectors**.
Changing the encrypted index can require enough setup that the steady-state
winner is a poor choice for a short index epoch.

This is homemade BGV/CUDA and client code. It does not select approved security
parameters, change the default client, or authenticate remote GPU execution.
The [previous radix report](bgv-radix-results.md) contains the algebra, scalar
reference and packed/vectorized ablations. Its separate measurements remain
available; this report adds joint selection and explicit setup accounting.

## Measurement contract

The [8,192-vector](../../benchmarks/results/bgv_radix_all_precision_8192.json)
and [32,768-vector](../../benchmarks/results/bgv_radix_all_precision_32768.json)
runs use source `2d84065`, N=16,384, d=512, Q120, eta=21, an owner-encrypted
index and an RTX 3080 / Ryzen 5800X. Four layouts each have three Pareto
precision plans, giving 12 measured choices per vector count. The modes are
ordinary g=1, balanced g=2, direct-distance g=2 and direct-distance g=3.

Ten local and five paced-link rounds follow one excluded warmup per variant
and connection. Variant order is shuffled. Within a layout, precision choices
share the same freshly encrypted query each round; layouts use independent
keys and encryption coins. Every result is checked against all plaintext
distances and stable top-three selection. Ordinary g=1 keeps its existing fused
native decoder; radix layouts use packed private arithmetic and NumPy plaintext
decoding. No scalar-client ablation is mixed into this run.

Complete local timing includes owner encoding/encryption, codecs, CUDA server
work, response parsing, private arithmetic, distance decoding and selection.
The paced TCP fixture adds directional application bandwidth limits, 40 ms RTT
and a four-byte length prefix each way. Expected-output fixtures are generated
and charged separately; their gate is not remote authentication. Neither TLS,
attestation nor an actual WAN is measured.

### All measured choices

P is the terminal modulus bit budget; `qdrop` and `rdrop` are the public query
and response rounding choices. Byte counts include the radix context envelopes
but exclude the four-byte TCP prefixes. All choices have independent exact
correctness bounds in the existing precision planner; larger t still needs
separate cryptographic parameter assessment.

| Variant | t | P / qdrop / rdrop | Query B | Response B, 8,192 / 32,768 | Local ms, 8,192 / 32,768 |
|---|---:|---|---:|---:|---:|
| g1-p0 | 1,031 | 26 / 82 / 22 | 100,513 | 84,123 / 168,098 | 47.21 / 87.88 |
| g1-p1 | 1,031 | 25 / 81 / 22 | 102,561 | 80,027 / 159,906 | 47.72 / 86.56 |
| g1-p2 | 1,031 | 25 / 80 / 23 | 104,609 | 77,979 / 155,810 | 47.37 / 85.69 |
| balanced2-p0 | 1,050,631 | 36 / 72 / 32 | 141,473 | 125,088 / 125,088 | 43.76 / 61.13 |
| balanced2-p1 | 1,050,631 | 35 / 71 / 32 | 143,521 | 120,992 / 120,992 | 42.98 / 60.45 |
| balanced2-p2 | 1,050,631 | 35 / 70 / 33 | 145,569 | 118,944 / 118,944 | 43.19 / 61.07 |
| distance2-p0 | 263,171 | 34 / 74 / 30 | 133,281 | 116,896 / 116,896 | 42.80 / 60.76 |
| distance2-p1 | 263,171 | 33 / 73 / 30 | 135,329 | 112,800 / 112,800 | 43.29 / 60.28 |
| distance2-p2 | 263,171 | 33 / 72 / 31 | 137,377 | 110,752 / 110,752 | 43.46 / 61.21 |
| distance3-p0 | 135,005,723 | 45 / 65 / 43 | 170,145 | 153,761 / 153,761 | 40.21 / 55.34 |
| distance3-p1 | 135,005,723 | 42 / 64 / 39 | 172,193 | 149,665 / 149,665 | 41.10 / 56.11 |
| distance3-p2 | 135,005,723 | 42 / 63 / 40 | 174,241 | 147,617 / 147,617 | 41.89 / 55.18 |

Ordinary packing needs two result ciphertexts at 32,768 vectors; both radix
layouts fit in one. This explains the discontinuity in response traffic.
Fewer GPU tiles alone do not establish smaller query or response packets.
Small differences between precision-plan timings may reflect local variation;
the planner uses the measurements without claiming that their ordering is
stable across machines or runs.

## Reporting planner and held-out transport checks

[`radix_planner.py`](../../experiments/bfv_search_lab/radix_planner.py) ranks
only measured layout/precision pairs. It validates context, public frontier,
exact framed bytes, sample counts and correctness flags. Radix selection must
be explicitly enabled; the default considers ordinary packing only. It never
interpolates an unmeasured precision or approves HE parameters.

For directional bandwidths in Mbps, the steady request model in milliseconds is:

```
local_median + RTT + 8*(query_bytes+4)/(upload_Mbps*1000)
                   + 8*(response_bytes+4)/(download_Mbps*1000).
```

Predictions use local samples; validation uses the separate paced-link samples,
not those samples as timing inputs. All layouts are assumed already resident
for this check. The [8,192](../../benchmarks/results/bgv_layout_planner_8192.json)
and [32,768](../../benchmarks/results/bgv_layout_planner_32768.json) reports also
contain 63 scenario rankings each: seven connections, three residency states
and three epoch lengths.

| Vectors | Upload / download Mbps, 40 ms RTT | Predicted choice | Model ms | Measured chosen ms | Measured best | Regret ms |
|---:|---|---|---:|---:|---|---:|
| 8,192 | 10 / 100 | g1-p0 | 174.36 | 177.10 | g1-p0 | 0.00 |
| 8,192 | 10 / 10 | g1-p2 | 233.45 | 236.10 | g1-p1, 234.46 ms | **1.64** |
| 8,192 | 100 / 10 | g1-p2 | 158.13 | 159.61 | g1-p2 | 0.00 |
| 32,768 | 10 / 100 | distance2-p0 | 216.74 | 220.70 | distance2-p0 | 0.00 |
| 32,768 | 10 / 10 | distance2-p1 | 298.79 | 302.19 | distance2-p1 | 0.00 |
| 32,768 | 100 / 10 | distance2-p2 | 200.80 | 203.05 | distance2-p2 | 0.00 |

The predicted winner matches five of six cases. The remaining choice costs
1.64 ms, rather than being silently counted as correct. The simple serial
model also consistently understates the measured paced fixture by a few
milliseconds. Six local paced cases do not establish deployment accuracy or
justify reacting to small timing differences without hysteresis.

## Setup can reverse the choice

`resident_layouts` means the keys, encrypted index and **all measured terminal
plans** for that layout are already prepared. For a fresh layout, the planner
charges measured key generation, index encoding/encryption, server/index/client
preparation and planning. Repeated terminal widths can hit a client cache;
cold setup uses the largest measured preparation for that same layout/width,
not a later near-zero cache hit.

It also charges upload of the full raw public/evaluation-key and encrypted-index
coefficients. The public/evaluation-key coefficient count is 20,152,320 bytes
for each layout. Index coefficient bytes are:

| Vectors | g=1 | g=2 | g=3 |
|---:|---:|---:|---:|
| 8,192 | 125,829,120 | 62,914,560 | 42,270,720 |
| 32,768 | 503,316,480 | 251,658,240 | 168,099,840 |

This is a coefficient-only registration-transfer floor under the current
full-index/key representation. Framing, TLS, attestation, registration and
deployment copies are unmeasured, not free. Seeded key/index representations
could change that representation and require a different model. The present
model uses sequential costs and fresh keys for a layout change; it does not
assume an unimplemented cross-layout key reuse or re-encryption protocol.

For an epoch of H queries, the score is `steady_ms + setup_ms_floor/H`.
The persistent break-even against a resident layout is the first H for which
the alternative stays no slower. If its steady cost is higher, there is no
persistent break-even. These are projections using one set of setup timings,
not measurements of complete index epochs.

| Vectors | Connection | Alternative to best resident g=1 | Break-even queries, modeled floor |
|---:|---|---|---:|
| 8,192 | Local compute only | distance3-p0 | 907 |
| 8,192 | Any of the three paced profiles | Any radix choice | None |
| 32,768 | Local compute only | distance3-p2 | 464 |
| 32,768 | 10 / 100 Mbps | distance2-p0 | 50,430 |
| 32,768 | 10 / 10 Mbps | distance2-p1 | 6,680 |
| 32,768 | 100 / 10 Mbps | distance2-p2 | 685 |

For example, at 32,768 vectors and symmetric 10 Mbps, distance2-p1 saves
35.23 ms per steady request but costs a modeled 235.33 seconds to prepare and
upload from a g=1-resident state. At H=100 the model keeps g1-p2 at 334.03 ms
per query; at H=10,000 it selects distance2-p1 at 322.33 ms including amortized
setup, versus 298.79 ms steady state. Real registration overhead can push the
break-even later. Conversely, with **no layout resident**, a smaller g=3 index
can win a short epoch through lower setup cost despite losing steady network
latency. Treating all setup as zero misses both effects.

## Reproduction and next decisions

Use the existing homemade BGV CUDA, native codecs and owner builds; the reporting
step needs no GPU. Run benchmarks serially, without concurrent builds or tests.

```bash
.venv/bin/python benchmarks/bgv_radix.py --num-vectors 8192 --index-modes owner \
  --packed-radix --vectorized-radix --all-precision \
  --links 10up-100down-40ms 10Mbps-40ms 100up-10down-40ms \
  --json-out benchmarks/results/bgv_radix_all_precision_8192.json
.venv/bin/python benchmarks/bgv_layout_report.py \
  benchmarks/results/bgv_radix_all_precision_8192.json \
  --json-out benchmarks/results/bgv_layout_planner_8192.json
# Repeat both commands with 32768 instead of 8192.
.venv/bin/python -m pytest experiments/bfv_search_lab/test_radix_planner.py -q
```

The planner's tests cover malformed reports, missing samples, byte accounting,
opt-in policy, residency, directional links, terminal cache reuse and break-even
edge cases. See the [validation record](../../benchmarks/results/bgv_layout_checked_validation.md).
Source and input-artifact hashes are included in both reports.

Next measure actual registration and epoch turnover, additional dimensions/tails
and independent reruns before developing an online policy. Charge memory when
keeping multiple layouts resident, and add a conservative switching margin.
Before connecting this to protected clients, bind layout/t/precision/coverage
to the complete verified execution contract. The
[checked-switch experiment](bgv-checked-switch.md) is one part of that work,
not protection for these raw search measurements.
