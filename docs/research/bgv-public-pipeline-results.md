# Homemade BGV: public pipeline, concurrency and terminal precision

2026-09-24, branch `research/bfv-search-lab`. This follows the
[joint-packing/RNS/CUDA milestone](bgv-butterfly-results.md). All evaluated
schemes, C++ evaluators and CUDA kernels are our own implementations, using
GMP and CUDA primitives. SEAL remains a separate correctness oracle. No SEAL
code is linked into the measured backends.

## Same-parameter implementation experiment

Keep N=16,384, t=1,031, Q=p0*p1 (two 60-bit primes), eta=21, four 30-bit gadget
digits and the same joint-packing circuit. Each run shares keys, index and
fresh seeded queries across variants. Hardware is the same Ryzen 7 5800X and
RTX 3080 10 GB as the preceding milestone. Ten measured trials follow one
excluded warmup, with variant order shuffled each round. Setup is recorded
separately and no other test/build/benchmark runs concurrently.

The new code lives in [cuda_trace.cuh](../../experiments/bfv_search_lab/_native/cuda_trace.cuh),
[compact.h](../../experiments/bfv_search_lab/_native/compact.h), and
[native_bgv.py](../../experiments/bfv_search_lab/native_bgv.py). Every kernel
level remains selectable for ablation; the original level 0 default is preserved.

| 8,192 vectors x 512 bits | Evaluation | Evaluation + compaction | Local measured phases |
| --- | ---: | ---: | ---: |
| Original CUDA pipeline | 44.08 ms | 61.73 ms | 160.90 ms |
| GPU query NTTs | 43.36 ms | 61.24 ms | 160.80 ms |
| First fusion, scattered gadget writes | 45.55 ms | 63.82 ms | 161.99 ms |
| Fusion + shared key reads | 41.78 ms | 59.53 ms | 158.63 ms |
| First fusion + native compaction | included at right | 48.06 ms | 146.39 ms |
| Shared key reads + native compaction | included at right | 44.95 ms | 143.33 ms |
| Gathered gadget writes + shared keys | 39.19 ms | 56.73 ms | 155.88 ms |
| Gathered writes + shared keys + native compaction | included at right | **41.13 ms** | **141.33 ms** |

The complete public evaluation/compaction stage is **1.50x faster**, with
33.4% less time. Local measured phases fall by **12.2%**. Across the ten paired
trials, the stage speedup ranges from 1.46x to 1.54x (median 1.51x); this range
is a sample description, not a confidence interval or a p95 guarantee.
The baseline stage ranges from 60.38–64.31 ms and the final stage from
39.89–44.07 ms. Medians of individual phases need not sum to the median total.

All rows in this table retain a **131,164-byte response**, 245,866-byte seeded
query and **377,030-byte round trip**. Native compaction changes where rounding
runs, not the format or the rounded coefficients. The local phase sum includes
fresh query creation, seed expansion, synchronized evaluation/native conversions,
compaction, packet construction, decryption, distance decoding and stable top-3.
It excludes parsing, network, attestation, setup and concurrent service load.

Raw [8,192-vector data](../../benchmarks/results/bgv_public_pipeline_8192.json)
measures implementation `d6ff114`, including source/binary hashes and every
sample. There are 45 full-ciphertext and 77 compact-ciphertext comparisons in
the single-request experiment, plus an independent RNS CPU oracle on warmup.
Every distance and stable top-three answer is checked.

## What the kernels change

1. Move the query's four forward NTTs from the CPU to the GPU.
2. Initially fuse sum/difference, automorphism and gadget extraction. This
   reduces launches but scatters writes into eight gadget residue polynomials.
   That variant is a **negative result** at this workload: it is slightly slower.
3. Load each evaluation-key strip once for eight ciphertexts, and reuse each
   digit for both output components. Small batches use the original kernel.
4. Gather input coefficients with the inverse automorphism, then write gadget
   polynomials contiguously. Compute the remaining sum/permuted c0 in the final
   merge. Alternate two work buffers so no thread overwrites another's inputs.
5. Round the final result in C++ using the exact same GMP floor-division formula
   and public bound as Python, exporting only the small coefficients.

The memory-traffic explanation for the first fusion's loss is an inference
from the kernel layout and ablations, not a measured hardware-counter result.
The final kernel needs **832.5 MiB** of coefficient workspace for this workload,
versus **960.5 MiB** in the baseline (128 MiB less). These are allocation counts,
not measured peak VRAM: the 128 MiB resident index, evaluation keys and runtime
allocations are separate. No secret key or private operation enters the server.

## Larger workload

The 32,768-vector experiment uses the same parameters and two result ciphertexts.

| 32,768 vectors x 512 bits | Evaluation | Evaluation + compaction | Local measured phases |
| --- | ---: | ---: | ---: |
| Original CUDA pipeline | 87.74 ms | 122.07 ms | 250.64 ms |
| First fusion + shared key reads | 81.72 ms | 116.00 ms | 245.06 ms |
| Gathered gadget writes + shared keys | 78.04 ms | 113.03 ms | 244.02 ms |
| Gathered writes + shared keys + native compaction | included at right | **81.30 ms** | **209.28 ms** |

The stage improvement is again **1.50x**; local measured time falls by **16.5%**.
The response is 262,247 bytes, query + response 508,113 bytes. The resident
device index is 512 MiB and the final coefficient workspace 1,664.5 MiB, reused
across the two output groups. Index encryption takes 137.14 s and GPU index
preparation/upload 7.73 s, both excluded from recurring timings. For comparison,
the 8,192-vector run records 33.19 s and 1.90 s for those setup phases.

Raw [32,768-vector data](../../benchmarks/results/bgv_public_pipeline_32768.json)
measures `674307d` (the same native binaries as the smaller run), with 46 full
and 66 compact-ciphertext comparisons. The CPU oracle and every distance/top-3
check pass. The size experiments use separately generated keys/queries; their
within-run variant comparisons are paired, cross-size timing ratios are not.

At this size, the circuit has 1,024 relinearizations and 1,022 automorphisms,
versus 256 and 511 respectively at 8,192 vectors. More vectors fill the result
polynomials more fully, so four times as many vectors do not require four times
as many key switches.

## Concurrent requests

The same 8,192-vector index serves four distinct fresh queries per batch.
Compare one, two and four worker threads using the final kernel and native
compaction; each worker owns its own stream/scratch. This is concurrent service
on one GPU, **not** a new fused multi-query kernel. Ten paired batches follow
one excluded warmup. Query creation and client verification are recorded
separately; server timing begins with already-available seeded query packets.

| Workers | Four-request batch | Requests/second | Median per-request service time |
| --- | ---: | ---: | ---: |
| 1 | 218.30 ms | 18.32 | 53.93 ms |
| 2 | 180.79 ms | 22.13 | 85.10 ms |
| 4 | **156.90 ms** | **25.50** | 132.20 ms |

Four workers improve server throughput by **1.39x**, while individual service
time rises under contention. The table does not claim lower interactive latency
or higher client throughput. Timing includes seed expansion, native evaluation,
compaction, response packing, host scheduling and device synchronization.
The service column is the median of the ten within-batch service medians; it
excludes waiting for a worker. Batch wall time includes that queueing.
The four-worker coefficient workspace is about 3.25 GiB, versus 832.5 MiB for
one request. All 88 additional compact-ciphertext comparisons pass, as do all
distance/top-three checks. Samples are in the `concurrency` section of the
8,192-vector artifact. No plaintext queries or ciphertext bytes are persisted.

## Terminal precision

The follow-up sweep holds the keys, Q, t, ring, circuit and encrypted index fixed,
then tests terminal sizes against the existing conservative rounding bound.
For two components under the original ternary secret, that bound is

```text
B_terminal = ceil(P * B_original / Q) + ceil((N+1) * t / 2).
```

Each P must satisfy P=Q mod t and 2*B_terminal<P. A smaller P changes the terminal
representation; it does not reduce the evaluation ring or change key generation.
The sweep compares every compact ciphertext with Python rounding and every
plaintext coefficient with decryption before reduction, including unused result
positions. Rejected moduli never reach decryption.

| Terminal bits | Response bytes | Query + response bytes | Local measured phases |
| --- | ---: | ---: | ---: |
| 24 | rejected by bound | — | — |
| **25** | **102,488** | **348,354** | 130.69 ms |
| 26 | 106,584 | 352,450 | 130.29 ms |
| 28 | 114,776 | 360,642 | 131.04 ms |
| 32 | 131,164 | 377,030 | 131.29 ms |

At 25 bits the response is **21.9% smaller**, and total recurring traffic is
**7.6% smaller** than the 32-bit control in this sweep. Sizes include actual
MsgPack framing; the 25-bit polynomial bodies also cross a framing-size threshold.
Timing differences among accepted precisions are small; this is principally a
communication improvement. The sweep is a separate run from the earlier kernel
table, so compare timings within each table rather than treating 160.90 to
130.69 ms as a paired measurement.

The bound is 8,446,469 at each accepted precision. The 24-bit candidate P is
16,771,981, below twice the bound (16,892,938), so it is rejected before native
evaluation/decryption. The 25-bit candidate has P/(2*bound) about 1.99. This is
a correctness margin, not a security level. Since the rounding term alone
exceeds half of any 24-bit modulus, fewer bits cannot pass this particular
conservative bound at N=16,384 and t=1,031.

Raw [terminal-precision data](../../benchmarks/results/bgv_terminal_precision_8192.json)
measures `674307d`: ten paired trials plus warmup, 44 complete compact-ciphertext
comparisons and **720,896 plaintext-coefficient comparisons**. Every distance
and stable top-three result passes. The default remains 32 bits; select
`search_compact(..., bits=25)` explicitly for this experiment. A protocol must
bind that terminal format and context before any real-data use.

## Validation and remaining work

The full repository/lab suite passes **526 tests with 10 skips**, with BFV/BGV
CUDA and the independent SEAL oracle enabled. Two additional terminal-precision
boundary cases then pass in the focused nine-test native-compaction suite.
The skips are the unavailable Paillier GPU extensions (nine) and real AWS Nitro
integration (one). Ruff and mypy pass for the package and experimental modules.

AddressSanitizer/UndefinedBehaviorSanitizer passes 33 focused CPU tests and the
two subsequent precision-boundary cases, including native compaction and
defensive bindings. The standalone CUDA oracle compares
all five kernel levels against the CPU at N=16 and N=2,048 with arbitrary
canonical coefficients and multiple output groups. GPU tests additionally cover
N=16,384, tails, concurrent calls and repeated fresh-query uploads. The prior
Compute Sanitizer instrumentation limitation remains unresolved; this is not
a GPU memory-sanitizer pass.

The next large remaining local cost is fresh owner query encryption (~60.6 ms
in the paired run), followed by private response decryption (~20.6 ms). Moving
those operations to a reviewed native implementation deserves its own design
and side-channel assessment. A true multi-query kernel could avoid some host
and allocation contention seen in the thread experiment. Narrower RNS limbs
remain a separate parameter/arithmetic experiment, rather than part of these
same-Q results.

These are engineering experiments using established BGV/trace identities, not
a novelty or production-security claim. Private Python/GMP remains variable-time;
BGV parameter assurance and authenticated GPU execution are still open. Correct
bounds and regression tests do not authorize decrypting adversarial responses.
See the [lab README](../../experiments/bfv_search_lab/README.md) for reproduction.
