# BGV compute and joint precision experiments

This follow-up on `research/bfv-search-lab` keeps the homemade scheme, Q120,
ring, keys and exact Hamming circuit. It tests independent public GPU arithmetic
and client representation changes alongside further communication experiments.
Package defaults and all earlier reference paths remain available.

## Public GPU arithmetic

The [service profile](bgv-service-results.md) attributes about 70% of GPU kernel
time to NTTs. `ntt_variants.cuh` adds shift-based power-of-two indexing and
optional warp shuffles for the five smallest inner butterfly stages. Its
variants are `baseline`, `indexed`, `warp1024`, `warp512`, and `warp2048`.
Tile size trades shared memory, synchronization and coalescing; a smaller tile
is not assumed to win. All use the same roots and exact canonical residues.

Shuffle groups have 32 active lanes and use the same XOR distance/mask. Tiny
rings below 32 retain shared-memory butterflies. No thread skips a block
barrier. These participation requirements follow the
[CUDA 12 guide](https://docs.nvidia.com/cuda/archive/12.0.1/cuda-c-programming-guide/index.html#warp-shuffle-functions).
The kernel code is our own implementation.

The [isolated NTT measurements](../../benchmarks/results/bgv_ntt_schedule.json)
use N=16,384 on the RTX 3080, one warmup and 20 trials with shuffled variant
order. Times below are median GPU milliseconds for a forward/inverse pair;
each polynomial has two 60-bit limbs. They exclude a complete search's other
kernels, conversion, transfers and client work.

| Polynomials | Baseline | Indexed | Warp, tile 1024 | Warp, tile 512 | Warp, tile 2048 |
|---:|---:|---:|---:|---:|---:|
| 2 | 0.0358 | 0.0296 | 0.0347 | **0.0256** | 0.0553 |
| 32 | 0.2048 | **0.1673** | 0.1842 | 0.1720 | 0.2099 |
| 256 | 1.3117 | **1.0291** | 1.1894 | 1.1786 | 1.2713 |
| 1,024 | 5.2429 | **4.0438** | 4.7207 | 4.7580 | 4.9536 |

Indexing lowers the largest transform time by 22.9%. Warp shuffles and smaller
tiles help the two-polynomial case but lose to indexed shared-memory stages
on larger batches. All variants remain available; the full-pipeline comparison
selects `indexed` from this study. A per-transform adaptive policy is a possible
later experiment, not something assumed to improve complete search time here.

`terminal_cuda.cuh` reconstructs a canonical coefficient from two 60-bit RNS
limbs and applies the existing exact terminal rounding on the GPU. With
`r=c mod t`, it computes

`k = floor((2*P*c - 2*Q*r + Q*t)/(2*Q*t))`, then `(k*t+r) mod P`.

Q is at most 120 bits, P < 2^60 and t < 2^30. Three 64-bit words
suffice for the numerator, subtraction and shifted denominators; the largest
quotient is bounded by `floor(P/t)+1`. A negative numerator is greater than
`-Q*t`, so its floor quotient is -1. The implementation uses exact unsigned
word operations and long division, without floating-point estimates. Output
equals the CPU/GMP rounding coefficient for coefficient; the phase bound and
wire precision do not change.

GPU terminal scratch is allocated on first explicit use and retained by the
workspace. Its coefficient storage adds `2*N*8` bytes plus a small public plan.
The same native lease serializes uploads, evaluation, modulus changes and close.
Failed GPU calls retire the workspace. Default CPU terminal calls retain their
existing allocation and conversion path.

## Client and server representation

`GPUWorkspace.search_packet()` exports canonical bit-packed coefficients
directly from the native server into the existing compact-v1 envelope.
`OwnerClient.finish_packed_fixture()` passes those bytes to the existing native
owner without a Python integer export/repack cycle. The response bytes and
private arithmetic are unchanged. The native client validates **every
coefficient in every ciphertext before the first private multiplication**.

The fixture entry point compares the entire received packet with locally pinned
expected bytes before parsing or private work. This retains the earlier test
gate, whose duplicate evaluation is excluded from benchmark request timings.
It is not a remote verification protocol. Variable-time private arithmetic,
parameter assurance and authenticated BGV execution remain separate open work.

## Joint query and response precision

`compressed_response_bgv.py` applies the earlier plaintext-congruent query map
to **only c0 of a terminal response**. For `R=2^d`, write `c=R*h+r`, send
`w=t*h+(r mod t)`, and reconstruct `R*h+(r mod t)+t*floor(K/2)` modulo P,
where `K=floor((R-1)/t)`. Before reduction the difference is a multiple of t
with absolute value at most `E=t*ceil(K/2)`. Since c1 is unchanged, this adds
E directly to the terminal phase bound, without a secret multiplication.
The caller must reject unless `B_terminal+E < P/2`.

This is deterministic public post-processing of an existing ciphertext. It
does not change the ring, secret distribution or evaluation modulus Q; it is
not a claim of a new compression primitive. Each response precision still
uses the existing public terminal modulus and its full correctness bound.
The rounded-response envelope pins context and precision and carries no
trusted phase bounds. Independent Python and C++/GMP implementations agree
on exact packets, including rounding boundaries and canonical encodings.

`joint_precision_bgv.py` propagates the **query** rounding error through the
entire multiplication, key switching, packing and terminal schedule, then
checks response rounding against the remaining bound. It enumerates query
drops, P widths 25/26/28/32 and response drops. Its Pareto frontier retains
choices where shrinking either direction requires growing the other; byte
counts include actual MessagePack framing. Transfer-only selection uses
`query_bytes/upload_rate + response_bytes/download_rate`. It deliberately
does not predict codec compute or cryptographic security. Complete local and
paced-TCP timings determine whether each choice is useful.

The benchmark uses the same fresh query encryption for each paired variant.
It isolates NTT indexing, GPU terminal rounding and packed response processing,
then combines them and tests joint precision on several link ratios. Every
compute variant must produce identical complete ciphertext bytes. Every joint
precision variant must recover every distance and the stable top three.
No measured precision is selected from observed private noise.

```bash
.venv/bin/python benchmarks/bgv_pipeline_followup.py --num-vectors 8192 --repeats 10 --transport-repeats 5 --json-out /tmp/pipeline-8192.json
.venv/bin/python benchmarks/bgv_pipeline_followup.py --num-vectors 32768 --repeats 10 --transport-repeats 5 --json-out /tmp/pipeline-32768.json
.venv/bin/python benchmarks/bgv_pipeline_followup.py --mode joint --index-modes owner --num-vectors 8192 --repeats 10 --transport-repeats 5 --json-out /tmp/joint-owner-8192.json
.venv/bin/python benchmarks/bgv_pipeline_followup.py --mode joint --index-modes owner --num-vectors 32768 --repeats 10 --transport-repeats 5 --json-out /tmp/joint-owner-32768.json
.venv/bin/python benchmarks/bgv_pipeline_followup.py --mode joint --compare-codecs --num-vectors 8192 --repeats 10 --transport-repeats 5 --json-out /tmp/joint-word-8192.json
.venv/bin/python benchmarks/bgv_pipeline_followup.py --mode joint --compare-codecs --num-vectors 32768 --repeats 10 --transport-repeats 5 --json-out /tmp/joint-word-32768.json
```

Owner-encrypted indexes require a fresh index and owner secret access at
ingestion, as in the preceding query study. They are measured separately from
public-key-encrypted indexes. Setup includes resident workspaces and terminal
private caches; per-search totals include fresh encryption, codecs, server
work, framing/parsing and client finishing. Application-paced loopback links
do not model WAN congestion, packet loss or remote authentication.

### Bounded word codec

The first complete measurements show that joint precision's additional codecs
can erase its transfer savings on fast links. `word_codec.h` therefore adds a
public unsigned-128-bit specialization when both input and output coefficient
widths are at most 120 bits. A coefficient plus its byte offset occupies at
most 127 bits. Canonical-preimage checks bound reconstruction below `2*Q`,
which fits in 121 bits. The code uses exact integer division and preserves
every canonicality check, partial-bin rejection and output bit.

The native codec dispatches to this path where admissible and keeps the GMP
mapping for wider widths. `backend="native-gmp"` explicitly selects the prior
mapping; `backend="python"` remains the default reference. Native response
validation reads c1 directly, avoiding Python coefficient objects. Validation
still checks all coefficients before any private work. `--compare-codecs` adds
paired fixed-word/GMP variants to the full benchmark; both use the new native
c1 validator, isolating the arithmetic difference between those two variants.

### Complete compute results

The [8,192-vector](../../benchmarks/results/bgv_pipeline_followup_8192.json) and
[32,768-vector](../../benchmarks/results/bgv_pipeline_followup_32768.json)
experiments at commit `29640f2` use dimension 512, N=16,384, Q120, t=1031,
eta=21, the public-key-encrypted index and P25 responses. They share fresh
query encryption across variants, check complete ciphertext equality, and
report medians of ten shuffled measured rounds after one warmup.

The machine is an AMD Ryzen 7 5800X with an RTX 3080 (10 GiB), Python 3.12,
GCC 12 and CUDA 12. These measure client and server on the same host. The final
CLI rejects N=32,768 before setup because its fixed P25 baseline cannot satisfy
the worst-case terminal bound at that degree; all reported full workloads use
N=16,384. The general evaluator still supports larger rings with suitable
response precision. Vector count and ring degree are separate parameters.

| Change from previous persistent/RNS baseline | 8,192 local total, ms | 32,768 local total, ms |
|---|---:|---:|
| Baseline | 66.92 | 129.05 |
| Indexed NTT only | 64.13 | 122.71 |
| GPU terminal rounding only | 61.80 | 119.78 |
| Packed server/client responses only | 53.28 | 103.12 |
| Indexed NTT + GPU terminal rounding | 59.82 | 112.08 |
| All three compute changes | **46.76** | **85.39** |

The combined changes lower local time by **30.1% / 33.8%** (a 1.43x / 1.51x
speedup in this latency comparison). Median server
processing falls from **40.51 to 28.28 ms / 87.99 to 62.41 ms**. Median client
response processing, including the fixture gate, parsing and private finish,
falls from **11.66 to 4.43 ms / 23.58 to 8.87 ms**. Request totals also include
fresh query encoding/encryption, wrapper overhead and object lifetimes; sums
of separately reported phase medians need not equal the total median.

No communication or index re-encryption is needed for these compute changes:
query/response sizes remain **245,866 / 102,488 bytes** at 8,192 vectors and
**245,866 / 204,895 bytes** at 32,768. The fixed-word codec above was added after
these measurements; seeded compute variants do not invoke a rounding codec.
Each resident workspace adds 262,144 coefficient bytes on first GPU terminal
use. Index/key uploads and scratch allocation are reported separately as setup.

### Codec and communication results

The first joint-precision run at `29640f2` retains an instructive negative
result. At 8,192 vectors, its balanced rounding produces fewer bytes but takes
**226.67 ms** on the 10-up/100-down, 40-ms paced link versus **221.71 ms** for
query-only rounding. On the 100-up/10-down link, response savings outweigh
those codec costs: the download-oriented choice takes **174.48 ms** versus
**186.89 ms** for query-only rounding. The smaller packet alone does not decide
the best representation.

The subsequent [8,192-vector codec comparison](../../benchmarks/results/bgv_joint_word_8192.json)
at `1b1e6ef` pairs the new word codec with the retained GMP mapping, sharing
fresh input packets, exact output packets, public bounds and native c1
validation. All use indexed NTTs, GPU terminal rounding and packed responses.
There are ten local and five trials per paced link after one warmup.

| 8,192-vector balanced plan, median | GMP mapping | Word mapping |
|---|---:|---:|
| Client query compression | 1.838 ms | 0.356 ms |
| Server query expansion, including seeded c1 generation | 6.519 ms | 4.298 ms |
| Server response compression | 1.312 ms | 0.347 ms |
| Client response expansion | 2.238 ms | 0.371 ms |
| Complete local request | 54.78 ms | **48.47 ms** |

The seeded baseline is 47.40 ms locally in that run. Joint precision now adds
about **1.1 ms** while reducing **348,354 bytes to 229,583 bytes** (34.1%).
Query-only rounding takes 47.62 ms and 252,100 bytes. The independent medians
and small sample count do not establish a reliable local winner among choices
whose times differ by less than about a millisecond.

The [32,768-vector paired codec run](../../benchmarks/results/bgv_joint_word_32768.json)
shows the same effect: balanced local time falls from **98.43 to 89.04 ms**
with identical bytes. Its seeded baseline is 87.20 ms, so the final joint codec
adds about **1.84 ms**. It reduces 450,761 bytes to **309,462 bytes** (31.3%).

| 8,192 vectors, word codec, median | Seeded | Query-only | Balanced joint |
|---|---:|---:|---:|
| Local | 47.40 ms | 47.62 ms | 48.47 ms |
| 100/100 Mbps, 20 ms added RTT | 96.47 ms | 89.34 ms | 88.55 ms |
| 10 up / 100 down Mbps, 40 ms RTT | 293.97 ms | 216.75 ms | 215.88 ms |
| 10/10 Mbps, 40 ms RTT | 368.60 ms | 292.13 ms | 276.37 ms |
| 100 up / 10 down Mbps, 40 ms RTT | 191.14 ms | 184.29 ms | 166.96 ms |

| 32,768 vectors, word codec, median | Seeded | Query-only | Balanced joint |
|---|---:|---:|---:|
| Local | 87.20 ms | 88.25 ms | 89.04 ms |
| 100/100 Mbps, 20 ms added RTT | 145.81 ms | 138.11 ms | 134.34 ms |
| 10 up / 100 down Mbps, 40 ms RTT | 342.77 ms | 266.18 ms | 266.98 ms |
| 10/10 Mbps, 40 ms RTT | 489.33 ms | 415.04 ms | 378.33 ms |
| 100 up / 10 down Mbps, 40 ms RTT | 311.36 ms | 306.49 ms | 266.66 ms |

These links are application-paced loopback fixtures, not actual WAN measurements.
The byte planner ranks candidates without codec cost; it does not automatically
replace the seeded format or choose a deployment policy from these samples.

### Index choice and precision frontier

The [8,192-vector owner-index run](../../benchmarks/results/bgv_joint_owner_word_8192.json)
and [32,768-vector owner-index run](../../benchmarks/results/bgv_joint_owner_word_32768.json)
repeat the word-codec study with a fresh owner-encrypted index. Their smaller
honest-encryption bound permits additional query rounding. This choice requires
owner secret-key access during ingestion, unlike the public-key index used in
the compute comparison. It does not change response packing or need a secret
on the public evaluator. Do not interpret cross-run local timing differences
between index types as a controlled computation-speed comparison.

| Vectors | Index encryption | Balanced query bytes | Balanced response bytes | Total bytes | Reduction vs seeded in that group |
|---:|---|---:|---:|---:|---:|
| 8,192 | Public key | 149,612 | 79,971 | **229,583** | 34.1% |
| 8,192 | Owner secret | 118,892 | 79,971 | **198,863** | 42.9% |
| 32,768 | Public key | 153,708 | 155,754 | **309,462** | 31.3% |
| 32,768 | Owner secret | 122,988 | 155,754 | **278,742** | 38.2% |

All balanced points above use P25. At 8,192 vectors the public/owner query drops
are 58/73 and response drop is 22. At 32,768 the query drops are 56/71 and
response drop is 23. The latter retains one more bit per query coefficient
than query-only rounding, to save one more bit in c0 of **each** response.
Framed byte counts are checked against actual emitted packets on every trial;
the two four-byte TCP length prefixes add eight more bytes per exchange.

The frontier also retains a P26 upload-oriented option. At 32,768 vectors it
uses query drop 58/73, response drop 22 and **149,612/118,892 query bytes** with
**168,042 response bytes**. At 8,192 the corresponding query drops are 59/74,
with **147,564/116,844 query bytes** and **84,067 response bytes**. At 8,192,
the P25 download-oriented point exchanges an extra 2,048 query bytes for 2,048
fewer response bytes; its total equals the balanced point. These are explicit
link tradeoffs, not a universal best modulus or representation.

| Owner index, word codec, median | Seeded local | Balanced local | Seeded 10/10 Mbps + 40 ms | Balanced 10/10 Mbps + 40 ms |
|---|---:|---:|---:|---:|
| 8,192 vectors | 45.86 ms | 47.22 ms | 366.04 ms | **248.10 ms** |
| 32,768 vectors | 84.10 ms | 85.68 ms | 487.94 ms | **350.88 ms** |

The public-key index gains remain available without rebuilding an existing
index. The owner option provides additional upload savings when ingestion can
use that secret. Both retain the same Q120 ring, encrypted operands, exact
all-distance/top-three contract and unmodified private arithmetic.

## What the evidence supports next

Keep indexed NTTs, GPU terminal rounding and packed response handling as the
combined compute candidate, while retaining every baseline. Keep joint rounding
explicit and measure its complete codec/transfer cost on the intended link.
The latest results support further profiling of public query expansion and
remaining native coefficient conversions; the previous profile's percentages
should not be assumed to describe this faster pipeline. Per-stage NTT selection
is still a hypothesis: warp512 wins a tiny transform but loses large batches.

Before choosing a paper configuration, repeat on real binary embeddings and a
second GPU, collect enough samples for tail-latency claims, refresh comparisons
with the other schemes and review parameter/security assumptions independently.
A remotely usable BGV authenticity gate and private side-channel hardening are
separate requirements. The excluded duplicate fixture computation is not that
gate, and these timings do not include authentication or attestation overhead.

## Validation and reproduction

The complete package/BFV-example/research suite at `4eea5ff` passes **787 tests**
with the independent SEAL BGV oracle and CUDA required. The only skip is live
Nitro integration; the deliberate multithreaded-fork regression emits its
expected Python deprecation warning. A subsequent eight-test GPU pipeline run
at `1b1e6ef` extends the terminal-modulus loop to the maximum supported 60-bit P;
the arithmetic implementation is unchanged. The [full log](../../benchmarks/results/bgv_followup_tests.txt)
and [boundary follow-up](../../benchmarks/results/bgv_followup_max_terminal_tests.txt)
record both runs.

ASan/UBSan passes **118 public-codec/parsing tests** and **96 private-owner/result
tests**. Instrumented modules are injected before imports and their paths are
asserted. The documented PyCryptodome deepbind override is used, and Python-hosted
leak detection is disabled. [Validation metadata](../../benchmarks/results/bgv_followup_cpu_validation.json)
records build flags, scope and source/binary fingerprints; the
[public](../../benchmarks/results/bgv_followup_public_asan.txt) and
[private](../../benchmarks/results/bgv_followup_private_asan.txt) logs contain the
actual summaries. Package Ruff/mypy and explicit changed-module checks pass.

The word-codec tests exercise every drop position at nineteen widths from
16 through 240 bits, including the 120-bit specialization cutoff, unaligned
fields, canonical edges and holes. Python and retained GMP implementations
must match complete bytes. The standalone terminal oracle checks random values
and rounding transitions through N=16,384, including Q-1 and 60-bit responses.
The NTT oracle checks each CPU forward transform and exact inverse round trip.

Compute Sanitizer **12.9.79** passes **memcheck, racecheck and synccheck** on
all three standalone executables: full evaluator/workspaces/batches, exact
terminal rounding and the N=16,384 NTT schedule oracle. All nine runs exit zero
with zero errors/hazards. The evaluator covers the baseline kernel levels,
all five NTT variants, both circuits, query batches, reusable workspaces,
terminal-plan changes and close refusal. The
[GPU validation metadata](../../benchmarks/results/bgv_followup_gpu_validation.json)
records every command, diagnostic log and source/binary hash. Instrumented
NTT timings in those diagnostic logs are **not performance results**. The
existing verified `/tmp` sanitizer installation is reused; no driver or
system policy was changed. These are finite correctness/memory checks,
not parameter assurance, a constant-time proof or a remote protocol audit.

```bash
make -C experiments/bfv_search_lab/_native all cuda PYTHON="$PWD/.venv/bin/python" CXX=g++-12 CUDA_CXX=g++-12 CUDA_ARCH=86
CUHEPY_REQUIRE_BGV_CUDA=1 .venv/bin/python -m pytest experiments/bfv_search_lab/test_cuda_pipeline_bgv.py experiments/bfv_search_lab/test_packed_owner_bgv.py experiments/bfv_search_lab/test_transport_feature_bgv.py -q
nvcc -O3 -std=c++17 -ccbin g++-12 -gencode arch=compute_86,code=sm_86 -Isrc/cuhepy/bfv/_cpu_ext experiments/bfv_search_lab/_native/ntt_schedule.cu -lgmpxx -lgmp -o /tmp/cuhepy-ntt-schedule
/tmp/cuhepy-ntt-schedule 16384 256 20
nvcc -O2 -lineinfo -std=c++17 -ccbin g++-12 -gencode arch=compute_86,code=sm_86 -Isrc/cuhepy/bfv/_cpu_ext experiments/bfv_search_lab/_native/sanitize_terminal.cu -lgmpxx -lgmp -o /tmp/cuhepy-terminal-sanitizer
/tmp/cuhepy-terminal-sanitizer
```

Performance jobs run separately from builds, correctness checks and sanitizers.
Only public parameters, samples and source/binary hashes are saved; no keys,
ciphertexts or private randomness are measurement artifacts.
