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

## Validation and reproduction

The initial focused run passes 26 GPU pipeline, packed-client and transport
tests. The standalone terminal oracle checks random coefficients and values
near rounding boundaries through N=16,384, including Q-1 and 59-bit responses.
The NTT oracle checks the CPU forward transform and exact inverse round trip.
Full workload performance and sanitizer results will be recorded below.

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
