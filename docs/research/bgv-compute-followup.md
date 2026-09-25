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

`terminal_cuda.cuh` reconstructs a canonical coefficient from two 60-bit RNS
limbs and applies the existing exact terminal rounding on the GPU. With
`r=c mod t`, it computes

`k = floor((2*P*c - 2*Q*r + Q*t)/(2*Q*t))`, then `(k*t+r) mod P`.

Q is at most 120 bits, P below 60 bits and t below 30 bits. Three 64-bit words
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
