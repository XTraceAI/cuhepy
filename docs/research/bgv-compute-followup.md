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
