# E13: cost of moving canonical gadget digits through a trusted CPU

This standalone experiment measures the first partition proposed in the
[verification inventory](bgv-verification-relations.md): leave transforms and
fixed-key products on the GPU, but perform every canonical CRT reconstruction
and gadget decomposition on a CPU. It supplies conversion and transfer cost
evidence, **not a verifier, attested service or proof system**. The existing
authenticated CPU path is unchanged.

## What is implemented

The homemade [CPU header](../../experiments/bfv_search_lab/_native/digit_boundary.h)
reconstructs a canonical integer from two 60-bit residues using a fixed inverse
and exact unsigned-128-bit arithmetic. It checks residue ranges and extracts
four base-2^30 digits. Its independent oracle uses GMP integer inversion and
reconstruction. No Microsoft SEAL implementation, HE secret key, hidden check
challenge or reusable verification material is used here.

The [CUDA executable](../../experiments/bfv_search_lab/_native/digit_boundary.cu)
uses the current GPU digit kernel as a baseline and adds four CPU round-trip
layouts. All restore the same native device digit array:

| Layout | Device → CPU, per coefficient | CPU → device | Total | Additional GPU work |
|---|---:|---:|---:|---|
| Native | Two uint64 residues: 16 B | Four uint64 digits, duplicated in two limbs: 64 B | 80 B | None |
| Shared | 16 B | Four uint64 digits: 32 B | 48 B | Replicate each digit into both limbs |
| Packed | Two 60-bit residues in 15 B | Canonical 120-bit integer in 15 B | 30 B | Pack residues; split the returned integer into digits and replicate |
| Aligned words | 16 B | Canonical 120-bit integer in two uint64 words: 16 B | 32 B | Split the returned integer into digits and replicate |

In the packed layout the CPU receives **both residues**, not a GPU-selected
integer representative. It validates those transmitted residues and chooses
the canonical CRT integer itself. A future verification protocol must still
bind the transmitted residues to the preceding checked arithmetic. In
particular, range checks after bit packing do not establish that an untrusted
GPU started with canonical residues or faithfully packed them.

The aligned variant retains the native input residues and uses aligned word
loads/stores for the CPU output. It sends 6.7% more bytes than tight packing but
avoids the GPU input-pack kernel and the CPU's 15-byte-stride extraction/store
work. This variant was added after the initial tight-packing measurements;
both initial [8,192](../../benchmarks/results/bgv_digit_boundary_v1_8192.json)
and [32,768](../../benchmarks/results/bgv_digit_boundary_v1_32768.json) artifacts
at `e77573b` are retained. The four-layout follow-up uses `1917f99`.

At N=16,384 and padded dimension D=512, the executable follows the actual joint
evaluator's batch sizes: one relinearization per tile and one switch per active
butterfly node. It repeats synthetic public coefficients at each boundary,
with one or eight CPU workers. Each stage completes its device-to-host copy,
CPU work and host-to-device copy before the next stage starts. These are cost
probes at real stage sizes, not a captured search transcript or complete search.

Pinned host buffers and a resident GPU input/output allocation are prepared
outside the measurements. GPU-only digit launches are queued on one stream and
then synchronized. CPU variants include all stage synchronizations; packing and
expansion kernels are charged to their corresponding transfer phase. OpenMP
uses static scheduling, eight workers only at ≥65,536 coefficients, and
`OMP_WAIT_POLICY=PASSIVE`. One-worker controls use the same C++ arithmetic.

The [Python runner](../../benchmarks/bgv_digit_boundary.py) checks the measured
batch counts/bytes against the independent Python schedule model, records all
samples and source/binary hashes, and reports medians. Variant order is shuffled
for ten rounds following one excluded warmup.

## Measured conversion and transfer costs

The final [8,192-vector](../../benchmarks/results/bgv_digit_boundary_8192.json)
and [32,768-vector](../../benchmarks/results/bgv_digit_boundary_32768.json) runs
use an RTX 3080 10 GiB and Ryzen 7 5800X, CUDA 12.0/GCC 12, architecture 86.
All times below are milliseconds, with setup/oracle checks excluded and actual
stage synchronization included. Eight actual OpenMP workers are checked before
measurement. These are ten-round medians, not latency percentiles.

| Digit boundary | 8,192-vector schedule | 32,768-vector schedule |
|---|---:|---:|
| GPU-only existing digit kernel | 1.50 | 3.98 |
| Native transfers, one CPU worker | 171.84 | 461.15 |
| Shared digits, one worker | 105.08 | 278.93 |
| Tight packing, one worker | 199.17 | 530.28 |
| Aligned words, one worker | 64.11 | 168.23 |
| Native transfers, eight workers | 130.53 | 348.84 |
| Shared digits, eight workers | 75.75 | 200.82 |
| Tight packing, eight workers | 52.14 | 139.05 |
| **Aligned words, eight workers** | **43.95** | **121.41** |

Aligned words reduce internal bytes by 60% relative to the native layout and
reduce the measured eight-worker boundary cost by 66.3%/65.2%. Tight packing
minimizes bytes, but its byte conversion costs make it slower. This is most
pronounced in the one-worker controls. More threads alone do not solve the
native representation's memory traffic.

| Aligned, eight workers | Device → host | CPU CRT/word stores | Host → device/expansion | Complete boundary |
|---|---:|---:|---:|---:|
| 8,192 | 8.95 | 22.31 | 12.19 | 43.95 |
| 32,768 | 23.63 | 64.02 | 33.62 | 121.41 |

Independent phase medians need not sum to the median total. All paths retain
the same range checks and exact CRT relation. Neither the smallest payload nor
the fastest GPU-only kernel predicts the cost of this CPU/GPU partition.

## Interaction with radix packing

E16 changes the physical candidate count to `ceil(M/g)`. At the same N/D/Q
widths, this removes tile and switch work from the proposed digit boundary too.
Additional microbenchmarks measure those exact schedules. They do **not**
integrate verification into the radix search implementation.

| Logical vectors M | Radix g | Physical candidates | Tiles | Butterfly switches | Aligned internal traffic | Aligned/eight-worker boundary |
|---:|---:|---:|---:|---:|---:|---:|
| 8,192 | 1 | 8,192 | 256 | 511 | 402,128,896 B | 43.95 ms |
| 8,192 | 2 | 4,096 | 128 | 383 | 267,911,168 B | 27.65 ms |
| 8,192 | 3 | 2,731 | 86 | 299 | 201,850,880 B | 20.60 ms |
| 32,768 | 1 | 32,768 | 1,024 | 1,022 | 1,072,693,248 B | 121.41 ms |
| 32,768 | 2 | 16,384 | 512 | 511 | 536,346,624 B | 60.70 ms |
| 32,768 | 3 | 10,923 | 342 | 511 | 447,217,664 B | 50.01 ms |

Raw schedules: [4,096](../../benchmarks/results/bgv_digit_boundary_4096.json),
[2,731](../../benchmarks/results/bgv_digit_boundary_2731.json),
[16,384](../../benchmarks/results/bgv_digit_boundary_16384.json), and
[10,923](../../benchmarks/results/bgv_digit_boundary_10923.json). Their
`num-vectors` command argument denotes **physical** candidates; logical M/g is
the interpretation in this table. The partial group is charged in full.

The boundary alone costs more than the corresponding raw GPU server in the
one-vector layout. Even after radix packing, it remains substantial before
linear checks, commitments or real enclave transport are added. This does not
establish that verification must lose against full protected CPU evaluation;
it does reject treating trusted digit work as a negligible receipt overhead.

The next E13 decision is to measure **one complete checked subcircuit** with
fresh challenges, all preprocessing and the true deployment transfer path.
Compare the aligned/radix boundary with a proof-backed alternative for the
nonlinear relations. Keep actual attested-GPU execution as a separate trust
model. Do not add these microbenchmark times to raw search and label the sum
an authenticated-service measurement.

## Validation and scope

Host checks compare canonical CRT and every gadget digit against GMP at ring
sizes 8 and 2,048, batch size 33, one/eight workers, random residues and corner
values. Noncanonical residues and invalid CRT contexts must be rejected.
The CUDA executable also compares **every output digit** for each layout and
worker count against the existing GPU digit kernel at the largest stage batch.

The host harness passed GCC AddressSanitizer and UndefinedBehaviorSanitizer.
The CUDA smoke workload N=64, M=131, D=16 passed Compute Sanitizer 12.9 memcheck
with zero errors and complete CPU/GPU agreement. The system's default sanitizer
could not load its injection library; the recorded run uses the separate
working 12.9 installation.
The [host log](../../benchmarks/results/bgv_digit_boundary_host_sanitizer.txt)
and [CUDA log](../../benchmarks/results/bgv_digit_boundary_memcheck.txt) cover
the final aligned-layout implementation.

This direct pinned-host experiment excludes linear checks, commitments,
preprocessing/refill, terminal rounding, index binding and receipts. It also
excludes Nitro/vsock transfers and any additional enclave/host copies. Treating
these times as an authenticated Nitro/GPU service would omit necessary work.
The GPU-only row is only the digit substage; it is not full search latency.

## Reproduction

Run separately from tests, builds and other GPU workloads:

```bash
make -C experiments/bfv_search_lab/_native digit-boundary \
  PYTHON="$PWD/.venv/bin/python" CUDA_CXX=g++-12 CUDA_ARCH=86
.venv/bin/python benchmarks/bgv_digit_boundary.py --num-vectors 8192 \
  --json-out benchmarks/results/bgv_digit_boundary_8192.json
.venv/bin/python benchmarks/bgv_digit_boundary.py --num-vectors 32768 \
  --json-out benchmarks/results/bgv_digit_boundary_32768.json
# For radix-reduced schedules, repeat with 4096, 2731, 16384 and 10923.

g++-12 -O1 -g -std=c++17 -fopenmp -fsanitize=address,undefined \
  -fno-omit-frame-pointer -fno-sanitize-recover=all \
  -I src/cuhepy/bfv/_cpu_ext \
  experiments/bfv_search_lab/_native/test_digit_boundary.cpp \
  -lgmpxx -lgmp -o /tmp/cuhepy-bgv-digit-boundary-asan
OMP_WAIT_POLICY=PASSIVE /tmp/cuhepy-bgv-digit-boundary-asan

# Use a working installation; this host used the separately installed 12.9 tool.
OMP_WAIT_POLICY=PASSIVE compute-sanitizer --tool memcheck --error-exitcode 1 \
  /tmp/cuhepy-bgv-digit-boundary 64 131 16 1
```

The Makefile target builds only the standalone public microbenchmark. It does
not replace existing BGV Python extensions or change private arithmetic.
