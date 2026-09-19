# Fused CUDA BFV evaluation and index reuse

This continues the original CUDA implementation on `perf/bfv-cuda-server`.
Ciphertexts, cryptographic parameters, terminal compaction, and CPU fallbacks
are unchanged. The former CUDA implementation is retained as a selectable
comparison path. The changes accelerate public server evaluation; client key
generation/encryption/decryption remain CPU operations.

## Why a faster NTT alone was insufficient

The first implementation launched one kernel for every NTT stage. At N=16,384
that meant 14 forward kernels and 15 inverse kernels (including normalization)
for each transform. It also unpacked every index coefficient into a GMP integer
on the CPU and reduced it separately into three RNS primes on every query.

In a synchronized diagnostic run over 8,192 vectors, forward/inverse NTTs took
about 0.47 s combined, while host packed import and residue conversion took
about 0.52 s. These are diagnostic phase costs, not additive shares of the
original 0.86 s search: normal execution overlaps some host work and queued GPU
work, whereas profiling synchronizes every phase. Fusing transforms cut their
diagnostic time to about 0.10 s, but full raw searches still took about 0.80 s
until the CPU conversions were removed.

The implementation follows the locality and synchronization principles in
[NVIDIA's kernel fusion discussion](https://developer.nvidia.com/blog/?p=119743)
and [CUDA best practices](https://docs.nvidia.com/cuda/pdf/CUDA_C_Best_Practices_Guide.pdf).
Performance conclusions below come from this repository's measurements, not
external benchmark claims.

## Changes

1. **Two-pass shared-memory NTT.** A block owns 1,024 coefficients. The first
   forward pass owns a strip spanning all outer rows; the second owns one
   contiguous row. All butterflies within each pass stay inside the block.
   The inverse reverses those passes and folds normalization into its final
   stores. N<=1,024 needs only one pass. No block relies on another block's
   shared memory or on implicit warp synchronization.
2. **GPU packed-wire import.** Upload the existing 180-bit packed coefficients
   and convert them to residues on the GPU. Every coefficient, including unused
   lanes, is checked against Q. A device error flag is checked before evaluation
   or publication of a prepared index. CPU framing checks remain in place.
3. **Shared evaluation keys.** Eight ciphertext tiles reuse one key-coefficient
   strip loaded into shared memory. Each gadget digit contributes to both
   output components, reducing repeated key and digit loads. Separate shared
   value/quotient arrays avoid the extra bank conflicts of a 16-byte struct
   layout. Tiny rings retain the original pointwise kernel.
4. **Explicit resident indexes.** `prepare_cuda_index` validates and uploads an
   immutable snapshot. Later queries avoid repeated index conversion and
   transfer. It owns its exact server plan/device and cannot be passed to a
   different plan. The original Python index may be changed or released without
   changing the snapshot. Dropping references releases device memory.

The optional controls on `BFVCudaServer` are for paired experiments:

| `kernel_level` | Transform | Raw index import | Key product |
| ---: | --- | --- | --- |
| 0 | Original per-stage CUDA kernels | CPU GMP | Original |
| 1 | Shared-memory NTT | CPU GMP | Original |
| 2 | Shared-memory NTT | GPU | Original |
| 3 (default) | Shared-memory NTT | GPU | Shared across eight tiles |

`batch_tiles` is an integer in [1,256], default 32. It bounds scratch allocation;
it is not a cryptographic parameter. Each call still owns its scratch and stream
so concurrent requests cannot overwrite one another's buffers.

For ordinary use, the existing packed-search method selects level 3. For a
stable index, use:

```python
prepared = server.prepare_cuda_index(encrypted_index, vector_count)
response = server.encode_hamming_server_prepared(encrypted_query, prepared)
```

The server must be a public `BFVClient(server_backend="cuda", ...)` loaded with
the owner's public key/configuration. Create a new snapshot when replacing the
index. A snapshot adds `tile_count * 6 * N * 8` bytes of device storage: 192 MiB
for 8,192 vectors × 512 bits and 768 MiB for 32,768 at N=16,384. This is in
addition to plan and per-query scratch memory. Raw searches remain available
when GPU index retention is unsuitable. CUDA extension ABI is now 5; rebuild
the optional extension after updating (CPU ABI remains 4).

## Measurement method

Hardware is the same Ryzen 7 5800X and 10 GiB RTX 3080, driver 580.173.02, CUDA
12.0, GCC 12.4.0, Python 3.12.3, GMP 6.3.0. N=16,384, t=65,537, Q is the same
three-prime product, decomposition is 30 bits, and terminal responses use 50 bits.

`benchmarks/bfv_cuda_scaling.py` generates a fresh corpus of 32,768 distinct
512-bit vectors and freshly encrypts every packed tile. Smaller workloads use
prefixes of that index. Every backend sees identical public keys and encrypted
inputs. One warmup precedes three measured searches, with alternating backend
order. Raw timings include index/query upload, validation, allocations, GPU
arithmetic, response download and CPU compaction/export. Prepared timings exclude
the separately reported one-time index preparation. They still include query
upload, scratch allocation and complete response production. Owner operations
and network transit are outside these server-call timings.

A CPU residue evaluation checks each size, and the owner verifies every returned
distance against plaintext. CPU timings in this follow-up are single samples
with a prepared plan, not medians. Initial CPU medians remain in the first report.

The concurrency experiment submits eight distinct encrypted queries per wave
over an 8,192-vector index, using one, two and four workers. It compares a shared
immutable plan/index with independent plans/index copies. Setup and one warmup
wave are excluded; task scheduling and all eight completed responses are timed.
These wave timings measure throughput, not individual concurrent-query latency.

```bash
PYTHONPATH=src .venv/bin/python benchmarks/bfv_cuda_scaling.py \
  --sizes 1024,8192,32768 --repeats 3 \
  --json-out /tmp/bfv-cuda-scaling-optimized.json
```

## Paired results

All rows use the same N=16,384 parameters and 512-bit vectors. GPU values are
medians of three warm searches. The CPU reference is one warm-plan search per
size, so CPU/GPU ratios are approximate, not comparisons of two medians.

| Vectors | CPU reference | Original CUDA | Fused NTT only | + GPU import | + Shared keys (default) | Prepared GPU index |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,024 | 2.613 s | 0.179 s | 0.133 s | 0.055 s | 0.054 s | 0.035 s |
| 8,192 | 20.283 s | 0.943 s | 0.866 s | 0.394 s | 0.354 s | 0.179 s |
| 32,768 | 80.896 s | 3.338 s | 3.129 s | 1.232 s | 1.067 s | 0.669 s |

At 8,192 vectors, the default raw path is **2.66× faster than the original CUDA
path**, and the prepared path is **5.28× faster**. Relative to this run's CPU
reference, they are approximately 57× and 114× faster, respectively. At 32,768,
the corresponding improvements over original CUDA are 3.13× and 4.99×, and the
CPU/GPU ratios are about 76× and 121×. Ciphertexts match the CPU exactly at all
sizes; every decoded distance is checked outside the timed region.

Larger indexes improve throughput without changing the cryptographic ring:
prepared throughput is 29,471, 45,885 and 49,006 vectors/second for the three
sizes. Going from 8,192 to 32,768 vectors improves throughput by only 6.8%, while
query latency grows about 3.75×. Most of the available benefit from filling the
GPU is already present at 8,192 vectors on this hardware.

Preparing the index costs 0.031, 0.141 and 0.512 s for the three sizes, separately
from the prepared search measurements. It retains 24, 192 and 768 MiB,
respectively. Include this cost when evaluating a workload that replaces its
index for every query. These timings describe server evaluation, not total
client/server latency or an additional reduction in response bytes.

The complete samples, parameters, profiles, setup costs and source/binary hashes
are in [the scaling artifact](../../benchmarks/results/bfv_cuda_fused_scaling.json).
Its recorded HEAD is the preceding commit and its working tree is marked dirty;
the hashes identify the implementation measured here.

## Concurrent queries and separate server instances

This experiment uses the prepared path and eight distinct encrypted queries
over 8,192 vectors per wave. Each row is a median of three measured waves after
one warmup. All instances use the same physical RTX 3080.

| Workers | Shared plan/index: wave time | Queries/s | Independent plans/indexes: wave time | Queries/s |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 1.441 s | 5.55 | 1.443 s | 5.54 |
| 2 | 1.386 s | 5.77 | 1.390 s | 5.76 |
| 4 | 1.387 s | 5.77 | 1.391 s | 5.75 |

Two workers give about 4% more throughput than one; four give no further gain.
Independent instances do not improve on a shared immutable plan/index and
duplicate their device storage. A shared plan still requires independent scratch
for every active request. These results favor a reused index and a bounded
request queue on this GPU, rather than increasing the number of objects or
simultaneous requests. They do not measure multiple GPUs or separate machines.

Together with the size experiment, this is consistent with one large search
already using most of the available GPU throughput. It does not by itself prove
whether the remaining limit is arithmetic, memory bandwidth or synchronization.
The synchronized 8,192-vector prepared profile still spends about 0.101 s on
forward/inverse transforms and 0.027 s on pointwise products. These are useful
targets for further profiling, but their synchronized costs should not be added
up as shares of the unsynchronized wall time. Shared-key tiling reduced the
diagnostic pointwise cost from about 0.066 s to 0.023 s on the raw path.

Possible follow-ups are fusing adjacent decomposition/transform operations,
reducing global-memory passes, and reusing per-request scratch through a bounded
pool. They need their own measurements and concurrency/lifetime checks; simply
raising the batch or worker count is not supported by these results.

## Batch-size experiment

An earlier paired tuning run on 8,192 vectors, with one warmup and three samples,
compared tile-batch limits using the same public-only encrypted fixture. Larger
batches did not improve performance on this GPU:

| Tile limit | Raw search median | Prepared-index search median |
| ---: | ---: | ---: |
| 8 | 0.281 s | 0.188 s |
| 16 | 0.277 s | 0.181 s |
| 32 | 0.278 s | 0.180 s |
| 64 | 0.312 s | 0.185 s |
| 128 | 0.338 s | 0.190 s |
| 256 | 0.419 s | 0.195 s |

The default remains 32. This is a measured choice for the test GPU, not a promise
that the same limit is optimal on other hardware. Larger batches allocate
larger scratch and staging buffers; increasing their size does not create more
GPU execution resources.

[The preliminary tuning samples](../../benchmarks/results/bfv_cuda_batch_tuning.json)
come from a separate run and are not mixed with the final scaling table above.

## Validation

**380 BFV tests passed; one optional AWS test skipped.** The CUDA-specific tests
also passed after adding public prepared-index client coverage. Standalone
CPU/GPU comparisons passed at N=8, 16, 256, 1,024, 2,048, 8,192, 16,384 and 32,768.
Tests cover all kernel levels, batch sizes including partial batches, exact
canonical coefficient extremes, every packed coefficient alignment, immutable
snapshot/context/lifetime rules, concurrent queries, empty and malformed inputs,
and error recovery. Ruff and mypy check the changed Python code.

Compute Sanitizer 12.0 still cannot instrument an executable on this host; it
exits before its first instrumented API call even with its executable/libraries
colocated. Memcheck and racecheck remain validation gaps. The shared-memory
barriers have explicit block ownership, regression coverage and source review;
these are not a substitute for a successful sanitizer run.

The existing Nitro restriction is unchanged. GPU attestation integration is a
separate future protocol task; this work does not add a GPU execution receipt.
