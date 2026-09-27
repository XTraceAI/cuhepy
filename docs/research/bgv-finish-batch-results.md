# BGV result handling and distinct-query CUDA batches

This follow-up adds two independent experiments to the homemade BGV branch:
local distance decoding/top-k after decryption, and public GPU evaluation of
several distinct queries against one key/index context. Both preserve the
previous [native owner](bgv-owner-results.md), single-query server and references.
The new C++/CUDA code is ours; SEAL remains a separate optional test oracle.

At 8,192 vectors, native finishing cuts its client phase by **30.3%** and the
measured local phase sum by **5.9%**. The fused GPU batch improves throughput
over sequential calls but loses to four existing host workers in this run.
It also increases the first-response delay. Neither result changes defaults.

Measurements use a Ryzen 7 5800X and RTX 3080, N=16,384, t=1,031, the same Q120
product of two 60-bit evaluation primes, eta=21, 30-bit gadget digits, and
25-bit terminal responses. Each workload uses one key/index set across its
variants; the two vector counts use separately generated keys. Fresh query
randomness is included in client timings; no preprocessing pool is used.

## Client result handling

Each result polynomial holds D-scaled signed correlations, where
`D = next_power_of_two(dimension)`. The original decoder computes an inverse
of D modulo t, centers each correlation, checks its range/parity, and derives
the Hamming distance. The new table instead inserts

```text
table[D * (dimension - 2*distance) mod t] = distance
for distance = 0 .. dimension.
```

For odd t and `t > 2*dimension`, those entries are distinct. All other entries
are invalid. This gives precisely the same acceptance rule as the original
decoder; it does not change the plaintext/ciphertext modulus. At d=512,t=1031
the table has only 1,031 entries, of which 513 represent valid distances.
Native decoding uses the arithmetic formula instead when t exceeds 65,536,
so a large public modulus cannot trigger an unbounded allocation.

The Python heap path replaces a complete sort with O(M log k) selection. The
native path performs decryption, lookup decoding and heap selection inside the
private owner module, avoiding intermediate Python plaintext lists. Rank pairs
are `(distance, original index)`, so ties are identical to the original stable
sort. All requested distances are checked, including nonwinning entries.
The decoder also checks canonicality of unused plaintext coefficients.

`OwnerClient.finish(..., all_distances=True)` returns the top entries and all
distances. The optional top-only mode avoids returning the full distance array
to Python, but still checks all requested scores. It changes only that local
API return contract; it saves no encrypted response traffic or server work.

### 8,192 vectors x 512 bits

All variants use the native owner introduced previously. Each round reuses one
response for the result-handling ablations; only its finishing implementation
changes. Ten measured rounds follow one excluded warmup; order is shuffled.

| Client finish | Decrypt + decode + select | Local measured phases |
| --- | ---: | ---: |
| Previous decoder + full sort | 15.42 ms | 77.53 ms |
| Previous decoder + heap | 14.00 ms | 76.15 ms |
| Lookup decoder + heap | 13.00 ms | 75.17 ms |
| Fused native finish, all distances | **10.75 ms** | **72.96 ms** |
| Fused native finish, top only | 10.65 ms | 72.85 ms |

The comparable full-result improvement is **1.43x** in finishing, 30.3% less
time. The local phase sum improves by 5.9%. Top-only provides very little extra
speed here; it is not the explanation for the full-result win. Wire sizes stay
245,866 bytes up and 102,488 bytes down, or 348,354 bytes combined.

Local phase sums include the first query's measured encoding, fresh native
encryption, public seed expansion, individual serial CUDA evaluation/native
compaction, framing, and the indicated client finishing. They exclude setup,
network, response parsing, attestation, batching wait and concurrent request
load. Common phases are shared across finish variants within each round.
These figures are paired within this report, not with the earlier owner's
81.87 ms measurement on separately generated keys/queries.

[Raw 8,192-vector measurements](../../benchmarks/results/bgv_finish_batch_8192.json)
record implementation `853d229`, public parameters, source/binary hashes, setup
and every sample. Index encryption takes 31.56 s and GPU index preparation
1.76 s; the native owner plus terminal cache takes 5.27 ms and the Python LUT
0.034 ms to prepare. These are excluded setup costs. The run compares 308 exact
compact ciphertexts across server variants, four against the CPU oracle, and
720,896 distance values against the independent plaintext Hamming calculation.

### 32,768 vectors x 512 bits

This workload returns two ciphertexts under the same N/t/Q/terminal parameters.

| Client finish | Decrypt + decode + select | Local measured phases |
| --- | ---: | ---: |
| Previous decoder + full sort | 39.59 ms | 151.07 ms |
| Previous decoder + heap | 33.44 ms | 145.26 ms |
| Lookup decoder + heap | 29.10 ms | 140.98 ms |
| Fused native finish, all distances | **21.66 ms** | **133.72 ms** |
| Fused native finish, top only | 21.38 ms | 133.26 ms |

The comparable full-result path reduces finishing by **45.3%** (1.83x) and
the local phase sum by **11.5%**. The reference finishing samples span
39.13–40.17 ms; native finishing spans 21.16–22.05 ms. These are ten samples,
not a p95 or a cross-machine estimate. Individual phase medians need not sum
to the median total. Response bytes remain 204,895 and query bytes 245,866,
or 450,761 bytes combined.

[Raw 32,768-vector measurements](../../benchmarks/results/bgv_finish_batch_32768.json)
use the same `853d229` implementation and native binary hashes. Index encryption
takes 127.67 s, GPU preparation/upload 7.87 s, native owner/cache setup 8.10 ms,
and the Python LUT 0.243 ms. These excluded setup times are recorded as observed;
the native finisher's small table construction remains inside its online timing.
The run compares 352 exact compact ciphertexts across server variants, eight
against the CPU oracle, and 2,883,584 distance values against the plaintext result.

## Public GPU batch experiment

`search_many_compact` accepts up to 32 distinct queries for one immutable
key/index context and processes them in waves of one to eight. It does not
combine different clients' secret keys or perform any private-key arithmetic.
The joint trace circuit and level-4 kernels are unchanged algebraically.

The new implementation:

1. Allocates per-call scratch once, reusing it across query waves/result groups.
   Even a wave of one tests that amortization separately from parallel batching.
2. Transforms all queries in a wave and evaluates the tensor products together.
3. Optionally loads each encrypted-index strip into shared memory once for the
   query warps. The unshared tensor kernel remains as an explicit ablation.
4. Keeps butterfly input/output offsets separate per query at every stage, then
   treats their gadget polynomials as one batch of NTTs/key products. Existing
   tiled key kernels can reuse coefficients across queries in small trace stages.
5. Downloads the wave's results together. Exact CPU terminal reduction and
   Python output construction remain inside the timed public call.

Sharing strips follows the general memory-reuse technique described in
[NVIDIA's CUDA Best Practices Guide](https://docs.nvidia.com/cuda/cuda-c-best-practices-guide/index.html#shared-memory-in-matrix-multiplication-c-ab).
Whether it helps this encrypted workload is measured below; this is not a
claim to have invented shared-memory tiling or multi-query HE evaluation.

### 8,192 vectors: four requests ready together

| Evaluation strategy | Four-request batch | Requests/s | First result available | Coefficient scratch |
| --- | ---: | ---: | ---: | ---: |
| Separate sequential calls | 161.32 ms | 24.80 | **39.24 ms** | 832.5 MiB |
| Two host workers | 141.11 ms | 28.38 | 64.42 ms | 1,665 MiB |
| Four host workers | **126.48 ms** | **31.63** | 98.50 ms | 3,330 MiB |
| One native call, wave=1 | 141.61 ms | 28.25 | 141.61 ms | 832.5 MiB |
| Native wave=2 | 140.60 ms | 28.45 | 140.60 ms | 1,665 MiB |
| Native wave=2, shared index | 140.28 ms | 28.51 | 140.28 ms | 1,665 MiB |
| Native wave=4 | 140.09 ms | 28.55 | 140.09 ms | 3,330 MiB |
| Native wave=4, shared index | 138.22 ms | 28.94 | 138.22 ms | 3,330 MiB |

The best fused batch is 1.17x faster than sequential calls but takes **9.3%
longer than four existing workers**. Shared index reads improve its median by
only about 1.3% over the unshared wave of four, small beside the sample variation.
Wave=1 already captures much of the sequential-call improvement with one quarter
of the wave=4 coefficient scratch. Larger waves do not yield a compelling win.

Batch throughput here begins with expanded query ciphertexts available. It
includes Python/native conversions, GPU evaluation, native compaction and output
construction; query creation, seed expansion, wire framing and client work are
reported separately or excluded. It must not be compared directly with the
earlier 25.50 requests/s figure that included expansion and framing. Per-request
completion offsets include waiting behind the other ready requests. Native
batches return only once the whole call completes, including its smaller waves;
no early response streaming or arrival-time scheduler is implemented.

Why might fusion lose to threads? The single-query work already fills the GPU
in its large stages, while the threaded path can overlap host processing and
independent GPU streams. The new batched path still composes/reduces results on
the CPU and uses more live scratch for wider waves. These are explanations
suggested by the implementation and ablations, not hardware-counter findings.
We retain the negative result and the existing threaded option.

### 32,768 vectors: four requests ready together

The same 4 GiB experiment budget admits at most two simultaneous query workspaces
at this size. Four-worker/four-query-wave configurations need **6,658 MiB** of
coefficient scratch and are recorded as skipped, not as slower measurements.

| Evaluation strategy | Four-request batch | Requests/s | First result available | Coefficient scratch |
| --- | ---: | ---: | ---: | ---: |
| Separate sequential calls | 362.99 ms | 11.02 | **84.88 ms** | 1,664.5 MiB |
| Two host workers | **311.78 ms** | **12.83** | 145.53 ms | 3,329 MiB |
| One native call, wave=1 | 315.91 ms | 12.66 | 315.91 ms | **1,664.5 MiB** |
| Native wave=2 | 318.72 ms | 12.55 | 318.72 ms | 3,329 MiB |
| Native wave=2, shared index | 321.03 ms | 12.46 | 321.03 ms | 3,329 MiB |

The native wave of one is 1.15x faster than separate sequential calls. Its median
is only 1.3% slower than two workers while using half their coefficient scratch,
but all results wait until the call returns. Wider waves and explicit index
broadcast again add no convincing benefit; the shared wave of two is slightly
slower in this run. This points toward investigating reusable workspaces with
earlier response delivery, rather than assuming more parallel fusion will help.
It does not establish allocation as the only source of the wave=1 improvement.

Both full-size runs explicitly test the raw native 4 GiB refusal on the real
prepared index, outside the timed regions. All variants in a round receive the
same four fresh ciphertexts, with no query mixing or randomness reuse across
distinct requests. Timings include all output conversions rather than only
CUDA kernel events. Source hashes in both artifacts match the recorded commit;
binary hashes match the loaded compiled extensions.

## Bounds, correctness and security

The coefficient workspace is exactly `wave * (4 + 26*min(D,tiles)) * N * 8`
bytes. A per-call 4 GiB cap rejects oversized waves before CUDA allocation.
The index, keys, host allocations and runtime are additional; concurrent callers
still need a global scheduler/memory budget. Scratch belongs to one invocation,
and all host/device transfer buffers outlive its stream, including on exceptions.

The new tests compare complete ciphertexts against the independent CPU and old
single-query path, for full/tail groups, partial waves, repeated/distinct queries,
arbitrary canonical coefficients, N through 16,384, and concurrent calls. The
plaintext tests independently scatter known distances, exhaust every residue
for small odd moduli, test stable ties, composite t, k=0/64, empty/tail results,
native fallback above the table cap, and invalid unselected/padding coefficients.
Native finishing validates every packed ciphertext before its first private
multiplication, and retains owner locking, fork refusal and close semantics.

The full suite passes **598 tests with 10 expected skips**, with CUDA and the
independent SEAL oracle enabled. The skips are nine unavailable Paillier GPU
cases and one live Nitro integration; the existing deliberate fork test emits
Python's multithreaded-fork warning. Ruff and mypy pass for the package and
changed modules. **66 owner/seeded/result tests pass with ASan/UBSan** using the
documented PyCryptodome loader override and disabled Python-hosted leak checking.

The standalone CUDA oracle passes both packing circuits, all five old kernel
levels and the new batch kernels. Compute Sanitizer initially cannot find its
injection library (exit 13); supplying the installed directory still fails
before the first instrumented API call (exit 255). **GPU memory-sanitizer
coverage remains incomplete.** Arithmetic comparisons do not replace it.

Private GMP, LUT lookup and selection remain variable-time. Closing an owner is
not guaranteed secret erasure. None of these experiments authenticates a remote
response, changes the parameter-assurance status, or connects this BGV circuit
to the production verification/TEE path. Use synthetic trusted fixtures under
the existing research boundary; the ordinary BFV/Paillier clients are unchanged.

## Reproduction and next decisions

Build/test/benchmark commands and explicit APIs are in the
[lab README](../../experiments/bfv_search_lab/README.md#result-handling-and-distinct-query-gpu-batches).
The code is in [`results_bgv.py`](../../experiments/bfv_search_lab/results_bgv.py),
[`_owner/finish.h`](../../experiments/bfv_search_lab/_owner/finish.h),
[`_native/cuda_batch.cuh`](../../experiments/bfv_search_lab/_native/cuda_batch.cuh)
and [`bgv_finish_batch.py`](../../benchmarks/bgv_finish_batch.py).

The index uses the existing deterministic synthetic binary-data generator;
each measured request uses a fresh independently sampled binary plaintext query
and fresh cryptographic randomness. No plaintext queries, indices, ciphertexts,
seeds or secret keys are written into the measurement artifacts. Real embedding
distributions may change the small plaintext selection cost and still need tests.

Keep native client finishing as the promising local path, with reference and
lookup ablations intact. Keep GPU batching experimental: the measured wide
waves do not justify replacing the existing concurrent server. Before adding
more fusion, profile host conversion/compaction, allocation/synchronization and
GPU stages/memory traffic. Evaluate per-worker reusable workspaces with prompt
individual completion, and narrower RNS limbs, as separate ablations.
An independently reviewed private RNS/NTT backend remains a separate candidate
for the remaining owner arithmetic and side-channel work. Real transport,
authenticated execution and a second GPU are still needed for deployment or
paper-level performance claims.
