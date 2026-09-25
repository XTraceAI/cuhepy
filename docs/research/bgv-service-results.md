# BGV service, arithmetic and algorithm experiments

This iteration follows the [finish/batch study](bgv-finish-batch-results.md) on
`research/bfv-search-lab`. All new arithmetic is homemade. SEAL is still only an
optional independent oracle. The package BFV/Paillier implementations and default
research backends are preserved.

The work covers the six proposed directions at different levels of maturity:

| Direction | Concrete result | Remaining boundary |
| --- | --- | --- |
| Profile the server | Nsight Systems capture, kernel/API breakdown and reproducible summary tool | Nsight Compute counters require permissions unavailable to this account |
| Persistent workspaces | Reusable single-request stream/buffers with native locking, close and fork guards | Application admission control still owns the global memory budget |
| Real transport | Bounded loopback TCP requests, parsing and finishing, with explicit application pacing | No AWS/WAN, TLS, congestion or TEE latency claim |
| Arithmetic | Private RNS/NTT backend and independent 30-bit GPU NTT experiment | Private CRT/export remain variable-time; narrow server conversion is not implemented |
| Algorithms | Encrypted feature-major delayed relinearization and exact plaintext filtering oracle | Query expansion and protected selective execution need further protocol work |
| Evidence/security | Differential tests, private sanitizers and working GPU memcheck/racecheck | Real embeddings, second GPU, parameter review and authenticated BGV execution remain open |

## Reproducibility and comparison scope

Ryzen 7 5800X, RTX 3080 10 GiB, driver 580.173.02; Python 3.12, GCC 12 and CUDA 12
compilation. BGV search measurements use N=16,384, t=1,031, the existing Q120 product
of two 60-bit primes, eta=21, 30-bit gadget digits and explicit 25-bit terminal
responses. Public metadata, samples, setup times and source/binary hashes are
recorded; keys, ciphertexts, entropy and plaintext datasets are not saved.
The six paired workspace/owner/transport artifacts were run against commit
`07c99f0`; the eight-way comparison is at `36afcca` and the hybrid follow-up
at `0120a97`. Source and binary hashes in each artifact pin its actual
implementation. The earlier
diagnostic capture includes its own metadata and has the same core CUDA
workspace code as `07c99f0`.

Each paired BGV workspace/owner/transport workload has one key/index set and
fresh owner query randomness.
Variant order is shuffled and one warmup is excluded. Separate workload sizes
generate separate keys. No profiled/sanitized timings are mixed into ordinary
benchmarks. The desktop also uses this GPU; these are workstation measurements,
not isolated datacenter or production service estimates.

The query remains **245,866 bytes**. Responses remain **102,488 bytes** at 8,192
vectors and **204,895 bytes** at 32,768 vectors. None of the winning arithmetic
or allocation experiments changes the cryptographic parameters or these bytes.

## What the trace actually says

The [Nsight summary](../../benchmarks/results/bgv_nsight_workspace_8192.json)
contains three calls of each variant, with setup/private work outside capture.
The installed Systems 2022.4 captures successfully; its automatic importer
lookup fails, but invoking the installed `QdstrmImporter` directly works.

| Diagnostic mean per request | Transient workspace | Persistent workspace |
| --- | ---: | ---: |
| Entire Python/public-evaluator NVTX range | 42.41 ms | 34.97 ms |
| Sum of GPU kernel durations | 19.90 ms | 20.58 ms |
| Of which NTT kernels | 13.53 ms | 14.19 ms |
| Actual GPU copies, both directions | 0.044 ms | 0.043 ms |

NTTs account for roughly 68–69% of GPU kernel time in this capture. Transient
calls make six allocations and six frees per request; the six `cudaFree` calls
average approximately **7.56 ms combined**. Those calls disappear from the
persistent request path. Kernel work is algebraically identical, and its measured
time does not improve with the workspace change.

The CPU API trace charges substantial waiting time to `cudaMemcpyAsync` with
pageable host output. That is **not** evidence of a slow PCIe copy: the actual
device-copy intervals are about 0.04 ms per request. CPU and GPU intervals
overlap; adding them double-counts work. Remaining Python/GMP conversion and CPU
compaction are still candidates after this allocation improvement.

Nsight Compute exits with `ERR_NVGPUCTRPERM`. Running only the profiler through
`sudo -n` also fails because a password is required. We did not change the
machine-wide counter policy. No occupancy, bandwidth-saturation or hardware
instruction-throughput conclusion is claimed from this trace.

## Explicit reusable GPU workspaces

`NativeServer.prepare_workspace(index)` returns a lease bound to that immutable
index and server. Its stream, host transfer storage and device scratch survive
individual searches. A native mutex serializes use of one lease; distinct leases
may overlap. A failed CUDA operation retires the workspace, synchronizing before
its buffers are freed. Close waits for native use, is idempotent, and subsequent
searches fail. Fork use is refused before touching inherited locks or CUDA.

The original per-call allocation path remains available. Benchmark request
completion uses individual futures, so results are observable before the whole
four-request group finishes. There is no cryptographic query combination.

| 8,192 vectors, four ready requests | Group median | Requests/s | First result median |
| --- | ---: | ---: | ---: |
| Transient, one worker | 173.18 ms | 23.10 | 49.23 ms |
| Persistent, one worker | 133.97 ms | 29.86 | 34.79 ms |
| Transient, two workers | 151.22 ms | 26.45 | 74.80 ms |
| Persistent, two workers | 113.00 ms | 35.40 | 53.94 ms |
| Transient, four workers | 130.21 ms | 30.72 | 103.53 ms |
| Persistent, four workers | 104.91 ms | 38.13 | 94.06 ms |

The four-worker comparison improves throughput by **24.1%**; its group takes
19.4% less time. One persistent worker uses 832.5 MiB coefficient scratch; four
use 3,330 MiB. First-response improvement is smaller with four concurrent workers
because they contend for GPU and host resources.

| 32,768 vectors, four ready requests | Group median | Requests/s | First result median |
| --- | ---: | ---: | ---: |
| Transient, one worker | 380.74 ms | 10.51 | 97.54 ms |
| Persistent, one worker | 322.98 ms | 12.39 | 86.71 ms |
| Transient, two workers | 319.88 ms | 12.50 | 155.01 ms |
| Persistent, two workers | 284.63 ms | 14.05 | 139.67 ms |

Two-worker throughput improves **12.4%**, using 3,329 MiB coefficient scratch.
Four workers are skipped at the experiment's 4 GiB budget. Index, keys, runtime,
host storage and the desktop's allocations are additional to these scratch counts.

The [8,192](../../benchmarks/results/bgv_workspace_8192.json) and
[32,768](../../benchmarks/results/bgv_workspace_32768.json) artifacts contain ten
measured groups per variant. Their completion samples describe **four requests
already ready together**, not a production arrival/queueing distribution.
Nearest-rank sample p95 values are recorded but are not a reliable deployment
tail-latency estimate. Workspace creation is excluded setup; scopes include
Python/native conversion, evaluation and CPU compaction, but exclude query
creation/expansion, framing, network and client finishing.

## Separate private RNS/NTT owner

`OwnerClient(..., native=True, rns=True)` opts into `_owner/rns_product.h`.
For Q equal to the product of the generated transform primes, multiplication
runs directly modulo Q. For a general modulus (including the terminal prime),
the auxiliary product M satisfies **M > 2*N*(q-1)**, enough to reconstruct the
signed integer product of a canonical public polynomial and a ternary secret.
The centered integer is then reduced modulo q. Public context caching is bounded
to 16 moduli. Secret spectra are cached separately from public server state.

The NTT butterflies reuse our existing private fixed-schedule implementation;
public-spectrum multipliers operate on secret spectra. GMP CRT, export,
plaintext decoding and selection still prevent an end-to-end constant-time
claim. Close releases references without a secure-erasure guarantee.

Twenty paired rounds at each workload size give:

| Vectors | Client phase | Native GMP | Native RNS/NTT |
| ---: | --- | ---: | ---: |
| 8,192 | Fresh seeded query encryption | 17.08 ms | 11.83 ms |
| 8,192 | Decrypt, decode and stable top-3 | 11.07 ms | 9.19 ms |
| 32,768 | Fresh seeded query encryption | 16.67 ms | 12.17 ms |
| 32,768 | Decrypt, decode and stable top-3 | 21.82 ms | 18.07 ms |

At 8,192 vectors that is **30.7% less query time** and **17.0% less finishing
time**; at 32,768 the reductions are 27.0% and 17.2%. Fresh OS
entropy, encoding at the native boundary and output conversion are included.
Every encryption is independently checked with the GMP owner, and both finish
paths return all exact distances and the same stable top-3. Setup is separate.
See the [8,192](../../benchmarks/results/bgv_owner_rns_8192.json) and
[32,768](../../benchmarks/results/bgv_owner_rns_32768.json) raw measurements.

## TCP and communication

The trusted loopback harness measures socket framing, server seed expansion,
GPU evaluation, CPU compaction, response packing, client parsing and finishing.
It adds measured query encoding/fresh encryption to that wall interval. Both
TCP frame headers add eight bytes per request/response exchange.

Using persistent scratch and the opt-in RNS owner:

| Configured application pacing | 8,192 vectors, median | 32,768 vectors, median |
| --- | ---: | ---: |
| Ordinary loopback, no added delay | 66.54 ms | 127.19 ms |
| 100 Mbps each direction, 20 ms added round trip | 114.35 ms | 182.80 ms |
| 10 Mbps upload / 100 Mbps download, 40 ms round trip | 311.77 ms | 380.01 ms |
| 10 Mbps each direction, 40 ms round trip | 385.55 ms | 526.83 ms |

The [8,192](../../benchmarks/results/bgv_transport_8192.json) and
[32,768](../../benchmarks/results/bgv_transport_32768.json) transport measurements
include all ten trials and phase timings. These are real TCP transfers with
**application pacing**, not a model of TCP congestion/loss and not measured
AWS/WAN conditions. Timers on the same host also do not represent independent
client/server CPU resources. Setup, attestation, TLS and document retrieval are
excluded. Unlike older local sums, these numbers include response parsing and
transport framing, so they are not a direct paired comparison with those sums.

For each fresh query, an **excluded local evaluation** pins the expected complete
ciphertext. The received bytes must match it before any private decryption, even
with Python assertions disabled. No acceptance/rejection acknowledgement is
sent back. This is a safe benchmark fixture, not an efficient remote verification
protocol; charging its excluded evaluator would duplicate server work.

The result reinforces the original communication objective: upload is 70.6% of
traffic at 8,192 vectors. Smaller query representations deserve attention once
their encryption and expansion costs are made explicit.

## Fresh BFV and Paillier comparison

The [eight-way comparison](../../benchmarks/results/bgv_scheme_comparison_8192.json)
uses the same 8,192 x 512 corpus and fresh plaintext queries across variants,
with fresh encryption randomness for each invocation. One warmup is excluded,
five measured rounds shuffle variant order, and every distance and stable top-3
is checked. These are complete **local** request timings, including encoding,
encryption, query/response framing and parsing, server evaluation, decryption,
decoding and selection. Network, setup, attestation and content retrieval are
excluded. Phase medians need not sum exactly to the median total.

| Implementation | Client prepare | Server, including framing | Client finish | Local total |
| --- | ---: | ---: | ---: | ---: |
| Paillier CPU | 10.39 ms | 49.92 ms | 56,679.51 ms | 56,739.42 ms |
| Paillier CUDA | 150.82 ms | 88.64 ms | 1,960.09 ms | 2,219.03 ms |
| Paillier lookup CPU | 0.83 ms | 49.88 ms | 8,825.98 ms | 8,876.66 ms |
| Paillier lookup CUDA | 4.26 ms | 347.18 ms | 305.55 ms | 667.00 ms |
| Paillier lookup hybrid (separate follow-up) | 3.75 ms | 50.93 ms | 310.04 ms | 364.64 ms |
| Package BFV CPU | 199.05 ms | 19,816.35 ms | 28.85 ms | 20,043.72 ms |
| Package BFV prepared CUDA | 199.79 ms | 176.18 ms | 29.01 ms | 402.49 ms |
| Research BGV CPU, RNS owner | 11.15 ms | 2,473.12 ms | 11.13 ms | 2,495.42 ms |
| Research BGV workspace CUDA, RNS owner | 11.45 ms | 38.85 ms | 11.10 ms | **61.53 ms** |

Paillier CUDA uses a GPU at the client too; BFV/BGV use CPU clients. The lookup
server's existing public GPU API charges integer conversions, allocation and
copies every call, and its measured server time exceeds GMP multiplication here.
This is an API measurement, not an isolated GPU-kernel comparison or a claim
about the best possible Paillier implementation. The
[hybrid follow-up](../../benchmarks/results/bgv_paillier_hybrid_8192.json) therefore
also measures the existing GPU client with a GMP server. It uses the same corpus,
dimensions and sampling distribution, with separate keys and later query
plaintexts; its five-round measurement is not paired with the other eight cases.
For these configurations, BGV CUDA completes local requests **6.54x faster than
package BFV CUDA**, **10.84x faster than Paillier lookup CUDA**, and **5.93x faster
than the measured lookup hybrid**.

The selected configurations differ. Paillier has a 2,047–2,048-bit actual modulus;
lookup requests `alpha_len=280` (actual secret exponent 279–280 bits), preserving
the current minimum-length policy. BFV uses N=16,384, Q180, t=65,537 and a 50-bit
response. BGV uses N=16,384, Q120, t=1,031 and a 25-bit response. **Q120/Q180 are
coefficient-modulus sizes, not security-bit estimates.** This compares concrete
repository configurations, without establishing equivalent security, production
readiness or an intrinsic ranking of the encryption schemes. SEAL is not involved
in these performance paths.

| Configuration | Query bytes | Response bytes | Query + response |
| --- | ---: | ---: | ---: |
| Paillier variants | 544 | About 4,226,950 | About 4,227,500 |
| Package BFV | 737,394 | 204,900 | 942,294 |
| Research BGV | 245,866 | 102,488 | 348,354 |

Paillier packet sizes vary slightly with integer encodings; each sample is saved.
BGV sends about **41.2x fewer response bytes** and **12.1x fewer query-plus-response
bytes** than these Paillier paths. Against this BFV configuration those ratios
are **2.0x** and **2.70x**. These are framing-inclusive application payloads, not
TCP/TLS wire captures. They exclude encrypted index and key setup traffic.

## Algorithm and narrow-limb decisions

The 30-bit CUDA NTT uses four primes and 32-bit storage/quotients, compared to
two 60-bit primes and 64-bit storage. Both bases total roughly 120 bits and have
the same data-buffer byte count, but **different Q**. Forward coefficients are
checked against our CPU transform, and the inverse returns the original input.
Only resident NTT round trips are timed, not a full BGV request. Twenty measured
round trips per base, at degree 16,384 with 1,024 polynomials, give:

| Variant order | Two 60-bit primes | Four 30-bit primes |
| --- | ---: | ---: |
| Wide then narrow | 5.14 ms | 6.99 ms |
| Narrow then wide | 5.22 ms | 7.03 ms |

The 30-bit prototype is about **35–36% slower** in both orders. Its cheaper
operations do not offset the extra transforms in this implementation. This
does not justify a full narrow-limb server rewrite on this GPU. The
[artifact](../../benchmarks/results/bgv_narrow_ntt.json) preserves both orders,
correctness checks, public moduli and source/binary hashes.

The feature-major implementation stores each signed feature across N rows and
encrypts each query feature as a constant polynomial. Summing three-component
products before relinearization changes **dimension switches per output** into
**one switch per output**, with no rotations. Both schedules decrypt correctly,
including tails and terminal reduction. Their ciphertexts need not match because
key-switch noise is introduced differently.

At 8,192 x 512 and N=16,384, its simple query format needs **512 ciphertexts**:
125,829,120 seeded coefficient bytes before framing, compared to 245,760 for the
current single-query polynomial. The encrypted reference makes the operation
saving real, but useful query expansion is needed to make this a communication
competitor. This is a layout experiment, not a claim that delayed relinearization
itself is novel.

The [encrypted CPU/GMP reference measurements](../../benchmarks/results/bgv_algorithm_portfolio.json)
use N=256 and 513 rows, hence three output ciphertexts. Five measured trials
after one warmup give:

| Features | Eager switches | Delayed switches | Eager median | Delayed median |
| ---: | ---: | ---: | ---: | ---: |
| 8 | 24 | 3 | 62.50 ms | 29.07 ms |
| 32 | 96 | 3 | 261.07 ms | 106.55 ms |

These **2.15x and 2.45x** reference evaluator improvements establish that the
implemented schedule saves work. They are not full-size GPU or complete-request
speedups, and the tiny ring is a correctness/performance fixture without a
deployment security claim.

The filter oracle uses the exact lower bound
`sum_blocks(abs(weight(query_block) - weight(row_block))) <= Hamming(query,row)`.
Candidates are ordered by `(lower_bound,index)` and skipped only when that pair
is worse than the kth exact `(distance,index)`. Exhaustive small binary domains
and randomized tails/duplicates verify stable exact winners. The oracle exposes
weights and accesses and is **not** an encrypted filtering protocol.

The 8,192 x 512 plaintext study records exact distance evaluations:

| Block width | Uniform random rows | Synthetic clustered rows | Block-weight comparisons |
| ---: | ---: | ---: | ---: |
| 16 | 8,192 | 15 | 262,144 |
| 32 | 8,192 | 39 | 131,072 |
| 64 | 8,192 | 144 | 65,536 |
| 128 | 8,192 | 319 | 32,768 |

The clustered fixture flips each bit with probability 3% around 16 centers;
the query is exactly one center, making this an optimistic near-duplicate case.
Uniform data gets no pruning. The comparison counts are charged for both
datasets, but encrypted comparisons, sorting, authentication and protected
access costs are not implemented or timed. Real embeddings and a declared
access-leakage policy are needed before turning this into a private-search
performance claim.

Encrypted top-3 also needs an output-representation cost model. At 8,192 rows,
the current result already occupies one RLWE ciphertext. Packing just three
winners into another ciphertext with the same N, component count and terminal
modulus saves essentially **no coefficient bytes**. At 32,768 rows, two such
ciphertexts could become one. Larger savings need a different ciphertext format,
ring conversion or a separately declared trusted execution model; plaintext
winner count alone does not determine encrypted packet size.

## Validation and remaining security work

The new private arithmetic is compared against independent Python/GMP products,
identical-entropy encryption, all-distance decoding and stable top-k. Tests
cover arbitrary/noncanonical coefficients, direct and auxiliary CRT contexts,
tiny/large degrees, tails, repeated and concurrent calls, close and fork guards.
The transport parser bounds frame/array/bin sizes and pins shape, modulus, key
context and locally computed bounds. It never accepts correctness metadata
from a remote response as permission to decrypt.

**80 private owner/result tests pass under ASan/UBSan**, with the documented
PyCryptodome deepbind override and Python-hosted leak checking disabled.
The final full suite passes **635 tests with one skip**, with both Paillier GPU
extensions, required BGV CUDA and the independent SEAL oracle enabled. The skip
is the live Nitro integration; the intentional multithreaded fork regression emits
Python's expected deprecation warning. Package Ruff/mypy and explicit checks of
the changed research modules pass.
The [full test log](../../benchmarks/results/bgv_service_tests.txt) records the
run; the additional Paillier CUDA build closes the nine previously unavailable
GPU cases without changing package source.
Compute Sanitizer **12.9.79 memcheck reports zero errors**, and **racecheck
reports zero hazards**, on the standalone public evaluator covering all five
kernel levels, both circuits, distinct-query batches and persistent workspaces.
The new narrow-limb NTT also passes memcheck. Sanitizer validation is finite
coverage, not a memory-safety proof or cryptographic assurance.
The [memcheck](../../benchmarks/results/bgv_service_memcheck.txt),
[racecheck](../../benchmarks/results/bgv_service_racecheck.txt) and
[narrow NTT](../../benchmarks/results/bgv_narrow_ntt_memcheck.txt) logs contain
the actual tool summaries. [Validation metadata](../../benchmarks/results/bgv_service_validation.json)
records the tool version and source/binary fingerprints.

The official sanitizer archive SHA-256 is
`e23aad21132ff58b92a22aad372a7048793400b79c625665d325d4ecec6979bf`, checked against
[NVIDIA's CUDA 12.9.1 manifest](https://developer.download.nvidia.com/compute/cuda/redist/redistrib_12.9.1.json).
The tool was unpacked under `/tmp`; no installed toolkit/driver was replaced.

Before remote deployment, this BGV circuit needs a reviewed authenticity gate
that binds the **scheme/parameter context, index digest and epoch, query digest
and nonce, layout/circuit version, terminal modulus and complete response**.
That verification must complete before private arithmetic or any
decryption-dependent feedback. A Nitro signer must not approve unchecked host
GPU output. Existing BFV receipts are not valid BGV receipts. Private side
channels, erasure, parameter assurance and the trusted execution boundary remain
open; arithmetic equivalence and public no-wrap bounds do not resolve them.

Next evidence to collect: a supplied real binary-embedding dataset, additional
dimensions/counts, a second GPU, actual AWS transport and reviewed authentication
cost. The fresh Paillier/BFV comparison above replaces reliance on historical
timings for this workload; a same-circuit SEAL performance comparison and
independent parameter review are still needed.

## Code and reproduction

The public API is in [`native_bgv.py`](../../experiments/bfv_search_lab/native_bgv.py),
with reusable allocation ownership in
[`cuda_trace.cuh`](../../experiments/bfv_search_lab/_native/cuda_trace.cuh).
The private implementation is in
[`rns_product.h`](../../experiments/bfv_search_lab/_owner/rns_product.h), selected
through [`owner_bgv.py`](../../experiments/bfv_search_lab/owner_bgv.py).
The algorithm references are
[`feature_major_bgv.py`](../../experiments/bfv_search_lab/feature_major_bgv.py),
[`filter_oracle.py`](../../experiments/bfv_search_lab/filter_oracle.py), and
[`narrow_ntt.cu`](../../experiments/bfv_search_lab/_native/narrow_ntt.cu).

The [lab README](../../experiments/bfv_search_lab/README.md#persistent-workspaces-private-rns-and-transport-follow-up)
contains build, profiling and benchmark commands. Run performance trials alone,
after correctness checks and without a profiler or sanitizer attached. The
Paillier CUDA comparison builds use `KEY_BITS=1024`, `ALPHA_LEN=280` for lookup,
`SMS=86`, `CUDA_PATH=/usr` and `NVCC='nvcc -ccbin g++-12'`; CGBN and pybind11
headers come from the existing sibling `CppCrypto/include` directory. These
optional extensions were built locally; no binaries or vendor sources are added
to the branch.
