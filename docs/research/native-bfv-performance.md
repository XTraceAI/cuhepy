# BFV versus Paillier: repeated-search performance

Date: 2026-09-18. This comparison measures the current homemade BFV path,
standard Paillier and Paillier-Lookup on the same synthetic Hamming workload.
It separates client computation, server computation and communication volume.
At 8,192 vectors, BFV with the local signed-response protocol takes **20.74 s**
per warm search, versus **57.87 s** for standard CPU Paillier, **2.32 s** for
CPU Paillier-Lookup and **0.235 s** for a CUDA Lookup client with a CPU server.
BFV reduces communication and standard CPU client work, but increases server
computation substantially. It is not currently the fastest overall path.

These are elapsed API timings without network transfer or setup. The Nitro
case uses synthetic attestation evidence; it is not an AWS performance result.

## Measured search latency

Warm medians of three searches after one first search, in seconds. Prepare
and finish are client operations. The local total also includes the timed
top-three sort; individual columns are independent medians and need not sum
exactly to the median total. Both tables use the same parameters and input
generation described below.

### 1,024 vectors

| Configuration | Prepare (s) | Server (s) | Finish (s) | Local total (s) | Warm total range (s) |
| --- | ---: | ---: | ---: | ---: | ---: |
| Paillier CPU | 0.0103 | 0.0065 | 7.2706 | 7.2877 | 7.2781–7.3093 |
| Paillier-Lookup CPU | 0.0008 | 0.0061 | 0.2789 | 0.2864 | 0.2862–0.2877 |
| Paillier CUDA client / CPU server | 0.1564 | 0.0068 | 0.2684 | 0.4328 | 0.4316–0.4336 |
| Lookup CUDA client / CPU server | 0.0057 | 0.0062 | 0.0220 | 0.0341 | 0.0333–0.0361 |
| BFV N=8,192 | 0.1002 | 2.4577 | 0.0126 | 2.5720 | 2.5684–2.5729 |
| BFV N=16,384 | 0.2072 | 2.5566 | 0.0245 | 2.7882 | 2.7875–2.7900 |
| BFV N=16,384 + local Nitro protocol | 0.2126 | 2.5628 | 0.0285 | 2.8022 | 2.8018–2.8145 |

### 8,192 vectors

| Configuration | Prepare (s) | Server (s) | Finish (s) | Local total (s) | Warm total range (s) |
| --- | ---: | ---: | ---: | ---: | ---: |
| Paillier CPU | 0.0105 | 0.0528 | 57.8049 | 57.8735 | 57.7218–58.2141 |
| Paillier-Lookup CPU | 0.0008 | 0.0515 | 2.2671 | 2.3229 | 2.3105–2.3535 |
| Paillier CUDA client / CPU server | 0.1599 | 0.0511 | 1.9978 | 2.2128 | 2.2084–2.2132 |
| Lookup CUDA client / CPU server | 0.0049 | 0.0511 | 0.1755 | 0.2349 | 0.2346–0.2366 |
| BFV N=8,192 | 0.1024 | 19.7262 | 0.0142 | 19.8442 | 19.8011–19.8587 |
| BFV N=16,384 | 0.2096 | 20.4902 | 0.0262 | 20.7326 | 20.7285–20.7348 |
| BFV N=16,384 + local Nitro protocol | 0.2098 | 20.4832 | 0.0450 | 20.7409 | 20.5789–20.9699 |

At the larger count, the signed BFV path spends **0.257 s on the client** and
**20.483 s on the server**. It is 2.79× faster overall than standard CPU
Paillier, but 8.93× slower than CPU Lookup and 88.30× slower than the CUDA
Lookup client / CPU server combination. BFV's client total is also higher
than that CUDA Lookup client's 0.182 s: BFV query preparation costs about
0.210 s despite its fast response decoding. The hypothesis that smaller
responses reduce computation on **both** sides is not supported here.

The native review-profile and signed-protocol rows have similar total times.
They use independently generated keys/ciphertexts, so their small difference
is not an isolated protocol-overhead estimate. The retained `bfv_nitro.py`
harness supports an identical-ciphertext baseline for that separate question.

### Paillier server placement

The CUDA run also exercises the existing public GPU multiplication API,
batching all ciphertext chunks into one call. The hybrid run uses the same
CUDA client APIs with public GMP multiplication on the server. Each run has
fresh keys/index; these are configuration comparisons, not paired kernel
microbenchmarks.

| Vectors | CUDA client | CPU server (s) | GPU server (s) | Total with CPU server (s) | Total with GPU server (s) |
| --- | --- | ---: | ---: | ---: | ---: |
| 1,024 | Paillier | 0.0068 | 0.0115 | 0.4328 | 0.4335 |
| 1,024 | Lookup | 0.0062 | 0.0439 | 0.0341 | 0.0725 |
| 8,192 | Paillier | 0.0511 | 0.0916 | 2.2128 | 2.2007 |
| 8,192 | Lookup | 0.0511 | 0.3497 | 0.2349 | 0.5335 |

The GPU server path is slower for this operation through the current APIs.
These timers include representation conversions, allocations, copies,
synchronization and arithmetic; they do not isolate which component dominates.
For Lookup, the faster CPU server makes a substantial difference. Standard
CUDA Paillier's roughly 2.2-second totals are similar across the two runs;
the small total difference should not be interpreted as a reliable speedup.

## Workload and measurement boundaries

The harness is `benchmarks/bfv_latency.py`; the complete records are
`benchmarks/results/native_bfv_latency_cpu.json` and
`benchmarks/results/native_bfv_latency_gpu.json`, plus
`benchmarks/results/native_bfv_latency_hybrid.json`. It runs 1,024 and 8,192
vectors of 512 bits, using seed 1337 only for plaintext generation. Every
configuration receives the same plaintext vectors and query at each candidate
count. Keys and encryption randomness are fresh. Each configuration prepares
one encrypted index, then executes four queries with fresh randomized
encryption of the same plaintext query. No result is cached.

The first query is recorded separately; reported warm medians use the next
three queries on the reused index and evaluator. This is a small descriptive
experiment, with raw samples and ranges retained, not a tail-latency or
concurrent-throughput estimate. Cases run sequentially in the order recorded
in the JSON; no other benchmark or test is intentionally run concurrently.

Both logical roles run on the same AMD Ryzen 7 5800X/Linux host, using Python
3.12.3, gmpy2 2.3.0 and GMP 6.3.0. The optional native BFV extensions use the
existing C++ build. Source and binary hashes, compiler version, configuration,
wall-clock seconds and process CPU seconds are saved. The CPU run's sandboxed
GPU probe failed, but a host-level check confirmed an NVIDIA GeForce RTX 3080
with driver 580.173.02. Paillier CUDA measurements therefore run separately,
outside the sandbox and after the CPU experiment. BFV still uses only the CPU.
The CUDA rows use the existing in-tree extension binaries, whose hashes and
corresponding checkout source files are recorded. Both logical roles use the
same GPU sequentially; a GPU client timing requires a CUDA-capable **client**,
not merely a GPU on the remote server. Synchronous API timings include kernels,
host/device copies and Python/native conversions. Process CPU seconds count
host CPU work, not GPU device time.

| Measurement | Included operations |
| --- | --- |
| Client preparation | Encrypt the query and serialize it; the protocol case also authenticates/signs it |
| Server | Parse the received request, evaluate encrypted Hamming distances and serialize the response; the protocol case also checks authorization and signs the receipt |
| Client finish | Parse and decode distances; the protocol case verifies the receipt before private decoding and checks the result |
| Client total | Preparation + finish + the same stable top-three sort in every configuration |
| Local total | One continuous timer spanning the complete query through top-three selection, without network transfer |
| Setup | Key generation, private-context import, public-key export/import, index encryption and index serialization/import, recorded separately |

Raw cases roundtrip actual MessagePack packets before server evaluation and
client decoding. They use the previous matrix benchmark's common envelope,
little-endian integers and implicit candidate IDs. The Nitro case uses its
actual protocol packets and includes the receipt in response download bytes.
HTTP/TLS, RPC framing, document/content retrieval and real network transfer
are excluded. Setup is reused and excluded from per-query totals.

Every timed query is followed by an untimed comparison of **all** decrypted
distances and the top-three positions with a plaintext oracle. Inputs include
an exact match, its complement and a duplicate match; ties use input position.
Garbage collection is requested before each trial, never hidden between its
timed phases. The total is measured per trial before taking the median; it is
not constructed by adding independent phase medians.

## Configurations

| Label | Configuration |
| --- | --- |
| Paillier CPU | Existing client, 1,024-bit primes (approximately 2,048-bit public modulus), explicit CPU backend |
| Paillier-Lookup CPU | Existing optimized client, same prime length, `alpha_len=50`, explicit CPU backend |
| Paillier CUDA | Existing GPU client and public GPU multiplication, same prime length |
| Paillier-Lookup CUDA | Existing optimized GPU client and public GPU multiplication, same prime length and `alpha_len=50` |
| BFV N=8,192 | Earlier engineering parameters, public C++ `residue` evaluator, native terminal private decoder |
| BFV N=16,384 | Larger-ring review parameters, same evaluator and decoder |
| BFV local Nitro protocol | N=16,384 review parameters plus `BFVAttestedClient`/`BFVAttestedServer`, one evaluation and a signed response |

Both BFV parameter sets use a 180-bit product of NTT primes, plaintext modulus
65,537, decomposition width 30, error parameter 21 and 50-bit terminal response
compaction. The larger-ring configuration matches `bfv_review_policy()`.
These timings make **no equivalent-security claim** between the parameter
sets or schemes. The Lookup setting is the current client's benchmark/default
configuration, not a security recommendation.

The raw BFV rows use the current native decoder on honest locally generated
responses. They exclude the protection needed when responses come from an
untrusted server. The local Nitro row includes the current protocol's checks,
but substitutes a **synthetic test CA** using the existing test fixture. It
does not measure NSM, enclave isolation, vsock, an EC2 host or AWS networking.
Attestation is renewed before each trial outside query timers to respect the
unchanged session lease; its cost and bytes are recorded separately. This
benchmark does not provide production security approval.

## Why communication and computation differ

The current Paillier evaluator multiplies encrypted query/index values modulo
the public modulus squared. It returns one ciphertext per candidate for this
512-bit workload. Most of standard Paillier's per-query CPU cost is the
client's repeated decryption. The Lookup client uses its existing short
decryption exponent and encryption tables, so it is a necessary second
baseline for the optimized repository.

BFV moves the distance calculation to the evaluator. Polynomial arithmetic,
relinearization, rotations, key switching and packing let it return thousands
of distances in one ciphertext, but require considerably more server work
than Paillier's modular multiplications. The client decodes that packed result
quickly. This is a shift in where computation happens; fewer response bytes
do not imply a cheaper server calculation.

Both designs still return every candidate's distance for client-side top-three
selection. BFV packs those distances; it does not perform encrypted top-k or
return only the three winning distances. The native decoder makes decoding
cheap enough that BFV query encryption can become the larger client cost.

## Estimating network effects

Measured recurring payloads at 8,192 vectors, using warm median byte counts:

| Configuration | Query upload (bytes) | Response + receipt download (bytes) | Total (bytes) |
| --- | ---: | ---: | ---: |
| Paillier CPU | 544 | 4,226,848 | 4,227,392 |
| Paillier-Lookup CPU | 544 | 4,227,004 | 4,227,548 |
| Lookup CUDA client / CPU server | 544 | 4,226,923 | 4,227,467 |
| BFV N=8,192 | 368,754 | 102,496 | 471,250 |
| BFV N=16,384 + local Nitro protocol | 737,582 | 205,216 | 942,798 |

The signed BFV response, including its receipt, is about **20.6× smaller**
than Paillier's response, and query plus response is about **4.48× smaller**.
Fresh ciphertext randomness accounts for small Paillier size differences
between these runs and earlier reports.

For a single sequential request/response, an idealized transfer model is:

```text
latency = measured_local_total
        + 8 * query_bytes / upload_bits_per_second
        + 8 * (response_bytes + receipt_bytes) / download_bits_per_second
        + network_round_trip_time
```

This assumes full request/response buffering, constant effective throughput
and no overlap with computation. It excludes setup transfer, TLS/HTTP framing,
packet loss, congestion, service queuing and content retrieval. Real links can
be asymmetric: BFV's larger **query upload** matters on slow upstream links.
The model explains when I/O savings might outweigh extra server computation;
it is not a measured network result.

Applying that formula to each warm trial, then taking the median, gives the
following **modeled** totals. Upload and download have the same bandwidth;
RTT is set to zero. Mbps means 1,000,000 bits/second.

| Configuration, 8,192 vectors | 1 Mbps (s) | 10 Mbps (s) | 100 Mbps (s) |
| --- | ---: | ---: | ---: |
| Paillier CPU | 91.693 | 61.255 | 58.212 |
| Paillier-Lookup CPU | 36.143 | 5.705 | 2.661 |
| Lookup CUDA client / CPU server | 34.055 | 3.617 | 0.573 |
| BFV N=8,192 | 23.614 | 20.221 | 19.882 |
| BFV N=16,384 + local Nitro protocol | 28.283 | 21.495 | 20.816 |

With these measured computation times, the signed BFV path overtakes the
fastest Lookup configuration only below approximately **1.28 Mbps symmetric
bandwidth** in this model. At 100 Mbps, Lookup's approximately 0.338-second
transfer already exceeds its 0.235-second local computation: I/O can indeed
be its bottleneck. BFV reduces that transfer to about 0.075 seconds, but adds
roughly 20.5 seconds of computation, so the transfer saving does not compensate.
Different client/server hardware and asymmetric links change that threshold.

## One-time setup and resource observations

These are single setup measurements for the 8,192-vector cases, separate from
warm search latency. Setup total sums the recorded setup phases; lazy public
evaluator preparation remains in the first query. Initial upload is public
JSON keys plus the encrypted index in raw cases, or the complete registration
packet for the protocol case. It excludes attestation and transport framing.

| Configuration | Key generation (s) | Measured setup phases (s) | Initial upload (bytes) |
| --- | ---: | ---: | ---: |
| Paillier CPU | 0.816 | 86.890 | 4,229,356 |
| Paillier-Lookup CPU | 4.869 | 10.325 | 4,231,350 |
| Paillier CUDA client / CPU server | 0.006 | 2.379 | 4,229,549 |
| Lookup CUDA client / CPU server | 3.149 | 3.361 | 4,231,281 |
| BFV N=8,192 | 4.402 | 60.676 | 274,390,679 |
| BFV N=16,384 | 8.918 | 69.120 | 359,971,218 |
| BFV N=16,384 + local Nitro protocol | 8.899 | 74.024 | 360,011,385 |

Key generation is randomized and the CPU/CUDA clients use different existing
implementations, so these single setup samples are not stable key-generation
speed ratios. BFV's larger initial upload must be amortized over repeated
queries even where its recurring transfer savings help. Key/index rotation
or frequent index replacement changes that tradeoff.

Synthetic enrollment took about 8 ms per warm renewal and 2,135–2,136 bytes,
with real certificate/signature verification but no NSM or network latency.
The CPU process peaked at 2,822,716 KiB RSS (about 2.69 GiB); GPU and hybrid
processes peaked at 325,768 and 326,976 KiB host RSS. All recorded zero major
page faults and zero reported swaps. These are whole-process maxima across
sequential cases, including both logical roles, not per-role memory bounds
or GPU VRAM measurements.

## Validation and provenance

All **72 searches** across 18 cases matched every plaintext distance and the
same top three: **331,776 distance comparisons**. Additional 16-vector smoke
runs exercised all five CPU/protocol configurations and both CUDA clients.
Stored summaries were recomputed from raw samples, and source/binary hashes
were checked against the measured snapshots.

The CPU harness snapshot is commit `d8f81cc`; the CUDA-server snapshot is
`d53b353`. The subsequent harness extension adds the explicit GPU-client /
CPU-server switch. All three records include the SDK/native source and binary
hashes used for their run. The SDK implementations and arithmetic parameters
are the same across these benchmark additions.

## Reproduction

Install the repository's development dependencies and optional `bfv-nitro`
extra, and build both native BFV extensions using the existing Makefile:

```bash
make -C src/xtrace_sdk/x_vec/crypto/bfv_cpu_ext PYTHON="$(pwd)/.venv/bin/python"

# Optional small correctness/smoke run, with the same arithmetic parameters.
.venv/bin/python benchmarks/bfv_latency.py \
  --num-vectors 16 --repeats 2 --json-out /tmp/bfv-latency-smoke.json

# Recorded experiment: one first query plus three warm queries per case.
.venv/bin/python benchmarks/bfv_latency.py \
  --num-vectors 1024 8192 --repeats 4 \
  --json-out benchmarks/results/native_bfv_latency_cpu.json

# Require the existing Paillier CUDA extensions and host GPU access.
.venv/bin/python benchmarks/bfv_latency.py \
  --num-vectors 1024 8192 --repeats 4 \
  --variants paillier-gpu paillier-lookup-gpu \
  --json-out benchmarks/results/native_bfv_latency_gpu.json

# Same CUDA clients with public GMP multiplication on the server.
.venv/bin/python benchmarks/bfv_latency.py \
  --num-vectors 1024 8192 --repeats 4 \
  --variants paillier-gpu paillier-lookup-gpu --gpu-client-cpu-server \
  --json-out benchmarks/results/native_bfv_latency_hybrid.json
```

`--variants` accepts any subset of the seven labels shown by `--help`; the
default selects the five CPU/protocol configurations.
`--alpha-len` permits a separate Lookup parameter experiment; changing it
changes the comparison and must be reported. The harness writes completed
cases incrementally, then marks the JSON `complete` only after every case
finishes. Do not interpret an interrupted, incomplete report as a full run.
