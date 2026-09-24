# First search-lab experiments

2026-09-24, local branch `research/bfv-search-lab`. This is an implementation
and measurement notebook for the [research plan](bfv-search-experiment-plan.md).
The accepted Paillier/BFV clients remain the baseline. All new application
entry points are in the [experiment directory](../../experiments/bfv_search_lab).

## Scope and methodology

The CUDA study uses 8,192 vectors of 512 bits, ring degree 16,384, plaintext
modulus 65,537, a product of three 60-bit ciphertext primes, decomposition width
30, error eta 21, and 50-bit terminal responses. The machine is the local
Ryzen 7 5800X / RTX 3080 with CUDA 12.0 and GCC 12. All variants use the same
fresh key set and encrypted index. Seeded synthetic vectors include
intentional exact-match, complement and tie fixtures; cryptographic randomness
always comes from the encryption samplers, never the fixture seed.

Each variant gets one warmup and ten paired, shuffled measured rounds with
fresh ciphertexts and a changed query in each round. Every distance and stable
top-three result is checked outside timing. The accepted CUDA response is
also compared coefficient-for-coefficient with the CPU residue evaluator.
No network, attestation, content retrieval, concurrency load or index setup is
included in online time. Setup and actual packet sizes are recorded separately.
Phase medians need not add to the median of total time.

Artifacts contain public parameters, samples, timings, sizes and source/binary
hashes, without keys, plaintext datasets or ciphertext contents. They were
generated in a working tree based on the recorded Git revision: source hashes
identify the measured code. The benchmark programs are independent, and
an earlier snapshot of an unrelated lab source is not a dependency of a run.

## Complete-search measurements

Fresh run of committed code at `c9c44f9`; ten paired rounds. Raw data:
[CUDA/query comparison](../../benchmarks/results/bfv_search_lab_8192.json).
Every recorded source and release-binary hash matched the checkout after the run.

| Variant | GPU evaluation (ms) | Online local search (ms) | Including refill (ms) | Query + response bytes |
| --- | ---: | ---: | ---: | ---: |
| Accepted CUDA baseline | 171.50 | 397.05 | 397.05 | 942,294 |
| Native query products | 171.56 | 366.16 | 366.16 | 942,248 |
| Native products + encoder | 171.56 | 326.50 | 326.50 | 942,248 |
| Seeded query + native encoder | 171.68 | 273.46 | 273.46 | 573,637 |
| Seeded + native + 2 partials | 159.68 | 261.47 | 261.47 | 573,677 |
| Same, with one-use pool | 159.51 | 206.25 | 261.71 | 573,677 |
| Public-key query + native + 2 partials + pool | 159.74 | 201.05 | 315.30 | 942,288 |
| Seeded + native + 4 partials | 151.34 | 277.31 | 277.31 | 778,547 |
| Seeded + native + 8 partials | 146.25 | 320.79 | 320.79 | 1,188,287 |

The combined fresh-query variant takes **261.47 ms versus 397.05 ms**:
**34.1% less latency (1.52× faster)**, with **39.1% less recurring traffic**.
The seeded pool variant takes **206.25 ms online**, with a separately measured
**55.51 ms median refill**; median total including refill is **261.71 ms**.
The fastest purely local pooled variant uses public-key queries at **201.05 ms**,
but its query is larger and its refill costs more.

| Recurring phase | Accepted baseline (ms) | Seeded/native/2-partial fresh query (ms) | Same with pool (ms) |
| --- | ---: | ---: | ---: |
| Client query preparation | 197.45 | 63.50 | 8.23 |
| Server query expansion/parse | 0.35 | 10.28 | 10.33 |
| GPU evaluation | 171.50 | 159.68 | 159.51 |
| Client response decoding | 25.06 | 25.35 | 25.31 |
| Client top-three selection | 2.28 | 2.33 | 2.35 |

The accepted upload is **737,394 bytes** and download **204,900 bytes**.
The combined seeded/partial variant uploads **368,737 bytes** and downloads
**204,940 bytes**. Thus the traffic reduction comes from the query, while
partial reduction saves GPU work at essentially the same download size.

One-time setup in this run: key generation **8.43 s**, index encryption
**52.91 s**, and encrypted index packet **188,765,726 bytes**. Each resident
index snapshot is **192 MiB**; GPU plan tables are **174,328,848 bytes**.
The accepted plan took **1.13 s** to prepare and **205 ms** to upload its index.
The additional native query factories took about **2.3 ms** each.

The main improvement combines several independently switchable changes:

1. **Native SIMD encoding** reuses our existing C++ negacyclic transform. Tests
   compare the entire encoded polynomial against Python, including the full
   ring size, extreme coefficients, empty/padded slots and malformed buffers.
2. **Seeded symmetric queries** transmit one ciphertext polynomial and a fresh
   32-byte public seed. The server reconstructs the uniform second polynomial
   from domain-separated SHAKE256 with unbiased rejection sampling. Secret and
   error randomness are independent of that stream. Batching reads of the
   same stream avoids a Python/C transition per coefficient.
3. **One-use preprocessing** prepares an encryption of zero on the owner. The
   online query adds its encoded plaintext and consumes the token, including
   on encoding failure. Refill work is charged in the second total column.
4. **Partial reduction** retains two coordinate-block sums per candidate. The
   owner adds those after decryption, removing one rotation stage per tile.

Seeded encryption and precomputed encryptions of zero are established ideas,
not claimed inventions. SEAL also uses independently sampled noise with a
reconstructible uniform component; see its
[RLWE implementation](https://github.com/microsoft/SEAL/blob/main/native/src/seal/util/rlwe.cpp).
Our experiment does not invoke SEAL or make its formats interoperable.

### Why two partial sums help here

With dimension padding D, C partials, and L=N/(2D) lanes per SIMD row, reduction
stops after log2(D/C) stages. Tile packing uses D/C tiles per response; the
response capacity is N/C candidates. The input index and query layout are
unchanged. At 8,192 candidates and N=16,384, C=2 still fits **one** response.
Its only payload increase is the 40-byte experimental layout envelope.

There are 256 input tiles. C=1 performs 2,815 key switches when counting
relinearization, dimension reduction and packing. C=2 performs 2,559, saving
256 switches (9.1%). C=4 and C=8 remove more GPU work but require two and four
responses. Their increased decoding and transfer costs are recorded as useful
negative results. More partials are not a universal improvement: above N/2
candidates, C=2 can require an extra response where C=1 still fits one.

The compiled factory explicitly selects this layout. A C=1 search uses the
accepted private packed decoder; the partial decoder precomputes public offsets
and maximum block distances. Neither a decoder range check nor a layout tag is
authentication of a malicious evaluator.

### Preprocessing accounting and payload categories

**Online** starts at query preparation and ends after response decoding and
top-three selection. **Including refill** also charges the one-use token
generated for that request. A pool moves work away from request arrival; it
does not erase that work or establish sustained throughput. The current
benchmark refills synchronously before each measured online interval, with no
overlap. Index construction and native/GPU plan preparation are separate setup.

**Query bytes** are the client upload, **response bytes** the server download;
their sum is recurring application traffic. **Encrypted index bytes** are
one-time database upload/storage, and GPU-resident bytes use a different internal
representation. This experiment changes query and response behavior; it does
not shrink the existing public keys or index. All CUDA variants share the same
index plaintext/ciphertext content but retain separate GPU snapshots per layout.
Factory and plan timings are sequential: later plans reuse prepared public
CPU keys and must not be interpreted as independent cold-start comparisons.

## Network-dependent choice

Assuming the same upload/download bandwidth and a 20 ms RTT:

| Bandwidth | Best eligible fresh-query plan | Modeled latency (ms) | Best eligible pooled plan | Modeled online latency (ms) |
| --- | --- | ---: | --- | ---: |
| 10 Mbit/s | Seeded + 2 partials | 740.42 | Seeded + 2 partials + pool | 685.19 |
| 100 Mbit/s | Seeded + 2 partials | 327.37 | Seeded + 2 partials + pool | 272.15 |
| 1,000 Mbit/s | Seeded + 2 partials | 286.06 | Public-key + 2 partials + pool | 228.59 |

The [planner](../../experiments/bfv_search_lab/planner.py) adds upload time,
download time and one RTT to the measured local samples. These numbers are
**analytical projections, not measurements over a real connection**. They omit
TLS, attestation, congestion and overlap. Explicit capability flags enable
symmetric owner queries, one-use pools and disclosure of partial scores. The
planner selects only among variants measured for this workload; it does not
choose security parameters or extrapolate to another database size.

## Beyond BFV: coefficient-packed, depth-one RLWE

The [BGV-style reference](../../experiments/bfv_search_lab/shallow_bgv.py) uses
the phase convention `c0 + c1*s = m + t*e (mod Q)`. A ciphertext product can
therefore be computed directly modulo Q, avoiding BFV's wide integer product
followed by scale-and-round. It keeps three ciphertext components and supplies
no relinearization, rotations, modulus chain or bootstrapping. It is a restricted
depth-one experiment, **not a complete BGV implementation**. The scheme family
is described in the [BGV paper](https://eprint.iacr.org/2011/277).

Convert each bit b to 1−2b. Put query coefficients in reverse order within a
D-coefficient block, and index vectors in forward contiguous blocks. The
coefficient at rD+D−1 of their negacyclic product equals the signed dot product
for candidate r. Its Hamming distance is `(d−dot)/2`. The encrypted test suite
also checks all polynomial coefficients against an independent quadratic
schoolbook oracle, plus wraparound, incomplete tiles, complements and ties.

This packing requires t>2d to decode signed correlations, but does **not**
require the SIMD constraint t=1 mod 2N. The reference compares t=65,537/Q=180
bits with t=1,031/Q=90 bits. Neither comparison asserts an equivalent reviewed
security level. Fresh keys and a freshly encrypted index are mandatory.

For ternary s,u and errors bounded by eta, a fresh phase has the conservative
coefficient bound

`B = floor(t/2) + t*eta*(2N+1)`.

One negacyclic product has bound `N*B^2`. Key generation rejects parameters
unless `2*N*B^2 < Q`, which prevents wraparound of the underlying integer phase
for this depth-one computation. This is a **correctness bound**, not an RLWE
security estimate, authenticity guarantee, or permission to accept untrusted
decryption feedback. The implementation uses variable-time Python/GMP.

The three-product variant forms the middle tensor component as
`(a0+a1)(b0+b1) − a0*b0 − a1*b1 (mod Q)`. Tests require exactly identical
ciphertext coefficients to the four-product version. This is the standard
three-product multiplication identity; its value here is a measured ablation.

Five paired rounds plus warmup, **8,192 vectors × 512 bits, N=16,384**.
Both CPU schemes use the same prime Q for the matched 180-bit rows; this
differs from the CUDA experiment’s product-modulus representation. Raw data:
[coefficient comparison](../../benchmarks/results/coefficient_search_lab_8192.json).
The exact measured sources are preserved at commit `3612c64` (hashes verified);
a later benchmark refactor binds synchronous timing-call arguments explicitly.

| CPU reference variant | Server (s) | Complete local search (s) | Response bytes |
| --- | ---: | ---: | ---: |
| BFV, t=65,537, Q=180 bits | 36.676 | 62.785 | 283,119,715 |
| BFV, same input Q, terminal 50-bit response | 47.631 | 63.161 | 78,647,379 |
| BGV-style, matched t/Q, four products | 24.509 | 43.621 | 283,119,715 |
| BGV-style, matched t/Q, three products | 20.104 | 38.225 | 283,119,715 |
| BGV-style, t=1,031, Q=90 bits, three products | 15.929 | 30.942 | 141,561,942 |

The matched three-product BGV reference is **1.82× faster in server arithmetic**
than coefficient-packed BFV in this run, but still downloads about **270 MiB**.
Even the compacted BFV coefficient result is roughly **75 MiB**, versus about
**0.195 MiB** for the accepted SIMD CUDA response. Removing rotations without
repacking is a loss for the original communication objective.

These are CPU Python/GMP comparisons, using the same coefficient packing for
both schemes; they are not comparisons between equally optimized GPU backends.
The terminal-50 BFV row also retains three components and every product
coefficient. Unmasked coefficients disclose more than the requested distances
and can reveal substantial index information to the owner. This track assumes
the owner is authorized for the underlying database.

The missing component is **sparse-result conversion/repacking**. Simply
discarding ciphertext coefficients does not discard only irrelevant plaintext
coefficients: decryption mixes components with the secret polynomial. A valid
conversion must preserve the selected plaintext results homomorphically and
account for its keys, compute, noise, setup and leakage.

## Follow-up: encrypted ring trace and dense packing

The [trace prototype](../../experiments/bfv_search_lab/trace_bgv.py) implements
one conversion baseline. Shift a product by X^−(D−1), placing the desired
correlations at coefficients divisible by D. Set g=1+2N/D. For D<=N/2 and
power-of-two N,D, the automorphism X→X^g generates a subgroup of order D.
The operator

`T_D = (1 + sigma_g)(1 + sigma_(g^2)) ... (1 + sigma_(g^(D/2)))`

kills coefficients outside those positions and multiplies the retained ones
by D. Relinearization before the trace restores two components. Pack tile i
by multiplying its projected ciphertext by X^i and adding it into the response.
Those are signed coefficient permutations, requiring **no packing key switches**.
The owner multiplies decrypted results by D^−1 modulo t, avoiding a large
plaintext multiplication and its noise amplification on the server.

This still needs log2(D) automorphisms per tile. At the modeled full workload,
256 relinearizations plus 2,304 projection automorphisms gives 2,560 switches,
compared with the accepted BFV circuit's 2,815. It also replaces BFV scaling
with modular multiplication. These operation counts are a hypothesis for a
future native/GPU implementation, not a speedup measurement.

For ell gadget columns of width w, each switch contributes at most
`E = t*eta*N*ell*(2^w−1)` to the integer phase norm. After one product,
relinearization, trace and addition of T tiles, a sufficient bound is

`T * (D*N*B^2 + (2D−1)*E) < Q/2`.

The server checks the bound before evaluation and propagates it through each
operation. For N=16,384, d=D=512, t=1,031, eta=21 and 256 tiles, the bound has
90 bits: a 90-bit Q fails the conservative check, while 96 bits passes. The
secret remains a full-ring ternary polynomial. This is a correctness argument
for honestly generated local fixtures/evaluation keys, not security estimation
or validation of adversarial ciphertext metadata.

The pilot uses **65 vectors × 512 bits, N=16,384, t=1,031, Q=96 bits**:
three measured rounds plus warmup, with the same index for both paths.
Raw data: [trace pilot](../../benchmarks/results/trace_bgv_lab_65.json).

| CPU reference path | Server (ms) | Client decryption (ms) | Response bytes | Response ciphertexts |
| --- | ---: | ---: | ---: | ---: |
| unrepacked | 173.92 | 128.67 | 1,769,602 | 3 |
| trace-packed | 4238.27 | 23.30 | 393,309 | 1 |

All distances were exact. Projection reduces this pilot’s response by **4.50×**
and decryption by **5.52×**, but increases server time from **174 ms to 4.24 s**.
This unoptimized Python/GMP key-switch implementation is a correctness and
communication proof of concept, **not a performance win**. Timings above are
arithmetic phases, not a complete network/framing benchmark.

For **8,192 candidates**, the artifact separately models one two-component
**393,216-byte raw response** (before framing) and verifies the public worst-case
**90-bit phase bound** against the 96-bit Q. That full-size trace computation
was **not timed**. The measured pilot is not extrapolated into a GPU speedup.
Its evaluation keys contain **15 MiB of raw coefficients**; no evaluation-key
serialization format is implemented in this prototype.

Ring-trace packing is established prior art. A relevant recent paper is
[Algebraic Analysis of Homomorphic Trace Evaluation and Its Applications](https://eprint.iacr.org/2026/1604),
which studies more precise coefficient-wise noise behavior and packing. Our
simple bound does not implement that analysis. Compare against reviewed
extraction/repacking methods such as [HERMES](https://eprint.iacr.org/2023/1244)
before claiming a new algorithm or a competitive implementation.

## Validation and remaining research

- Repository plus research tests: **451 passed, 11 skipped**. The skips were
  nine unavailable Paillier CUDA-extension cases, one optional SEAL oracle,
  and one real AWS Nitro hardware test. BFV CUDA tests ran on the RTX 3080.
- After isolating the real-fork regression from previously initialized GPU/BLAS
  threads, the affected query tests plus trace/planner tests passed: **31 passed**.
  The fork child inherits a deliberately locked pool and must reject its PID
  before accessing the lock; it has a timeout to make a regression fail safely.
- A separate GCC 12 ASan/UBSan build of the modified public CPU extension passed
  **33 tests**, with six CUDA cases deliberately skipped. Leak detection was
  disabled for the Python host; address/undefined-behavior failures were fatal.
  This covers the native encoder and partial-server boundaries, not every
  dependency or the separate private decoder binary.
- Ruff passes for the package and explicitly selected experiment/benchmark
  files. Mypy passes for all **34 package files** and **six research modules**.
- NVIDIA Compute Sanitizer was attempted with the installed injection-library
  path and child-process tracking. It exited before the first instrumented API
  call and could not retrieve the target exit code. **No CUDA sanitizer pass is
  claimed**; device-memory instrumentation remains an environment limitation.

The query-pool tests cover exhaustion, invalid-query consumption, concurrent
consumers, copying/serialization rejection, failed refill and actual fork
rejection. Public seed expansion is compared against coefficient-by-coefficient
rejection sampling, including rejected draws. None of these tests is a proof
against process snapshots, memory disclosure, rollback or private-key timing
attacks. Tokens and pool memory must remain confidential to the owner.

The default BFV client, Paillier paths, SEAL oracle and guarded/Nitro protocol
contracts are preserved. New layouts/query formats are not registered as
approved circuits. A future deployment must bind the query, index, epoch and
new circuit into reviewed execution verification **before** private decryption
or feedback. This work adds no GPU attestation, CCA security, production
approval, or reviewed parameter assurance.

The next implementation priorities are native arithmetic for the trace experiment,
resident-index transformed representations, and a reviewed shallow-BGV oracle.
The [expanded plan](bfv-search-experiment-plan.md#expanded-scheme-portfolio-after-the-first-implementations)
also specifies CKKS error gates, TFHE selection and mixed-protocol alternatives.
Current primitives are established techniques. Any novelty claim needs a
separate prior-art review and evidence for the resulting algorithm or system.

Reproduction commands and the file map are in the
[lab README](../../experiments/bfv_search_lab/README.md).
