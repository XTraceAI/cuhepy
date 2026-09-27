# Fresh BGV owner arithmetic

This experiment accelerates the client bottleneck identified in the
[public-pipeline measurements](bgv-public-pipeline-results.md). All four paths
are our own BGV implementation. The optional native path uses C++ and GMP;
it does not call Microsoft SEAL. The separate SEAL executable remains an
independent circuit oracle in the test suite.

At 8,192 vectors, the native owner reduces median local computation from
**136.62 ms to 81.87 ms** (1.67x, 40.1% less time), with unchanged ciphertext
sizes and evaluation parameters. This is a within-run comparison against the
original owner using the already optimized public server, not against the older
unoptimized CUDA pipeline.

## Paired results

Ten measured fresh queries per variant on a Ryzen 7 5800X and RTX 3080, each
searching 8,192 vectors of 512 bits. One warmup is excluded. Times are medians;
the median total need not equal the sum of individual phase medians.

| Owner variant | Query creation | Public seed expansion | Private decryption | All client phases | Local measured total |
| --- | ---: | ---: | ---: | ---: | ---: |
| Original reference | 59.63 ms | 7.84 ms | 19.79 ms | 85.22 ms | 136.62 ms |
| Bulk sampling/decoding | 29.37 ms | 4.02 ms | 21.16 ms | 56.94 ms | 105.57 ms |
| Bulk + shifted ternary | 24.24 ms | 3.92 ms | 15.87 ms | 46.03 ms | 93.50 ms |
| Bulk + native ternary | **16.92 ms** | 3.98 ms | **11.03 ms** | **34.59 ms** | **81.87 ms** |

Native query creation is **3.52x** faster and decryption **1.79x** faster than
the reference; all client phases fall by **59.4%**. CUDA evaluation/compaction
stays near 40 ms for every variant. Public seed expansion improves because
bulk decoding also runs at that server boundary. The bulk-only owner's extra
validation makes generic decryption slightly slower; the table retains that
negative result instead of attributing all improvement to sampling.

All variants upload **245,866 bytes**, download **102,488 bytes**, and total
**348,354 bytes** per query. This is the same 25-bit terminal representation
already measured in the earlier precision sweep. There is no new communication
reduction or weaker parameter choice in this experiment.

The native owner takes **4.46 ms** to create, including the query-modulus cache,
and **0.69 ms** to prepare the terminal cache. This measured extra setup is less
than the recurring query-encryption saving on the first request. Common index
encryption takes 33.01 s and GPU preparation/upload 1.85 s; those remain setup
costs and are not optimized here. The indexed ciphertexts occupy 125,832,025
serialized bytes. No private key is part of that public index.

Reference total times range from 134.49 to 143.10 ms; native times from 78.20 to
85.23 ms. The bulk variant includes one 140.00 ms sample, retained in the raw
results. Ten trials support this local comparison, not a p95 or a cross-machine
throughput claim. [Raw 8,192-vector results](../../benchmarks/results/bgv_owner_pipeline_8192.json)
record implementation `11c4125`, every sample, public parameters, setup times,
and source/binary hashes. This run checks 720,896 plaintext coefficients,
44 expanded queries and four exact CPU/CUDA compact ciphertexts on warmup.

### 32,768 vectors

The larger run keeps the same ring and parameters. The seeded query still
uploads one explicit polynomial plus its seed; the expanded ciphertext has two
components. The response now contains two ciphertexts. This run uses separately
generated keys from the smaller run; its within-run comparisons are paired.

| Owner variant | Query creation | Private decryption | All client phases | Local measured total |
| --- | ---: | ---: | ---: | ---: |
| Original reference | 59.16 ms | 38.51 ms | 117.28 ms | 216.98 ms |
| Bulk sampling/decoding | 29.45 ms | 43.03 ms | 92.47 ms | 187.83 ms |
| Bulk + shifted ternary | 24.16 ms | 31.70 ms | 75.35 ms | 171.87 ms |
| Bulk + native ternary | **16.52 ms** | **22.30 ms** | **58.07 ms** | **153.25 ms** |

The final path reduces local measured time by **29.4%** (1.42x) and client
time by **50.5%**. Query creation is 3.58x faster and stays close to the smaller
workload, as expected from its fixed ring size. Decryption is 1.73x faster than
the paired control and roughly doubles with two result ciphertexts. Public
CUDA evaluation/compaction occupies 84.60–86.45 ms across the four variants;
it now accounts for over half the total in the native-owner case.

All variants send **245,866 query bytes** and **204,895 response bytes**, or
**450,761 bytes** combined. The serialized encrypted index is 503,327,833 bytes.
Index encryption takes 135.86 s, GPU preparation/upload 8.15 s, and the native
owner creation plus terminal-cache preparation 5.25 ms. Those setup costs
remain separate. Reference total times range from 213.42 to 219.78 ms; native
times from 150.54 to 157.48 ms.

[Raw 32,768-vector results](../../benchmarks/results/bgv_owner_pipeline_32768.json)
also measure `11c4125`, with identical native binary hashes. All 1,441,792
plaintext-coefficient comparisons, 44 query-expansion comparisons, eight warmup
CPU/CUDA compact-ciphertext comparisons, distances and stable top-three checks
pass. The reported source hashes in both artifacts match that committed source.

## What changes

The original seeded owner encrypts a coefficient plaintext using
`c0 = m + t*e - a*s mod Q`, `c1 = a`. The server reconstructs `a` from a public
seed; the errors `e` require separate fresh randomness. The measured bottlenecks
were thousands of small randomness calls, Python coefficient conversions, and
large packed integer operands when `-1` in the ternary secret is stored as `Q-1`.

The ablations retain the original reference and add three steps:

1. **Bulk:** request fresh error entropy in one OS-backed call, decode it into
   independent centered-binomial coefficients, and bulk-decode the identical
   rejection-sampled SHAKE256 public stream. Keep the generic private product.
2. **Ternary:** compute private products with shifted small secret coefficients
   and a public prefix-sum correction. Cache the secret's packed representation
   at the query and terminal widths. Keep the Python/GMP implementation.
3. **Native:** move that same identity, error decoding and coefficient arithmetic
   into a separate optional C++/GMP owner extension. Keep public stream expansion
   in Python/PyCryptodome and the existing public CUDA server unchanged.

The seed and error entropy are independent fresh requests on **every** encryption.
There is no precomputed zero-encryption pool, refill cost, reused randomness or
smaller secret/error distribution. Python's
[secrets interface](https://docs.python.org/3/library/secrets.html) supplies
OS-backed random bytes; no custom cryptographic random generator is introduced.

For each error, consume `ceil(2*eta/8)` bytes, take the popcount of the low `eta`
bits minus the popcount of the next `eta` bits, and ignore only unused high
padding bits. The two disjoint fields produce exactly the original difference
of independent `Binomial(eta, 1/2)` variables. At eta=21, this consumes six bytes
per coefficient. Bulk public expansion preserves every candidate's original
byte grouping, high-bit mask, rejection decision and order, including zero tails.
It is a representation optimization of the same stream, not a new sampler.

## Exact ternary multiplication

Work in `Z_Q[X]/(X^N+1)`. Write the secret as signed coefficients in `{-1,0,1}`
and let `J=1+X+...+X^(N-1)`. Then

```text
a*s = a*(s+J) - a*J
(a*J)[i] = 2 * sum(a[0:i+1]) - sum(a).
```

The shifted coefficients `s+J` lie in `{0,1,2}`. For public coefficients
`0 <= a[i] < Q`, every coefficient of the ordinary convolution `a*(s+J)` is at
most `2*N*(Q-1)`. Choose the public packing width
`w = bit_length(2*N*(Q-1))`. Packing into base `2^w` and multiplying with GMP
therefore has no carries between coefficients. Unpack, fold the upper half
using `X^N=-1`, subtract the prefix-sum expression, and reduce modulo Q.

This identity needs neither sparse secrets nor a smaller ring. It works for
every ternary secret, including all-minus-one, all-zero and all-plus-one tests.
At N=16,384 and Q120 the digit width is 135 bits instead of the generic product's
255-bit worst case. At the 25-bit terminal modulus it is 40 rather than 65 bits.
The secret packing is cached by public width, so the same signed secret also
works at the terminal modulus. This is a reusable key representation, not a
consumable encryption mask.

Smaller packed operands motivate the experiment because GMP chooses among
several [multiplication algorithms](https://gmplib.org/manual/Multiplication-Algorithms)
according to operand size. We do not infer a particular GMP dispatch threshold
or establish a new cryptographic algorithm. The performance claims come from
the paired measurements, not solely from the reduced operand sizes.

## Measurement contract

Use N=16,384, t=1,031, Q120, eta=21, gadget width 30, the level-4 public CUDA
evaluator and an explicit 25-bit terminal response. Each run shares keys and
an encrypted index across variants. Ten paired rounds follow one excluded
warmup; order is shuffled, and each round gives all variants the same plaintext
query with fresh independent encryption randomness for each variant.

Local measured time sums query encoding/encryption, seeded-query parsing and
expansion, synchronized CUDA evaluation with native compaction, response packing,
private decryption, distance decoding and stable top-three selection. It excludes
response parsing, network transfer, attestation, queuing and concurrent load.
Setup and owner cache preparation are recorded separately. These numbers do not
measure a deployed request or a security-equivalent Paillier/SEAL comparison.

Outside the timers, check every distance and stable top-three, all returned
plaintext coefficients against the original decryptor, exact seeded expansion
against the original stream, and complete CPU/CUDA compact ciphertext equality
on warmup. Random ciphertexts differ between variants; their plaintexts are
compared. Separate controlled-entropy tests establish byte-for-byte equality of
the encryption implementations when given identical seed/error bits.

## Validation and boundaries

The full repository/lab suite passes 568 tests with ten expected skips: nine
unavailable Paillier GPU cases and one live AWS Nitro integration. The BFV/BGV
CUDA paths and the separate SEAL circuit oracle are enabled. Ruff and mypy pass
for the package and new modules. After two final local boundary/lifetime
tightenings, the 43 focused owner/seeded tests pass again both normally and under
AddressSanitizer/UndefinedBehaviorSanitizer.

Tests include exhaustive centered-binomial histograms at small eta, bit-field
extremes through eta=64, exact public stream/rejection equivalence, all 81 ternary
secrets at N=4 against an independent naive negacyclic oracle, generic GMP
products through N=32,768 and Q240, the native 256-bit packing boundary,
controlled-entropy encryption, malformed packed inputs, close/concurrent calls,
and actual fork refusal. The full suite reports Python's expected warning for
the test deliberately calling fork in a process with other threads.

The sanitizer harness uses PyCryptodome's supported
`PYCRYPTODOME_DISABLE_DEEPBIND=1` setting: its default CFFI deep binding caused
ASan to abort during import before any test ran. With that loader setting,
all 43 focused tests pass. Leak checking is disabled for the Python-hosted run;
the extension is instrumented, not GMP/Python themselves. The earlier CUDA
Compute Sanitizer instrumentation limitation is unchanged.

The private module bounds coefficient widths, dimensions, message/error lengths,
and canonical encodings before private multiplication. Its calls release the
GIL but serialize on a native mutex. The Python owner also serializes operations,
rejects inherited instances before touching locks after fork, and refuses
copying/pickling. `close()` drops its references and native cached storage.

These are research lifecycle controls. **GMP arithmetic remains variable-time;
neither Python nor GMP copies have a secure-erasure guarantee.** The caller may
also still hold the original secret key. This code does not authenticate server
responses, bind a Nitro measurement to this BGV circuit, assess parameters for
deployment, or provide a remote decryption service. Keep local trusted fixtures
until those protocol/private-backend requirements have been independently
addressed. Production BFV clients and their verification paths are unchanged.

## Code and reproduction

- [`owner_bgv.py`](../../experiments/bfv_search_lab/owner_bgv.py): sampling,
  exact Python/GMP product, explicit owner lifecycle and reference ablations.
- [`native_owner_bgv.py`](../../experiments/bfv_search_lab/native_owner_bgv.py):
  optional private native wrapper.
- [`_owner/owner.h`](../../experiments/bfv_search_lab/_owner/owner.h) and
  [`bindings.cpp`](../../experiments/bfv_search_lab/_owner/bindings.cpp): our
  C++/GMP implementation, separate from the public `_native/` server.
- [`bgv_owner_pipeline.py`](../../benchmarks/bgv_owner_pipeline.py): paired
  benchmarks with public source/build hashes and no key/ciphertext dumps.
- [Build and test commands](../../experiments/bfv_search_lab/README.md#fresh-owner-arithmetic).

## Next experiments

The shifted-ternary identity has earned a place as a fast local reference. A
fixed-schedule RNS/NTT private backend is the next arithmetic candidate: benchmark
cached secret transforms and bounded modular operations against this baseline,
while reviewing secret-dependent control flow, memory access, key handling and
compiler output. Fast GMP timings are not evidence that those requirements can
be skipped. Keep all private code separate from the public evaluator.

The remaining public evaluation cost motivates a genuine multi-query GPU kernel
with shared evaluation-key reads and bounded workspace. Its payoff should be
measured separately for single-request latency and concurrent throughput. The
existing thread experiment already showed that higher throughput can increase
individual request latency. Real transport and authenticated execution remain
separate experiments before drawing a deployment or paper-level conclusion.

There is also a small, simpler client target: at 32,768 vectors, Python distance
decoding and a full stable sort for three answers consume about 19 ms combined.
Benchmark linear top-three selection with identical tie ordering, and a fused
decoder, as separate ablations. They do not change the cryptographic circuit
and should not be presented as new cryptographic techniques.

The [result-handling and GPU-batch follow-up](bgv-finish-batch-results.md) now
implements those client ablations and distinct-query public kernels, with paired
measurements, explicit completion delays, memory caps and retained negative results.
