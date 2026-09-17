# Complete C++ BFV server evaluation

`BFVClient(server_backend="native")` evaluates a complete encrypted Hamming
search inside our own C++ implementation. Python passes packed ciphertext
buffers in and receives packed result buffers out. Masks, polynomial operations,
rotations, the result merge tree, and terminal modulus compaction run in C++.
Key generation, encryption and decryption continue to use `encryption/bfv.py`.

This is an optional server backend with the same parameters, keys, packing and
wire format as the earlier native BFV implementation. The `optimized`,
`reference` and `rns` backends remain available. It uses GMP and the C++ standard
library, and does not compile or link SEAL. Like the existing scheme, this is
experimental leveled BFV without a security audit or bootstrapping.

## Build and use

Rebuild the extension from the repository root. This backend originally used
ABI 2; the current extension is ABI 3 after adding the
[persistent RNS backend](native-bfv-residue.md). An older binary raises a rebuild error.

```bash
make -C src/xtrace_sdk/x_vec/crypto/bfv_cpu_ext PYTHON="$PWD/.venv/bin/python"
```

```python
import json
from xtrace_sdk.x_vec.crypto.bfv_client import BFVClient

client = BFVClient(embed_len=512)
server = BFVClient(skip_key_gen=True, server_backend="native")
server.load_config(json.loads(client.stringify_config()))
server.load_stringified_keys(client.stringify_pk())
assert server.keys is None

query = [0, 1] * 256
vectors = [query, [1 - bit for bit in query]]
encrypted_query = client.encrypt_vec_one(query)
encrypted_index = client.encrypt_vec_packed(vectors)
response = server.encode_hamming_server_packed(encrypted_query, encrypted_index, 2)
assert client.decode_hamming_client_packed(response, 2) == [0, 512]
```

The existing individual `encode_hamming_server` interface also uses the complete
native evaluator. Reuse a server across queries to reuse prepared public keys
and the full-tile mask. Loading keys or changing the configured layout resets
the native plan. `server_backend` remains a runtime option; the default is
`optimized`. This does not add BFV support to the production HTTP endpoints.

## What profiling established

The first instrumented full tile at N=8192 and dimension 512 spent about 35% of
native time in forward/inverse transforms and 30% in CRT reconstruction and
reduction modulo q. These measurements motivated both arithmetic changes and
moving the rest of the search into C++. The original Python profile could not
separate these costs inside a native call.

The benchmark now supports `--native-profile`. After its timed searches, it runs
one additional warm search for each compiled backend and records exclusive
native phase durations and call counts. Nested timings are subtracted from their
parent category. Timers read the clock only during an opt-in profiling session.
Sessions are per-thread and restored when a call raises an exception.

`other` includes Python work, binding overhead and native work outside named
scopes. `buffers` covers explicitly instrumented buffer setup. GMP allocations
remain included in the arithmetic operations that perform them; the profile
does not claim to isolate every allocator call. Use normal benchmark samples,
not instrumented runs, for speed comparisons.

```bash
.venv/bin/python benchmarks/bfv_server.py --num-vectors 1024 \
  --backends rns,native --seal --repeats 4 --native-profile \
  --json-out /tmp/bfv-native-server-1024.json
```

Omit `--seal` when TenSEAL is unavailable. Native backends share exactly the
same encrypted input and must return identical ciphertexts. SEAL uses the same
plaintext vectors with its own parameters and format. The comparison is a local
server-call measurement, not an equal-security or identical-kernel comparison.
Native search times include ciphertext framing/buffer conversion, arithmetic
and compaction, but exclude outer MessagePack. SEAL includes its envelope and
binding temporary-file I/O. Key import, encryption, client decryption and network
latency are excluded from both.

## Recorded results

Measured on the same AMD Ryzen 7 5800X CPU with Python 3.12.3, GMP 6.3.0,
GCC 13.3.0 (`-O3`) and TenSEAL 0.3.16. Each vector has 512 bits. Both native
backends use N=8192, t=65537, the original 180-bit q, six 30-bit gadget digits,
and 50-bit response compaction. Each backend has one first search and three
subsequent searches; the warm column reports their median.

| Vectors | Backend | First search (s) | Warm median (s) |
| ---: | --- | ---: | ---: |
| 32 | Previous `rns` | 0.4936 | 0.2602 |
| 32 | Complete C++ `native` | 0.5134 | 0.1639 |
| 32 | SEAL prototype | 0.0763 | 0.0741 |
| 1,024 | Previous `rns` | 8.2124 | 7.9266 |
| 1,024 | Complete C++ `native` | 5.6817 | 5.3426 |
| 1,024 | SEAL prototype | 2.3662 | 2.3592 |

For 1,024 vectors, the complete C++ backend is **1.48 times faster** than the
previous RNS backend, reducing server time by **32.6%**. SEAL remains **2.26
times faster** in this practical comparison. Native ciphertexts matched exactly
on every run. The 102,496-byte response, 471,250-byte query plus response and
26-bit minimum response noise budget are the same for both native backends.

The additional whole-search profile explains where time changed:

| Exclusive phase, 1,024 vectors | Previous `rns` (s) | Complete C++ `native` (s) |
| --- | ---: | ---: |
| Forward transforms | 1.562 | 1.565 |
| Inverse transforms | 0.759 | 0.557 |
| CRT reconstruction/conversion | 1.384 | 0.865 |
| Reduction modulo q | 0.486 | 0.491 |
| Pointwise work | 0.421 | 0.408 |
| Other: Python, binding and unscoped native work | 2.388 | 0.503 |

The remaining phases are recorded in the JSON files. These are exclusive
instrumented durations, not additional speed benchmark samples. The biggest
reductions are in Python/binding work and CRT conversion; inverse transforms
also improve. Forward-transform and pointwise times are essentially unchanged
in this profile, so it does not establish an individual speedup for every new
primitive. The certified CRT fallback count is zero on these searches; the
boundary tests exercise it deliberately.

The native plan prepares all 18 keys needed by this layout, while `rns` prepares
keys as operations request them (16 for 1,024 vectors, 11 for 32). This explains
the slightly higher first-use cost for the small workload. The native cache has
56,623,104 bytes of key coefficient arrays, 2,752,512 bytes of transform tables
and 655,360 bytes of prepared plaintext tables/mask. These are additional to the
loaded public key, exclude containers/CRT constants/temporary allocations, and
are not peak process memory.

Raw samples, native profiles, parameters and source/binary hashes are in
`benchmarks/results/native_bfv_cpp_server_32.json` and
`benchmarks/results/native_bfv_cpp_server_1024.json`. The earlier benchmark
files are retained.

## Changes inside the native server

- `bfv_server.h` owns the public evaluation-key handles, prepared plaintext NTT
  tables and transformed full-tile mask. A partial mask is local to a search.
  The same mask transforms are reused for both ciphertext components.
- `packed_wire.h` imports/exports the original bit-packed polynomial format
  directly in C++. It checks lengths and coefficient bounds. Python validates
  the small framing header, without unpacking N Python integers per polynomial.
- A streaming binary merge tree retains O(log(padded dimension)) intermediate
  ciphertexts. It parses each indexed tile once and keeps results in C++ through
  compaction. Native calls release the GIL; plans are immutable and working
  arrays belong to each call.
- The `native` arithmetic mode uses lazy NTT butterflies and reciprocal-based
  Barrett reduction. The `rns` mode retains the earlier canonical butterflies
  and general remainder operations for comparison.
- Key switching and prepared-mask multiplication compute their final result
  modulo q using certified CRT conversion. Ciphertext multiplication still
  reconstructs its full signed tensor product before BFV scale-and-round.

These build on the [earlier SEAL source review](native-bfv-ntt.md). The
[SEAL evaluator](https://github.com/microsoft/SEAL/blob/v4.1.2/native/src/seal/evaluator.cpp)
and [NTT routines](https://github.com/microsoft/SEAL/blob/v4.1.2/native/src/seal/util/ntt.cpp)
use specialized modular arithmetic and lazy transforms. Our implementations and
the CRT bounds below are independent.

## Exact CRT conversion modulo q

The auxiliary primes p_j still provide enough range to identify the signed
integer convolution, as described in [the original bounds](native-bfv-ntt.md).
Let M be their product, M_j = M/p_j, and r_j an output residue after inverse NTT.
Define:

```text
y_j = r_j * inverse(M_j mod p_j) mod p_j
theta = sum(y_j / p_j)
k = floor(theta + 1/2)
signed result = sum(y_j * M_j) - k*M
```

We need only the last expression modulo q for key switching and mask products.
Precomputing `M_j mod q` and `M mod q` lets us form that residue without first
constructing the full integer modulo M. GMP still holds the final coefficients.

The value k must be exact. With entirely integer arithmetic, compute:

```text
F = sum(floor(2^64 * y_j / p_j))
F/2^64 <= theta < (F + number_of_primes)/2^64
```

If both ends of this interval round to the same integer, k is certified. If
they straddle a rounding boundary, use the original exact GMP CRT reconstruction
for that coefficient. No floating-point approximation or probabilistic
correctness assumption is used. Tests explicitly place integers on either side
of M/2 and verify that this fallback runs and agrees with the integer oracle.

Ciphertext tensor products require the unreduced integer before multiplication
by t/q. They keep the original exact reconstruction and signed rounding rule;
reducing them modulo q early would be incorrect.

## Native arithmetic bounds

The fast forward transform keeps internal values below 2p and canonicalizes
its final output. The fast inverse keeps internal values below 4p and produces
canonical coefficients after inverse scaling. With p<2^60, these additions and
Shoup products fit the existing word bounds. Canonical forward outputs preserve
the key-switch accumulator proof: products are below 2^120, and batches of 256
fit unsigned 128-bit accumulators.

Barrett reduction stores `floor(2^128/p)`. The estimated quotient is at most one
below the true quotient, so a single correction gives the exact remainder for
any unsigned 128-bit input. The certified CRT fraction calculation specializes
this reciprocal calculation to `floor(y*2^64/p)`, with y<p. Standalone tests
compare both operations with integer division, including maximum inputs.

## Code and verification

| File, relative to the repository root | Responsibility |
| --- | --- |
| `src/xtrace_sdk/x_vec/crypto/bfv_cpu_ext/bfv_server.h` | Complete C++ public-key server and prepared masks |
| `src/xtrace_sdk/x_vec/crypto/bfv_cpu_ext/packed_wire.h` | Direct packed ciphertext import/export |
| `src/xtrace_sdk/x_vec/crypto/bfv_cpu_ext/profile.h` | Per-thread exclusive native timings |
| `src/xtrace_sdk/x_vec/crypto/bfv_cpu_ext/rns_ntt.h` | Original and fast exact arithmetic modes |
| `src/xtrace_sdk/x_vec/crypto/encryption/bfv_native.py` | BFV wire interface to the native server |
| `src/xtrace_sdk/x_vec/crypto/bfv_client.py` | Backend selection through the existing client |
| `tests/x_vec/test_bfv_native.py` | Public-only evaluation, direct wire path, profiling and native lifetimes |
| `tests/x_vec/native/test_bfv_rns.cpp` | Integer arithmetic, rounding-boundary and packed-wire sanitizer oracles |
| `benchmarks/bfv_server.py` | Identical-input comparisons and optional native phase profiles |

The existing BFV client and evaluator tests also run against `native`, including
partial tiles, multiple responses, a separate public-only server process and
exact ciphertext comparisons. Tests assert that complete searches do not call
the Python polynomial conversion, batching or modulus-compaction functions.

Validation passed 172 offline tests, including 90 BFV tests, plus Ruff,
formatting and mypy checks. API integration and GPU tests were excluded. Both
the standalone arithmetic and Python binding address/undefined-behavior
sanitizer runs passed. A built platform-tagged wheel imported its own native
module and completed an encrypted search. The example above passed; Sphinx
built with the existing README cross-reference warning in `bfv-packed-hamming.md`.

CI runs standalone address/undefined-behavior sanitizer oracles and builds a
separate sanitized extension for `run_binding_sanitizers.py`. The latter runs
the Python/native boundary and complete-server tests against that binary.
Leak checking is disabled for the Python-hosted sanitizer run; the standalone
CI run retains it. As documented for the earlier backend, the local tracing
sandbox requires `ASAN_OPTIONS=detect_leaks=0` for standalone runs as well.

The [persistent RNS backend](native-bfv-residue.md) now keeps coefficients in RNS
across key switches, rotations, masks and the merge tree, with an optional new
ciphertext modulus. The `native` backend described here retains its GMP
intermediates and existing-key compatibility. Further opportunities include
reusing more working buffers and moving client-side operations into C++. A
rewrite of encryption or key generation would not directly improve the
server-search timing measured here.
