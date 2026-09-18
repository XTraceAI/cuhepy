# Native BFV RNS/NTT server arithmetic

The optional `server_backend="rns"` evaluator uses independently implemented C++
kernels to accelerate native BFV. It retains the existing keys, ciphertext
modulus, error distribution, packing layout and wire format. The default
`"optimized"` GMP evaluator and the original `"reference"` evaluator remain
available. The earlier SEAL experiment is preserved for comparison.

The subsequent [`native` server backend](native-bfv-server.md) runs complete
searches inside C++, adds native phase profiling, and further optimizes this
arithmetic while preserving the same keys and ciphertexts.

## What we learned from SEAL

The source review used the pinned **SEAL v4.1.2** tag, rather than an unversioned
branch. The comparison executable is the separately installed TenSEAL prototype;
its package version and actual modulus sizes are recorded by the benchmark.

| SEAL source | Relevant technique | Native implementation |
| --- | --- | --- |
| [`evaluator.cpp`, `bfv_multiply`](https://github.com/microsoft/SEAL/blob/v4.1.2/native/src/seal/evaluator.cpp) | RNS base extension, NTT polynomial products, and scale/base conversion | Auxiliary RNS bases reconstruct the exact signed tensor product before our existing rounding rule |
| [`keygenerator.cpp`, `generate_one_kswitch_key`](https://github.com/microsoft/SEAL/blob/v4.1.2/native/src/seal/keygenerator.cpp) | Evaluation keys are generated in NTT form | Lazily convert our existing gadget keys into NTT form and cache them |
| [`evaluator.cpp`, `switch_key_inplace`](https://github.com/microsoft/SEAL/blob/v4.1.2/native/src/seal/evaluator.cpp) | Pointwise key products and delayed reduction in wide accumulators | Sum gadget products in unsigned 128-bit accumulators before inverse transforms |
| [`util/ntt.cpp`](https://github.com/microsoft/SEAL/blob/v4.1.2/native/src/seal/util/ntt.cpp) | Prepared transform tables and inverse scaling | Cached roots, twists and inverse scaling; matching forward/inverse orders avoid explicit bit reversal |
| [`util/uintarithsmallmod.h`](https://github.com/microsoft/SEAL/blob/v4.1.2/native/src/seal/util/uintarithsmallmod.h) | Precomputed quotient operands for modular multiplication | Shoup multiplication avoids division in transform butterflies |

SEAL's multiplication also uses specialized RNS conversion routines in
[`util/rns.cpp`](https://github.com/microsoft/SEAL/blob/v4.1.2/native/src/seal/util/rns.cpp).
Our backend deliberately keeps the original BFV scheme and exact GMP
reconstruction, so it does not implement SEAL's full BEHZ multiplication or
special-prime key-switching scheme. No SEAL source is compiled or linked into
the native extension. These are independent implementations of the arithmetic
techniques identified during that review.

## Arithmetic and correctness bounds

The existing q is a single large prime and need not support an NTT of the
required length. The backend instead selects distinct 60-bit auxiliary primes
`p_i = 1 mod 2N`. A polynomial is temporarily represented by its residues modulo
each `p_i`. These primes are arithmetic scratch space; they do not replace q.

Each prime gets an N-point negacyclic transform. Multiplying coefficient i by
`psi^i`, where psi has order 2N, changes multiplication modulo `X^N+1` into a
cyclic transform calculation. The forward transform produces bit-reversed
values; the complementary inverse accepts that same order and combines division
by N with the inverse twist. Pointwise products compute the convolution.

The Chinese Remainder Theorem reconstructs the **signed integer** result. Let
`M = product(p_i)`, b be the gadget digit width and L the number of digits.
We choose enough primes that:

- Key switching: `M > 2*N*L*(2^b - 1)*(q - 1)`.
- Ciphertext multiplication, including the two cross products:
  `M > 4*N*(q - 1)^2`.
- A general polynomial product uses the bound
  `M > 2*N*max(lhs)*max(rhs)`.

Every result coefficient then lies strictly between `-M/2` and `M/2`, making
centered CRT reconstruction unique. For BFV multiplication, the reconstructed
coefficient c is rounded with `floor((2*t*c + q)/(2*q))` before reduction modulo
q. Premature reduction modulo q would destroy information needed by that step.
The default key switch uses four auxiliary primes; the tensor product uses
seven. All transforms and rounding use integer arithmetic.

Transform values remain canonical residues. A fixed twiddle w stores
`floor(w*2^64/p)`; its high-word product gives a quotient estimate requiring at
most one correction. Gadget products are below `2^120`, allowing batches of
256 terms in 128-bit accumulators. Longer gadgets reduce between batches.
Digits of at most 60 bits are extracted directly from GMP limbs on supported
64-bit GMP builds; larger digits retain a GMP path.

The complete subtract/square/relinearize/rotate/add/mask circuit for one Hamming
tile stays inside C++. This avoids returning thousands of intermediate GMP
coefficients to Python after each rotation. Result merging and public client
interfaces retain their existing structure. Native calls release the GIL during
computation; immutable shared plans and per-call scratch arrays support concurrent
evaluations. Input lengths, coefficient ranges, capsule types and native plan
ownership are checked at the extension boundary.

## Build and use

From the repository root, using a Linux 64-bit environment with a C++17 compiler,
Python development headers and GMP development files:

```bash
make -C src/cuhepy/bfv/_cpu_ext PYTHON="$PWD/.venv/bin/python"
```

There is no additional runtime Python package, pybind11, SEAL, or CUDA dependency.
The built module needs the system GMP and C++ runtime libraries. It is optional;
the Python/GMP path works without a compiler or this extension. Wheels include
the native binary when built locally and receive a Python/OS/architecture tag.

```python
import json
from cuhepy.hamming.bfv import BFVClient

client = BFVClient(embed_len=512)
server = BFVClient(skip_key_gen=True, server_backend="rns")
server.load_config(json.loads(client.stringify_config()))
server.load_stringified_keys(client.stringify_pk())
assert server.keys is None

query = [0, 1] * 256
vectors = [query[:], [1 - bit for bit in query]]
response = server.encode_hamming_server_packed(
    client.encrypt_vec_one(query), client.encrypt_vec_packed(vectors), len(vectors)
)
assert client.decode_hamming_client_packed(response, len(vectors)) == [0, 512]
```

Reuse the server to amortize transformed-key preparation. Key loading discards
the cache. Select `server_backend="optimized"` for the previous GMP optimization
or `"reference"` for the original arithmetic. `"rns"` reports a build instruction
if the native extension cannot be imported; it does not silently change the
requested backend. The setting is runtime-only and does not alter saved crypto
configurations.

## Code map

| File | Responsibility |
| --- | --- |
| `crypto/bfv_cpu_ext/rns_ntt.h` | NTT plans, fixed-multiplier reduction, exact CRT, gadget multiplication, BFV scaling and native tile evaluation |
| `crypto/bfv_cpu_ext/bindings.cpp` | Checked CPython boundary and native object lifetimes |
| `crypto/bfv_cpu_ext/Makefile` | Optional local C++ build |
| `crypto/encryption/bfv_rns.py` | Existing GMP polynomial types to native buffers and cached key handles |
| `crypto/encryption/bfv_evaluator.py` | Backend selection and common validation/reference arithmetic |
| `crypto/bfv_client.py` | Existing individual/packed Hamming interfaces |
| `tests/unit/test_bfv_rns.py` | Independent arithmetic oracles, bounds, native lifetimes, concurrency and default parameters |
| `tests/unit/native/test_bfv_rns.cpp` | Standalone native oracles for sanitizer runs |
| `benchmarks/bfv_server.py` | Repeated native comparisons and optional SEAL comparison |

Crypto paths above are relative to `src/cuhepy/x_vec/`.

## Verification and benchmarks

```bash
.venv/bin/python -m pytest tests/unit/test_bfv_encryption.py \
  tests/unit/test_bfv_evaluator.py tests/unit/test_bfv_rns.py \
  tests/unit/test_bfv_client.py -q

g++ -std=c++17 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
  -I src/cuhepy/bfv/_cpu_ext \
  tests/unit/native/test_bfv_rns.cpp -lgmpxx -lgmp -o /tmp/test_bfv_rns
/tmp/test_bfv_rns

.venv/bin/python benchmarks/bfv_server.py --num-vectors 1024 \
  --backends optimized,rns --seal --repeats 3 --json-out /tmp/bfv-rns-1024.json
```

Omit `--seal` when TenSEAL is not installed. The test suite covers zero, maximum,
sparse and random coefficients; digit boundaries at 59/60/61 bits; 512 one-bit
digits; exact signed rounding; repeated multiplication; malformed buffers;
partial tiles and multiple responses; public-only evaluation in another process;
key reload; and missing-extension fallback. Standalone tests reach N=32768.
LeakSanitizer cannot run under the local tracing sandbox: setting
`ASAN_OPTIONS=detect_leaks=0` keeps address and undefined-behavior checks enabled
there. CI runs the standalone sanitizer executable without that override.

Native backends share identical public keys and encrypted inputs. Every timed
search must produce identical native ciphertexts and correct plaintext distances.
SEAL uses the same vectors with its own keys and parameters; its result is
checked against every plaintext distance. Search order alternates, and first-use
preparation is reported separately from subsequent warm searches. Profiles are
extra runs excluded from timing samples.

Native timings include ciphertext decoding/encoding and terminal compaction,
but exclude the outer MessagePack envelope. SEAL timings include its envelope
and temporary-file binding I/O. Neither includes key import, index/query
encryption, client decryption, network time, or top-k content retrieval. The
comparison measures practical server calls; it does not establish equal security
or identical cryptographic work across schemes.

Validation for this change passed 151 offline tests across the BFV experiment,
CLI and SDK crypto suites, including 69 BFV tests. API integration and GPU tests
were excluded. Ruff, formatting checks, mypy and the standalone address/undefined-
behavior sanitizer run passed. A built platform-tagged wheel loaded its own
native module and completed an encrypted Hamming search. The Sphinx build passed
with the pre-existing README cross-reference warning in `bfv-packed-hamming.md`.

### Recorded measurements

Measured on 2026-09-10 on an AMD Ryzen 7 5800X with Python 3.12.3, GMP 6.3.0,
GCC 13.3.0 (`-O3`, without `-march=native`) and TenSEAL 0.3.16. Each vector has
512 bits. Native parameters
are N=8192, t=65537, q=180 bits, six 30-bit gadget digits and a 50-bit terminal
response modulus. The SEAL context has four active primes of 43/43/44/44 bits,
plus a 44-bit special prime for keys, with its TC128 security setting.

| Vectors | Server backend | First search (s) | Warm median (s) |
| ---: | --- | ---: | ---: |
| 32 | Previous GMP (`optimized`) | 1.7459 | 1.6894 |
| 32 | Native C++ RNS/NTT (`rns`) | 0.5007 | 0.2624 |
| 32 | Preserved SEAL prototype | 0.0775 | 0.0748 |
| 1,024 | Previous GMP (`optimized`) | 55.7613 | 55.9025 |
| 1,024 | Native C++ RNS/NTT (`rns`) | 8.3291 | 8.0355 |
| 1,024 | Preserved SEAL prototype | 2.4032 | 2.3901 |

The 32-vector run has one first search and three warm searches per backend;
the 1,024-vector run has one first search and two warm searches. On the larger
workload the native backend is **6.96 times faster** than the previous GMP
backend. SEAL remains **3.36 times faster**, compared with 23.39 times faster
than GMP in the same measurement. These are local repeated measurements, not
a claim about all machines or parameter sets.

Both native backends returned exactly the same encrypted responses on every
run. For 1,024 vectors, each response is 102,496 bytes and query plus response
is 471,250 bytes with the benchmark's MessagePack envelope. The minimum native
response noise budget is 26 bits. The arithmetic optimization changes neither
those ciphertext bytes nor the original scheme's security assumptions.

The 1,024-vector native server caches 16 transformed keys: 50,331,648 bytes of
coefficient arrays plus 2,752,512 bytes of transform tables. The previous GMP
server reports 52,083,728 bytes of prepared-key payload. Both are additional
to the loaded public key and exclude containers, CRT constants and temporary
allocations; these figures are not peak process memory.

Raw samples, parameters, correctness checks, source/binary hashes and timing
boundaries are saved in `benchmarks/results/native_bfv_rns_32.json` and
`benchmarks/results/native_bfv_rns_1024.json`. The additional Python profile is
`benchmarks/results/native_bfv_rns_profile_32.txt`. Profiles show native tile
evaluation alongside the remaining Python validation and serialization work;
they do not separately attribute time inside the C++ kernel.

## Remaining differences from SEAL

The native backend still reconstructs large GMP coefficients after key switches
and uses them between operations. SEAL has an integrated RNS representation and
specialized base conversion. Our backend also allocates scratch arrays per call
and retains Python wire parsing/validation and result merging. Those are further
optimization opportunities. Current code remains experimental, variable-time
leveled BFV with the same limitations as the [native implementation](native-bfv.md).
