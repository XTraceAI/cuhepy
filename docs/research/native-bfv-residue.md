# Persistent RNS BFV server

The measurements below describe the initial residue backend. The follow-up
[fused NTT and RNS scaling report](native-bfv-fused-rns.md) documents the current
default kernels and ABI 4; the earlier kernels remain available as controls.

`BFVClient(rns_modulus=True, server_backend="residue")` keeps ciphertexts as
arrays of 60-bit residues after the initial BFV tensor scale-and-round. Key
switching, rotations, additions, plaintext masks and the result merge tree run
on these arrays in our own C++. The reference, optimized, `rns` and `native`
backends can evaluate the same keys and ciphertexts and give exactly the same
output coefficients. The existing Paillier and SEAL implementations are retained.

## Configuration and compatibility

This is an explicit new cryptographic configuration. It requires **fresh keys
and a fresh encrypted index**. Existing prime-modulus keys cannot be used with
`residue`; they continue to work with the previous backends. Nothing migrates
keys or ciphertexts automatically.

The default remains `rns_modulus=False` and `server_backend="optimized"`.
When the RNS option is off, parameter serialization and key fingerprints retain
their original representation, including compatibility with saved v1 keys.
When enabled, `rns_modulus: true` is serialized in the configuration and public
key parameters and included in the fingerprint. Ciphertexts keep the same
packed format and contain the actual Q and key identity.

The first residue layout supports ciphertext modulus sizes 60, 120, ..., 480
bits. For each ring degree, it selects distinct primes below 2^60 with
`p = 1 mod 2N`, in the same deterministic order as the auxiliary NTT bases.
The default 180-bit Q is the product of three such primes. The binary gadget,
error sampling, plaintext modulus, batching, encryption and exact rounding
algorithms are unchanged. An equal-bit response-compaction request retains Q
instead of increasing it to the same-bit prime.

This remains experimental leveled BFV with no independent audit or security-level
claim; see the [internal security review](native-bfv-security.md). It uses no SEAL
code and performs no bootstrapping. The performance
comparison below does not establish equivalent security to SEAL's parameters.

## Build and use

The extension interface is now ABI 3. Rebuild an older binary:

```bash
make -C src/cuhepy/bfv/_cpu_ext PYTHON="$PWD/.venv/bin/python"
```

```python
import json
from cuhepy.hamming.bfv import BFVClient

client = BFVClient(embed_len=512, rns_modulus=True, server_backend="residue")
server = BFVClient(skip_key_gen=True, server_backend="residue")
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

Both individual and packed search methods use the new server. Reuse a server
across queries to amortize public-key and mask preparation. Key generation,
encryption and client decryption continue to use our Python/GMP scheme.
Top-k selection still happens on the client. These local interfaces do not add
BFV support to the production HTTP endpoints.

## Why the representation matters

Previously, auxiliary primes only accelerated polynomial products. Their
product M differed from the ciphertext modulus q. Every key switch had to
convert both output components back to GMP integers and reduce them modulo q.
Rotations, additions and the merge tree then operated on those GMP objects.

With Q equal to the product of the ciphertext primes, the Chinese Remainder
Theorem identifies arithmetic modulo Q with componentwise arithmetic modulo
each prime. A key-switch product needs only these primes, regardless of the
unreduced integer convolution's size: its result is needed modulo Q. The
default key-switch basis shrinks from four primes to three. Ciphertext additions
and automorphisms become small-word loops; masks multiply directly in this
basis. This follows the residue representation described in the textbook's
[RNS operations section](https://fhetextbook.github.io/ApplyingRNSTechniquestoFHEOperations.html).

Binary gadget decomposition still needs the unique coefficient in [0,Q).
`ResidueArithmetic::compose_words` reconstructs it with exact mixed-radix
(Garner) arithmetic, using fixed 64-bit limbs and 128-bit products. It neither
allocates GMP integers nor estimates a CRT quotient with floating point. For
residues r_j, it finds mixed-radix digits d_j by repeatedly computing
`(value - d_k) * inverse(p_k) mod p_j`, then forms
`d_0 + p_0*(d_1 + p_1*(...))`. Each d_j is in [0,p_j), so this is the canonical
representative. Its binary gadget digits are the same as the reference's.
Digits up to 60 bits are extracted once and reused across primes. Wider gadgets
are reduced in chunks of at most 60 bits; the maximum supported Q uses eight
64-bit limbs. No additional evaluation keys or special key-switch prime are
introduced.

The scale-and-round in ciphertext multiplication still requires the signed
integer tensor before reducing modulo Q. It uses the existing sufficiently
large auxiliary base, exact GMP CRT and signed rounding. After that step, the
ciphertext remains in RNS until the final response is composed and compacted.
This preserves exact coefficient equality with our reference, including its
rounding choices and noise behavior for the same key. Ciphertexts normally use
coefficient-form residues between operations; transforms are applied for
polynomial multiplication, rather than keeping every operation in NTT form.

## Reproduce the comparison

```bash
.venv/bin/python benchmarks/bfv_server.py --num-vectors 1024 \
  --rns-modulus --backends native,residue --seal --repeats 4 \
  --native-profile --json-out /tmp/bfv-residue-1024.json
```

Use `--num-vectors 32` for the small workload. Omit `--seal` when TenSEAL is
unavailable. `benchmarks/bfv_client_matrix.py` also accepts `--rns-modulus` and
`--server-backend residue`. Native backends receive identical public keys and
encrypted inputs; every result must match exactly and decrypt to all expected
Hamming distances. SEAL gets the same plaintext vectors with its own parameters.
The first search includes lazy cache setup; three warm searches follow, with
backend order alternating. Additional profiled searches are excluded from
timing medians. Run without concurrent tests or benchmarks.

## Recorded results

The final comparisons and phase profiles are recorded below. All times are
seconds on the AMD Ryzen 7 5800X, Python 3.12.3, GMP 6.3.0, GCC 13.3.0 (`-O3`)
and TenSEAL 0.3.16. There is one CPU evaluation thread, with no GPU or SEAL code
in our backend. Each native row uses N=8192, t=65537, a 180-bit product Q, six
30-bit gadget digits, error eta=21 and 50-bit terminal compaction.

| Vectors | Backend | First search | Median of three warm searches |
| ---: | --- | ---: | ---: |
| 32 | `native`, same product Q | 0.5182 | 0.1591 |
| 32 | `residue` | 0.3970 | 0.0873 |
| 32 | SEAL prototype | 0.0772 | 0.0775 |
| 1,024 | `native`, same product Q | 5.6354 | 5.2780 |
| 1,024 | `residue` | 3.1145 | 2.8064 |
| 1,024 | SEAL prototype | 2.4680 | 2.4814 |

At 1,024 vectors, residue takes **46.8% less server time** than native with the
same keys and inputs: a **1.88x speedup**. Its warm time is **13.1% longer** than
SEAL's in this run. The small workload improves by 45.1%. Every ciphertext from
our two backends matches exactly, including the compacted response. Every
decoded distance matches the plaintext oracle for every backend.

SEAL uses active coefficient-prime sizes [43,43,44,44] and an additional 44-bit
special key-switch prime, with its TC128 setting. Our scheme has different
parameters and key switching, with no matching security-level claim. Native
server times include framing, ciphertext decoding/encoding, arithmetic and
compaction, but exclude outer MessagePack. The preserved SEAL prototype also
includes its MessagePack and temporary-file binding I/O. Key import, encryption,
client decryption and network time are excluded. These are practical server
calls, rather than timings of identical cryptographic kernels.

The 1,024-vector response is 102,496 bytes and query plus response is 471,250
bytes, matching the preceding native experiment's measured sizes. The encrypted
index is 23,598,495 bytes and serialized public keys are 85,603,326 bytes. This
change targets compute, with the same packed wire structure. Small byte-count
variation between fresh keys/runs is possible. Both native backends have a
26-bit minimum response noise budget here; SEAL reports 19 bits for its own
parameters and noise diagnostic.

Prepared C++ key payload falls from 56,623,104 to 42,467,328 bytes (25% less),
with the same 18 keys. This is an additional runtime cache, not the serialized
BFV setup-key download. Transform-table payload is 2,752,512 bytes in either
backend; prepared plaintext tables/masks use 655,360 versus 589,824 bytes.
These figures exclude containers, small CRT constants and transient allocations.

Raw samples, environment, exact modulus/primes, ciphertext checks and source/
binary hashes are in `benchmarks/results/native_bfv_residue_32.json` and
`benchmarks/results/native_bfv_residue_1024.json`.

An additional 1,024-vector control kept the original prime-modulus configuration
and `native` backend: first search 5.8559 seconds, warm median 5.4560 seconds.
Its raw data is in `benchmarks/results/native_bfv_residue_prime_control_1024.json`.
This is a separate run with fresh random encryption, not part of the interleaved
same-key comparison used to calculate the 1.88x speedup. The earlier recorded
5.3426-second native result is retained in [the previous report](native-bfv-server.md).

## What remains slower than SEAL

The additional exclusive phase profile for 1,024 vectors shows the effect of
retaining residues. These are instrumented extra searches, excluded from the
performance medians above.

| Phase | `native` | `residue` |
| --- | ---: | ---: |
| Forward NTT | 1.5804 | 1.2114 |
| Inverse NTT | 0.5974 | 0.4784 |
| GMP CRT reconstruction/conversion | 0.7341 | 0.1790 |
| Separately instrumented reduction modulo Q | 0.4763 | 0 |
| Fixed-word RNS composition | 0 | 0.0589 |
| Gadget extraction/conversion | 0.0637 | 0.0816 |
| Automorphisms | 0.3657 | 0.0311 |
| Additions/subtractions | 0.1871 | 0.0586 |
| Pointwise products/accumulation | 0.4527 | 0.2873 |
| Scale-and-round | 0.1639 | 0.1625 |

Both perform 703 key switches. Forward transforms fall from 18,280 to 13,934;
inverse transforms fall from 7,480 to 5,946. The residue path has 194 GMP CRT
operations: three tensor components for each of 64 tiles, plus two final
response components. The earlier native path has 1,726. Reductions inside the
remaining tensor/compaction work are charged to their own scopes, so the zero
`mod_q` entry does not mean that all big-integer modular arithmetic is gone.
The full JSON retains the other phases and exact call counts.

Forward/inverse NTT now account for about **60%** of our profiled time. The
remaining GMP CRT and scale-and-round account for about **12%**. The fixed-word
reconstruction needed for binary gadget extraction is about **2%**. Python,
binding and unscoped work together account for about **3%**.

Source inspection points to two concrete areas for the next optimization:

- SEAL's [NTT implementation](https://github.com/microsoft/SEAL/blob/v4.1.2/native/src/seal/util/ntt.cpp)
  and [transform handler](https://github.com/microsoft/SEAL/blob/v4.1.2/native/src/seal/util/dwthandler.h)
  use transform-ordered root tables and specialized/unrolled Harvey butterflies.
  Our kernels still use a separate negacyclic twist pass and generic cyclic
  butterfly loops with strided root access. Tuning that kernel now targets most
  of our search time. The installed SEAL wheel's optional acceleration features
  have not been established; these results do not assume Intel HEXL is enabled.
- SEAL's [BFV evaluator](https://github.com/microsoft/SEAL/blob/v4.1.2/native/src/seal/evaluator.cpp)
  and [RNS tools](https://github.com/microsoft/SEAL/blob/v4.1.2/native/src/seal/util/rns.cpp)
  perform BEHZ-style multiplication with RNS base conversion, division and
  scaling. Our tensor scale-and-round still reconstructs exact GMP integers.
  Replacing that boundary requires preserving BFV's rounding/noise semantics;
  dividing each residue independently would be incorrect.

These are source-based explanations and measured bottlenecks in our code.
We have not instrumented SEAL's internal phases, so we cannot assign an exact
fraction of the remaining 0.325-second gap to each difference. Changes to
transform kernels and RNS multiplication can be measured independently using
the preserved native engine as an oracle. Further changes to private key
generation or encryption would not affect this server-search metric.

## Implementation files and verification

| Path relative to the repository | Responsibility |
| --- | --- |
| `src/cuhepy/bfv/_cpu_ext/bfv_residue.h` | Persistent RNS ciphertexts, fixed-word reconstruction and complete server |
| `src/cuhepy/bfv/_cpu_ext/rns_ntt.h` | Shared NTT/key dot products and optional ciphertext-prime basis |
| `src/cuhepy/bfv/_cpu_ext/bfv_server.h` | Shared layout, masks and streaming merge order |
| `src/cuhepy/bfv/_cpu_ext/bindings.cpp` | Validated ABI 3 boundary and native plan selection |
| `src/cuhepy/encryption/bfv.py` | Optional product modulus and compatible key serialization |
| `src/cuhepy/encryption/bfv_rns.py` | Compiled arithmetic context and key preparation |
| `src/cuhepy/bfv_client.py` | Client configuration and backend selection |
| `tests/unit/test_bfv_residue.py` | Saved-key compatibility, parameters, exact search comparisons |
| `tests/unit/native/test_bfv_rns.cpp` | Independent integer/gadget oracles across all supported Q widths |

The common native boundary tests also run with the residue backend: malformed
inputs, public-only evaluation, direct packed buffers, concurrent searches,
profiling, cache invalidation and capsule lifetimes. Standalone tests compare
mixed-radix reconstruction, gadget digits, key switching and rotations with
GMP and schoolbook integer oracles, including zero, Q-1, prime/word boundaries,
one-bit gadgets, wide gadgets and 480-bit Q. They also assert that a residue
key switch performs no GMP CRT reconstruction or reduction modulo Q.

Validation passed 192 offline tests, including 110 BFV tests; production API and
GPU tests were excluded. Ruff lint, mypy, and formatting checks for the BFV
modules, tests and benchmarks passed. A broader SDK formatting check reports
existing formatting differences in other modules and unchanged portions of
`xtrace_types.py`; those unrelated sections were left alone. Standalone
arithmetic and Python-binding AddressSanitizer/UndefinedBehaviorSanitizer runs
passed; the latter ran 25 server, compatibility and boundary tests against the
sanitized binary. The local tracing sandbox requires leak checking to be
disabled, as in the previous native-backend verification.

A built CPython 3.12 platform wheel includes the new header and ABI 3 extension.
An isolated import from that wheel passed public-only residue search and exact
native fallback comparison, without importing SEAL or TenSEAL.
The default N=8192 example above and both matrix-benchmark interfaces passed.
Sphinx built successfully with the existing README cross-reference warning in
`bfv-packed-hamming.md`; no new documentation warning was introduced.
