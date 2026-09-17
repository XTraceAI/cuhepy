# Native BFV implementation

The SDK now has its own BFV arithmetic and Hamming client. It uses Python and the
existing `gmpy2` dependency; it does not import SEAL or TenSEAL. The earlier
`experiments/bfv/` implementation remains an independent SEAL reference.

This is a **leveled BFV research implementation** for understanding the scheme and
developing faster kernels. It has no bootstrapping, is not constant time, and has
not undergone an independent cryptographic audit. The
[internal security review](native-bfv-security.md) records hardening, tests and
open production blockers. The parameter settings below are arithmetic defaults,
not a claim of a particular security level.

The optional [authenticated session layer](native-bfv-verified-sessions.md)
adds request/index binding, private Hamming result checks, encrypted private
exports and admission limits. It preserves the server arithmetic and raw APIs;
the follow-up report measures its overhead and records the remaining blockers.

The newer [pre-decryption approval layer](native-bfv-predecryption.md) requires
an owner-controlled verifier to recompute and approve exact response bytes.
It also introduces a separate native private decoder and a larger parameter
review profile. Its report explains the additional trust/compute cost, attack
regressions and remaining production review requirements.

## Code map

All paths are relative to the repository root.

| File | Responsibility |
| --- | --- |
| `src/cuhepy/encryption/bfv.py` | Polynomial arithmetic, key generation, encryption/decryption, batch encoding, homomorphic operations, evaluation keys, modulus switching, serialization |
| `src/cuhepy/encryption/bfv_evaluator.py` | Cached public-key server arithmetic, with optimized, reference and optional RNS backends |
| `src/cuhepy/encryption/bfv_rns.py` and `src/cuhepy/bfv/_cpu_ext/` | Optional native RNS/NTT CPU arithmetic and its Python boundary |
| `src/cuhepy/bfv_client.py` | `HammingClientBase` interface, binary-vector layout, public-only server evaluation, packed responses, client decoding |
| `src/cuhepy/x_vec/utils/xtrace_types.py` | BFV parameter, polynomial, ciphertext and key types alongside the existing scheme types |
| `tests/unit/test_bfv_encryption.py` | Independent polynomial oracle and cryptographic arithmetic tests |
| `tests/unit/test_bfv_evaluator.py` | Fused key-switch oracle, exact reference comparisons, validation and cache lifecycle tests |
| `tests/unit/test_bfv_client.py` | Client, persistence, process separation, packing boundaries, default settings and optional SEAL comparison |
| `benchmarks/bfv_client_matrix.py` | Native BFV and existing CPU Paillier/Lookup timing and wire-size comparison |
| `benchmarks/bfv_server.py` | Native comparisons on identical encrypted inputs, with first/warm searches, optional SEAL comparison and profiles |

The only shared cryptographic interface correction is to the return annotations
in `HomomorphicBase`: encryption returns a ciphertext, and decryption returns a
plaintext. Existing Paillier code uses the same type for both, so its behavior is
unchanged. No Paillier implementation or SEAL experiment was replaced.

## Local use

```python
import json

from cuhepy.bfv.client import BFVClient

client = BFVClient(embed_len=512, device="cpu")
query = [0, 1] * 256
vectors = [query[:], [1 - bit for bit in query], [1 - query[0], *query[1:]]]

# The server gets configuration and public/evaluation keys only.
server = BFVClient(skip_key_gen=True, server_backend="optimized")
server.load_config(json.loads(client.stringify_config()))
server.load_stringified_keys(client.stringify_pk())
assert server.keys is None

encrypted_index = client.encrypt_vec_packed(vectors)
encrypted_query = client.encrypt_vec_one(query)
response = server.encode_hamming_server_packed(
    encrypted_query, encrypted_index, vector_count=len(vectors)
)
distances = client.decode_hamming_client_packed(response, len(vectors))
assert distances == [0, 512, 1]
top3 = sorted(range(len(vectors)), key=lambda i: (distances[i], i))[:3]
assert top3 == [0, 2, 1]

# Keep this on the private client when saving/restoring its state.
saved_sk = client.stringify_sk()
restored = BFVClient(skip_key_gen=True)
restored.load_config(json.loads(client.stringify_config()))
restored.load_stringified_keys(client.stringify_pk(), saved_sk)
assert restored.decode_hamming_client_packed(response, len(vectors)) == distances
```

For the existing per-vector interface, use `encrypt_vec_batch(vectors)`, call
`server.encode_hamming_server(encrypted_query, ciphertext)` for each result, and
pass those results to `decode_hamming_client_batch`. This returns one encrypted
distance per vector. `encrypt_vec_batch` deliberately keeps that contract;
packing is exposed through separate methods.

`device="auto"` currently resolves to CPU. `device="gpu"` raises a clear error.
`server_backend="optimized"` is the default; use `"reference"` for the original
server arithmetic. This is a runtime setting, so it is not stored in
`stringify_config()` and is preserved when loading a crypto configuration.
Reuse a server instance across queries to reuse its prepared public keys.
`load_stringified_keys()` discards the evaluator cache when loading keys. Change
keys through this method rather than mutating an initialized public-key dictionary.

An optional `server_backend="rns"` uses our compiled CPU RNS/NTT kernels. See
[native BFV RNS/NTT arithmetic](native-bfv-ntt.md) for the SEAL source review,
build instructions, exact arithmetic bounds and benchmark comparisons.

`server_backend="native"` uses the [complete C++ server](native-bfv-server.md)
with direct packed-buffer import/export, native result merging and compaction,
and faster exact arithmetic. Client encryption and decryption retain this
scheme's implementation and format.

BFV is available directly as a local client; `ExecutionContext`, `DataLoader`,
and the current XTrace HTTP endpoints do not implement its index/wire protocol.
Adding a production server path is separate work. Distances are computed at the
server; selecting the top three still happens after client decryption.

## How the scheme works

The polynomial ring is `Z_q[X]/(X^N + 1)`. Plaintexts have N coefficients modulo
`t`; ciphertexts normally have two polynomials modulo `q`. `BFV.batch_encode`
maps N integer slots into a polynomial using the Chinese Remainder Theorem. Our
finite-field NTT performs that transform, with no floating-point arithmetic.
The slots form two independently rotating rows of N/2 entries. This follows the
[textbook's BFV batching construction](https://fhetextbook.github.io/BatchEncoding.html).

In the implementation's sign convention:

```text
Delta = floor(q/t)
secret key: s, with coefficients in {-1, 0, 1}
public key: (b, a), where a is uniform and b = -a*s + e mod q
encrypt m: (b*u + e0 + Delta*m, a*u + e1) mod q
decrypt:   round(t * (c0 + c1*s mod q) / q) mod t
```

`u` is another random ternary polynomial. Each error coefficient is sampled as
the difference between two independent sums of `eta` random bits. Key generation
and encryption use Python's OS-backed `secrets` module. Benchmark seeds affect
synthetic input vectors only. See the textbook's
[encryption and decryption section](https://fhetextbook.github.io/EncryptionandDecryption1.html)
for the underlying scale-and-noise construction.

Multiplication first computes the three tensor-product polynomials as **exact
integers**, rounds each coefficient after multiplication by `t/q`, and then
reduces modulo `q`. Reducing the tensor product modulo `q` before scaling would
lose information required to recover the message. Relinearization replaces the
third component's dependence on `s²` with two components under `s`, using public
gadget keys. Scaling before relinearization is a valid ordering; see
[BFV multiplication](https://fhetextbook.github.io/CiphertexttoCiphertextMultiplication.html).

The public gadget key for a source polynomial `f` has pairs satisfying
`b_i + a_i*s = 2^(i*decomposition_bits)*f + e_i mod q`. It is used with `f=s²`
for relinearization and `f=s(X^g)` for a rotation. The evaluator decomposes the
corresponding ciphertext component into radix digits and combines these pairs.
It does not receive `s`. A key fingerprint catches accidental key mixups; it
does not authenticate ciphertexts or serialized key material.

### GMP polynomial multiplication

`_poly_product` is the main optimization boundary. It packs nonnegative
coefficients into one GMP integer with a radix wider than any possible
convolution coefficient. A GMP integer multiplication then computes the ordinary
convolution. Unpacking and subtracting the upper half implements `X^N = -1`.
The result remains exact, including negative coefficients, until the caller
scales or reduces it. Squaring reuses the packed operand and one cross product.

This is **Kronecker substitution**. The reference and optimized GMP backends use
a single large modulus; only their plaintext batch transform uses an NTT.
The small-ring schoolbook oracle tests products through 512-bit
coefficients, including worst-case all-maximum inputs that exercise radix carries.

The optimized evaluator accelerates gadget decomposition/key switching as
described below. The optional [RNS/NTT backend](native-bfv-ntt.md) now implements
an alternative polynomial multiplication path on the CPU. It preserves the
unreduced product needed by BFV's scale-and-round step. CUDA kernels remain
future work.

### Cached and fused server evaluation

The original server profile is dominated by key switching for rotations and
relinearization. With the default six gadget digits, each switch originally
made twelve polynomial products. Each product scanned coefficient widths,
packed both operands, unpacked the convolution, folded its upper half and
reduced coefficients. Intermediate results were added and reduced again.

`BFVEvaluator` keeps the same arithmetic but performs less repeated work:

1. Lazily pack each public evaluation key once, then reuse it across tiles and
   queries. Cache entries belong to one public-key snapshot and are limited to
   the number of evaluation keys in that snapshot.
2. Pack each ciphertext digit once for both output components. Accumulate all
   six products for each component inside GMP, before unpacking or reducing.
3. Fold the accumulated product inside GMP using a guarded radix subtraction.
   Unpack just two N-coefficient polynomials per switch, instead of twelve
   ordinary convolutions with up to 2N coefficients each.
4. Check native integer coefficient types without repeated `Integral` ABC
   lookups or conversions to Python integers, and check ranges using `min` and
   `max`. Other integer types still use the reference validator. Wire parsing
   and validation remain in place.

This follows the same digit/key dot product as the textbook's
[BFV key switching](https://fhetextbook.github.io/HomomorphicKeySwitching1.html).
It changes how that dot product is evaluated, not the keys or error terms.
The packing uses the existing
[GMP `pack` and `unpack` operations](https://gmpy2.readthedocs.io/en/latest/mpz.html).
Ciphertext multiplication still uses the reference exact tensor product and
scale-and-round, followed by the optimized relinearization.

For the packing bound, let L be the number of gadget digits and b their width.
An ordinary convolution coefficient in the accumulated dot product is less
than `L*N*2^b*q`. The radix width is
`w = bit_length(q) + b + bit_length(L*N) + 1`. Thus each coefficient is below
`H = 2^(w-1)`. Split the packed product at N radix digits, subtract its upper
half from its lower half, and add H in every digit. Each resulting digit lies
strictly between zero and `2^w`, so there is no borrow or carry between lanes.
Unpack N digits, subtract H, and reduce modulo q. Linearity makes this exactly
the same as folding and reducing every individual product before summation.
Tests cover zero, sparse, random and maximum coefficients, including a one-bit
gadget radix, a single gadget digit and 512-bit coefficients.

The tradeoff is extra server RAM for prepared public keys. These are local
caches; no cache data is serialized or sent to the client. Both backends produce
identical ciphertext coefficients for identical inputs, including after response
compaction, so their noise budgets and query/response sizes also match.

## Packed Hamming layout

Let `D` be the embedding length rounded up to a power of two, and let
`B = N/(2D)`. Each ciphertext stores `2B` database vectors. Within each row,
dimension `j` occupies the B slots beginning at `j*B`; those slots belong to
different candidate vectors. Query encryption repeats its bit across those
lanes. Missing dimensions and unused candidate lanes are padded with zeros.

The server squares the slotwise difference: for binary inputs, `(a-b)^2` is the
XOR bit. Rotating and adding by `B, 2B, 4B, ...` sums the D dimensions separately
for each candidate. A plaintext mask retains one copy of each distance and
clears unused lanes. A binary merge tree rotates distance tiles into disjoint
positions, filling up to N result slots per response ciphertext.

For the defaults, `N=8192`, `D=512`, `B=8`: an encrypted index ciphertext holds
16 vectors, while a response ciphertext holds up to 8192 distances. Input order
is restored during decoding. IDs stay with the caller; it must supply the true
`vector_count` and preserve the index order. Dimension, key and layout must be
shared consistently between client and evaluator.

The finished response is rounded to a smaller modulus to reduce transmitted
bytes. This terminal switch changes its coefficient width from 180 to 50 bits.
The implementation does not provide evaluation keys for multiplication or
rotation at the reduced modulus. Pass `compact=False` to server evaluation to
retain the original modulus for further work or noise comparisons.

## Parameters and limits

| Setting | Default | Meaning |
| --- | ---: | --- |
| `poly_modulus_degree` | 8192 | N, the ring degree and number of batch slots |
| `plain_modulus` | 65537 | t, a prime congruent to 1 modulo 2N |
| `coeff_modulus_bits` | 180 | q is the largest probable prime below 2^180 |
| `decomposition_bits` | 30 | Gadget radix is 2^30; six digit pairs per evaluation key |
| `error_eta` | 21 | Centered-binomial error variance is eta/2 |
| `response_modulus_bits` | 50 | Terminal response modulus width |

`embed_len` must be positive, at most N/2, and smaller than t, so valid Hamming
distances do not wrap modulo t. The parameter checks enforce algebraic
constraints, not cryptographic security or sufficient noise for every circuit.
Small ring settings used in tests are explicitly insecure. The defaults and
SEAL's settings are different; performance comparisons do not imply equivalent
security.

`BFV.noise_budget` is a private diagnostic requiring the secret key. It must not
be exposed as a server oracle. A positive budget cannot establish the integrity
of a result or rule out earlier noise overflow. Tests and benchmarks compare
every decoded distance against independent plaintext computation. The client
also rejects distances outside `[0, embed_len]`, but in-range errors can still
occur if an unsupported circuit exhausts its noise.

## Tests and benchmarks

```bash
.venv/bin/python -m pytest tests/unit/test_bfv_encryption.py \
  tests/unit/test_bfv_evaluator.py tests/unit/test_bfv_client.py -q
.venv/bin/python benchmarks/bfv_client_matrix.py --num-vectors 1024 \
  --json-out /tmp/native_bfv_matrix.json

# Compare original and optimized native servers using the same ciphertexts.
.venv/bin/python benchmarks/bfv_server.py --num-vectors 1024 --repeats 3 \
  --json-out /tmp/native_bfv_server_1024.json

# Smaller comparison, plus separate profiles (not included in timing samples).
.venv/bin/python benchmarks/bfv_server.py --num-vectors 32 --repeats 4 \
  --profile-dir /tmp/bfv-profiles --json-out /tmp/native_bfv_server_32.json

# Compare both BFV layouts and both existing CPU Paillier clients on a small batch.
.venv/bin/python benchmarks/bfv_client_matrix.py --num-vectors 16 \
  --variants bfv-packed,bfv-individual,paillier-cpu,paillier-lookup-cpu
```

The optional SEAL sanity test runs when `tenseal` from
`experiments/bfv/requirements.txt` is installed; otherwise that test is skipped.
The core and all other new tests work without it. Tests cover two multiplication
levels, rotations, public-only evaluation in another process, invalid inputs,
key persistence, multiple response groups, partial tiles and default 512-bit
vectors. No account, network connection or GPU is needed.

The benchmark reports key generation/export/import, index and query encryption,
server evaluation, client decryption/decoding, and serialization separately.
`--repeats` generates independent runs; raw results and median timings are saved.
Use `--server-backend reference` in the matrix benchmark to run the original
native evaluator. Its server time includes first-use cache preparation for the
optimized backend. The focused `bfv_server.py` benchmark instead shares one key
set and encrypted input between both backends, alternates their execution order,
and reports first-search and subsequent warm-search times separately. Every
search must return the same ciphertexts and all plaintext-oracle distances.
Its profiles are additional runs excluded from reported timings.
The four size categories are:

| Measurement | What is included | When it is paid |
| --- | --- | --- |
| Encrypted index | Encrypted database vectors with count/framing | Upload/storage, then updates |
| Public keys | Public encryption and evaluation keys serialized as JSON; no secret key | Server setup or key rotation |
| Query | One encrypted query with framing | Each search, client to server |
| Response | Encrypted distances with framing | Each search, server to client |

Index, query and response use the same MessagePack envelope across schemes;
large integers are encoded as little-endian byte strings. These are measured
serialized lengths, not Python object sizes. IDs are implicit positions. AES
content, HTTP/TLS overhead, network latency and top-k content retrieval are
excluded. The public-key JSON representation is intentionally readable and
considerably larger than a compact binary format would be. Comparisons use the
current branch's explicit CPU Paillier clients, not GPU timings.

The ratio `Paillier(query + response) / BFV(query + response)` measures recurring
traffic savings. Index and key costs are separate. A smaller BFV response alone
does not guarantee less total traffic for a small database.

### Initial measurement: 1,024 vectors of 512 bits

The [saved run](../../benchmarks/results/native_bfv_1024.json) is in
`benchmarks/results/native_bfv_1024.json` (2026-09-10,
Python 3.12.3, gmpy2 2.3.0, GMP 6.3.0). Both variants used the same synthetic
inputs. Each decrypted all 1,024 distances correctly and selected positions
`[0, 1023, 81]` as the top three, with distances `[0, 0, 220]`. This is one CPU
run, not a statistically established performance claim. The JSON includes
source-file SHA-256 hashes because the implementation was uncommitted during
measurement; no other test or benchmark was running concurrently. All SDK source
hashes identify the initial reference implementation; the server optimization
is measured separately below. The benchmark harness received formatting and
lint fixes outside the measured operations afterward.

| Bytes | Native BFV, packed | Existing Paillier CPU, key_len=1024 |
| --- | ---: | ---: |
| Encrypted index | 23,598,496 | 528,396 |
| Public/evaluation keys, JSON | 85,602,812 | 2,502 |
| Query | 368,754 | 544 |
| Response | 102,496 | 528,403 |
| Query + response | 471,250 | 528,947 |

The response is **5.16 times smaller**, while query plus response is **1.12 times
smaller**, about **10.9% fewer bytes**. The BFV index contains 64 ciphertexts and
the response contains one; Paillier uses 1,024 ciphertexts for each. These native
results do not inherit the earlier SEAL experiment's traffic ratios.

| Seconds, excluding wire serialization | Native BFV, packed | Paillier CPU |
| --- | ---: | ---: |
| Key generation | 4.323 | 0.526 |
| Encrypt index | 6.749 | 10.528 |
| Encrypt query | 0.104 | 0.010 |
| Server compute | 108.296 | 0.00545 |
| Client decrypt and decode | 0.0413 | 7.045 |

BFV's result retained a 26-bit diagnostic noise budget after compaction.
Server compute and larger index/key storage are the present costs of moving
distance decoding off the client. The result is a working optimization baseline,
not an end-to-end latency improvement.

Validation for the initial implementation: 121 offline tests passed across `experiments/bfv`,
`tests/cli`, and `tests/x_vec`, with the live Hamming/metadata service tests and
CUDA tests excluded. The new native modules account for 39 of those tests,
including the optional SEAL oracle in this environment.

### Server optimization measurements

The paired benchmark keeps the same native BFV parameters, public keys, query
and encrypted index for both backends. Its first search includes lazy cache
preparation; later searches reuse the prepared keys and plaintext masks. Each
search checks both exact ciphertext equality and every decoded Hamming distance.
The server uses only public keys. These are local CPU measurements with no
concurrent tests or other benchmarks, not network or production latency results.

Saved data and a profile summary:

- [32-vector comparison](../../benchmarks/results/native_bfv_server_32.json):
  one first search and three warm searches per backend.
- [1,024-vector comparison](../../benchmarks/results/native_bfv_server_1024.json):
  one first search and two warm searches per backend.
- [32-vector profiles](../../benchmarks/results/native_bfv_server_profile_32.txt):
  separate extra searches after warming both servers. Instrumented timings are
  excluded from the speedup calculations.

| 512-bit vectors | Search | Reference seconds | Optimized seconds | Speedup |
| ---: | --- | ---: | ---: | ---: |
| 32 | First, including preparation | 3.391 | 1.878 | 1.81x |
| 32 | Warm median, 3 searches | 3.648 | 1.866 | 1.96x |
| 1,024 | First, including preparation | 121.564 | 60.355 | 2.01x |
| 1,024 | Warm median, 2 searches | 118.244 | 58.627 | 2.02x |

The earlier 108.296-second result is retained as historical data. Ratios here
use reference and optimized runs from the same benchmark session, so variation
between sessions is not counted as an optimization benefit. The saved JSON
includes the environment, all timing samples, execution order, source hashes,
cache payload size, wire sizes and correctness results.

In the 32-vector profiles, Python function calls fall from 19,838,069 to
3,581,974, and GMP unpack calls from 268 to 58. Most remaining evaluation time
is in the fused gadget dot products, primarily the large GMP integer products.
The cache trades extra server memory for less repeated work; its recorded byte
count covers prepared GMP integers and folding constants, not total process
memory or peak temporary allocations. Ciphertext outputs, noise and transmitted
sizes match exactly between backends for the same input.

The 1,024-vector run prepared 16 switch keys with 52,083,728 bytes of cached
GMP values (about 52.1 MB, additional to the original public key). Both backends
returned one 102,496-byte response; query plus response was 471,250 bytes. All
1,024 distances matched, top-three positions were `[0, 1023, 81]`, and the
compacted result retained a 26-bit diagnostic noise budget. These native settings
remain distinct from SEAL's; this benchmark compares native backends only.

Validation after optimization: 130 offline tests passed, including 48 native BFV
tests and the optional SEAL oracle. Ruff and mypy passed for the SDK and BFV
benchmark files. The live service and CUDA tests remain excluded from this CPU
change. An offline Sphinx build retains the preexisting README cross-reference
warning in the earlier SEAL research report.

### 8,192-vector comparison (2026-09-17)

There is no 1,024-vector limit in the homemade BFV client. That was the earlier
development workload; packed evaluation processes additional index tiles and
returns `ceil(vector_count/N)` response ciphertexts. With 8,192 vectors, both
parameter profiles below still return **one** response ciphertext, while
Paillier returns 8,192. The larger batch amortizes BFV's fixed query cost.

These new runs use the same 8,192 synthetic 512-bit vectors and query, seed 1337,
the current C++ `residue` backend, and standard CPU Paillier with 1,024-bit primes.
One Paillier baseline is shared between the two BFV comparisons. The runs were
sequential, with no concurrent tests or other benchmarks. Each variant checked
**every distance** against plaintext Hamming distance and selected the same top
three positions: `[0, 8191, 2654]` with distances `[0, 0, 217]`.

Both BFV profiles use t=65,537, a 180-bit product modulus, 30-bit gadget digits,
eta=21 and 50-bit response compaction. N=8,192 retains the earlier engineering
ring size; N=16,384 matches the arithmetic parameters in `bfv_review_policy()`.
Neither comparison establishes equivalent cryptographic security to Paillier
or SEAL.

| Exact serialized bytes | Paillier CPU | Homemade BFV, N=8,192 | Homemade BFV, N=16,384 |
| --- | ---: | ---: | ---: |
| Query upload per search | 544 | 368,754 | 737,394 |
| Response download per search | 4,226,979 | 102,496 | 204,900 |
| **Query + response per search** | 4,227,523 | 471,250 | 942,294 |
| Encrypted index | 4,226,979 | 188,787,740 | 188,765,728 |
| Public/evaluation keys, JSON | 2,502 | 85,603,562 | 171,204,881 |

| BFV profile versus the same Paillier baseline | Response reduction factor | Query + response reduction factor | Fewer query + response bytes |
| --- | ---: | ---: | ---: |
| N=8,192 | 41.24× | 8.97× | 88.9% |
| N=16,384 review parameters | 20.63× | 4.49× | 77.7% |

A reduction factor is `Paillier bytes / BFV bytes`. Index and public/evaluation
keys are initial upload/storage or key-rotation costs, excluded from recurring
query-plus-response totals. They are substantially larger for BFV. The index
contains 512 ciphertexts at N=8,192 and 256
at N=16,384. Increasing the ring halves the index ciphertext count while
doubling each ciphertext's size; it also increases the query and response size.

All three variants use the same MessagePack framing with implicit candidate IDs
and little-endian integer bytes. Counts exclude HTTP/TLS, explicit IDs, content
retrieval and private keys. This measures raw BFV, including when using the
review parameters: it does not include the authenticated/Nitro protocol,
receipts, attestation or network transport. The local Nitro protocol is
measured separately in the [Nitro report](native-bfv-nitro.md). These sizes do
not inherit the original SEAL experiment's different framing or security
configuration.

Single-run CPU timings on an AMD Ryzen 7 5800X are included for context:

| Seconds, excluding serialization | Paillier CPU | Homemade BFV, N=8,192 | Homemade BFV, N=16,384 |
| --- | ---: | ---: | ---: |
| Encrypt index | 86.237863 | 54.573942 | 56.275379 |
| Public server computation, first search | 0.043897 | 19.836359 | 20.878492 |
| Client decrypt/decode | 57.763218 | 0.041912 | 0.086103 |

These are one fresh setup and one first search per variant, not warm medians or
a statistically established latency comparison. BFV's first search includes
lazy public-key cache preparation. Client decode uses the raw client's GMP
path, without the guarded/attested client's native private decoder or receipt
checks. No GPU, EC2 or live service was used. Minimum compacted diagnostic noise
budgets were 26 bits (N=8,192) and
25 bits (N=16,384); these diagnostics are
correctness observations, not security-level estimates.

Raw records, including exact commands, configuration, phase timings, correctness
and source/native-binary hashes:

- `benchmarks/results/native_bfv_8192.json`: N=8,192 BFV and the shared Paillier baseline.
- `benchmarks/results/native_bfv_review_8192.json`: N=16,384 BFV on the same input.

Reproduce sequentially from the repository root:

```bash
.venv/bin/python benchmarks/bfv_client_matrix.py \
  --num-vectors 8192 --embed-len 512 --poly-modulus-degree 8192 \
  --server-backend residue --rns-modulus \
  --variants bfv-packed,paillier-cpu --repeats 1 \
  --json-out benchmarks/results/native_bfv_8192.json

.venv/bin/python benchmarks/bfv_client_matrix.py \
  --num-vectors 8192 --embed-len 512 --poly-modulus-degree 16384 \
  --server-backend residue --rns-modulus \
  --max-public-key-chars 268435456 --variants bfv-packed --repeats 1 \
  --json-out benchmarks/results/native_bfv_review_8192.json
```

The benchmark's explicit public-key import allowance accommodates the larger
locally generated review-profile key bundle. SDK and protocol defaults are
unchanged. The records identify base commit `be71b0d`
and the measured working-tree source hashes; the benchmark-only changes add
that import option and native source/binary provenance.
