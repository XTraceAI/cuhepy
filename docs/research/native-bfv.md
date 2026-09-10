# Native BFV implementation

The SDK now has its own BFV arithmetic and Hamming client. It uses Python and the
existing `gmpy2` dependency; it does not import SEAL or TenSEAL. The earlier
`experiments/bfv/` implementation remains an independent SEAL reference.

This is a **leveled BFV research implementation** for understanding the scheme and
developing faster kernels. It has no bootstrapping, is not constant time, and has
not undergone a security audit. The parameter settings below are arithmetic
defaults, not a claim of a particular security level.

## Code map

All paths are relative to the repository root.

| File | Responsibility |
| --- | --- |
| `src/xtrace_sdk/x_vec/crypto/encryption/bfv.py` | Polynomial arithmetic, key generation, encryption/decryption, batch encoding, homomorphic operations, evaluation keys, modulus switching, serialization |
| `src/xtrace_sdk/x_vec/crypto/bfv_client.py` | `HammingClientBase` interface, binary-vector layout, public-only server evaluation, packed responses, client decoding |
| `src/xtrace_sdk/x_vec/utils/xtrace_types.py` | BFV parameter, polynomial, ciphertext and key types alongside the existing scheme types |
| `tests/x_vec/test_bfv_encryption.py` | Independent polynomial oracle and cryptographic arithmetic tests |
| `tests/x_vec/test_bfv_client.py` | Client, persistence, process separation, packing boundaries, default settings and optional SEAL comparison |
| `benchmarks/bfv_client_matrix.py` | Native BFV and existing CPU Paillier/Lookup timing and wire-size comparison |

The only shared cryptographic interface correction is to the return annotations
in `HomomorphicBase`: encryption returns a ciphertext, and decryption returns a
plaintext. Existing Paillier code uses the same type for both, so its behavior is
unchanged. No Paillier implementation or SEAL experiment was replaced.

## Local use

```python
import json

from xtrace_sdk.x_vec.crypto.bfv_client import BFVClient

client = BFVClient(embed_len=512, device="cpu")
query = [0, 1] * 256
vectors = [query[:], [1 - bit for bit in query], [1 - query[0], *query[1:]]]

# The server gets configuration and public/evaluation keys only.
server = BFVClient(skip_key_gen=True)
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

This is **Kronecker substitution**, not SEAL's RNS implementation. Ciphertext
arithmetic uses a single large modulus; only the plaintext batch transform uses
an NTT. The small-ring schoolbook oracle tests products through 512-bit
coefficients, including worst-case all-maximum inputs that exercise radix carries.

Natural next optimizations are cached transform plans, RNS/NTT polynomial
products, faster gadget decomposition/key switching, then CUDA kernels behind
the same primitive operations. Any replacement must preserve the unreduced
product needed by BFV's scale-and-round step.

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
.venv/bin/python -m pytest tests/x_vec/test_bfv_encryption.py tests/x_vec/test_bfv_client.py -q
.venv/bin/python benchmarks/bfv_client_matrix.py --num-vectors 1024 \
  --json-out benchmarks/results/native_bfv_1024.json

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
hashes match this implementation. The benchmark harness received formatting and
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

Validation for this change: 121 offline tests passed across `experiments/bfv`,
`tests/cli`, and `tests/x_vec`, with the live Hamming/metadata service tests and
CUDA tests excluded. The new native modules account for 39 of those tests,
including the optional SEAL oracle in this environment.
