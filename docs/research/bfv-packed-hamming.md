# BFV for XTrace: repository analysis and first experiment

Research date: 2026-09-08. Experimental branch: `research/bfv-packed-hamming`,
based on `staging-GPU-paillier-client` at `c8fc6838aec81e2c3a05fbd5c0c9c0e8635beb26`.
The local `main` reference used for comparison is
`0f8522e449d00622e10f4111ac8eb89d52ca577b`. No remote refresh was performed.

**BFV can substantially reduce the distance-response payload.** The implemented
experiment computes distances under BFV and packs them before returning them.
For 8,192 binary vectors of dimension 512, the measured response fell from
4.26 MB to 127 KB including IDs and framing, a 33.4× reduction. Query plus response
fell by 7.6×. The cost was an approximately 52× larger encrypted index and a
39.6 MB public/evaluation-key bundle. These are local measurements, not a production
service or GPU performance claim.

Packing still returns all candidate distances. Returning only the top three
requires a separate encrypted comparison and selection protocol. No such protocol
is implemented here. Existing Paillier ciphertexts are not automatically usable
as BFV ciphertexts.

## What the repository implements

The repository is the Python **client SDK**, with public arithmetic helpers and
CUDA client extensions. It does not contain the deployed search server. The
experiment therefore supplies a local server evaluator rather than changing the
live API.

| Area | Responsibility and relevance |
| --- | --- |
| `src/xtrace_sdk/x_vec/inference/embedding.py` | Produces embeddings through Sentence Transformers, Ollama, or OpenAI. `float_2_bin` thresholds each coordinate with `> 0`. Search operates on those binary vectors, not the original floating-point vectors. Provider selection determines where embedding plaintext is processed. |
| `x_vec/data_loaders/loader.py` | AES-encrypts document text, binarizes embeddings, encrypts the binary index through the homomorphic client, and uploads via the integration. Supports per-vector and batch encryption. Metadata is supplied separately. |
| `x_vec/crypto/encryption/paillier.py` | Standard additive Paillier over plaintexts modulo `n`, with ciphertext multiplication modulo `n²` implementing plaintext addition. `key_len` is the bit length of **each prime**. |
| `x_vec/crypto/encryption/paillier_lookup.py` | Custom variant with an alternative decryption exponent `a`, tables for powers of `g` in 8-bit message chunks, and a randomization table. Its parameter/security analysis is separate from this BFV experiment. |
| `x_vec/crypto/{paillier_client,paillier_lookup_client}.py` | Packs bits with zero separators, dispatches CPU/GPU encryption and decryption, serializes keys/configuration, and supplies an offline public-key Hamming-encoding helper. |
| `x_vec/crypto/*_gpu_ext/` | CUDA/GMP/pybind11 implementations using CGBN for big integers, batched modular operations, and decoding/popcount. The lookup implementation also caches tables and exposes decrypt/re-encrypt helpers; those helpers require secret material and cannot simply move to an untrusted server. |
| `x_vec/crypto/device.py` | Chooses the requested CPU/GPU implementation or probes for automatic selection. It changes execution, not the result format or candidate count. |
| `x_vec/crypto/encryption/aes.py`, `crypto/key_provider.py` | AES-256-GCM for contents and protected secret-key storage; scrypt passphrases or AWS KMS envelope keys. BFV does not need to replace content encryption. |
| `x_vec/utils/execution_context.py` | Bundles the homomorphic client and AES/key-provider state, serializes/restores it locally or remotely, and enforces the embedding/key-size constraints. Current supported contexts remain Paillier and Paillier-Lookup. |
| `integrations/xtrace.py` | Async HTTP API for chunks, metadata, contexts, knowledge bases and administration. Queries use base64 ciphertexts in JSON. Distance responses are read completely and decoded as MessagePack or JSON. |
| `x_vec/retrievers/retriever.py` | Encrypts queries, downloads candidate encodings, decrypts/decodes every distance, then calls `np.argsort(... )[:k]`. A second request fetches selected chunks for AES decryption. Optional multiprocessing changes client decoding, not the wire volume. |
| `cli/` | Initialization/environment and cached session state; file chunking; load/upsert/fetch/retrieve and knowledge-base commands; interactive shell. These routes ultimately use the same SDK clients and integration. |
| `x_vec/inference/llm.py` | Optional RAG inference using retrieved plaintext context. Provider choice defines its separate plaintext boundary. |
| Other crypto / `x_mem` | Goldwasser–Micali is a separate XOR-capable implementation; Merkle commitments are a partial utility and do not provide search-result verification. Signatures and `x_mem` are placeholders. |
| `tests/` | Offline encryption, embedding conversion, execution-context/key persistence and CLI tests; separate live API tests; CPU/GPU interoperability tests. |
| `docs/`, `examples/` | Sphinx API/manual pages and a quick-start notebook documenting the same client workflow. |
| `pyproject.toml`, `hatch_build.py`, `build_gpu_binaries.sh`, `.github/workflows/` | Hatch/VCS packaging, CUDA builds and binary wheel tagging, lint/type checks, offline tests, gated GPU/integration tests and release/docs workflows. |

Paths abbreviated to `x_vec/...` in the table are relative to `src/xtrace_sdk/`.
The existing untracked `benchmarks/paillier_client_matrix.py` is preserved.

The branch comparison shows the GPU work primarily changes client dispatch,
CUDA implementations, configuration, packaging and tests. The primitive encryption
modules, retriever and integration are identical between the recorded `main` and
starting GPU-branch commits. Their response protocol has not been changed by the
GPU work.

## The current arithmetic and I/O bottleneck

For a binary vector `x`, the client effectively encodes a base-four integer:

```text
P(x) = sum_j x[j] * 4^(d - 1 - j)
```

Each base-four digit is represented by the binary pair `0x[j]`. Adding two such
encodings produces digits in `{0, 1, 2}` without carries between coordinates.
The low bit of each digit is `x[j] XOR q[j]`. Counting those low bits after
decryption gives the Hamming distance.

The server can obtain `Enc(P(x) + P(q))` through Paillier ciphertext multiplication.
It cannot use Paillier's additive operation alone to evaluate the nonlinear bit
extraction and popcount that the SDK currently performs after decryption.
Consequently, the returned encrypted object encodes coordinate-wise sums, not a
single scalar distance already computed on the server.

`XTraceIntegration.compute_hamming_distances` awaits `res.read()` and parses the
whole response. `Retriever.nn_search_for_ids` then decodes all candidate results
and ranks them. There is no `k` argument in the distance API request. Reducing
`k` from ten to three does not reduce this response.

The payload consists of one encrypted **result per candidate** (possibly multiple
chunks for larger vectors), not all AES-encrypted documents. Metadata/range
filters can restrict the candidate set first. Only the selected documents are
fetched afterwards. Thus the relevant scaling variable is the number of candidates
after filtering, which can be much smaller than the whole database.

At the benchmark defaults, `key_len=1024` means approximately 2,048-bit `n`, so
each ciphertext modulo `n²` occupies about 512 binary bytes. GPU execution and
lookup tables retain that ciphertext representation. Streaming the existing
response could overlap download and decryption and reduce memory, but would not
remove these bytes.

## What BFV adds, and what “put Paillier inside BFV” could mean

BFV supports exact modular-integer addition and multiplication. With batch
encoding, one ciphertext holds many independent integer slots. SEAL's BFV
batching has `N` slots arranged as two rows of `N/2`; a prime plaintext modulus
congruent to `1 mod 2N` enables that encoding.
[SEAL batch-encoding example](https://github.com/microsoft/SEAL/blob/main/native/examples/2_encoders.cpp)

For binary vectors, the distance is the low-depth arithmetic expression

```text
h_i = sum_j (x[i,j] - q[j])²
    = sum_j (x[i,j] + q[j] - 2*x[i,j]*q[j]).
```

The first form needs one encrypted subtraction and square per packed input,
followed by encrypted sums. Both database and query remain encrypted. If the
plaintext modulus exceeds `d` and the noise budget remains positive, decoding
gives the exact integer distance. This experiment uses `t=65537` and `d<=4096`.

There are three distinct interpretations of the mentor's suggestion:

| Interpretation | Assessment |
| --- | --- |
| Encrypt the bytes/limbs of existing Paillier ciphertexts inside BFV | This retains the Paillier representation and adds an encryption layer. It does not itself extract the small distance or make randomized ciphertext bytes compressible. |
| Evaluate Paillier decryption and distance decoding homomorphically under BFV | Possible in principle with appropriately encrypted secret-key material and a sufficiently capable circuit. It requires large-integer modular arithmetic and bit extraction; it is not ordinary BFV key switching. No practical implementation of this conversion was established in this investigation. |
| Compute the distances directly under BFV, then pack results from many input ciphertexts | Implemented here. This is a plausible interpretation of the demo, but cannot be identified as the actual demo without its code. It requires BFV-encrypted index data. |

These distinctions follow from the two schemes' plaintext representations and
available operations; they are design conclusions, not a claim that all possible
hybrid protocols have been ruled out. An interactive conversion protocol is also
a separate avenue and would need its own trust, leakage and round-trip analysis.
The textbook's BFV key-switching discussion concerns changing the secret key of
an RLWE ciphertext, not a turnkey Paillier-to-BFV conversion.

## The implemented packing layout

Let `M` be the number of candidates, `d` the embedding dimension, `N=8192` the
slot count, and `D` the next power of two at least `d`. Define
`B=N/(2D)` lanes in each BFV row and `C=2B` records per input ciphertext.
At `d=512`, `D=512`, `B=8`, and `C=16`.

Each input tile arranges a BFV row as follows; the second row holds another
eight candidates:

```text
row 0: [dimension 0 of candidates 0..7]
       [dimension 1 of candidates 0..7]
       ...
       [dimension 511 of candidates 0..7]

row 1: the same arrangement for candidates 8..15
```

The query repeats each bit across the eight lanes, then repeats that row.
The same one-ciphertext query is reused for every tile. This avoids sending
one full BFV ciphertext per query dimension.

1. Subtract query from encrypted tile and square slotwise. Relinearize to two
   ciphertext polynomials.
2. Rotate rows by `B, 2B, 4B, ...` and add. This sums across dimensions while
   keeping different candidate lanes separate. It takes `log2(D)` rotations.
3. Apply a public plaintext mask, keeping only the first `B` distances in each
   row and zeroing invalid candidates in the final tile.
4. Merge results from different ciphertexts with rotations and additions. A
   binary carry tree uses one rotation per merge and logarithmic intermediate
   ciphertext memory. It handles incomplete groups as well as full groups.
5. After up to `D` tiles, the output holds up to `N` distances. Drop unused
   coefficient-modulus primes before serialization.

This reduction uses approximately `ceil(M/C)` input ciphertexts and
`ceil(M/N)` response ciphertexts. For a full 8,192-record, 512-dimensional group,
there are 512 input ciphertexts, 512 squares, 4,608 dimension-sum rotations,
511 packing rotations, and one returned ciphertext. The whole index packet is
still materialized in memory; the logarithmic bound applies to intermediate
arithmetic, not index storage or MessagePack parsing.

Rows rotate independently in BFV. The code keeps both rows separate and decodes
their known layout back to original record order. It does not assume a flat
8,192-slot circular rotation. This matches SEAL's
[rotation model](https://github.com/microsoft/SEAL/blob/main/native/examples/6_rotation.cpp).

The server uses fixed, SEAL-validated `TC128` parameters. Final modulus switching
reduces ciphertext size while consuming remaining computation capacity. It happens
only after packing, when no further encrypted arithmetic is needed.
[SEAL's levels example](https://github.com/microsoft/SEAL/blob/main/native/examples/3_levels.cpp)

`noise_probe.py` demonstrates why simply halving the ring is unsuitable for this
particular circuit and parameter set. In the 4,096-slot trial, coefficient-prime
sizes were `[36,36,37]`: remaining noise was about 21 bits after the square, 13
after summation, and **zero after masking**. The 8,192-slot version retained ample
budget at that stage. Exact numbers vary with fresh encryption randomness.
This is a failure of that tested configuration, not a proof that every possible
4,096-slot Hamming design fails. The main prototype excludes that configuration.

## Measurements and interpretation

The raw [measurement records](../../experiments/bfv/results/measurements.jsonl)
contain seed, dependency versions, source hashes, exact byte counts, phase timings
and the baseline commit. These runs use 512-dimensional synthetic binary vectors,
sequential integer IDs, `k=3`, standard Paillier with 1,024-bit primes, and one
query per newly built index. Encryption randomness is fresh; only the synthetic
plaintext data is seeded. Every decoded distance and selected ID was checked.

Sizes below use decimal KB/MB. **Response sizes include IDs and MessagePack framing.**
For a full BFV block, the ciphertext itself is about 103 KB; the remainder is
primarily candidate IDs. Real ID widths and transport framing affect the ratio.

| Candidates | Paillier response | BFV response | Response reduction | Query + response reduction |
| ---: | ---: | ---: | ---: | ---: |
| 256 | 132.7 KB | 103.6 KB | 1.28× | 0.25×: BFV transfers about 4× more |
| 2,048 | 1.065 MB | 109.0 KB | 9.77× | 1.97× |
| 8,192 | 4.259 MB | 127.4 KB | 33.43× | 7.61× |

The BFV query is approximately 432.6 KB in all these runs; the modeled current
Paillier JSON/base64 query is 798 bytes. Ignoring setup, the first BFV result block
therefore needs roughly a thousand candidates before **bidirectional** byte
savings begin. The much lower download-only crossover is not enough to establish
total I/O savings.

For 8,192 candidates:

| Cost | Paillier | BFV |
| --- | ---: | ---: |
| Binary index model | 4.26 MB | 221.44 MB |
| Public/evaluation setup | About 2.5 KB | 39.59 MB |
| Local server evaluation + response serialization | 0.105 s | 20.093 s |
| Local client response decoding + stable top-k | 56.958 s | 0.012 s |

The BFV index is about 52× larger. Each input ciphertext holds only 16 vectors;
packing the **results** more tightly does not remove the storage needed for the
input coordinates. At this candidate count, about 3.70 MB are saved per query.
Byte-only amortization takes approximately 11 queries for the extra key bundle,
or 70 queries including the extra index. At 2,048 candidates those counts are
approximately 76 and 180. These calculations use binary Paillier index storage;
the actual JSON/base64 ingest protocol adds further overhead.

These timing figures are illustrative local CPU measurements, not controlled
service benchmarks. They include the prototype's file-based serialization and
input parsing; they exclude actual network transfer, HTTP/TLS, authentication,
embeddings, AES content fetch, and multi-user contention. The large run overlapped
part of the existing test execution, so use isolated repeated runs for timing
decisions. Byte counts and correctness checks are unaffected. The baseline uses
the recorded `main` CPU cryptography and a local reference server operation,
with the same stable client top-k routine on both paths; it is not a replay of
the live service or its exact sorting implementation.

**Do not infer a speedup over the optimized GPU/lookup branch from this table.**
Its decryption cost may be much smaller than this CPU baseline. BFV adds server
work; at a fast network link that extra work can outweigh the reduced traffic.
A useful next timing comparison is:

```text
latency = query encryption + server evaluation + client decoding/selection
          + query_bytes / upload_bytes_per_second
          + response_bytes / download_bytes_per_second
          + common round-trip overhead
```

Apply that model with the intended GPU server/client hardware, actual candidate
counts, index update rate, and asymmetric link bandwidth. Amortize setup and
index costs separately. The experimental code does not automatically choose a
backend from these estimates.

## Boundaries and next steps

The implementation and commands are in the
[experiment README](../../experiments/bfv/README.md). Production source and
dependencies remain unchanged. The generated assets contain measurements only;
no document data, API credentials, ciphertext indexes or secret keys are committed.

For a usable BFV option, the next steps are:

1. **Reconcile this layout with Liwen's demo.** Determine whether it used native
   BFV distances, a hybrid conversion, or encrypted selection. Its parameters,
   trust model, input format and measured bytes matter more than the scheme name.
2. **Benchmark the real workload and hardware.** Compare standard Paillier and
   Paillier-Lookup with their effective parameter settings, include GPU decode,
   and measure update/storage costs and amortized key transfer. The current
   measurements compare configurations, not equal-security cryptosystems.
3. **Introduce a separate BFV index and endpoint.** The existing `EncryptedVector`
   and `HammingClientBase` interfaces model per-record integer ciphertext lists.
   Packed BFV tiles and multi-distance responses need an explicit, versioned
   interface rather than changing the meaning of those existing methods.
4. **Reindex on the client.** Use retained binary vectors, regenerated local
   embeddings, or client-side decryption of existing Paillier index encodings.
   Keep the AES content and record IDs, and retain a Paillier index for fallback.
   An existing Paillier-only knowledge base cannot answer a BFV query as-is.
5. **Implement tile-aware storage, updates and filtering.** Selecting arbitrary
   IDs cannot simply relabel packed slots. Metadata/range filters need matching
   lane masks and result compaction or prepartitioned indexes. A single-record
   update may require rewriting a tile or a separately designed update protocol.

If the goal is strictly **only three encrypted results on the wire**, add a
separate encrypted top-k experiment after packed distance evaluation. Exact
comparisons are not a native cheap BFV operation: a sorting/selection network
needs comparison circuits plus conditional moves, increasing depth and server
cost. IDs may need multiple limbs because real 64-bit IDs do not fit in one slot
modulo 65,537. Tie handling and whether the server learns selected IDs must be
specified. A final ordinary fetch by client-selected ID reveals an access pattern,
as it does in the current SDK.

OpenFHE provides comparison/argmin examples through CKKS↔FHEW scheme switching.
That is a concrete direction to investigate, not a drop-in Paillier→BFV or
BFV→top-k conversion. Integer ranking correctness and conversion boundaries would
need testing. [OpenFHE scheme-switching example](https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/scheme-switching.cpp)

The threat model for this prototype is a single key owner and honest evaluation.
The server sees IDs, count and dimension, and receives encrypted vectors/query
plus public evaluation keys. Key-ID/schema checks catch accidental mismatches;
they do not authenticate messages, bind responses to queries, prevent replay or
prove correct computation. Noise and decrypted-result diagnostics remain local.
These protocol limits follow SEAL's documented distinctions around authenticity,
circuit privacy and decryption feedback.
[SEAL security guidance](https://github.com/microsoft/SEAL/blob/main/SECURITY.md)

There is also a concrete dependency issue before any deployment: Microsoft now
recommends SEAL 4.4.0 or later for fixes involving untrusted inputs and native
memory safety. The convenient TenSEAL 0.3.16 experiment wheel must not be treated
as evidence of an updated native backend. Use a verified, maintained backend
before exposing the evaluator or deserializer to service traffic.
[SEAL update notice](https://github.com/microsoft/SEAL)

## Reading guide for the provided textbook

The supplied PDF is Ronny Ko's *The Beginner's Textbook for Fully Homomorphic
Encryption*, arXiv:2503.05136v26, dated 2026-06-02. Its relevant **printed** pages
and sections are:

| Section | Printed page | Why it matters here |
| --- | ---: | --- |
| D-2.2, Batch Encoding | 137 | Explains SIMD integer slots and encoding. |
| D-2.3, Encryption and Decryption | 139 | Explains the plaintext/noise distinction and correctness conditions. |
| D-2.4–D-2.7, Arithmetic | 140–149 | Covers addition, plaintext masking, ciphertext multiplication and relinearization. |
| D-2.8, Key Switching | 151 | Clarifies that key switching is within the RLWE construction. |
| D-2.9, Slot Rotation | 151–163 | Supplies the operation used for dimension sums and result packing. |
| D-2.11, Bootstrapping | 164 onward | Useful for deeper circuits; unnecessary for this one-square distance circuit. |

The book's [online BFV chapter](https://fhetextbook.github.io/BFVScheme.html)
is also available. For implementation details, use the SEAL batching, rotation
and modulus-level examples linked at the relevant points above; the low-level
Python bindings are exposed by
[TenSEAL's `sealapi`](https://github.com/OpenMined/TenSEAL/blob/main/tenseal/sealapi/__init__.py).

## Validation recorded for this branch

The BFV suite passed all 28 tests, including a separate-process server, full and
partial output groups, both batching rows, dimension padding, exact matches,
complements, ties, randomized encryption, malformed messages, and modulus
compaction. The three benchmark sizes also checked every distance and top-k.

The final combined run passed **82 tests**: 28 BFV tests and 54 existing CPU/CLI
tests. It excluded the live API modules and the GPU test module:

```bash
.venv/bin/python -m pytest experiments/bfv tests/cli tests/x_vec \
  --ignore=tests/x_vec/test_hamming_search.py \
  --ignore=tests/x_vec/test_meta_search.py \
  --ignore=tests/x_vec/test_GPU_paillier_clients.py -q
```

Ruff and mypy passed for the production source and the typed experiment code.
The initial existing offline regression run had 56 passes and seven GPU failures:
the compiled extensions import, but encryption raises `cudaErrorNoDevice`, and
`nvidia-smi` cannot communicate with the driver. This predates the experiment;
no production source was modified. Live API tests were not run.
