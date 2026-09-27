All notable changes to this project will be documented in this file.

## [Unreleased]

### Research

- Add a separate E15 joint-packing support-bound policy, with a deterministic
  whole-polynomial derivation, independent symbolic error propagation and
  CPU/CUDA precision-frontier regressions. Retain the conservative bound and
  authentication policies. Add paired byte/compute/transport measurements.
- Update the experimental agenda after a primary-source literature review of
  BioZKFHE, encrypted search, verifiable FHE, packing and conversion. Add E13–E19
  hypotheses with mathematical starting points, comparison contracts, cost
  ceilings and stop criteria. Separate raw GPU results from protected CPU
  execution and preserve all existing implementation/results baselines.
- Add a separate BGV Nitro protocol with owner-authorized immutable setup and
  queries, measured CPU evaluation, domain-separated receipts, replay/lease
  limits and mandatory verification before response parsing or decryption.
  Preserve the unauthenticated CUDA/fixture baselines. Add a local regression
  demonstrating why plaintext distance validation permits key recovery.
- Add a homemade fixed-work BGV terminal decoder using locked/wiped buffers,
  public-parameter selection of one-prime or exact two-prime NTT arithmetic,
  bounded native packed input and compiled GCC/Clang secret-taint tests. Query
  encryption/key generation and plaintext processing remain outside its scope.
  Include an isolated Nitro service/image recipe and authentication benchmarks;
  this remains research code pending independent review and real AWS testing.
- Record an additional 30.1%/33.8% reduction in complete local BGV search time
  at 8,192/32,768 vectors versus the previous persistent/RNS baseline. Record
  joint-precision payload reductions and codec/link tradeoffs for both index
  types, with raw paired trials and source/binary provenance. Validate 787 full
  suite tests, 118 public and 96 private ASan/UBSan tests, plus GPU memcheck,
  racecheck and synccheck on the public evaluator and new kernels.
- Add a bounded unsigned-128-bit public query/response codec specialization and
  native canonical response validation. Preserve the GMP mapping as an explicit
  reference and fallback; exhaustively compare drop positions across width and
  byte-alignment boundaries. Record complete compute gains and joint-precision
  tradeoffs in `docs/research/bgv-compute-followup.md`.
- Add c0-only terminal-response rounding and a joint query/response precision
  planner using complete public correctness bounds and exact framed byte counts.
  Retain independent Python/native codecs and malformed-input tests. Add paired
  compute ablations and joint-precision local/TCP benchmarks with complete
  ciphertext/distance checks and separate setup/fixture costs.
- Add independent BGV NTT indexing/warp/tile experiments and exact 192-bit
  terminal reduction on the GPU. Keep the existing kernels and CPU reduction
  as defaults and coefficient-level oracles.
- Add native packed response export and packed owner fixture finishing to
  remove Python coefficient round trips while preserving compact-v1 bytes,
  the expected-ciphertext gate and validation before private arithmetic.
- Add an explicit C++/GMP backend for the public BGV query codec, retaining
  byte-identical packets, the Python reference, strict native boundary checks
  and independent CPU/CUDA search comparisons.
- Record reduced BGV query traffic, codec costs and ingestion tradeoffs in
  `docs/research/bgv-query-compression.md`. Validate the public codec under
  ASan/UBSan (53 tests); the complete package/BFV-example/research suite passes
  719 tests with only the live Nitro integration skipped.
- Add an opt-in BGV seeded-query codec that rounds c0 by bounded multiples of
  the plaintext modulus, preserving exact messages under propagated no-wrap
  bounds. Add strict packet parsing, CPU/CUDA differential tests, a public
  precision planner, and paired local/TCP experiments with public-key and
  owner-encrypted index variants. Keep the current query format as a baseline.
- Add explicitly leased persistent BGV GPU workspaces with per-request completion,
  close/fork guards and concurrent-use tests. Add a separate private RNS/NTT owner
  backend, preserving the GMP reference and unchanged ciphertext formats.
- Add Nsight capture/summary tools, paired workspace and owner benchmarks, and
  bounded loopback TCP trials with application bandwidth/latency pacing. The
  transport fixture pins expected ciphertexts before decryption; it is not a
  remotely deployable authentication protocol.
- Add a homemade 30-bit CUDA NTT microbenchmark, an encrypted feature-major
  accumulate-before-relinearization reference, and a plaintext certified-filter
  cost oracle. Record negative results and communication tradeoffs explicitly.
- Validate the public CUDA oracle with Compute Sanitizer 12.9 memcheck/racecheck;
  extend private ASan/UBSan coverage to the opt-in owner RNS arithmetic.
- Add a fresh-query comparison of homemade BGV, BFV and Paillier CPU/CUDA paths,
  including Paillier lookup with the current 280-bit exponent configuration,
  role timings, actual packet sizes and source/binary provenance.
- Record the 8,192/32,768-vector workspace, private RNS and TCP studies,
  same-workload BFV/Paillier comparisons (including the Paillier hybrid),
  reversed-order narrow NTT results and algorithm tradeoffs in
  `docs/research/bgv-service-results.md`. The complete CUDA-enabled suite passes
  635 tests with only the live Nitro integration skipped.
- Add exact BGV result lookup tables, bounded heap top-k with stable ties, and
  a fused native owner finish path. Add explicit same-key/index multi-query
  CUDA evaluation with optional shared index reads, reusable per-call scratch,
  and a 4 GiB coefficient-workspace limit. Preserve independent single-query
  and reference paths; add paired latency/throughput and result-handling trials.
- Record ten-round finish/batch experiments at 8,192 and 32,768 vectors in
  `docs/research/bgv-finish-batch-results.md`, including faster client finishing,
  cases where existing host workers beat fused batches, memory/latency tradeoffs,
  native allocation refusals and public measurement artifacts.
- Add fresh BGV owner-query ablations: bulk independent OS error sampling,
  identical bulk SHAKE stream decoding, exact shifted-ternary GMP products, and
  a separate optional C++/GMP private owner extension. Add paired complete-search
  benchmarks, exhaustive sampling/algebra checks, native boundary and lifecycle
  tests. Keep the original reference and the public server independent; private
  arithmetic remains variable-time and outside the authenticated client paths.
- Record ten-trial owner comparisons at 8,192 and 32,768 vectors in
  `docs/research/bgv-owner-results.md`, with unchanged communication sizes,
  separate cache/setup costs, raw measurements and committed source hashes.
- Add paired BGV public-pipeline ablations: GPU query NTTs, fused and gathered
  automorphism/gadget kernels, shared evaluation-key reads, and exact C++ terminal
  compaction before export. Preserve every baseline and cryptographic parameter.
  Add concurrent-request throughput experiments and differential rounding,
  malformed-input, tail, stream-ordering and complete-ciphertext checks.
- Add a paired terminal-precision sweep with full-plaintext comparisons and
  explicit correctness-bound refusals; keep the 32-bit default and measure
  smaller responses under the same Q120 evaluation context.
- Record ten-trial BGV pipeline measurements at 8,192 and 32,768 vectors,
  concurrent-request throughput, and a 25-bit response experiment in
  `docs/research/bgv-public-pipeline-results.md`, with public measurement artifacts.
- Add joint BGV trace/packing with the established automorphism butterfly,
  an isolated native public evaluator with cached key/index transforms, and
  an independent SEAL 4.1.2 BGV circuit oracle. Preserve the per-tile reference
  and compare complete ciphertexts before measuring performance.
- Extend the isolated BGV evaluator with persistent RNS and CUDA, bounded
  terminal modulus reduction, fresh seeded owner queries, and paired 8,192-vector
  measurements. Fix query-upload ordering between pageable host transfers and
  nonblocking CUDA streams; add repeated-query and canonical-boundary regressions.
- Add a BFV search experiment plan covering client preparation, alternative
  circuits and layouts, GPU arithmetic, and communication. Include independent
  plaintext layout checks and an analytical partial-reduction cost model.
- Implement opt-in encrypted partial-sum CPU/CUDA experiments, a native SIMD
  encoder, seeded queries, and a bounded one-use preprocessing pool. Add paired
  complete-search measurements, capability-filtered network projections, and
  a depth-one BGV-style coefficient-packing reference with a correctness bound
  and three-product multiplication, plus encrypted ring-trace result packing.
  Preserve default clients and protocol
  bindings; the experiments have no production-security or novelty claim.

### Changed

- **The project is now `cuhepy`: a homomorphic-encryption library, not a client
  for a hosted service.** The XTrace vector-database integration, the `xtrace`
  CLI, the embedding/LLM wrappers, the data loader and retriever, the AES and
  key-provider layers, `ExecutionContext`, the Merkle commitment, and the
  Goldwasser-Micali scheme have all been removed. What remains is the Paillier
  and BFV schemes, their CPU and compiled backends, the encrypted Hamming
  kernel, and the research material.
- Layout separates primitives from the application built on them:
  `cuhepy.paillier.*` and `cuhepy.bfv.*` hold the schemes and their backends,
  and `cuhepy.hamming.*` holds the encrypted-search clients and BFV protocol
  layers that were previously mixed in with them. Imports run application →
  primitive only; the scheme packages no longer reference Hamming at all.
  Moved: `paillier.client` → `hamming.paillier`, `paillier.lookup_client` →
  `hamming.paillier_lookup`, `bfv.client` → `hamming.bfv`, and
  `bfv.{guarded_client,verified_client,attested_client,security,assurance,nitro}`
  → `hamming.bfv_{guarded,verified,attested,security,assurance,nitro}`.
  `device`, `keys`, `types`, `base` and `bench` sit at the top level.
- Runtime dependencies reduced to `gmpy2`, `numpy` and `pycryptodome`.
- Sphinx removed; documentation is Markdown in `docs/`.

### Added

- `cuhepy.keys` — save and load a keypair. Replaces `ExecutionContext`
  persistence without the key-management layer. Writes the secret key in
  plaintext at mode `0600` by design.
- `attacks/` — runnable demonstrations of the findings against our own schemes.

### Security

- **Paillier-Lookup `alpha_len` default raised from 50 to 280 (PL-01).** The
  public key exposes `g_n = g^n mod n^2`, whose order is the secret exponent
  `a`; at 50 bits, baby-step/giant-step recovered `a` from the public key alone
  in ~3.5 minutes on a laptop, after which any ciphertext decrypts. The new
  default matches the `ALPHA_LEN` the CUDA extension already compiled with, so
  CPU and GPU keys remain interchangeable. `PaillierLookupClient` now refuses to
  generate a keypair below `MIN_ALPHA_LEN` (256) unless `allow_weak_alpha=True`,
  and warns when loading a keypair generated with a weak exponent. Decryption
  cost rises from 0.15 to 0.66 ms/vector; encryption is unchanged.
  Demonstration: `attacks/pl01_alpha_recovery.py`. Full review:
  `docs/research/paillier-security.md`.

  **Keys generated with the previous default should be regenerated.**

### Changed

- Native `BFVClient` server evaluation now defaults to cached GMP key switching: gadget products are accumulated and folded before unpacking, with fewer coefficient checks in Python. `server_backend="reference"` retains the original arithmetic. Parameters, ciphertexts and serialized keys remain compatible. A paired server benchmark checks identical ciphertext outputs and separates first-query from warm-query timings.
- **Device selection moved from the `DEVICE` environment variable to a `device=` constructor keyword** on `PaillierClient`, `PaillierLookupClient`, `ExecutionContext.create`, `ExecutionContext.load_from_disk`, and `ExecutionContext.load_from_remote`. The new default is `device="auto"`: clients probe for the GPU extension at construction time and fall back to CPU silently when no GPU is present. If a GPU is detected on the host (`/dev/nvidia0`, `nvidia-smi`, or `CUDA_VISIBLE_DEVICES`) but the extension fails to load, a warning is emitted instead of a silent CPU fallback so misconfigured GPU hosts don't quietly run on CPU. `device="gpu"` raises if the extension is unavailable; `device="cpu"` skips probing entirely.
- The `DEVICE` environment variable is no longer read. Existing callers must migrate to the `device=` kwarg.

### Added

- Optional AWS Nitro `BFVAttestedClient`/`BFVAttestedServer` sessions: signed owner requests, exact image measurement pins, fresh attestation, and enclave response receipts checked before private decryption. The enclave evaluates once; the BFV secret stays on the owner. Includes the `bfv-nitro` extra, bounded relay/service, local image build records and an opt-in real AWS test. This remains experimental and requires hardware validation and independent review before production use.
- Persistent BFV `server_backend="residue"` arithmetic with a product of 60-bit primes, fused NTTs and exact RNS tensor scaling. Existing GMP, reference and earlier native backends remain available for differential tests; selecting the product modulus requires fresh keys and a new index.
- BFV execution policies, bounded authenticated sessions, protected private exports, and an owner-controlled recomputing verifier. A separate native private decoder provides fixed-work terminal arithmetic with locked/wiped buffers; this is not an end-to-end constant-time guarantee.
- Complete C++ BFV server evaluation through `server_backend="native"`: direct packed ciphertext buffers, prepared masks, native result merging and compaction, lazy transforms, Barrett reduction and certified CRT conversion modulo q with exact fallback. Includes opt-in native phase profiling; existing BFV keys, wire formats and backends remain compatible. The current optional extensions require public ABI version 4 and private ABI version 1.

- Optional native BFV `server_backend="rns"`, with independently implemented C++ RNS/NTT polynomial arithmetic, cached transformed evaluation keys, exact GMP reconstruction, and a native Hamming tile circuit. Preserves native BFV keys, ciphertext outputs and wire format. Includes native-boundary tests, sanitizer oracles, optional SEAL benchmarks and correctly tagged binary wheels. The previous GMP and reference backends remain available.
- Native GMP BFV primitives in `crypto/encryption/bfv.py` and a `BFVClient` in `crypto/bfv_client.py`, with CRT batching, ciphertext multiplication/relinearization, public-key Hamming evaluation, packed distance responses, and terminal modulus compaction. Includes CPU benchmarks and tests against plaintext algebra and an optional SEAL oracle. This is an experimental local implementation; the existing Paillier clients and SEAL research example are preserved.
- Offline BFV packed Hamming experiment under `experiments/bfv`, with an isolated public-key server evaluator, correctness tests, a comparison against an exported Paillier Git revision, and a research report. The production Paillier path and dependencies are unchanged.
- `cuhepy.device.resolve_device` — shared device-resolution helper used by both Paillier clients and intended for future homomorphic clients with optional GPU backends.
- `test_cross_device_interop` — parametrised test covering CPU↔GPU portability for both `PaillierClient` and `PaillierLookupClient`. Verifies that contexts saved on one device load correctly on the other (hash equality), and that ciphertexts produced on either backend round-trip correctly through the other for both encryption and server-side homomorphic add.

### Security

- BFV regression tests demonstrate secret-key recovery from malicious ciphertexts and observable post-decryption accept/reject behavior, even with private result checks. The guarded and Nitro clients require approval before decryption. Attestation authenticates approved execution under the TEE's assumptions; raw BFV remains malleable and is not given a general chosen-ciphertext security claim.
- Nitro rejects malformed certificate versions and duplicate extensions through the bounded protocol error path. Staging PRs now run quality checks, SEAL reference tests and strict documentation builds; the native sanitizer harness also supports the CFFI dependency installed by the Nitro extra.

## [0.2.0] - 2026-04-18

### Added

- **CUDA backend for Paillier and Paillier-Lookup homomorphic encryption.** The `.cu` sources are now in-tree under `src/cuhepy/paillier-GPU-{,lookup-}client/`, and the new `build_gpu_binaries.sh` script compiles both pybind11 extensions inside a pinned `nvidia/cuda:12.4.0-devel-ubuntu22.04` Docker container. No local CUDA toolkit is required on the build host — only Docker and `nvcc` (provided by the image). Runtime requires NVIDIA driver ≥ 550. Opt-in via `DEVICE=gpu`; CPU remains the default.
- `PaillierGPUClient` and `PaillierLookupGPUClient` — standalone GPU-backed Hamming clients for `ExecutionContext`. Type dispatch in `ExecutionContext.create` now accepts these as first-class alternatives to their CPU counterparts.
- Documented `DEVICE` environment variable in the configuration reference.
- "GPU acceleration" section in the installation docs covering build script usage, runtime requirements, and per-build knobs (`PYTHON_VERSION`, `SMS`, `KEY_BITS`, `ALPHA_LEN`, `CUDA_IMAGE`).

### Changed

- `DEVICE` is now resolved at client instantiation time rather than at module import time. Previously, setting `os.environ["DEVICE"]` after importing a client (common in notebooks) had no effect; the module-level constant was already frozen to `cpu`. The env var is now read fresh inside `PaillierClient.__init__`, `PaillierLookupClient.__init__`, and `PaillierLookupClient.__setstate__`, so CPU and GPU clients can be instantiated in the same process and ordering of imports no longer matters.
- Error messages raised when the GPU extension cannot be loaded now point users at `./build_gpu_binaries.sh` and document runtime driver requirements, replacing the previous stale reference to `src/crypto/` and non-existent documentation.

## [0.1.1] - 2026-03-31

### Fixed

- CLI commands failed to locate `.env` when installed from PyPI (`pip install xtrace-ai-sdk`). `dotenv.load_dotenv()` without arguments searches from the caller's file directory (site-packages), never reaching the user's working directory. All 13 call sites now use `find_dotenv(usecwd=True)` for cwd-based discovery. Editable installs (`pip install -e .`) were unaffected because the source tree sits under the user's home directory.
- `_chunk_into_pages` emitted oversized chunks when a single sentence exceeded `page_size`. These are now hard-split by character boundary. `_chunk_json` gains a `cap_json_elements` option to further split array elements that exceed the page size.
- `init` no longer warns about `.env` key conflicts when the existing value already matches the value being written. T

### Added

- `EmbeddingError` exception in `x_vec.inference.embedding` with `status` and `chunk_len` fields. The Ollama provider now parses error responses instead of raising a bare `aiohttp` `ClientResponseError`.
- `load` and `upsert-file` accept `--max-chunk-chars` to cap chunk size (splits oversized chunks via the text chunker) and `--max-parallel-embeddings` to limit concurrent embedding requests.
- All CLI commands that embed (`load`, `upsert`, `upsert-file`, `retrieve`) catch `EmbeddingError` and print context-specific hints (e.g. suggesting `--max-chunk-chars` for context-length errors, `--max-parallel-embeddings` for server-busy errors).

## [0.1.0] - 2026-03-30

### Initial release

- `XTraceIntegration` — HTTP client for the XTrace encrypted vector DB API (chunk CRUD, Hamming distance, metadata search, execution context management)
- `DataLoader` — encrypt and ingest document collections using Paillier homomorphic encryption + AES
- `Retriever` — encrypted nearest-neighbor search with optional multiprocessing decode (`parallel=True`)
- `ExecutionContext` — key-provider-protected container for all crypto state; save/load locally or via XTrace
- `KeyProvider` protocol with `PassphraseKeyProvider` (scrypt-based) and `AWSKMSKeyProvider` (envelope encryption via AWS KMS)
- `PaillierClient` and `PaillierLookupClient` — Paillier homomorphic encryption clients optimised for Hamming distance
- `GoldwasserMicaliClient` — Goldwasser-Micali homomorphic encryption client
- `Embedding` — embedding provider wrapper (Ollama, OpenAI, Sentence Transformers)
- `InferenceClient` — RAG inference wrapper (OpenAI, Anthropic, Redpill, Ollama)
