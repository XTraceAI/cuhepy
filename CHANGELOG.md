All notable changes to this project will be documented in this file.

## [Unreleased]

### Fixed

- Saving a GPU Paillier-Lookup client with `keys.save(..., include_tables=True)`
  now converts cached GMP integers to JSON-compatible integers, matching CPU
  table exports. Cached key files can be restored on CPU or GPU.

### Changed

- README installation now uses a source checkout while the renamed package's
  PyPI release is pending. Compiled-backend examples specify matching Python
  versions, the BFV residue modulus requirement, and when to reinstall built
  extensions. Test instructions distinguish dependency downloads, optional
  backend/protocol tests and offline execution.
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
