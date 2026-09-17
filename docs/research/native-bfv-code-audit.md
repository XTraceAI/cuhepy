# BFV code audit before staging review

Date: 2026-09-15. Branch: `research/bfv-packed-hamming`.
Comparison target: `origin/staging` at `d94ddf0`.
The previous committed BFV baseline is `46b637b`; the Nitro implementation and
the fixes described here are included in the staging pull request.

This internal audit reviewed readability, organization, correctness and test
coverage across the BFV work. It found and fixed integration and error-handling
defects. It is a bounded source review with local validation, not an independent
cryptographic assessment or approval to deploy the new protocol in production.

## Scope and organization

The audit followed the packed Hamming path from key generation and index
packing through public evaluation, response verification and private decoding.
It also examined native ownership and buffer boundaries, wire/import limits,
session state, Nitro evidence validation, deployment tooling, packaging and CI.
Existing Paillier/GPU work is already in the staging target and is preserved.

| Layer | Location under `src/xtrace_sdk/x_vec/crypto/` | Responsibility |
| --- | --- | --- |
| BFV scheme | `encryption/bfv.py` | GMP reference arithmetic, keys, encryption, batching and ciphertext operations |
| Client | `bfv_client.py` | Existing client-style API, packed index/query layout and distance decoding |
| Public evaluator adapters | `encryption/bfv_evaluator.py`, `encryption/bfv_rns.py`, `encryption/bfv_native.py` | Reference, cached GMP, RNS, complete native and persistent-residue backends |
| Public native kernels | `bfv_cpu_ext/` | RNS/NTT, exact scaling, complete search and packed wire handling |
| Private arithmetic | `encryption/bfv_private.py`, `bfv_cpu_ext/private_decoder.h` | Optional fixed-work terminal decoder, separate from public evaluation |
| Protocol baselines | `bfv_security.py`, `bfv_verified_client.py`, `bfv_guarded_client.py` | Execution policy, bounded sessions, private result checks and independent recomputation receipts |
| Attested protocol | `bfv_attested_client.py`, `bfv_nitro.py` | Owner authorization, AWS evidence, enrollment and verification before private work |
| Parameter review | `bfv_assurance.py` | Fixed review profile and conservative circuit correctness bounds |

The original Microsoft SEAL/TenSEAL example remains in `experiments/bfv/`.
Native BFV does not call SEAL. The evaluator backends remain independently
selectable so that the simpler implementations serve as differential oracles.
The Nitro service and relay stay in `experiments/bfv_nitro/`; production HTTP
endpoints and the existing execution context do not select BFV automatically.

## Findings and fixes

| Finding | Effect | Resolution and evidence |
| --- | --- | --- |
| CI's pull-request filter omitted `staging` | This PR would not run the quality gates intended for review | Added `staging` to the target filter; added offline Nitro tests, the preserved SEAL comparison and a strict documentation build |
| Malformed X.509 versions and duplicate extensions escaped the protocol error boundary | Two certificate parser exceptions bypassed the caller's expected rejection path; no decryption-gate bypass was observed | Catch `InvalidVersion` and `DuplicateExtension` explicitly; two tests mutate certificate DER and now assert `BFVProtocolError` |
| The Nitro dependency set changed PyCryptodome's loader during ASan tests | CFFI selected `RTLD_DEEPBIND`, causing ASan to abort before the binding suite could run | Set PyCryptodome's supported `PYCRYPTODOME_DISABLE_DEEPBIND=1` override before SDK import in the sanitizer harness only; rerun passed |
| Protocol message lengths were repeated in service and transport code | Wire changes could leave bounds inconsistent | Share named hello/query/receipt constants; format the new Nitro Python code consistently |
| A research link failed strict Sphinx builds, and the changelog lagged the implementation | Review documentation and ABI instructions were inaccurate | Fix the link, document public ABI 4/private ABI 1, and describe residue arithmetic, protocol baselines and Nitro status |
| The initial build record omitted native header hashes | The provenance record did not identify all arithmetic build inputs | Rebuild the audited image/EIF and record all included SDK source files, headers, build recipes and dependency locks; preserve the earlier record separately |

The certificate regressions failed before the catch was corrected. The loader
problem was reproduced with the Nitro extra installed; the fix leaves ASan
interposition enabled and changes only the test process. No baseline BFV
arithmetic or Paillier implementation was changed by these audit fixes.

## Correctness and attack coverage

The tests compare decoded distances with plaintext Hamming distance and compare
the native backends with the reference arithmetic. They cover packed boundaries,
partial tiles, modulus compaction, malformed native buffers, ownership and
lifetime handling, import budgets and fixed execution policies. The SEAL
reference is exercised with synthetic inputs; it is not a security-equivalence
claim for the homemade parameters.

The historical regression shows why result checks alone are insufficient:
a malicious evaluator can choose ciphertexts whose secret-dependent rounding
changes the owner's observable acceptance behavior. The attacker is allowed to
know the transport MAC key. Checks performed after private decoding therefore
do not close the oracle. This is the repository's protocol regression, not a
claim of a newly discovered flaw in Microsoft SEAL. SEAL also documents the
need to protect secret-dependent outputs at the application boundary in its
[security guidance](https://github.com/microsoft/SEAL/blob/main/SECURITY.md).

The retained guarded baseline requires an independent owner-controlled verifier
to recompute the search and issue a receipt before decryption. The Nitro path
moves that trust to an approved enclave: it authorizes the owner's query,
performs one search and signs the bytes it produced. The owner verifies a fresh
attested receipt identity and then checks each receipt's session, pending query
and response binding before parsing or privately decoding the result. Tests
instrument both private backends to ensure forged receipts and the original
rounding probes never reach private work.

That protection assumes the owner approves the correct measured program and
the enclave protects its signing key. Attestation authenticates execution under
the hardware/provider assumptions; it is not a mathematical execution proof or
a general chosen-ciphertext security transformation for BFV. See the
[Nitro protocol report](native-bfv-nitro.md) for the exact trust boundary,
owner signatures, replay handling and lifecycle limits.

## Validation completed

| Check | Result |
| --- | --- |
| Offline repository tests plus SEAL example | **433 passed, 1 skipped**, 102.91 s; only the real AWS enclave test skipped |
| ASan/UBSan Python binding suite | **211 passed, 1 skipped**, 45.50 s; ASan interposes `mlock`, so its failure-injection test runs only in the ordinary suite |
| Standalone native public/private arithmetic under ASan/UBSan | Passed |
| GCC and Clang `-O3` private-kernel secret-taint tests | Both clean; both deliberately leaking negative controls detected |
| Ruff and mypy | Passed; mypy checked all 50 SDK source files |
| Strict Sphinx HTML build | Passed with warnings treated as errors; external intersphinx fetching disabled for the local offline check |
| Wheel and source distribution | Built successfully; wheel includes BFV/Nitro code and native sources with the expected platform tag and optional extra |
| Audited evaluator container and amd64 EIF | Built; independent `describe-eif` matched measurements and passed CRC validation |

The broad offline test command was:

```bash
.venv/bin/python -m pytest tests experiments/bfv/test_packed_hamming.py \
  --ignore=tests/x_vec/test_meta_search.py \
  --ignore=tests/x_vec/test_hamming_search.py \
  --ignore=tests/x_vec/test_embedding.py -q
```

The ignored modules need live XTrace services or an external embedding model.
The environment had native extensions and the Nitro/SEAL optional dependencies
installed. Native sanitizer and compiler-taint commands are retained in
`.github/workflows/ci.yml`. Passing the narrow taint harness does not establish
that the entire Python client is constant time.

## Audit benchmark and build provenance

`benchmarks/results/native_bfv_nitro_audit_1024.json` records a new local run
after the SDK fixes. It uses the same ciphertexts in both paths, 1,024 vectors
of 512 bits, N=16,384 and the unchanged review profile. All distances were
correct and the ciphertext responses matched. The run alternates execution
order and separates one cold trial from three warm trials.

| Operation | Warm median |
| --- | ---: |
| Existing public search | 2.432182 s |
| Search with owner authorization and response receipt | 2.436256 s |
| Owner query encryption and signing | 206.385 ms |
| Owner receipt verification, decryption and distance checks | 28.232 ms |

This uses a test CA with actual certificate/signature verification. It measures
no NSM, vsock, enclave isolation or EC2 latency. The roughly 4 ms difference is
too small to establish a precise overhead from three warm samples. The useful
structural change remains eliminating the independent verifier's second full
search; the earlier guarded review-profile run took approximately 4.874 s
across server evaluation and recomputation.

The response is 205,018 bytes. Query, response and receipt total 942,798 bytes,
excluding 26 bytes of RPC framing and lower transport layers. The 198-byte
receipt adds no BFV ciphertext expansion. Public setup is 194,804,883 bytes;
registration adds 141 bytes. Combined peak process RSS is 2,320,364 KiB and
includes the owner and two evaluator instances, so it is not enclave memory.
The initial local benchmark is preserved in `native_bfv_nitro_local_1024.json`.

The audited `experiments/bfv_nitro/build-record.json` describes a 300,336,566-byte
version-4 amd64 EIF built with Nitro CLI 1.4.5, with SHA-256
`25ddd36f47d70bb9a4ee1786fd868dfa5f8c52b8bef1981c5715bb172141c278`.
The earlier build record is preserved as `build-record-before-audit.json` and
has different measurements. Owners must approve the measurements of their
actual build; historical pins do not authorize future rebuilds. Generated EIFs
remain outside git. No real Nitro boot or fresh NSM evidence was obtained.

## Remaining production work

Before production use, run the opt-in test against a fresh real enclave and
exercise restart, renewal, failed enrollment, resource limits and concurrency
on the intended EC2 configuration. Measure cloud latency and enclave memory
separately from the local benchmark. Obtain independent protocol/native-parser
review and BFV parameter/private-side-channel assurance. The current correctness
bound does not certify a security level.

The service supports one owner and immutable index per instance. Deployment
needs an admission policy, a durable owner epoch to resist configuration
rollback, and a reviewed process for withdrawing measurements and responding to
platform advisories. Certificate validity is enforced; automated revocation
retrieval is not implemented. The trusted image includes CPython and SDK
dependencies, and the host can still deny service or observe traffic metadata.
Verification failures must not trigger a fallback to unauthenticated private
decryption. These are explicit staging review items, not claims resolved by
the local code audit.
