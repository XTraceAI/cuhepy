# BFV evaluation with AWS Nitro attestation

Date: 2026-09-12 (local), with build and benchmark artifacts recorded in UTC.
Branch: `research/bfv-packed-hamming`. Baseline: `46b637b`.
Follow-up: [2026-09-15 code audit](native-bfv-code-audit.md), including updated
measurements, an audited image rebuild and additional regression coverage.

This implements the AWS path from the
[verification plan](native-bfv-verification-plan.md). The public BFV evaluator
runs once inside an enclave and signs its own response. The owner verifies
attestation at enrollment and a receipt before each private decryption. There
is no additional owner-side BFV evaluation. The arithmetic, packing, private
decoder and post-decryption checks reuse the existing code.

The implementation is optional and experimental. It preserves Paillier, the
SEAL example, raw BFV and the owner-controlled recomputing verifier. Production
HTTP integration is unchanged. Local validation and an EIF build are evidence
about the implementation, not a successful hardware deployment or independent
security review.

## Code map

| Location | New behavior |
| --- | --- |
| `src/xtrace_sdk/x_vec/crypto/bfv_attested_client.py` | `BFVAttestedClient`, `BFVAttestedServer`, signed owner requests, enrollment, response gate and protected state |
| `src/xtrace_sdk/x_vec/crypto/bfv_nitro.py` | `NitroAttestationPolicy`, AWS evidence verification, official NSM C adapter |
| `experiments/bfv_nitro/` | Measured service, untrusted relay, framed transport, owner demo, Docker/EIF build recipes and deployment README |
| `tests/x_vec/test_bfv_nitro.py` | Certificate, COSE, PCR, freshness and NSM ABI regressions |
| `tests/x_vec/test_bfv_attested_client.py` | Owner/session bindings, receipt gate, oracle regression and lifecycle tests |
| `tests/x_vec/test_bfv_nitro_transport.py` | Real framed-handler round trips, malicious framing and CLI measurement compatibility |
| `tests/x_vec/test_bfv_nitro_aws.py` | Explicitly enabled test against a fresh real enclave |
| `benchmarks/bfv_nitro.py` | Identical-input comparison, local protocol mode and AWS RPC mode |

Install with `uv sync --extra bfv-nitro`; ordinary BFV/Paillier installations do
not acquire the optional attestation dependencies. The runbook is
`experiments/bfv_nitro/README.md`. Large EIF artifacts stay in its ignored
`artifacts/` directory.

## Threat model and the decryption gate

The attacker controls the parent server, relay and storage. It sees public BFV
keys, encrypted index/query/response bytes and the old transport MAC key. It can
alter, omit, reorder and replay messages, and observe behavior after the client
receives a result. The owner controls key generation, plaintext queries, the
expected encrypted setup, application code, approved measurements and the local
clock. The BFV secret and an independent owner request-signing secret stay on
the owner.

The historical attack used crafted BFV ciphertexts whose secret-dependent
rounding could be detected through accept/reject behavior. Checks performed
after decryption did not stop that leakage. This protocol therefore requires
evidence of approved evaluation **before** ciphertext parsing or private
decoding. It authenticates the full packed-distance computation, not merely a
server-supplied output hash.

Under the additional assumption that approved enclave code executes correctly
and its signing secret remains protected, a malicious parent cannot sign a
replacement ciphertext. Nor can it obtain a receipt for a chosen malicious
query: the enclave requires a separate owner signature, and the client accepts
only receipts matching its own pending queries. The existing transport MAC
does not supply either authority.

AWS Nitro supplies isolation and attestation. The application must still
validate evidence and approve the measured program.
[AWS Nitro environment](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html).
If that program or the TEE is compromised, receipt-key misuse can reopen the
decryption oracle. This is not a chosen-ciphertext security transformation or a
mathematical proof of correctness for raw BFV.

```text
Owner                            Untrusted EC2 parent        Nitro enclave
BFV secret, owner signing key     ciphertexts and relay       public BFV setup
approved PCRs and expected epoch                             NSM receipt key
  | signed public registration -----------------------------> |
  | signed nonce + context ---------------------------------> |
  | <----- AWS document binds PCRs, nonce, context, receipt key |
  | <------------------------------ proof of key possession -- |
  | verify evidence and store a short-lived receipt identity   |
  | signed encrypted query ---------------------------------> |
  |                                              evaluate ONCE |
  | <----------------------- encrypted distances + signature -- |
  | verify session, pending query, response hash and signature |
  | decrypt, check distances, select top three locally         |
```

## Attestation verification

`bfv_nitro.py` uses a deliberately narrow Nitro document profile. OpenSSL checks
the certificate path; `cryptography` checks the P-384/ES384 COSE signature;
`cbor2` provides bounded decoding. The new code implements the format limits
and application policy. This integration has not received independent review.

- The only production trust anchor is the SHA-256 fingerprint of the AWS root
  DER certificate: `641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b`.
  A root sent by the peer is untrusted until that fingerprint matches.
- Validate the complete path, validity periods, critical constraints, CA
  authorization and key usage. Accept no unused or duplicate certificates.
  Real Nitro leaf certificates omit AKI/SKI, so OpenSSL's strict-profile flag
  would incorrectly reject them; normal path validation plus explicit
  application usage checks handles the actual AWS profile.
- Require protected algorithm ES384, a 96-byte signature, SHA384 PCRs and
  bounded claims. Reject duplicate CBOR keys, indefinite items, semantic tags,
  excessive nesting and trailing data. The optional outer COSE tag 18 is
  accepted. Documents are limited to 16 KiB.
- Require exact nonzero owner-provisioned PCR0, PCR1 and PCR2. Optional other
  PCRs are additional requirements. Debug measurements and peer-provided
  replacement pins are never acceptable.
- Require the current owner's 32-byte nonce and context, plus a canonical
  Ed25519 SubjectPublicKeyInfo. Reject small-order identities. Verify a
  separate proof of possession of that receipt key.
- Check local evidence age, future clock tolerance and handshake timeout.
  Receipt acceptance expires after at most five minutes and also respects
  certificate expiry. Monotonic time limits the lease.

AWS specifies the evidence format, root and PCR meanings in its
[validation guide](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html)
and [measurement guide](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html).
Exact image pins remain required if an EIF is signed: PCR8 alone could authorize
other programs signed by the same image-signing key.

The server calls AWS's official NSM library for entropy and evidence. The image
builds version 0.5.2 from commit
`1993eeb0620d35f5cefc50b17638b432325328f9`, with a checked archive hash and a
local Cargo lock. The SDK adapter calls its documented C ABI via `ctypes`.
[Official NSM source](https://github.com/aws/aws-nitro-enclaves-nsm-api).
There is no random-seed fallback if the NSM device fails, and no mock provider
in the deployed service entrypoint.

## Versioned bindings and wire format

All hashes below are SHA-256. Concatenated fields have fixed widths where
specified. Existing inner BFV records and the registration use bounded
MessagePack; epochs are unsigned 64-bit integers. Ed25519 uses separate RFC8032
contexts for owner authorization, enrollment possession and response receipts.

The application context commits to the shared circuit identifier, sorted JSON
execution-policy digest, **actual serialized setup** digest, 32-byte owner
public key and big-endian epoch. The setup includes the ordered IDs, count,
encrypted index, public/evaluation keys and parameters. The policy commitment
includes resource limits as well as arithmetic. Context and session hashes
have separate versioned domain prefixes in the code.

| Message | Binding and format |
| --- | --- |
| Registration | MessagePack `[setup, transport_mac_key, owner_public_key, epoch, owner_signature]`; signature covers `XBNI01`, context and transport-key hash |
| Enrollment challenge | `XBNH01 || context[32] || nonce[32] || owner_signature[64]` (134 bytes) |
| Evidence | AWS COSE document with `nonce`, `user_data=context`, and the enclave's DER receipt public key |
| Possession proof | Ed25519 enrollment signature over the unsigned challenge and document hash (64 bytes) |
| Session ID | Domain-separated hash of context, enrollment nonce and raw receipt public key |
| Query | `XBNQ01 || session[32] || inner_query || owner_signature[64]`; signature also binds context and inner-query hash |
| Receipt | `XBNR01 || context[32] || session[32] || query_hash[32] || response_hash[32] || signature[64]` (198 bytes) |

The server verifies the owner's registration signature before BFV key JSON
import and hashes the bytes it actually imports. Once registered, the public
setup cannot be replaced through the service. Each search verifies owner
authorization before inner parsing, performs exactly one complete evaluation,
then signs the produced response. It cannot sign an externally supplied
response, cache entry or digest.

The client checks bounds, receipt bindings, its locally pending request digest
and the enclave signature before calling the existing inner client's
`finish_query`. The outer lock spans this gate and private work so renewal
cannot race with decryption. The inner ticket is consumed once. A valid receipt
for an unrelated or already completed request is insufficient.

The transport adds a nine-byte header, `XBN1 || kind:u8 || length:u32be`, to each
RPC leg. It validates operation and length before reading the body, imposes an
absolute read deadline and handles one RPC per connection. A search reply is a
MessagePack `[response, receipt]`. At the measured 1,024-vector size, framing
adds 26 bytes beyond the query, response and receipt payload totals; TCP, vsock
and tunnel overhead are separate. The relay has four bounded workers. The
enclave services one request at a time and exposes no diagnostic payload logs.

## Lifecycle and deployment limits

This first service is single-owner and single-index. Initial registration is
self-authorized; whoever reaches an empty instance first can claim it. The
legitimate client will reject evidence for a different owner/setup. Account
admission and host availability remain deployment concerns.

Renewing attestation replaces the active session and discards pending queries
without importing the index again. Nonces are single-use and retained in a
bounded set of 1,024 entries. Restarting the enclave discards its receipt key,
replay state and imported index. A restart requires re-upload and fresh
attestation; an index update requires a new service instance and owner epoch.

Protected client exports include the owner signing secret and existing BFV
private state under a separate AES-GCM wrapping key. The expected setup, epoch
and both policies authenticate the envelope. They exclude enrollment and
pending queries; restore always requires fresh attestation. An owner must
retain its expected epoch in trusted durable state: restoring an entire old
owner configuration is outside what an encrypted backup can detect.

The entrypoint fixes the larger-ring review profile and public residue backend.
No host configuration selects weaker parameters, different libraries or a GPU
outside the enclave. BFV decryption remains on the owner, and selection of the
closest results remains local. This change does not add homomorphic top-k.

## Initial local measurements and image build

`benchmarks/results/native_bfv_nitro_local_1024.json` records the initial local
run on a Ryzen 7 5800X with 1,024 vectors of 512 bits, N=16,384 and the unchanged
review profile. Both paths evaluated the **same ciphertexts** and returned
identical response bytes and correct plaintext distances. Measurements use one
cold trial and three warm trials, with the execution order alternated.

| Measurement | Warm median | Interpretation |
| --- | ---: | --- |
| Existing public evaluation | 2.438622 s | One baseline search |
| New evaluation plus owner/receipt protocol | 2.439097 s | One search with signatures and session checks; synthetic attestor, no hardware |
| Owner query encryption and signing | 203.155 ms | Full query creation, not signature time alone |
| Owner receipt verification and finish | 28.105 ms | Includes parsing, private decoding and distance checks |
| Synthetic evidence verification | 4.992 ms | Test CA certificate path, COSE and possession checks; not AWS NSM latency |

The observed search difference is about 0.5 ms, below what these few samples
can resolve reliably. There is no meaningful speedup or precise overhead claim.
The structural improvement is avoiding the second complete search: the
historical guarded baseline took approximately 4.874 s for server evaluation
plus owner recomputation. Actual enclave overhead and cloud tail latency remain
unmeasured.

| Payload | Bytes for this run | Change from the same inner BFV payload |
| --- | ---: | --- |
| Public setup | 194,805,676 | Unchanged BFV setup format |
| Signed registration | 194,805,817 | Adds 141 bytes once |
| Query | 737,582 | Adds 102 bytes per request |
| Response | 205,018 | Identical ciphertext bytes |
| Receipt | 198 | Same length as the existing guarded receipt; distinct protocol |
| Query + response + receipt | 942,798 | Excludes 26 bytes of RPC framing and lower transport layers |

The setup includes public/evaluation keys and encrypted index, not private
BFV state. Its JSON integer lengths vary slightly with fresh random keys. The
synthetic document was 1,938 bytes plus a 64-byte possession proof; that is not
the real AWS document size. Process peak RSS was 2,319,872 KiB and includes the
owner, two evaluators and serialization buffers. It is not enclave-only memory.

The initial evaluator container and an **amd64 EIF** were built locally using the
official Nitro CLI 1.4.5. An independent `describe-eif` invocation reproduced
PCR0/1/2 and passed the EIF CRC check. That EIF was 300,334,519 bytes, version 4,
and has SHA-256
`a6b354a039abdda7399768a6d9b9138f729128d47ad60830dc33b2c074bcd70c`.
It is unsigned as an image artifact; the client pins its exact measurements
and still requires a valid **AWS-signed attestation document** at runtime.
Image signing and runtime attestation are different operations.

`experiments/bfv_nitro/build-record-before-audit.json` preserves that initial
build's PCRs and metadata. The current `build-record.json` and ignored
`artifacts/` output describe the audited rebuild documented in the
[code audit](native-bfv-code-audit.md). Its source hashes include the native
headers, and its measurements differ from the initial build. A trusted local
build record is not proof that the program has booted in an enclave. No EC2
resources were created and no fresh NSM evidence was obtained here.

## Validation and remaining release work

Initial local checks: **346 BFV tests passed, one real-AWS test skipped** in
50.30 seconds. The focused Nitro set contains 77 passing tests. Ruff passed on
the SDK and all new Python files, and mypy passed on all 50 SDK source files.
The lockfile check passed offline. Sphinx built successfully with the existing
unrelated missing-document warning in `bfv-packed-hamming.md:259`. The container
and EIF build checks described above also passed. No baseline arithmetic source
or the `main` branch was modified.

The subsequent [code audit](native-bfv-code-audit.md) fixed the documentation
warning and certificate error handling, added staging PR coverage, and passed
433 offline repository/reference tests plus 211 sanitizer-backed binding tests.
That report records the precise scope and skips for each run.

The offline suite covers exact output equality with the existing evaluator and
an assertion that only one evaluation occurs. Both private decoding backends
are instrumented during forged-receipt and historical rounding-oracle probes
to ensure that rejection happens before private work. Additional tests cover
wrong roots and certificate constraints, wrong/zero PCRs, stale evidence,
nonce/context/key substitution, failed possession, forged owner requests,
unrelated valid receipts, replay, renewal, expiry, restore binding and
concurrent completion. Socket tests exercise the actual framed service.

A public historical AWS document is accepted at its original valid time and
rejected at today's clock. It is not fresh evidence for this application. A
test-only C shim checks NSM argument ordering, lengths, failure statuses and
resource cleanup; the built official library loads and fails closed when the
real NSM device is absent. Synthetic roots exist only in test/benchmark code;
the production verifier rejects them by default.

The next release work is actual Nitro EC2 end-to-end execution and lifecycle
testing, matched cloud performance and isolated memory measurements, independent
protocol review, native/parser attack-surface review, and the existing BFV
parameter and client private-key side-channel assurance. The measured software
includes CPython, the SDK import tree and all image dependencies; shrinking that
trusted footprint is useful follow-up work.

Certificate expiry is enforced, but this verifier does not fetch CRLs or provide
an automated platform-advisory/revocation service. Owners need a reviewed process
for withdrawing measurements and updating trusted builds. Attestation establishes
program identity under AWS's assumptions; it does not remove these operational
and implementation obligations. Host denial of service and metadata observation
remain possible. Cryptographic execution proofs remain a separate future track.
