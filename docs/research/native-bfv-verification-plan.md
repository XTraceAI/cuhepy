# BFV server verification: TEE first, cryptographic proofs later

Date: 2026-09-12. Branch: `research/bfv-packed-hamming`.
Status: original research and proposed design, retained as the planning baseline.
The subsequent [AWS Nitro implementation](native-bfv-nitro.md) follows the user's
AWS deployment preference. Its local tests and EIF build do not yet establish
real EC2 execution. Cryptographic proofs remain future work.

## Recommendation and preserved baseline

Build the next experiment around **one BFV evaluation inside an attested TEE**.
The client establishes that an approved evaluator controls a response-signing
key, then checks its signed response before private decryption. This addresses
the duplicate computation in the current design while reusing our C++ RNS
arithmetic. Hardware attestation is an accepted trust assumption for this
project; preserving native performance is the main reason to prioritize it.
The performance advantage is a design expectation, not a measured TEE result.

Keep a second research track for cryptographic proofs, beginning with a small
experiment using an existing proof system for program execution. Consider
specialized proofs of BFV arithmetic only after measuring that experiment.
This order limits the amount of new cryptography we would have to design.

The code baseline is commit `46b637b`, described in
[the pre-decryption approval report](native-bfv-predecryption.md).
`BFVGuardedClient`, `BFVPublicVerifier`, their tests and benchmarks remain the
reference implementation. This document records the original planning-only step.
There is no change to Paillier, the SEAL example, BFV arithmetic or production
integration, and no cloud deployment is performed.

## What the client must establish

The threat model includes a malicious evaluator and relay that can replace,
omit, reorder and replay messages, knows the evaluator's transport MAC key,
and can observe application behavior after a response. The owner controls
key generation, the encrypted setup, query creation and the client software.
The BFV secret key stays on the owner.

The historical attack submitted crafted ciphertexts that passed public format
checks but exposed secret-dependent rounding. Acceptance after decryption
revealed information about the secret key. Consequently, a checksum of the
plaintext, valid serialization, or a MAC made with a key known to the evaluator
cannot supply the needed gate.
The existing regression in `tests/unit/test_bfv_verified_client.py` documents
this behavior; the guarded-client regression checks rejection before either
private decoder is invoked.

The proposed acceptance rule is:

```text
response = approved deterministic BFV evaluation(owner setup, owner query)
```

"Owner setup" includes the parameters, public and evaluation keys, complete
encrypted index, ordered vector IDs and count. The protocol must also bind the
index version, operation, output encoding and the client's pending request.
Correct arithmetic on a different index, a server-created query, or a subset of
the rows is insufficient.

This verifies the computation over the encrypted data the owner committed to.
It does not establish that those original embeddings were accurate. The existing
circuit returns packed encrypted distances; the client still decrypts and ranks
them. This proposal does not add encrypted top-k selection.

## Comparing the options

The implementation-risk judgments below are specific to this repository and
are planning assessments, not certifications or benchmark results.

| Approach | Work on the server side | Client work before decryption | Main trust assumption | Implementation assessment |
| --- | --- | --- | --- | --- |
| Current owner verifier | One search plus another complete search | Hashes, bindings and signature | Owner verifier and its signing key | Already implemented; useful reference |
| Attested evaluator | One search inside a TEE, plus attestation and signing | Attestation at session establishment; hashes and signature per response | Approved code, TEE isolation and attestation infrastructure | Best first experiment; preserves native arithmetic |
| Proof of program execution, such as a zkVM | Execute the evaluator in a supported guest and generate a proof | Verify proof, program identity and input/output bindings | Proof-system assumptions, sound implementation and correct guest program | Less bespoke cryptography; substantial porting and potentially expensive proving |
| Specialized arithmetic proof | Evaluate BFV and prove its exact arithmetic relation | Verify proof and bindings | Proof-system assumptions and correct BFV constraints | Potentially better proving cost; highest specialist review burden |
| Two independent matching evaluators | Two complete searches, potentially concurrent | Authenticate both results and compare exact bytes | At least one honest evaluator, with independent authenticated identities | Simpler cryptography, but retains duplication and adds a non-collusion assumption |

Two matching replicas would need genuinely independent response identities:
the shared transport MAC in the existing session protocol is not enough. Running
both replicas under the same compromised operator does not meet that assumption.

Encrypted canaries, sampled outputs and hidden checksums are not proposed as the
production gate. Research has broken particular lightweight schemes that embed
verification secrets inside HE ciphertexts; that does not prove every possible
lightweight verifier insecure, but it makes a new construction a research task.
Our private post-decryption summary already has a separate, demonstrated oracle
problem. [Cheon and Jang, ASIACRYPT 2025](https://arxiv.org/abs/2502.12628).

## Proposed TEE design

The protected evaluator replaces the full recomputing verifier's role. The host
stores ciphertexts and relays traffic; there is no second full search.

```text
Owner client                 Untrusted host             Attested evaluator
BFV secret key               Encrypted storage          Public BFV setup
Approved-code policy         Network relay              Ephemeral signing key
       |                           |                           |
       |---- fresh challenge and expected session context ---->|
       |<--- attestation binding approved code and signing key --|
       | verify evidence locally   |                           |
       |---- owner-authorized encrypted setup and query ------->|
       |                           |                  compute once
       |<-------------- encrypted response + signed receipt ----|
       | verify receipt and pending request                    |
       | decrypt, check distances and rank locally              |
```

### Establish the evaluator's identity

1. Package the public evaluator, native extension and dependencies in a fixed
   image. Provision approved measurements and protocol versions through an
   owner-trusted release/configuration path. A measurement advertised only by
   the host is not an independent reference value.
2. Generate an ephemeral signing key inside the protected runtime. Attestation
   must bind that public key to a fresh client challenge and an unambiguous,
   versioned session context. Include the circuit, expected setup digest and
   index epoch in that binding, directly or through a domain-separated digest.
3. Validate the attestation signature and trust chain, approved measurements,
   debug state, applicable platform security status, freshness and exact
   application-data binding. Use a pinned, reviewed dependency for the chosen
   platform's evidence format. Application policy remains our responsibility.
4. Require proof of possession of the bound signing key before accepting the
   session. Authorize the owner and setup through the established protocol;
   a transport MAC shared with the host cannot establish owner authorization.

Use existing cryptographic and attestation libraries. Do not turn the adjacent
toy key exchange into a new production handshake. An existing attested TLS
stack could establish a channel, but our first design should retain explicit
response receipts to fit the existing pre-decryption gate and allow the relay
to remain outside the trusted runtime.

### Compute and authenticate each response

The protected service imports and hashes the actual owner-authorized setup,
checks the supported circuit and admission policy, then executes the complete
public BFV search internally. It signs only the response it produced, binding
the session, circuit, setup/epoch, exact request and exact response bytes.
Expose a `search` operation, not a general-purpose `sign` or `approve_hash` API.

The client bounds the received bytes and verifies the evidence bindings and
signature before BFV parsing or private work. It then consumes its own pending
request once and follows the current private decoding and distance checks.
Preserve the existing rule that a valid receipt for a server-created request
does not authorize decryption on the owner.

Attestation can be amortized across a bounded session while ordinary signatures
authenticate individual responses. Require a new challenge and attestation on
session renewal, key rotation, restart or a relevant code/policy change. Start
the experiment with keys that are not persisted. Saved client state must not
silently restore an expired session or bypass attestation; owner-maintained
index epochs and replay policy need explicit persistence rules.

The current receipt is 198 bytes. A future receipt needs its own protocol
version and may be larger to bind session and index lifecycle information.
Attestation evidence and certificate/verification collateral are additional
setup traffic; their actual sizes and cache behavior must be measured.

### Preserve the protection boundary

All operations influencing the signed result must be protected or soundly
verified there, including setup import, preprocessing caches, RNS arithmetic,
compaction and serialization. Hashing an unchecked host-supplied result is not
verification. Offloading to an ordinary host GPU would reopen this boundary;
start with the current CPU implementation.

The trusted software includes more than the BFV kernel: the guest OS/runtime,
parsers, native extension, dependencies and any privileged management path can
affect the signing key. Pin executable dependencies and disable host-controlled
code loading, mutable image tags, debug access and unmeasured configuration
that can change computation. A memory-corruption bug in the protected service
could expose its signing key, so the existing parser limits and native checks
remain relevant.

Attestation establishes identity under the platform's assumptions; review and
testing establish confidence in what that identified program does. It is not
a mathematical correctness proof. If the TEE or signing-key custody fails,
the response gate can fail and the original oracle can return, despite keeping
the BFV secret key on the client. Availability, traffic analysis, client-side
private-key handling and independent BFV parameter/protocol assurance remain
separate concerns.

## Platform candidates and verification dependencies

**Phala/dstack on Intel TDX** is worth evaluating because the adjacent
`TEE-Key-Exchange-Toy` repository already targets eventual Phala integration.
Its current `ToyAttestationProvider` signs local claims; it supplies no hardware
isolation or genuine TDX quote verification. Reuse its lessons and test cases,
not its trust root.

Phala documents application verification using quote report data, measured
application configuration and replay of the RTMR event log. Our policy must
compare these against owner-approved values and immutable container digests,
not merely compare two values received from the host.
[Phala application verification](https://docs.phala.com/phala-cloud/attestation/verify-your-application).

Evaluate `dstack-verifier` and `dcap-qvl` as dependency candidates, checking
pinned versions, review coverage and failure behavior. Quote validity alone
does not approve our application. The dstack documentation separates automatic
platform checks from additional policy, KMS and network identity checks. For
the pilot, generate the response-signing key inside the runtime rather than
deriving it from a platform KMS; review the platform services that still affect
execution. Local attestation verification avoids adding a remote verification
service as another trusted party.
[Phala platform verification](https://docs.phala.com/phala-cloud/attestation/verify-the-platform),
[dcap-qvl source](https://github.com/Phala-Network/dcap-qvl).

**AWS Nitro Enclaves** is the other concrete candidate if deployment will use
compatible EC2 instances. It offers an isolated Linux environment with a local
socket to the parent and no direct external networking or persistent storage.
That maps to a small relay plus the existing Python/C++ public evaluator.
[AWS Nitro overview](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html).

Nitro evidence carries signed measurements and optional nonce, public-key and
application-data fields. Validate its COSE signature and certificate chain with
the provider's trust root, then apply our session and code policy.
[AWS attestation validation](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html).
Pin approved image measurements and reject debug evidence; trusting an image
signer's certificate alone permits other images signed by that key.
[AWS measurement documentation](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html).

At the time of this plan, provider selection was still open. The SDK's AWS dependencies do not establish
where this evaluator will run. Choose one provider for the first real hardware
experiment based on hosting fit and an acceptable verification dependency;
avoid implementing multiple evidence formats initially.

## Performance experiment and acceptance criteria

Use the larger-ring review profile and identical ciphertexts for comparisons.
The committed `benchmarks/results/native_bfv_guarded_review_1024.json` records
these results for 1,024 vectors of 512 bits, N=16,384, on a Ryzen 7 5800X:

| Existing measurement | Value | Meaning for the proposed experiment |
| --- | ---: | --- |
| Warm public search | 2.439 s | One complete evaluation to move inside the TEE |
| Additional owner-verifier approval | 2.435 s | The duplicated evaluation to remove |
| Warm sequential search plus approval | 4.874 s | Current combined compute baseline |
| Guarded client finish | 28.425 ms | Includes receipt handling, parsing, native decryption and private checks |
| Query / response | 737,480 / 205,018 bytes | BFV payload sizes to preserve for this profile |
| Existing receipt | 198 bytes | Excludes future attestation/session overhead |
| Setup per evaluator | 194,805,166 bytes | Public/evaluation keys plus encrypted index and envelope |

These are one cold trial and three warm trials, without network traffic. They
are not cloud measurements or evidence about tail latency. The historical
whole-process peak memory includes two evaluators and the client; it cannot
be used as the isolated enclave's RAM requirement.

Measure unprotected and protected execution on the **same cloud CPU**, with
matched compiler flags, vCPU allocation, workload, parameters and caches.
Record separately:

- Cold startup, setup upload/import, preprocessing and isolated evaluator RSS.
- Warm search time, throughput and p50/p95 latency over enough repetitions;
  include concurrency and realistic index sizes after the single-worker case.
- First-session attestation verification, collateral fetching and bytes;
  subsequent sessions with cached collateral and per-response receipt cost.
- Host relay/network time, complete client finish and all communication legs.
- Index replacement, session renewal, restart and failure/retry behavior.

A provisional target is warm TEE search latency within 20% of the matched
unprotected evaluator, with exactly one full search per query. This is an
engineering target to test, not a prediction or a user-specified service level.
Report any miss by component before changing BFV arithmetic. Do not reduce
security parameters or omit checks to improve the comparison.

## Cryptographic proof track

### Start with an existing system for proving program execution

A zkVM can prove execution of a supported guest program. The client must verify
the expected program identity and bind its public outputs to the requested
computation; a cryptographically valid receipt for a different program is
irrelevant. RISC Zero's receipt model explicitly separates the public journal
from the proof and verifies against a trusted image ID.
[RISC Zero receipts](https://dev.risczero.com/api/zkvm/receipts).

Shortlist RISC Zero and SP1, then select one based on guest compatibility,
verification dependencies, actual security assumptions and profiling. Neither
should be assumed to run the current CPython extension and host GMP build
unchanged. Inspect the exact release, audits, advisories, soundness parameters
and any proof compression or trusted-setup requirements. For example, SP1
documents different assumptions for its core proof and its wrapping proofs;
"uses a SNARK" does not specify a uniform security level.
[SP1 security model](https://docs.succinct.xyz/docs/sp1/security/security-model).

The proof statement must bind the circuit/program, parameters, owner setup
commitment and index epoch, exact owner request and canonical response digest.
The proven execution must check all data against that commitment and process
the complete ordered index. A Merkle root alone neither verifies evaluation
nor establishes that no rows were omitted.

The difficult relation is not just polynomial multiplication. Our implementation
also depends on canonical integer lifts, exact tensor scaling and rounding,
binary gadget decomposition and relinearization, rotations, masks, merging,
terminal modulus switching and wire encoding. RNS congruences alone do not
prove the necessary integer ranges and rounding. Host-provided arithmetic hints
or cached values must be checked in the proven computation.

Start with small correctness fixtures, then prove **one full N=16,384 tile**
(32 vectors at 512 dimensions), including compaction. Next cover multiple tiles
and the merge before attempting the full 1,024-vector search. Tiny polynomial
degrees can test integration but cannot establish production-profile proving
cost. Include hashing/import of the large setup in the accounting; reusable
authenticated preprocessing would be a separate design step.

Measure proving time, peak memory, verification time, proof bytes and the cost
of initial setup separately. Compare total query-to-verified-result latency,
not only the prover's final compression step. Zero knowledge is not itself
required to hide the public BFV ciphertexts from their owner; avoid adding a
proof wrapper solely for an unrelated blockchain use case.

### Specialize only if measurements justify it

A BFV-specific proof could avoid much of a general VM's execution overhead.
That is a plausible optimization direction, not a demonstrated result here.
It needs a reviewed integer/RNS constraint design, especially range, carry and
rounding conditions. The ringSNARK project implements ring-oriented proof
research, but explicitly labels itself a proof of concept unsuitable for
critical or production use. Use it as a reference, not a ready production
dependency for this homemade BFV implementation.
[ringSNARK source and status](https://github.com/zkFHE/ringSNARK).

Finally, proving this relation does not automatically give raw BFV a general
chosen-ciphertext security theorem. Manulis and Nguyen's verifiable-FHE
transformation combines ciphertext-integrity machinery with a SNARK. Its proof
does not transfer just by attaching a generic execution proof to our current
API. Review the actual owner-generated-input protocol, adaptive responses and
decryption behavior with a cryptographer before making a comparable claim.
[Manulis and Nguyen, EUROCRYPT 2024](https://eprint.iacr.org/2024/202).

## Proposed work order and repository layout

1. **Specify the TEE protocol.** Write the session/receipt byte formats, trusted
   measurement policy, key lifecycle, owner authorization, index epochs and
   failure state machine. Select one platform and verification dependency.
   Review the specification before treating a prototype as a security boundary.
2. **Prototype the public evaluator on real hardware.** Keep deployment files
   and the relay/service harness under `experiments/bfv_attestation/`. Reuse the
   current public evaluator and compare exact output bytes with the baseline.
   Local simulated evidence is for tests only and must be rejected by the real
   client configuration.
3. **Add an explicit opt-in client and benchmarks.** A future
   `src/cuhepy/bfv_attested_client.py` would keep the existing
   client style and mandatory gate. Put provider verification behind a narrow
   optional adapter; add `tests/unit/test_bfv_attested_client.py` and
   `benchmarks/bfv_attested.py`. Preserve the baseline APIs and dependencies.
4. **Test the boundary and obtain independent review.** Reuse the existing
   oracle regression with both private decoders instrumented to fail if called.
   Add rejected evidence for wrong roots, measurements, debug state, freshness,
   session/key binding and security policy; mutate signed responses and setup
   IDs; test server-created queries, omitted/reordered rows, replay, concurrent
   responses, restarts, state rollback and downgrade attempts. Include hostile
   relay integration tests and bounded parser/fuzz/sanitizer coverage inside the
   protected service. No test suite substitutes for a protocol/platform review.
5. **Run the proof feasibility experiment later.** Put the guest, verifier and
   fixtures in `experiments/bfv_proofs/`. Decide whether to extend the generic
   proof or investigate specialized arithmetic from measured full-profile
   costs. Introduce a separate proof-required client mode only after review;
   proof failures must never trigger automatic acceptance through another mode.

For both future modes, verification happens before private decryption, expected
inputs come from owner state, and the selected trust policy is explicit. These
are the common boundaries to preserve while changing how evidence is produced.
