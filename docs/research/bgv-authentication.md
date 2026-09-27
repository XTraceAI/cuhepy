# BGV response authentication and private arithmetic assurance

Date: 2026-09-25. Worktree: `cuhepy-bfv-research`.

This adds an **experimental, opt-in BGV protocol** analogous to the BFV Nitro
path. An owner-authorized CPU evaluator computes the prescribed search inside
a measured enclave and signs the complete response. The client verifies that
receipt **before response parsing, decompression, or decryption**. Its terminal
decryption uses a separate homemade fixed-work native kernel.

This closes the demonstrated chosen-response oracle **under the stated trust
assumptions**. It is not a claim of CCA-secure BGV, a general FHE proof, complete
constant-time client behavior, independent review, or production readiness.
Existing unauthenticated BGV fixtures, CUDA experiments, BFV, Paillier and the
SEAL oracle retain their behavior. Migration to the new client is required.

## Threat model and why a receipt helps

The attacker may control the parent EC2 instance, server process outside the
enclave, network/relay, storage and GPU. It can replace ciphertexts, index files
and public keys; replay responses; change compression settings; delay messages;
and observe subsequent application behavior. Availability, traffic analysis
and denial of service are not solved.

The owner machine, owner signing credential, configuration, retained index
epoch and plaintext handling are trusted. The owner provisions exact nonzero
PCR0/1/2 pins for code it has reviewed. The AWS attestation root/hypervisor,
measured evaluator and its receipt-key custody are trusted. An attacker with
arbitrary execution inside that enclave or inside the owner process is outside
this protection. A malicious owner sharing its own key is also outside scope.

BGV's homomorphism does not authenticate ciphertexts. A syntactically valid
result and a plausible Hamming distance do not establish that the intended
computation ran. The new local regression demonstrates this concretely: two
valid/invalid distance predicates per coefficient recover a generated 16-term
ternary test secret through the raw decoder. This is a deliberately small
regression, not a practical attack-time estimate. The same forged transcripts
are rejected by the protected client without reaching its parser or decoder.

This matches the broader distinction made in
[SEAL's security guidance](https://github.com/microsoft/SEAL/security) and the
[CPAD analysis of exact FHE](https://eprint.iacr.org/2024/116).
These are references, not imported scheme implementations.

The receipt is useful because its signing key is **inside the measured
evaluator**, and that evaluator has no sign-a-host-result endpoint. Giving a
signing/HMAC key to the malicious parent would not help. The enclave evaluates
once; the owner does not download or recompute the encrypted index per query.
Authentication establishes execution by that trusted implementation. It cannot
make a buggy implementation correct.

## Protocol and bound state

1. The owner serializes its public key, complete evaluation keys, ordered
   encrypted index and vector count. Canonical coefficient checks, reconstructed
   key fingerprint and circuit bounds reject invalid setup.
2. A separately generated Ed25519 owner key signs registration. The fixed
   registration header permits verification over opaque setup bytes **before**
   importing the large setup. An immutable context hash binds the exact setup,
   owner, owner-maintained 64-bit epoch, fixed circuit version and complete local
   admission policy.
3. The owner signs a fresh 32-byte enrollment challenge. The enclave generates
   its ephemeral receipt key from NSM randomness. AWS evidence binds its SPKI,
   the context hash and owner challenge, followed by proof of key possession.
4. The client uses the existing BFV Nitro evidence verifier: AWS root/certificate
   chain and COSE signature validation, exact nonzero PCR pins, bounded strict
   CBOR, timestamp/nonce/context checks, and a lease bounded by certificate
   expiry and monotonic time. There is no configurable synthetic root.
5. Each owner query carries a new 32-byte ticket and an owner signature binding
   its full encrypted bytes, current session and context. Both endpoints bound
   lifetime query counts; the client bounds pending queries. The server consumes
   a request before public expansion/evaluation. It computes the complete CPU
   butterfly search, terminal reduction and optional response rounding itself.
6. A receipt binds context, session, complete query digest and complete response
   digest. The client verifies all bindings and the Ed25519 signature before
   consuming the pending ticket and entering response parsing/private work.
   A valid receipt consumes the ticket even if later parsing or decoding fails.
   An invalid receipt does not consume the legitimate pending request.

All signature and hash domains, packet tags and transport magic are separate
from BFV. Layout, ring, modulus, plaintext modulus, noise distribution,
evaluation-key decomposition, index encryption mode and both compression
precisions are pinned by the owner policy/context. Bounds come from local
configuration and the owner-authorized index mode, never the response.

The new protocol supports public-key and owner-encrypted indices, and the
existing seeded query, query rounding, terminal compact and response rounding
formats. The measured service entrypoint fixes one policy in code; a different
profile requires a new reviewed image and owner pins. Small policies in tests
are not production parameter profiles.

| Item | Additional bytes |
|---|---:|
| Owner authorization on each encrypted query | 134 |
| Receipt accompanying each encrypted response | 198 |
| Registration wrapper around the public setup | 110 |
| Signed enrollment hello | 134 |

Evidence and proof of possession are occasional enrollment traffic, not included
in the per-query 332-byte total. Socket frames and MessagePack pair wrappers add
their own small overhead.

Renewal drops pending owner queries and invalidates old sessions. It does not
reset the lifetime query budget. Forked/copied clients and servers are rejected.
There is no saved-state/restore API: restart requires a new owner signing
identity and fresh enrollment. This does not implement durable anti-rollback
for the application; the owner must manage dataset epochs and approved image
versions externally. Position-to-document mapping stays with the owner and must
refer to the same ordered index. No acceptance acknowledgement is sent by the
remote helper.

## Fixed-work private terminal kernel

The scheme-specific decoder is in `_owner/bgv_private.h`.
It reuses our BFV fixed-schedule NTT, masked arithmetic, public-multiplier,
fixed-divider and locked-buffer primitives. It does **BGV centered reduction
modulo t**, not BFV scaling/slot decoding. No SEAL scheme code is imported.

The public limits are N=8..32768 (power of two), odd P<2^60 and odd
3<=t<2^30. Two public, independently validated 60-bit NTT primes exceed the
worst-case integer convolution range. For |s_i|<=1 and canonical c1,
|c1*s| < N*P.

* If 2*N*P < p0, a **public** decision selects one NTT prime. Centering its
  residue reconstructs the exact signed convolution. This includes the
  25/32-bit response profiles at N=16384.
* Otherwise two transforms plus exact centered CRT reconstruct the convolution.
  Its magnitude is below 2^75, far below p0*p1/2. A public N*P offset gives a
  nonnegative numerator; 77 fixed division steps reduce it modulo P.
* The small path uses a public reciprocal reducer. For any 64-bit x and public
  p<2^60, floor(x*floor(2^64/p)/2^64) underestimates floor(x/p) by at most one,
  so one masked subtraction suffices. The same reducer handles plaintext
  reduction after adding a public multiple of t and centering modulo P.
* Private transform indices, iteration counts and buffer sizes depend only on
  public dimensions. There is no secret-dependent table lookup or secret
  division in the kernel. Public setup and c1 transform precomputation may
  divide.
* Native parsing validates every coefficient in every response ciphertext
  before the first secret multiplication. The packed entrypoint avoids
  unpacking coefficients to Python/GMP and packing them again.
* Persistent secret spectra and temporary products use mandatory `mlock`,
  `MADV_DONTDUMP` and full mapped-region volatile wiping. Failure to lock
  memory aborts; there is no unlocked or variable-time fallback. Native and
  Python process checks run before locks that could be inherited across fork.
  Close waits for active use without holding the GIL.

At N=16384 the persistent spectra occupy 262,144 locked bytes; temporary private
work uses 131,072 bytes on the small path or 262,144 on the wide path. Native
plaintext export has a fixed size but is intentionally outside the erasure/
secret-taint boundary.

**Remaining private-side-channel scope:** key generation/import, seeded query
encryption, owner index encryption, Python/GMP key copies, Ed25519 owner signing,
plaintext correlation validation/top-k and Python memory erasure are not
covered. The new client uses arithmetic correlation decoding rather than the
plaintext-indexed result lookup table, but Python branching/selection is still
variable-time. This is not an end-to-end constant-time client. A local adversary
able to observe these stages remains an open threat.

## Code and deployment

| Path, relative to repository root | Responsibility |
|---|---|
| `experiments/bfv_search_lab/security_bgv.py` | Immutable public policy, bounded setup, context and correctness bounds |
| `experiments/bfv_search_lab/attested_bgv.py` | Owner authorization, Nitro enrollment, one CPU evaluation, pre-decryption receipt gate |
| `experiments/bfv_search_lab/private_bgv.py` | Explicit fixed-work decoder adapter |
| `experiments/bfv_search_lab/_owner/bgv_private.h` | Homemade BGV native terminal arithmetic |
| `experiments/bfv_search_lab/_owner/private_bindings.cpp` | Strict native batch/packed parsing and lifecycle |
| `experiments/bfv_search_lab/_owner/test_private.cpp` | Independent arithmetic oracle, dynamic taint and wipe checks |
| `experiments/bfv_search_lab/test_*bgv*.py` | Protocol, private kernel and bounded service regressions |
| `experiments/bgv_nitro/` | Separate fixed-policy vsock service, bounded remote transport and image recipe |
| `benchmarks/bgv_authentication.py` | Offline paired authentication/private cost experiment |

Build/run instructions are in the
[BGV Nitro README](../../experiments/bgv_nitro/README.md). These research modules
are deliberately outside the production package exports.

The default image is **CPU-only**. It cannot certify CUDA work performed by its
parent or GPU. The existing GPU experiment is retained as an unauthenticated
research path. Preserving GPU acceleration under this threat model still needs
a reviewed confidential-GPU attestation/data-binding protocol, a cryptographic
proof, or trusted recomputation. An NVIDIA capability by itself does not
connect that GPU result to this receipt.

The image reuses the pinned BFV Python dependencies, AWS NSM source checksum and
Cargo lock. A successful local Docker build/import check and missing-NSM
fail-closed test are not an AWS enclave execution test. This workstation has
no /dev/nsm. No new EIF/PCR set has been approved or deployed; do not reuse BFV
PCRs for the changed BGV application. AWS explains the
[measurement fields](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html)
and [evidence validation](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html).

## Validation and performance

At implementation commit `583839c`:

- The complete package, BFV-example and research suite passed **886 tests**,
  including **99 new BGV security/private/service tests**. The existing live
  AWS Nitro integration test was skipped; one existing multithreaded-fork
  deprecation warning remains.
- The separate private ASan/UBSan extension passed **69 tests**; its OS mlock
  failure test was skipped because ASan intercepts mlock. That test passed with
  the release extension in the full suite.
- GCC 13.3 and Clang 18.1.3 **-O3** kernels passed dynamic secret-taint checks:
  N=16,128,16384,32768; 17/25/60-bit arithmetic moduli; positive, negative and
  mixed ternary keys; narrow and wide reconstruction; reciprocal extremes;
  independent exact arithmetic; and wiping/closed-state checks. Both deliberately
  secret-dependent negative controls returned the required failure code 99.
- Package Ruff/mypy and explicit checks of the new protocol/decoder modules
  passed. The pinned Docker image built and imported its public extension and
  service. Running its real entrypoint without NSM failed closed as intended.

The benchmark deliberately uses a synthetic root override confined to its local
scope. Its timings exclude hardware attestation, network, setup and EC2/enclave
scheduling. They cannot be reported as Nitro or GPU performance. Ten paired,
shuffled trials follow two warmups, using the same fresh ciphertext within each
pair. Every response byte and distance is checked against the corresponding
local/plaintext reference. The implementation is the same as `583839c`; the
first measurement predates that commit but all recorded source hashes match it.

The host is the same Ryzen 7 5800X workstation used in the earlier experiments.
The two alternatives share the existing CPU RNS evaluator. The existing client
baseline uses its variable-time RNS owner plus native packed result handling;
the protected client adds receipt verification, the fixed-work terminal kernel
and arithmetic/Python result handling. This comparison does not isolate kernel
cost alone.

For the unrounded seeded-query/compact-response format at 8192 vectors:

| Median local stage | Existing fixture path | Protected protocol path |
|---|---:|---:|
| CPU server, including query expansion and response serialization | 2429.34 ms | 2430.18 ms |
| Client response handling, including stable top-three | 4.04 ms | 5.88 ms |

The median **paired** increase is 2.80 ms at the server and 1.85 ms at the
client. The server difference is small relative to its run-to-run variation;
the median difference and difference of medians are not identical statistics.
The fixed-work primitive avoids a large slowdown, but this CPU-in-enclave
architecture does not inherit the faster, unattested CUDA server timing.
Query authorization/signing/encryption took 11.20 ms in this run. Setup was
42.10 seconds and 145,984,898 registration bytes, reported separately.
The response remains 102,488 bytes plus its 198-byte receipt.

The compressed run pins query drop=58 and response drop=22, the prior balanced
public-index plan at P25. The existing/protected CPU-server medians are
2426.89/2428.56 ms; client finishing is 4.29/6.08 ms. Its paired median added
cost is 0.86 ms at the server and 1.80 ms at the client. Total authenticated
query+response+receipt traffic is **229,915 bytes**, versus 229,583 bytes before
authentication: **332 bytes (0.145%) extra**. The compression savings survive
the receipt protocol. Protected query construction takes 11.52 ms.

Public measurement artifacts, including every sample, order and source/binary
hash, are [the original-format run](../../benchmarks/results/bgv_auth_baseline_8192.json)
and [the compressed run](../../benchmarks/results/bgv_auth_rounded_8192.json).
The source manifests of both runs were independently checked against commit
`583839c`. No keys, plaintext vectors or ciphertext payloads are saved.

Validation logs: [full suite](../../benchmarks/results/bgv_auth_full_tests.txt),
[private ASan/UBSan](../../benchmarks/results/bgv_auth_private_asan.txt),
[GCC taint](../../benchmarks/results/bgv_auth_gcc_taint.txt), and
[Clang taint](../../benchmarks/results/bgv_auth_clang_taint.txt).

Dynamic secret-taint tests mark persistent secret spectra undefined under
[Valgrind Memcheck](https://valgrind.org/docs/manual/mc-manual.html), retaining
the taint through the entire decode before declassifying the output. A
deliberate secret branch must fail as a negative control. These tests detect
executed secret-dependent branches and addresses, not every processor latency,
compiler transformation, speculative execution, power/EM/fault attack or
unexecuted path. They supplement source review, independent arithmetic and
ASan/UBSan; they are not a constant-time proof or certification.

Before production, the remaining work is an independent protocol/code audit,
real AWS enclave testing and measured image approval, a private query/key
generation implementation with comparable validation, deployment-specific
client side-channel analysis, durable epoch/revocation operations and
independent lattice-parameter assurance (including evaluation-key assumptions
and compressed transcripts). The conservative correctness bound is not a
128-bit security certificate.
