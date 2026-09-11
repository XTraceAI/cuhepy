# Internal BFV security review — 2026-09-10

**Decision: keep this implementation experimental. It is not ready for a
production security claim.** The arithmetic and input handling have stronger
test coverage, but protocol integrity, parameter assurance and private-key
implementation assurance remain open. This is an internal, AI-assisted source
review and regression exercise, not an independent cryptographic audit,
penetration test of a deployed service, or proof of security.

The optimization baseline reviewed is commit `06d8d17`, following
`e5c0751`. This report and the accompanying hardening are on
`research/bfv-packed-hamming`. No production endpoint or `main` change is part
of this work. The Paillier implementations and SEAL experiment are preserved.

## Scope and trust model

The review covers `crypto/encryption/bfv.py`, `bfv_evaluator.py`, `bfv_rns.py`,
`bfv_native.py`, `crypto/bfv_client.py`, the BFV types in
`x_vec/utils/xtrace_types.py`, and every source header plus `bindings.cpp` in
`crypto/bfv_cpu_ext/`. It follows key generation, encryption, public evaluation,
packed serialization, response compaction, decryption, input checks and native
ownership/concurrency. Existing BFV tests, build rules and the benchmark's
secret/public separation were also inspected. Paillier, SEAL internals,
production HTTP services, dependency implementations and deployment
infrastructure are outside this review's audit scope.

The assumed data owner controls a trusted private client and its secret key.
The evaluator receives public encryption/evaluation keys, encrypted index and
encrypted queries. An adversary may replace, replay, reorder or corrupt the
server's output or network messages. A separate honest-but-curious model assumes
the server follows the specified circuit and only observes its inputs and
execution. Local side-channel attackers are considered a deployment concern,
but no timing, cache, power or fault-injection exploit was attempted.

The local BFV API supplies no authenticated network session, tenant policy,
query identifier, index-version binding or verified computation. The wire's
key ID is public. Decrypted distances and top-k selection are private-client
operations. A later document fetch, telemetry event, error response or retry
can cross that privacy boundary even if this arithmetic module never makes a
network call.

## Findings

Severity below describes impact **if the stated integration exposes the
relevant surface**. These are not claims that a deployed XTrace endpoint is
currently exploitable.

| ID | Severity / status | Finding and precondition |
| --- | --- | --- |
| BFV-01 | High; open deployment blocker | An attacker able to observe chosen-ciphertext decryptions can recover the secret. Error/noise feedback must also be treated as secret-dependent. |
| BFV-02 | High; open for an untrusted evaluator | Ciphertext validation and distance range checks do not establish correct computation or prevent replay. |
| BFV-03 | High; open assurance blocker | Algebraically accepted parameters have no established security level or negligible failure-probability guarantee. |
| BFV-04 | High with a local observation surface; open | Private Python/GMP operations are variable time, with no secret-memory erasure guarantee. Secret serialization is plaintext. |
| BFV-05 | Medium; locally hardened | Oversized byte/hex fields were converted before size rejection; key JSON lacked an import-size bound and admitted ambiguous encodings. Service-wide resource limits remain necessary. |
| BFV-06 | High if setup is unauthenticated; documented, open | The key fingerprint does not authenticate the public bundle and does not cover evaluation keys. |
| BFV-07 | Medium; open protocol policy | Distances, query-derived access, counts and stable identifiers have application-level leakage; shared-key query access does not enforce database confidentiality from that query holder. |

### BFV-01: a decryption oracle can disclose the key

For our formula `Decrypt(c) = round(t*(c0+c1*s)/Q) mod t`, construct
`c0=0` and the constant polynomial `c1=floor(Q/t)`. This requires only public
parameters and the public key ID. For a ternary secret and the test parameters,
decrypting yields each secret coefficient modulo t; mapping `t-1` to `-1`
recovers the entire secret. The regression test demonstrates this with a fresh
local key and no attack on an external system. The small ring makes the test
fast; the construction is algebraic, not a brute-force attack on its dimension.

`test_decryption_oracle_would_reveal_secret_key` intentionally **passes when
this disclosure is possible**. It records a forbidden integration pattern;
it is not a mitigation test. The demonstration uses the raw polynomial
decryption API, not a claim that one call to the range-checked Hamming decoder
returns the full key. Rejecting some decoded values can itself create a
secret-dependent success/failure oracle if that outcome is observable.

Do not expose `BFV.decrypt`, decoded distances, `noise_budget`, per-response
errors or decryption-dependent telemetry to the untrusted evaluator. A
production protocol must analyze any result-dependent follow-up, including
which document IDs are fetched. SEAL's own guidance likewise treats decryptor
outputs and noise diagnostics as private, and Apple's BFV guidance explicitly
warns about decryption-oracle key recovery.
[SEAL security guidance](https://github.com/microsoft/SEAL/blob/main/SECURITY.md),
[Apple BFV guidance](https://github.com/apple/swift-homomorphic-encryption/blob/main/README.md#homomorphic-encryption-he).

Client response parsing now limits accepted Hamming responses to two
components at the configured terminal modulus or original Q, before private
decryption. This rejects unexpected protocol shapes. **It does not provide
chosen-ciphertext security.** Blanket rejection of all-zero ciphertexts would
also reject legitimate homomorphic results and would not prevent an attacker
from constructing other chosen ciphertexts.

### BFV-02: plausible results and replays remain unauthenticated

Two tests show that the client accepts both a transparent zero ciphertext and
a fresh public-key encryption of the plausible distance 1. Neither proves
that the encrypted query was evaluated against the intended index. A third
test replays the response to one query while the correct answer to another
query is different. Key identity, shape and `0 <= distance <= embed_len`
checks all still pass. There is no query or index epoch in the response frame.

Authenticated transport and authenticated setup are necessary to exclude an
outside message replacement attack. Binding messages to a tenant, key, query
nonce, index version, ordered IDs, layout and parameters can exclude accidental
mixups and outsider replay when those bindings are authenticated. **A signature
from the evaluator alone does not prove it computed the right circuit.** An
actively malicious evaluator requires a reviewed verifiable-computation or
other protocol mechanism, or an explicit weaker trust assumption. No bespoke
authentication scheme was added around homomorphic ciphertexts in this change.
SEAL also distinguishes loading/decrypting a ciphertext from authenticating it.
[SEAL ciphertext authenticity guidance](https://github.com/microsoft/SEAL/blob/main/SECURITY.md#ciphertext-authenticity).

### BFV-03: parameter and failure assurance is incomplete

`BFV.validate_parameters` checks algebra, supported bounds and types. It
deliberately accepts insecure tiny rings for tests, and also accepts large
Q/small-N combinations that must not be selected for production merely because
the method returns successfully. The API does not advertise a 128-bit security
setting, enforce a deployment allowlist or estimate lattice attacks.

The optimized benchmark configuration is:

| Item | Actual construction |
| --- | --- |
| Ring | `Z_Q[X]/(X^8192+1)` |
| Q | Product of three 60-bit NTT primes; 180 total bits |
| Plaintext | t=65537, two-row batching |
| Secret and encryption ephemeral u | Independent uniform coefficients in `{-1,0,1}` |
| Error | Centered binomial, eta=21; variance 10.5 and standard deviation about 3.240 |
| Evaluation keys | Six 30-bit gadget digits for s² and required automorphic secrets, under the same secret |
| Terminal response | Exact componentwise rounding to a 50-bit prime |

Q's three primes are 1152921504606830593, 1152921504606748673 and
1152921504606683137. They are the actual encryption modulus; the larger tensor
NTT basis is only an arithmetic workspace. Counting its product as the RLWE
encryption modulus would be incorrect.

The older HE standard's classical ternary-secret table lists log2(Q)=218 at
N=8192 for its 128-bit target and specified error assumptions. Our Q=180 is
below that reference bound, but our binomial sampler and secret-dependent
evaluation keys still require a justified analysis. This table comparison
**does not establish security for our implementation**.
[HE Standard v1.1, Table 1, ternary section on PDF page 27](https://homomorphicencryption.org/wp-content/uploads/2018/11/HomomorphicEncryptionStandardv1.1.pdf).
The consortium points to newer parameter guidance; parameter selection must
cover both attacks and functional correctness.
[Current guidance index](https://homomorphicencryption.org/security-guidelines/),
[Security Guidelines for Implementing Homomorphic Encryption](https://cic.iacr.org/p/1/4/26).

Before making a security-level claim, record an expert-reviewed configuration
with concrete classical/quantum attack estimates, estimator version and cost
models, the exact secret/error distributions, sample exposure and the
assumptions needed by the evaluation keys. A modern estimator was not run in
this review. Its rough and full estimators can use different cost models;
one convenient output number is insufficient evidence.
[Lattice estimator documentation](https://github.com/malb/lattice-estimator).

Correctness also needs a circuit-specific bound on decryption failure,
including compaction, maximum dimensions/merge depth, message patterns,
key distributions and repeated queries. The tests cover fresh randomness,
extreme patterns and exact arithmetic boundaries. They cannot establish a
negligible failure probability. The benchmark's 26-bit noise budget measures
remaining noise margin on those results; it is neither 26-bit nor 128-bit
cryptographic security, and positive noise diagnostics cannot rule out an
earlier wraparound.

### BFV-04: private operations and key storage

Key generation, ephemeral/error sampling, encryption and decryption use
`secrets` and Python/GMP. The review found no benchmark PRNG feeding production
encryption: public uniform coefficients use `secrets.randbelow(Q)`, ternary
coefficients use `randbelow(3)`, and each binomial sample subtracts the popcounts
of two independent `randbits(eta)` results. Tests check mapping and bounds and
verify that an entropy-source exception aborts key generation/encryption.
They do not constitute an entropy audit or statistical security proof.

Python objects, GMP multiplication/packing, comparisons, allocation and error
paths have no constant-time contract. We did not measure an exploitable timing
channel, but cannot claim its absence. Moving **public server** evaluation to
constant-width RNS does not harden the private key operations. The server
kernels receive no secret key; tests enforce that public-only evaluation never
calls private phase computation.

`stringify_sk` is an explicit plaintext export. Secret tuples, GMP limbs and
JSON copies have no guaranteed erasure, locked-memory protection or encrypted
storage. Key custody, crash dumps, logs, process isolation and backup handling
need a deployment design. Do not claim that a Python zeroization helper would
erase every copy. Private arithmetic requires independent implementation and
side-channel review appropriate to the intended platform.

### BFV-05: input handling fixes and remaining resource policy

The review found that the original wire readers called `int.from_bytes` on
every field before checking size. Arbitrarily long high-order zero padding
could therefore consume conversion memory while representing a small valid
number. Public-key coefficients and native modulus text were similarly passed
to GMP before their bit limits were established. Key JSON had no pre-parse
size cap, silently accepted duplicate object fields, and accepted boolean
version values and multiple textual encodings of some integers.

The hardening adds:

- A shared Python wire reader with per-field byte and integer limits checked
  before big-integer conversion/unpacking. Negative values, bools and floats
  are rejected. C++ still checks every imported coefficient is strictly below
  Q before any arithmetic relies on the convolution bound.
- Public-key and secret-key JSON limits of 128 Mi and 1 Mi **characters**,
  respectively, checked before `json.loads`. These are local resource policy,
  not security parameters. `BFV.deserialize_*` accepts an explicit `max_chars`;
  `BFVClient.load_stringified_keys` exposes `max_public_key_chars` for larger
  trusted experiments. Existing default public bundles (~86 MB ASCII) fit.
- Duplicate-field rejection, bounded canonical lowercase coefficient hex,
  canonical decimal Galois exponents, strict key fields/version types, and
  normalization of excessive JSON nesting into `ValueError`.
- Native modulus-text bounds before GMP parsing and a modulus-type check on
  direct Python ciphertext objects. Failed key imports leave the client and
  existing evaluator context unchanged.

Previously emitted v1 keys and minimally encoded ciphertexts remain readable;
the serialization version and cryptographic values are unchanged. Noncanonical
hand-written JSON, excessive zero padding and over-limit bundles are now
rejected intentionally. JSON whitespace within the overall cap remains valid.

These caps do not bound a service's total memory or CPU use. JSON parsing still
allocates the entire permitted object tree. A character cap is not a byte cap
for Unicode; a service must restrict transport bytes before buffering or
decoding, authenticate and allowlist setup parameters, limit index/request
sizes and concurrent evaluations, and impose process/resource quotas. Direct
Python object APIs and private C++ capsules assume trusted application code;
they are not sandbox boundaries. GMP out-of-memory behavior was not fault
injected, and the native extension's exception handling is not an OOM survival
guarantee.

### BFV-06: authenticate the whole setup bundle

`_key_id` hashes serialized parameters plus encryption polynomials `(b,a)`.
It is useful for key mixup detection. It is unkeyed, and omits relinearization
and Galois keys. A test changes a relinearization coefficient, successfully
loads the bundle with the same key ID, and confirms the whole-bundle digest
changed. An attacker able to replace all of `(b,a)` can also recompute a new
fingerprint; neither equality check establishes ownership.

Public import cannot verify the secret-dependent algebraic relationship of
evaluation keys from their shape alone. Secret import checks ternary
coefficients and consistency with the public RLWE sample, but does not certify
key generation or authenticate the public setup. Provision and authenticate
the complete bundle, configuration and intended owner from a trusted source.
An unkeyed digest is meaningful only when its expected value is authenticated
out of band. No incompatible fingerprint change was made in this review.

### BFV-07: application leakage and authorization

This protocol returns all candidate distances in packed ciphertexts and lets
the client compute top-k. It does not reveal only three distances. A party with
chosen-query access to all Hamming distances can recover a binary database
vector v: querying the zero vector gives its weight w; querying unit vector
e_i gives `w+1-2*v_i`. These D+1 queries determine every bit. For a data owner
searching their own data this is expected; it is not an access-control scheme
for mutually distrustful users sharing the key or query capability.

The server also observes vector count, parameters, encrypted-index identity,
message sizes and query timing. Subsequent top-k document fetches may reveal
access patterns. Ciphertext randomization does not hide these metadata. No
circuit-privacy, multi-tenant isolation, forward secrecy or private retrieval
guarantee is established here. Define which leakage is acceptable and enforce
owner/key authorization in the application.

## Evidence and limits of testing

The new `tests/x_vec/test_bfv_security.py` contains **63 cases**. Coverage
includes the four explicit protocol-limit demonstrations, randomness handling,
public-only operation, parser limits/ambiguity, response shape before private
decryption, atomic key-load failure, 450 deterministic wire mutations across
kernel levels, and 100 native coefficient-buffer cases. Mutation tests compare
accepted attacker-modified ciphertexts with the GMP reference and reject
malformed framing; they do not assume ciphertext tampering must fail.

A default-size stress test uses two fresh N=8192, Q=180 RNS key sets, six query
patterns (zeros, ones, alternating bits, first/last one-hot and random bits),
and a 33-vector index with a partial tile and merge. Every distance is checked
against plaintext Hamming distance. Fixed PRNGs generate only test vectors and
mutation positions, never cryptographic randomness.

The standalone C++ suite checks old/fused NTT spectra through N=32768,
schoolbook products, certified CRT boundaries, gadget widths through the
supported maximum, and exact signed RNS scaling at all eight Q widths. The
review extended the scaling oracle to plaintext multipliers immediately below
2^60 where Q permits. Fixed-word corrections are exercised at ambiguous
rounding boundaries, not merely random points.

The source review checked the 60-bit-prime, 64/128-bit accumulator and
eight-/18-word storage bounds, the signed tensor quotient bound, immutable
server/key ownership while the GIL is released, byte-buffer lifetime, canonical
imports and guarded exports. No memory corruption was found in the exercised
paths. This is not formal verification, an exhaustive fuzzer campaign or an
independent proof of the RNS construction.

Validation on this branch:

- **263 offline tests pass**, including **181 BFV tests** and the existing
  Paillier/SEAL coverage. HTTP integration and unavailable GPU tests were excluded.
- The C++ arithmetic suite passes AddressSanitizer and UndefinedBehaviorSanitizer.
- **96 Python-binding/security tests pass** against an ASan/UBSan extension.
  This includes malformed inputs and the real-default stress case.
- Ruff and mypy pass for the SDK and BFV benchmark code. CI runs the new
  security tests and includes them in the sanitized binding run.

Reproduce the principal security checks:

```bash
make -C src/xtrace_sdk/x_vec/crypto/bfv_cpu_ext PYTHON="$PWD/.venv/bin/python"
.venv/bin/python -m pytest tests/x_vec/test_bfv_security.py -q
```

The exact standalone and binding sanitizer commands are in
`.github/workflows/ci.yml`. Sanitizer success covers the executed cases on this
compiler/platform; it does not establish constant-time behavior or memory
erasure. Test output contains no generated secret key material.

The final performance check after hardening used the same-key interleaved
1,024-vector × 512-dimension workload as the optimization report. Warm medians
were 2.7874 s for the previous residue kernels, 2.4236 s for the new kernels
and 2.4850 s for the preserved SEAL prototype. Native ciphertexts were identical
and all distances were correct; response size stayed 102,496 bytes. This
retains a 13.1% reduction in server time. Raw samples and final source/binary
hashes are in `benchmarks/results/native_bfv_security_1024.json`. The
[performance report](native-bfv-fused-rns.md) explains the different SEAL
parameters, timing boundary and absence of an equal-security comparison.

## Production gates

1. Have an independent HE cryptographer review the construction, exact RNS
   scaling proof, distributions, parameter estimates, evaluation-key assumptions
   and a complete circuit-specific decryption-failure analysis. Freeze and
   enforce a reviewed configuration separately from algebra-test parameters.
2. Specify the end-to-end threat model and every output channel. For an active
   server, provide a reviewed integrity/verifiability design and demonstrate
   that response handling, errors, retries and document retrieval do not expose
   a harmful decryption oracle. Authenticate setup and bind sessions, queries,
   index versions, IDs and layouts.
3. Review private arithmetic and key custody for the deployment platform.
   Establish appropriate side-channel controls, logging/storage policy,
   isolation, rotation and incident handling.
4. Apply service-level resource limits and authorization. Run sustained
   adversarial fuzzing, platform/compiler coverage, dependency review and load
   tests on the actual endpoint before rollout.

Passing the current tests closes specific regression risks. It does not close
these gates or make the homemade BFV interchangeable with an independently
reviewed production cryptosystem.
