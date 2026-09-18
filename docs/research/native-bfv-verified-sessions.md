# BFV authenticated sessions and remaining security blockers

Date: 2026-09-11. Branch: `research/bfv-packed-hamming`.

**Several audit risks now have concrete SDK protections, with the existing
RNS evaluator preserved. All findings are not closed, and this implementation
remains experimental.** In particular, a new regression demonstrates secret-key
recovery from observable accept/reject feedback even through the new result
checker. This follow-up is internal, AI-assisted engineering and testing, not
an independent cryptographic audit or production certification.

**Subsequent work:** [the guarded pre-decryption API](native-bfv-predecryption.md)
now blocks this demonstrated oracle using exact public recomputation by a
separately trusted owner verifier. That report covers its trust/compute cost,
native private arithmetic and parameter review. The results and open-status
table below describe the original result-checked API, which remains available.

This extends the [original audit](native-bfv-security.md). The raw BFV,
Paillier and SEAL paths remain available. Existing `BFVClient` calls do not
automatically acquire these protections; applications must explicitly use the
new local session API and provide trusted key provisioning.

## Code and usage

| Path relative to the repository | Purpose |
| --- | --- |
| `src/cuhepy/bfv_security.py` | Locally pinned parameters/limits, bounded authenticated framing, AES-GCM private exports |
| `src/cuhepy/bfv_verified_client.py` | Private result summary, client request lifecycle and public-only server wrapper |
| `tests/unit/test_bfv_verified_client.py` | Tampering/replay/storage/resource regressions and the residual oracle demonstration |
| `benchmarks/bfv_verified.py` | Same-key, same-ciphertext comparison against raw residue evaluation |

The following is a local experiment. It deliberately contains no network
callbacks: distances, errors and result-dependent behavior must remain inside
the trusted client. Provision the authentication key to the intended evaluator
over a trusted authenticated channel; keep the wrapping key exclusively in
separate trusted client storage or a suitable key-management service.

```python
import secrets

from cuhepy.hamming.bfv import BFVClient
from cuhepy.hamming.bfv_security import BFVExecutionPolicy
from cuhepy.hamming.bfv_verified import (
    BFVVerifiedClient,
    BFVVerifiedServer,
)

# The default policy pins the measured N=8192, Q=180-bit RNS configuration.
# This is an arithmetic/resource allowlist, not a 128-bit security claim.
policy = BFVExecutionPolicy()
authentication_key = secrets.token_bytes(32)  # Shared with this evaluator.
wrapping_key = secrets.token_bytes(32)        # Private; never sent to it.
raw_client = BFVClient(**policy.config())
client = BFVVerifiedClient(raw_client, authentication_key, policy=policy)
setup = client.prepare_index(
    [[0] * 512, [1] * 512], vector_ids=["document-a", "document-b"]
)

# Separate public-only instance, using the existing C++ residue implementation.
server = BFVVerifiedServer(setup, authentication_key, policy=policy)
request = client.begin_query([0] * 512)
response = server.search(request)
distances = client.finish_query(response)  # [0, 512], checked before return.
top3 = sorted(zip(client.vector_ids, distances), key=lambda item: (item[1], item[0]))[:3]

# Caller persists these bytes securely; no file is written by the SDK.
protected = client.protect_state(wrapping_key)
restored = BFVVerifiedClient.restore(
    setup, protected, authentication_key, wrapping_key, policy=policy
)
```

The compiled backend is built with the existing command:

```bash
make -C src/cuhepy/bfv/_cpu_ext PYTHON="$PWD/.venv/bin/python"
```

For CPU-only fallback, explicitly select `backend="optimized"` on
`BFVVerifiedServer`. The wrapper snapshots the private client's key dictionaries;
reloading the original `BFVClient` cannot silently change the active session.
An index is immutable within a session. Rebuild setup and its fresh private
summary for an updated index.

## What each protection does

**Whole-setup and message authentication.** A versioned, domain-separated
HMAC-SHA256 envelope covers the exact setup bytes: parameters, layout,
encryption keys, all evaluation keys, index ciphertexts, ordered unique IDs,
vector count and a fresh session identifier. Each request binds that setup's
SHA-256 digest and a fresh 256-bit ticket; each response additionally binds
the exact authenticated request's digest. Incoming byte limits and HMAC are
checked before MessagePack or key JSON parsing. The unkeyed BFV key ID remains
a compatibility check, not an ownership credential.

The caller supplies an independent, uniformly generated 32-byte authentication
key. Use distinct authorization/key domains for distinct data owners. The
server knows this key and can authenticate a false answer; HMAC protects
against outsiders and mixups, not dishonesty by the authenticated evaluator.
Setup authentication cannot certify that a malicious key generator sampled
valid keys or that an authorized client submits only permitted queries.

**One-use requests and bounded admission.** The client records at most eight
pending requests by default. An authenticated response bound to a pending
request consumes its ticket before any ciphertext decryption, including on a
subsequent rejection. A concurrent duplicate cannot trigger a second private
decryption. An unauthenticated or unrelated packet cannot consume a legitimate
ticket. Each client/server instance admits at most 65,536 queries; cancellation
does not reset the client count. The server defaults to one concurrent search
and rejects work immediately when busy. Its replay set is bounded by the query
budget.

Default caps are 65,536 vectors, 384 MiB setup, 128 MiB public JSON, 256 MiB
encoded index, 1 MiB query and 16 MiB response. These are independent upper
bounds, not a promise that every combination fits. The wrapper requires the
exact configured terminal response modulus and expected ciphertext count,
then inherits canonical coefficient/shape/range checks from the raw BFV code.
An explicit local policy can select tiny test parameters; received setup
cannot change the policy. A policy is not a security-level certificate.

Budgets and replay state are per object and in memory. Protected client state
preserves the count of started requests, but discards pending tickets on
restore. It has **no anti-rollback mechanism**. A service still needs durable
authorization/replay state or a fresh client-authorized setup after restart,
limits before transport buffering, aggregate memory/CPU quotas and admission
across tenants. Reinstantiating an object must not reset service quotas.

**Encrypted private storage.** AES-256-GCM uses a fresh 96-bit nonce and a
128-bit tag, authenticating before plaintext parsing. `protect_state` encrypts
the BFV secret key, verification summary and used query count, with the entire
authenticated setup digest as associated context. The wrapping key must
differ from the server authentication key. For a raw `BFVClient`,
`protect_bfv_secret_key` and `restore_bfv_client` provide a separate encrypted
export bound to the exact full public JSON, including every evaluation key.
This uses the existing PyCryptodome dependency's authenticated encryption API;
it is not a new block cipher or password-based key derivation scheme.
[PyCryptodome authenticated-mode documentation](https://www.pycryptodome.org/src/cipher/modern).

These APIs protect stored bytes. Existing explicit `stringify_sk()` exports
remain plaintext, and Python/GMP memory, temporary copies, crash dumps,
wrapping-key custody and local timing/cache behavior remain separate concerns.
No zeroization or constant-time guarantee is added.

## Private Hamming result check

For binary database rows `x_i` and query `q` of dimension D, Hamming distance
is `d_i = |x_i| + |q| - 2 * sum_j(x_ij*q_j)`. At index creation the client
generates an independent private seed and derives a pseudorandom weight `r_i`
for each row in the prime field `p = 2^255 - 19`. It retains:

```text
R   = sum_i r_i                   mod p
S_j = sum_i r_i * x_ij            mod p

expected(q) = sum_j S_j + R*|q| - 2*sum_j S_j*q_j   mod p
actual(d)   = sum_i r_i*d_i                         mod p
```

The client checks equality only after decrypting and range-checking the full
answer, and returns no unchecked or partial distance vector. Swapping unequal
distances or replacing them with plausible constant results changes this
fingerprint except for a collision. The seed and summary never go to the
evaluator; disclosing the columns can also disclose information about the
database, so they are encrypted alongside the secret key when persisted.

This adapts private preprocessing for verifying a fixed linear computation,
as described in Slalom's Lemma 3.1 and Appendix B. The Hamming identity above
is our derivation for this application; the Slalom paper does **not** prove
security for this BFV protocol or make it chosen-ciphertext secure.
[Tramèr and Boneh, Slalom, ICLR 2019](https://arxiv.org/pdf/1806.03287).

With independent uniform field weights, a fixed nonzero result error passes
one linear check with probability `1/p`. Finite repeated checks require a
query-bound analysis; using HMAC as a pseudorandom function adds that
computational assumption. HMAC-SHA256 is keyed with the private seed and binds
the session, row index and a rejection-sampling counter. Sampling rejects
values outside the field, with a bounded retry count that fails closed.
This reasoning motivates the experimental check, not a reviewed security
theorem for its implementation, key reuse or the complete application. The
255-bit field is unrelated to BFV's plaintext modulus and does not establish
255-bit or 128-bit BFV security.

Preprocessing is O(MD); online checking is O(M+D), with no additional server
arithmetic or verification ciphertext. The binary summary payload is
`32*(D+2)` bytes: seed, R and D columns. At D=512 this is **16,448 bytes**,
excluding IDs, session metadata and Python object overhead. The client need
not retain the original binary vectors after setup.

## The oracle blocker still exists

`test_acceptance_feedback_still_allows_key_recovery` intentionally demonstrates
an attack on the new wrapper when the evaluator can observe whether a response
was accepted. It uses fresh toy keys and a known zero-distance answer; there
is no external target. It forges authenticated packets as a malicious server
that already knows the transport authentication key.

At the negotiated terminal modulus q, choose the constant coefficient of c0
as `floor(q/(2*t)) + offset`, where `offset` is 0 or 1. Choose c1 as a monomial
that places one signed secret coefficient at position zero in `c1*s`.
The tested decryption rounding makes every decoded slot either zero or one.
Both are plausible distances. For the known zero answer, the result check's
acceptance tells whether this chosen phase crossed the rounding boundary.
Two observed responses per coefficient recover the ternary secret in the
test, using fresh legitimate query tickets each time. Terminal-modulus checks,
HMAC, replay rejection and the private result fingerprint all remain enabled.
This is an algebraic demonstration, not a brute-force attack on small N; the
test does not time a full attack at the benchmark parameters.

Consequently, a uniform exception message does not solve the problem. Neither
does returning only correct plaintexts: **accept/reject, timing, retries,
telemetry or subsequent document fetches can themselves convey a decryption
predicate.** The class name means result-checked, not a public proof of valid
evaluation before decryption. SEAL likewise requires private handling of
decryptor outputs and noise diagnostics and distinguishes ciphertext loading
from authenticity.
[SEAL security guidance](https://github.com/microsoft/SEAL/blob/main/SECURITY.md).

Closing BFV-01 for an active server with observable client behavior needs a
reviewed protocol boundary. Possibilities to evaluate include verifying a
proof of the prescribed public computation **before decryption**, or a trusted
evaluation environment with an appropriate attestation and side-channel
model. Merely signing the result using a key held by an untrusted evaluator
does not suffice. Neither mechanism is implemented here, and its performance
cannot be inferred from this wrapper benchmark. Removing all harmful feedback
requires analysis of the actual application, not just a local Python API.

## Audit status after this change

| Finding | Implemented mitigation | Still open |
| --- | --- | --- |
| BFV-01: chosen decryption | Authenticated framing, exact response shape/modulus, one attempt per request, no partial plaintext | Confirmed accept/reject key-recovery oracle if feedback reaches the server; no CCA-secure or pre-decryption verified protocol |
| BFV-02: forged/replayed results | Private Hamming fingerprint; authenticated query/index/ID binding; in-memory one-use tickets | Experimental verifier requires independent review; no durable replay or arbitrary-circuit proof; BFV-01 remains |
| BFV-03: parameter assurance | Measured parameter profile pinned by trusted local policy | Independent attack estimates, evaluation-key assumptions and circuit-specific failure bounds |
| BFV-04: private implementation/storage | Authenticated encryption for exported keys and summary, bound to complete setup | Variable-time Python/GMP, secret memory erasure, platform isolation and wrapping-key custody |
| BFV-05: resource exhaustion | Auth-before-parse, packet/index caps, query budgets and concurrent-search admission, retaining earlier parser hardening | Transport/aggregate/process quotas, deployment fuzzing and durable service policy |
| BFV-06: unauthenticated bundle | Keyed authentication covers configuration and every public/evaluation key, index and ordered IDs | Trusted key provisioning and ownership authorization in the application; malicious key-generation assurance |
| BFV-07: leakage/authorization | Explicit owner/session boundary and authenticated ordered IDs | All-distances/chosen-query leakage, sizes/counts/timing, follow-up access patterns, tenant authorization and private retrieval |

The BFV-07 leakage is inherent in the current functionality: a query holder
that can obtain all distances for zero and unit-vector queries can reconstruct
a binary row. A data owner searching their own index may accept that capability;
mutually distrustful query holders need a different access-control/protocol
design. This session wrapper does not implement private top-k selection, PIR,
ORAM, circuit privacy or multi-tenant key isolation.

## Performance and validation

The benchmark compares the wrapper with raw evaluation using the **same BFV
keys, index ciphertexts, query ciphertexts and unchanged residue kernels**.
Both server measurements include MessagePack ciphertext decoding/encoding and
native evaluation. The wrapper also includes authentication and request
bookkeeping. Separate client measurements include decryption/slot decoding;
the wrapper adds authentication and the private result check. Setup/import,
arithmetic-context construction and query encryption are outside server
timings. One cold search is followed by five warm searches per variant,
alternating order in a single process without concurrent tests.

On the Ryzen 7 5800X CPU, Python 3.12.3 and GMP 6.3.0, using 512-bit vectors,
N=8192, t=65537, a 180-bit RNS Q and a 50-bit terminal modulus:

| Warm median | Raw BFV path | Authenticated/result-checked path |
| --- | ---: | ---: |
| Server, 1,024 vectors | 2.36799 s | 2.37360 s |
| Client decode, 1,024 vectors | 39.55 ms | 41.58 ms |
| Server, 32 vectors | 75.00 ms | 75.40 ms |

At 1,024 vectors, the measured server difference is **+0.24%**, smaller than
the spread of the warm samples; this is not evidence of a material slowdown.
Client overhead is **2.03 ms**. The isolated private check takes 2.13 ms and
its one-time summary preprocessing takes 25.15 ms. Index encryption, summary
construction, public export and setup authentication together take 8.08 s;
authenticated setup import takes 1.74 s. These setup measurements are reported
separately rather than charged to each search. Cold search times, including
lazy evaluation-key/mask preparation, are 2.657 s raw and 2.674 s wrapped.
All measured ciphertext outputs are exactly identical and every distance
matches an independent plaintext Hamming calculation.

The same 1,024-vector run gives the following serialized sizes (decimal bytes):

| Item | Size |
| --- | ---: |
| Public BFV setup keys, unchanged JSON encoding | 85,603,219 |
| Encrypted-index ciphertext array | 23,598,467 |
| Complete authenticated setup, including keys, index, IDs and metadata | 109,205,980 |
| Authenticated query | 368,840 |
| Authenticated response | 102,614 |
| Authenticated query + response | 471,454 |
| Private summary payload, never sent to server | 16,448 |
| AES-GCM private export, including secret key and summary | 36,729 |

Authentication/session framing adds **113 query bytes + 147 response bytes**
over the bare ciphertext arrays used by both variants in this benchmark.
Using the earlier benchmark's dictionary framing on these exact ciphertexts
gives 368,754 query bytes and 102,496 response bytes: 471,250 combined. The
authenticated combined transfer is therefore only **204 bytes (0.043%) larger
than that earlier framing**. This distinction avoids calling the 260-byte
overhead a difference from an envelope that already contained 56 bytes of
other metadata. Encryption, compaction and public-key serialization are
unchanged; fresh random keys can cause small JSON-size variations.

Raw samples and source hashes are saved in
`benchmarks/results/native_bfv_verified_1024.json` and
`benchmarks/results/native_bfv_verified_32.json`. The recorded base revision
is `b7841e4` with the new files present in a dirty working tree; the recorded
hashes identify the measured source. These are local measurements, not a
network/load benchmark, and they do not include any future proof or isolated
private-arithmetic implementation needed to close the remaining blockers.

Reproduce the comparison and regression suite:

```bash
.venv/bin/python benchmarks/bfv_verified.py --num-vectors 1024 --repeats 6 \
  --json-out /tmp/bfv-verified.json
.venv/bin/python -m pytest tests/unit/test_bfv_verified_client.py -q
```

Benchmark JSON records raw timings, environment and source/binary hashes, not
keys, ciphertexts or private summary values. The wire-size table separates
the new array framing from the previous benchmark's dictionary framing; the
same ciphertexts can therefore be compared without attributing envelope bytes
to a cryptographic change. No security equivalence with SEAL is asserted.

Validation after the change:

- **302 offline tests pass**, including **220 native BFV cases** and the existing
  Paillier/SEAL coverage. The service HTTP integrations and unavailable GPU
  tests are excluded, as in the original audit.
- The new session test file has **39 cases**: correct results across tile/row/
  response boundaries, public-only evaluation, plausible authenticated
  forgeries, cross-query/session replay, tampering before parsing/decryption,
  bounded MessagePack, terminal-modulus enforcement, concurrent duplicate
  consumption, parameter/resource policy, entropy failures, NumPy/GMP integer
  compatibility and encrypted-state binding/restoration. One case intentionally
  demonstrates the remaining accept/reject oracle; its passing status means
  the attack succeeds under that forbidden integration.
- **135 binding/security cases pass** against a freshly compiled extension
  with AddressSanitizer and UndefinedBehaviorSanitizer. Leak detection is
  disabled for the Python runtime, as in the existing CI command. No C++
  arithmetic or ABI change is part of this patch.
- Ruff and mypy pass for the SDK and BFV benchmark scripts; the new Python
  files pass the scoped formatter check. Existing repository-wide formatting
  differences were not reformatted.
- A built wheel imports both new modules and ABI 4 from a separate extracted
  package and passes public-only residue evaluation, checked decoding and
  encrypted-state restore. No SEAL implementation is imported by this API.
- CI includes the new session tests in both the regular BFV and sanitized
  binding runs. The documentation build is checked separately; the original
  research page's pre-existing `experiments/bfv/README.md` cross-reference
  warning is unrelated to this change.

Tests demonstrate the covered behavior. They neither establish a negligible
BFV failure probability nor prove absence of side channels or oracle leakage
in a deployed application. The open entries in the status table remain
production blockers wherever their threat model applies.
