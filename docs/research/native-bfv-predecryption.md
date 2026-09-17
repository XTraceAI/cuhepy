# BFV approval before decryption, private arithmetic and parameter review

Date: 2026-09-11. Branch: `research/bfv-packed-hamming`.

**The new `BFVGuardedClient` blocks the demonstrated malicious-response oracle
under an explicit additional trust assumption:** an owner-controlled verifier
independently recomputes the prescribed public BFV result and approves its exact
bytes. The client checks that approval before parsing or decrypting the result.
The verifier needs public BFV keys and ciphertexts, but no BFV secret key,
plaintext vectors or private result summary.

This is an implemented protocol baseline for review, not a claim of general
CCA2-secure BFV or production readiness. It costs another full evaluation and
depends on the verifier's integrity and signing-key custody. It is neither a
succinct cryptographic proof nor attestation of an untrusted server. A signer
controlled by the malicious evaluator provides no protection. If the owner can
simply use the trusted verifier as the evaluator, the extra untrusted evaluation
can be avoided at the application level; this implementation intentionally
measures independent checking of an existing evaluator.

The [earlier session report](native-bfv-verified-sessions.md) remains the record
of the vulnerable post-decryption check. Its attack test is retained. The raw
BFV and old session APIs retain their behavior and require explicit migration
to acquire the new gate. Paillier, the SEAL experiment and production endpoints
are unchanged. This work is internal, AI-assisted engineering, with no
independent cryptographic review.

## Code map and local use

All paths below are relative to the repository root.

| File | Purpose |
| --- | --- |
| `src/cuhepy/bfv_guarded_client.py` | Owner verifier, Ed25519 receipts, mandatory pre-decryption checks and bound private exports |
| `src/cuhepy/bfv_assurance.py` | Larger-ring review profile and exact conservative circuit bounds |
| `src/cuhepy/encryption/bfv_private.py` | Python adapter to the separate private native decoder |
| `src/cuhepy/bfv/_cpu_ext/private_decoder.h` | Fixed-width private NTT, CRT, rounding, locked buffers and wiping |
| `src/cuhepy/bfv/_cpu_ext/private_bindings.cpp` | Bounded CPython interface, capsule ownership and GIL handling |
| `src/cuhepy/bfv_verified_client.py` | Small change: optional native private decoding; original default remains Python |
| `tests/unit/test_bfv_guarded_client.py` | Forgery/oracle, pin, replay, concurrency and saved-state regressions |
| `tests/unit/test_bfv_private.py` | Independent arithmetic, boundary, ownership and memory-lock tests |
| `tests/unit/test_bfv_assurance.py` | Bound checks and observed-phase comparisons |
| `tests/unit/native/test_bfv_private.cpp` | Standalone sanitizer, wipe and compiled secret-taint tests |
| `benchmarks/bfv_guarded.py` | Same-ciphertext performance and all communication legs |
| `benchmarks/bfv_parameter_audit.py` | Actual parameter manifest and pinned external lattice estimates |

Build both optional CPU extensions on Linux with GCC or Clang:

```bash
make -C src/cuhepy/bfv/_cpu_ext PYTHON="$PWD/.venv/bin/python"
```

The public `_bfv_rns` ABI remains 4; the new, separate `_bfv_private` ABI is 1.
The guarded client defaults to native private decoding and the review profile.
Missing binaries, incompatible ABIs, unsupported parameters and memory-lock
failure raise errors; there is no automatic private-backend fallback.
`private_backend="python"` is an explicit research option with the same receipt
gate and the old variable-time private implementation.

```python
import secrets

from cuhepy.bfv.assurance import bfv_review_policy
from cuhepy.bfv.client import BFVClient
from cuhepy.bfv.guarded_client import (
    BFVGuardedClient, BFVPublicVerifier, bfv_verifier_public_key,
)
from cuhepy.bfv.verified_client import BFVVerifiedServer

policy = bfv_review_policy()  # N=16384; fresh keys and index required.
authentication_key = secrets.token_bytes(32)  # Shared with evaluator.
signing_seed = secrets.token_bytes(32)       # Owner-controlled verifier ONLY.
wrapping_key = secrets.token_bytes(32)       # Private client storage ONLY.
pin = bfv_verifier_public_key(signing_seed)  # Provision through a trusted path.
client = BFVGuardedClient(
    BFVClient(**policy.config()), authentication_key, pin, policy=policy
)
setup = client.prepare_index(
    [[0] * 512, [1] * 512], vector_ids=["document-a", "document-b"]
)

# Untrusted evaluator; only public BFV material is imported.
server = BFVVerifiedServer(setup, authentication_key, policy=policy)

# Run locally on the owner, or in a SEPARATELY TRUSTED owner-controlled service.
# Obtain the expected digest directly from the owner, not from the evaluator.
verifier = BFVPublicVerifier(
    setup, authentication_key, signing_seed,
    expected_setup_digest=client.setup_digest, policy=policy,
)
request = client.begin_query([0] * 512)
response = server.search(request)
receipt = verifier.approve(request, response)  # A second full public evaluation.
distances = client.finish_query(response, receipt)
assert distances == [0, 512]

protected = client.protect_state(wrapping_key)
restored = BFVGuardedClient.restore(
    setup, protected, authentication_key, wrapping_key, pin, policy=policy
)
```

This example is local orchestration, not a network service or secure process
isolation. In deployment the signing seed must never reach the untrusted
evaluator. Pin both the verifier identity and owner setup through trusted
configuration, authenticate owner authorization at the verifier, and review
the actual components running inside that trusted service.

## Why approval changes the oracle boundary

The previous result fingerprint checked plaintext *after* decryption. A
malicious server could submit carefully chosen ciphertexts and learn a secret
coefficient from the client's acceptance. Transport authentication could not
exclude that server because it knew the shared authentication key.

The new sequence is:

1. The owner creates an immutable authenticated index setup and a fresh query
   ticket, retaining the SHA-256 digest of its exact encrypted request.
2. The evaluator produces its response. The owner-controlled verifier uses an
   independently imported copy of the owner-pinned setup to recompute the
   complete canonical response, including terminal modulus switching.
3. The verifier compares every response byte, then signs only that transcript.
   Its API cannot sign arbitrary caller-provided hashes. These decisions use
   public ciphertexts only; even malicious queries cannot invoke BFV decryption
   at the verifier.
4. The client checks fixed receipt length, version, circuit, setup, pending
   owner-request binding, response digest and Ed25519 signature **before BFV
   response parsing or any private decoding**. Rejection cannot expose the
   BFV decryption predicate used in the historical attack.
5. The inner session still consumes the request once, enforces response shape
   and modulus, and checks the private Hamming fingerprint before returning
   the complete distance list. Concurrent replays cannot decrypt twice.

The owner-request check is essential. The evaluator knows the transport MAC
key and can construct its own authenticated requests. A valid receipt for one
of those requests must not authorize decryption on the owner. Tests cover this
case as well as the earlier rounding-oracle ciphertexts and check that neither
the GMP nor native decoder is reached.

Each receipt is **198 bytes**: a 6-byte version prefix, four 32-byte fields
(circuit identifier, setup digest, request digest, response digest), and a
64-byte Ed25519 signature. Signing uses a versioned Ed25519 context. The pin
comes only from local configuration; small-order public keys, including the
encoded identity accepted by the underlying import API, are explicitly
rejected. Cryptographic signing uses the existing dependency, not a new
signature implementation.
[PyCryptodome EdDSA documentation](https://www.pycryptodome.org/src/signature/eddsa).

The circuit identifier describes the implemented deterministic computation;
it is not a proof that arbitrary software follows it. Semantic or canonical
wire changes require a new circuit version, compatible trusted code and fresh
deployment review. A bad proposed result consumes the verifier's query ticket,
so a retry needs a new owner request. Missing, forged or unrelated receipts do
not consume the client's legitimate pending ticket. The outer AES-GCM saved
state additionally binds this gate and verifier pin, preventing accidental
restoration through the old unguarded session API. It adds 34 bytes over the
inner protected export and does not supply durable anti-rollback protection.

This implements an explicit trusted-computation boundary, **not** the
SNARK-based transformation analyzed in the verifiable-FHE literature.
That literature motivates binding permitted outputs to original inputs before
opening a decryption interface; it does not prove this SDK protocol secure.
[Manulis and Nguyen, EUROCRYPT 2024](https://eprint.iacr.org/2024/202).
SEAL also warns that decryptor outputs/noise information require private
handling; importing a ciphertext does not establish its authenticity.
[SEAL security guidance](https://github.com/microsoft/SEAL/blob/main/SECURITY.md).

## Private arithmetic: scope and evidence

The separate C++ decoder imports a ternary key once and keeps two secret NTT
spectra. For each two-component terminal ciphertext it computes exact
negacyclic `c1*s`, adds `c0`, rounds the phase modulo the plaintext modulus,
and batch-decodes all N slots. The input/output lengths and loop bounds depend
on public parameters, never a secret coefficient or decoded distance.

Two descending 60-bit NTT primes allow exact signed CRT reconstruction:
`|c1*s| < N*q < 2^65`, while half their product exceeds `2^117`. The private
path supports power-of-two N from 8 through 32768, `t < 2^30` with batching
roots, and terminal `t < q < 2^50`. Fixed 67- and 82-iteration binary dividers
replace division on secret phase values. Root setup and Shoup precomputation
can divide public values; private multiplication uses fixed-width products
and masked correction. The public server's faster variable-time NTT is not
reused for secret transforms.

Testing exposed Clang 18 turning ordinary masked corrections into branches.
A GCC/Clang register value barrier now prevents that optimization in the
tested builds. This is a known compiler-control technique, also documented in
[BoringSSL's constant-time helpers](https://boringssl.googlesource.com/boringssl/+/refs/heads/main/crypto/internal.h).
The resulting GCC 13.3 and Clang 18 `-O3` kernels pass dynamic secret-taint
checks for N=16,128,8192 and positive, negative and mixed ternary keys. The test
marks persistent secret spectra and transform inputs undefined in Valgrind,
then declassifies plaintext only after decoding returns. A deliberate secret
branch is a negative control and must fail. CI runs both compilers.

These tests detect executed secret-dependent branches and addresses. They do
not prove constant latency for every instruction, compiler, processor or
input, or cover speculative execution, faults, power analysis, hostile kernels
or physical access. Source review, the independent arithmetic oracles and
sanitizers supplement the taint tests; none is a side-channel certification.

Persistent native secret buffers and temporary private work use separate
`mmap` allocations, mandatory `mlock`, Linux `MADV_DONTDUMP` and volatile
full-region wiping. Lock/exclusion failure stops the operation. Decode and
close share a mutex; closing waits without holding Python's GIL and wipes the
native key before rejecting further decode calls. Capsule destruction also
wipes. At N=16384, a decoder locks 262,144 persistent bytes plus 393,216
temporary bytes during a decode; page rounding may matter for small rings.
Provision sufficient per-process lock limits. An isolated OS-limit test checks
that failure never silently falls back to unlocked storage.

**The whole private client is still not constant time or fully erasable.**
Python/GMP key generation, key import, encryption, private summary checking,
Python key objects, temporary imported key bytes and returned plaintext remain
outside the native kernel's guarantees. Existing keys are retained for future
encryption and protected exports. Wiping native buffers does not erase those
copies, registers, allocator remnants or the caller's results. A production
review must address those paths and process/key custody as well.

## Concrete parameter estimates

The runner records the actual product Q, not the larger multiplication
workspace basis. Both profiles use t=65537, uniform ternary secret/ephemeral
coefficients, centered-binomial error eta=21 (variance 10.5), six 30-bit gadget
digits and a 50-bit terminal response prime.

| Profile | N | Q primes | Public-key JSON cap |
| --- | ---: | --- | ---: |
| Original arithmetic default | 8192 | 1152921504606830593, 1152921504606748673, 1152921504606683137 | 128 MiB |
| Guarded review default | 16384 | 1152921504606748673, 1152921504606683137, 1152921504606584833 | 256 MiB |

Sage 10.9 ran lattice-estimator commit
`53da5982597709ba0fdf94ea37a84d822310fd84`, with `ND.Uniform(-1,1)` and
`ND.CenteredBinomial(21)`. Each profile has 24 estimates: primal uSVP, primal
BDD, dual and dual-hybrid, each with m=N and unbounded independent samples,
under three reduction-cost models. Primal runs use the geometric-series shape
model. The following are minima of reported `log2(rop)` across the selected
attacks and sample counts, **not assigned security levels**.

| Cost model | Original N=8192 | Review N=16384 |
| --- | ---: | ---: |
| MATZOV classical | 154.40 | 339.59 |
| ADPS16 classical sensitivity | 124.69 | 316.82 |
| ADPS16 quantum-sieving sensitivity | 113.42 | 287.53 |

The disagreement matters: a historical modulus table or one favorable model
cannot justify calling the original profile 128-bit secure. The larger ring
provides more estimated margin, at a measured cost. It requires fresh keys
and index creation; existing raw defaults remain unchanged for reproducibility.

Important limits of these estimates: generic LWE models do not certify RLWE
structural security or the circular/key-dependent-message assumptions of the
published s² and automorphism evaluation keys. m=infinity is a sensitivity
case, not a proof that related ring samples are independent. Unlisted attacks
and cost/shape models are not evaluated. The MATZOV source describes a fit
through block size 1024; some larger-ring runs exceed it and extrapolate.
ADPS16 quantum sieving is not a complete quantum attack analysis. Moreover,
Ed25519 receipts are not post-quantum signatures, so the whole guarded protocol
must not be described as post-quantum secure based on an LWE number.
[Lattice-estimator source and interpretation](https://github.com/malb/lattice-estimator),
[current HE parameter guidance](https://homomorphicencryption.org/security-guidelines/).

Results, all attack outputs, versions and manifest/source hashes are in:

- `benchmarks/results/native_bfv_parameter_estimates.json`
- `benchmarks/results/native_bfv_review_parameter_estimates.json`

Reproduce with an independently installed Sage Python and the pinned estimator:

```bash
git clone https://github.com/malb/lattice-estimator /tmp/xtrace-lattice-estimator
git -C /tmp/xtrace-lattice-estimator checkout 53da5982597709ba0fdf94ea37a84d822310fd84
.venv/bin/python benchmarks/bfv_parameter_audit.py manifest --profile review \
  --json-out /tmp/bfv-review-manifest.json
DOT_SAGE=/tmp/xtrace-sage /opt/sage/bin/python benchmarks/bfv_parameter_audit.py estimate \
  --manifest /tmp/bfv-review-manifest.json --estimator /tmp/xtrace-lattice-estimator \
  --json-out /tmp/bfv-review-estimates.json
```

The Sage executable path is installation-specific. `--profile original`
exports the other profile. No BFV keys are generated or stored by this audit.

## Conservative correctness bound for this circuit

`hamming_noise_bound` provides a source-level derivation for independent
review. It uses exact integers and rational numbers with outward rounding,
assuming honestly generated keys, bounded CBD errors, binary owner inputs and
the implemented square-difference/rotate/mask/merge circuit. It is not a
ciphertext validity test, formal proof, or assurance for malicious setup or
arbitrary FHE circuits. The guarded client requires this sufficient bound at
index creation and restoration, separately from receipt validation.

Let `Q = delta*t + r`, canonical plaintext polynomial coefficients lie in
`[0,t-1]`, and the phase invariant be
`Phi(c) = delta*m + v (mod Q)`, with `||v||_infinity <= V`.
For negacyclic polynomials, use `||a*b|| <= N*||a||*||b||`.

Fresh encryption has `Venc=(2N+1)*eta`; subtracting two ciphertexts gives
`Vdiff=2*Venc+r`. A gadget switch contributes at most
`S=N*digits*(2^gadget_bits-1)*eta`. For a canonical two-component difference,
write its **integer** phase as `delta*m+v+Q*k`, with

```text
L = ceil(((N+1)*(Q-1) + delta*(t-1) + Vdiff) / Q)
||k|| <= L
P = N*(t-1)^2
C = ceil((P+t-1)/t)       # Plaintext-product carry bound.
```

BFV tensor multiplication computes integer component products before rounding
each by t/Q. Expanding the two integer phases introduces lift terms
`t*(v*k' + v'*k) - r*(m*k' + m'*k)` modulo Q. Omitting them would incorrectly
treat scale-and-round as an operation on phase representatives alone. With
both input bounds equal to Vdiff, a sufficient bound after relinearization is

```text
Vsquare = ceil(
    r*C + delta*r*P/Q
    + 2*N*(t-1)*Vdiff + t*N*Vdiff^2/Q
    + 2*t*N*Vdiff*L + 2*r*N*(t-1)*L
    + (1+N+N^2)/2
) + S
```

The last fraction bounds the three component rounding errors after evaluation
under `1,s,s²`. Let W be the next power of two at least the vector dimension.
Apply `V <- 2V+S+2r` for each of the log2(W) dimension-reduction rotations and
adds. Multiplication by the plaintext selection mask gives
`Vtile=N*(t-1)*V+r*C`. At most K=W tiles enter one response ciphertext, with
K-1 further rotate/add nodes, so
`Vmerged=K*Vtile+(K-1)*(S+2r)`; partial response groups use their actual K.

Compacting to q' gives
`Vterminal=ceil(q'*Vmerged/Q + (t-1) + (N+1)/2)`.
The extra terms cover the delta-scale mismatch and two component rounding
errors. Exact decryption of every coefficient follows from the sufficient
strict inequalities

```text
2*(t*Vmerged + (Q mod t)*(t-1)) < Q
2*(t*Vterminal + (q' mod t)*(t-1)) < q'
```

For D=512 at the policy's numerical maximum of 65,536 rows, these bounds pass
for both 180-bit-Q profiles. `Vterminal` is 69,633 at N=8192 and 73,729 at
N=16384. This covers more rows than the default index byte cap permits; the
independent resource caps still apply and do not promise every maximum can
fit together. A 120-bit-Q probe passed small random correctness tests but
failed this sufficient full-workload bound, so it was not adopted as the
guarded default. A failing bound means assurance is insufficient; it does
not by itself demonstrate a decryption failure.

## Performance and validation

On a Ryzen 7 5800X, Python 3.12.3 and GMP 6.3.0, the final-source benchmark
uses 1,024 vectors of 512 bits, one cold trial and three warm trials. The
following times are warm medians. Setup/import and query encryption are
separate from server evaluation. Within each profile the evaluated ciphertexts
are identical; the two profiles have fresh keys and different ciphertexts.
No network timing or concurrent overlap is claimed.

| Measurement | Original N=8192 | Review N=16384 |
| --- | ---: | ---: |
| Evaluator search, authentication and serialization | 2.35395 s | 2.43866 s |
| Additional owner-verifier recomputation and receipt | 2.35376 s | 2.43529 s |
| Paired evaluator + verifier time | 4.70963 s | 4.87396 s |
| Python reference distance decoding and parsing | 39.42 ms | 80.29 ms |
| Native distance decoding and parsing | 12.46 ms | 24.65 ms |
| Complete guarded client finish, including receipt and private check | 16.13 ms | 28.43 ms |
| Query encryption and binding | 100.59 ms | 204.76 ms |

At the larger ring, native decoding is **3.26 times faster** than the Python
reference on the same responses. The evaluator itself is **3.6% slower** than
the original-ring run: doubling N halves the number of packed index tiles in
this workload, offsetting much of the extra arithmetic per tile. These are
local measurements, not a general scaling guarantee. The required second
evaluation dominates the added protocol cost; overall delegated compute is
about doubled, despite preserving the existing fast evaluator.

One-time key generation takes 4.32/8.87 seconds and index encryption, private
summary construction, export and authentication take 8.08/9.42 seconds for the
original/review profiles. Each evaluator imports setup in roughly 1.73/3.37
seconds; the verifier has its own comparable import cost. Cold searches take
2.67/3.07 seconds as lazy public key/mask caches are prepared. The benchmark
process, holding both evaluators and the private reference, peaks at
1,094,104/1,985,372 KiB RSS. This is whole-process memory, not a per-server or
locked-secret-buffer measurement.

| Serialized item, decimal bytes | Original N=8192 | Review N=16384 |
| --- | ---: | ---: |
| BFV public/evaluation keys, per evaluator | 85,602,438 | 171,205,156 |
| Encrypted-index array, per evaluator | 23,598,467 | 23,595,715 |
| Complete authenticated setup, per evaluator | 109,205,199 | 194,805,166 |
| Client query | 368,840 | 737,480 |
| Evaluator response | 102,614 | 205,018 |
| Approval receipt | 198 | 198 |
| Client response + receipt download | 102,812 | 205,216 |
| Client query + response + receipt | 471,652 | 942,696 |
| Additional query + response input to a remote owner verifier | 471,454 | 942,498 |

The review profile approximately doubles the client exchange and public key
size. Packed index size stays almost constant because fewer larger tiles hold
the same rows; small framing/JSON differences depend on the particular random
keys and ciphertexts. The private summary stays at 16,448 bytes for D=512 and
never goes to either evaluator. Both public evaluators need their own setup.

Results live in `benchmarks/results/native_bfv_guarded_original_1024.json` and
`benchmarks/results/native_bfv_guarded_review_1024.json`. JSON contains synthetic
workload dimensions, timings, sizes and source/binary hashes, with no keys,
ciphertexts or private summaries.

```bash
.venv/bin/python benchmarks/bfv_guarded.py --profile original \
  --json-out /tmp/bfv-guarded-original.json
.venv/bin/python benchmarks/bfv_guarded.py --profile review \
  --json-out /tmp/bfv-guarded-review.json
.venv/bin/python -m pytest tests/unit/test_bfv_guarded_client.py \
  tests/unit/test_bfv_private.py tests/unit/test_bfv_assurance.py -q
```

For a remote owner verifier, each search additionally sends it the query and
proposed response, on top of provisioning a second copy of public keys/index.
The client receives the 198-byte receipt. Counting only those 198 bytes as the
cost of the entire distributed protocol would omit that additional traffic
and full recomputation. If verification runs locally, the owner instead needs
the public setup and compute resources locally. The larger ring separately
changes query, response and key sizes.

Validation of the final implementation:

- **351 offline tests pass:** 323 SDK tests, including 269 BFV cases, plus
  28 retained SEAL experiment tests. Production HTTP integrations and GPU
  hardware tests are excluded. All 49 new security/arithmetic/bound cases pass.
- **183 binding/security tests pass under AddressSanitizer and
  UndefinedBehaviorSanitizer.** One OS memory-lock test is deliberately skipped
  because ASan intercepts `mlock`; it passes with the release binary and a
  zero-lock-limit child process. Both sanitized extension paths are explicitly
  loaded, preventing an accidental release-binary fallback. LeakSanitizer is
  disabled in this environment because execution uses ptrace.
- The standalone private arithmetic/wipe test passes ASan/UBSan. The GCC 13.3
  and Clang 18 optimized secret-taint runs each report zero errors and no heap
  leaks; both deliberately branching negative controls fail as required.
- SDK and BFV benchmark lint/type checks pass. The platform wheel contains
  both native modules and the new Python APIs. Documentation builds offline
  with the pre-existing SEAL research-link warning. The documented N=16384
  example, including guarded state restoration, passes from the extracted wheel.

The benchmark JSON records base revision `0cd7b41` with a dirty working tree;
the recorded source/binary hashes identify the measured implementation and
match the final files. Estimator outputs likewise match their pinned manifests
and runner hash. These checks are reproducible engineering evidence, not an
independent security audit.

## Remaining production gates

| Area | Evidence added here | Remaining requirement |
| --- | --- | --- |
| Malicious-result oracle | Exact public recomputation receipt checked before private work; old attack blocked in guarded regression | Independent protocol review and actual owner-verifier isolation, pinning and key custody; no general CCA2 or succinct proof claim |
| Private implementation | Separate fixed-work decoder, locked/wiped native buffers, GCC/Clang taint tests, arithmetic oracles and sanitizers | Full private key generation/encryption/import/summary path, compiler/CPU review, Python copies and deployment side channels |
| Parameters and failures | Pinned actual-distribution estimates and conservative circuit-specific bounds; larger review profile | Independent analysis of models, omitted attacks, ring/evaluation-key assumptions and bound derivation |
| Service integrity/availability | Existing per-object tickets, caps and admission; guarded exports bind verifier pin | Durable anti-rollback/replay and quotas, owner authorization at verifier, tenant/process isolation and transport limits |
| Application leakage | Explicitly unchanged all-distance interface | Review chosen-query capability, result-dependent fetches, IDs/sizes/timing; private top-k/PIR and circuit privacy remain unimplemented |

The implemented trust boundary materially changes which ciphertexts may reach
decryption, while these deployment and cryptographic assurance tasks still
prevent an honest production-security sign-off.
