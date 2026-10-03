# Q56/B1 independent complete-admission review

This is a source review of the native complete-control architecture, written on
2026-10-03. It is not an enclave audit, parameter approval, timing result or new
cryptographic construction. The existing tiny reference remains a known control.
Native additions reviewed later are recorded in an addendum rather than silently
changing the scope of this initial review.

## Scope and conclusion

Reviewed `complete_checked_bgv.py`, `checked_product_bgv.py`,
`checked_switch_bgv.py`, `native_check_bgv.py`, `native_boundary_oracle.py`, their
complete-path tests, `_verify/check.h`, `_verify/product.h`, `_verify/bindings.cpp`,
and the Q56/Q59 sections of the system blueprint. The source hashes and exact
scope are retained in
`../research-data/native-verification-system-20261003/review/initial-review.json`.

The existing composition is suitable as a specification for a secretless native
control: locally derive the product's third component, check every unshifted
relinearized tile against the enrolled query/index, then compute the entire
butterfly and terminal conversion inside the checker. All bytes released must
come from that checked computation. A producer or deterministic replay control
may use `NativeProductArithmetic.evaluate`; checked admission must use the
independent product equations and must not call an expected-response oracle.

Reusing the project's public ring/NTT/GMP arithmetic inside the trusted suffix is
consistent with this architecture. It is not independent implementation evidence
for those primitives. A separate schoolbook oracle and archived full packet are
therefore valuable test controls. Comparing to the same full native evaluator is
not, by itself, evidence that the admission equations cover the full relation.

## Exact admission invariants

| Boundary | Required invariant | Why it matters |
|---|---|---|
| Owner enrollment | Fix an immutable index, switching keys, actual native prime order, graph shape, terminal parameters, ordered IDs and epoch. Hash the complete public statement. | A valid computation for a substituted index or key is not the enrolled computation. |
| Profile | Admit only the implemented two-prime Q120, four common 30-bit digit profile and explicit size limits. Validate the exact native primes, rather than only their product or bit length. | The native check engine derives specific primes and its arithmetic bounds rely on them. |
| Original query | Pin exact immutable original query bytes; independently validate their header, key ID, seed, drop value, packed tail and compressed coefficient envelope before expansion. | A producer cannot select a different expansion or hidden noncanonical preimage. |
| Complete coverage | The controller owns block positions and sizes. Require each block exactly once, in order, with no omissions, duplicates, overlaps, tails or extra bytes. | A stage checker has no knowledge that the parent has checked every tile. |
| Grammar before entropy | Validate every block and any claimed final packet before sampling any product challenge. Use exact `bytes`, not aliases to mutable buffers. | A challenge must test a complete immutable candidate, not an adaptively supplied suffix. |
| Product third component | Compute c2 locally, or separately verify an explicitly admitted c2 witness. Never treat a supplied c2 as a trusted input. | Correct switching of a malicious tensor does not authenticate multiplication. |
| Canonical gadget source | Reconstruct one integer in `[0,Q)` from both canonical limbs for each coefficient, then derive the four digits from that same integer. | Independent per-limb digits or modular-only decomposition admit different relations. |
| Trusted suffix | Apply the initial monomial shift exactly once, every enrolled butterfly stage in the enrolled order, and common-Q switching at each rotation. | Product verification alone does not verify later GPU rotations or output extraction. |
| Partial group | If a right child is absent, use the actual native rule `plus = minus = left`, then still rotate and add. | Omitting that rotation or treating the missing branch as an omitted equation changes the final polynomial. |
| Terminal conversion | Compute the nearest congruent integer lift with sufficiently wide arithmetic and serialize every component/coordinate of every group. | `P*c` can exceed 128 bits. Unused output lanes are still part of the authenticated packet. |
| Claimed response | Parse its complete grammar, then require exact equality with the authoritative canonical packet. | Semantic equality between different encodings must not substitute for the signed/bound bytes. |
| Release | Any public instrumentation occurs only after successful complete checking and exact packet construction. No decoder, signer or private callback is invoked on any rejection. | Full admission must precede any secret-dependent behavior observable by the host. |
| Attempt lifecycle | Consume an attempt before grammar checking or entropy use. Guard process identity before locks; prevent copy, pickle, repeated use and concurrent double completion. | Malformed requests, entropy failures and concurrency must not create uncounted retries. |

The existing reference's query parser permits alternative outer MsgPack encodings
of the same semantic query. This is not a statement-substitution issue when the
exact original bytes are hashed, but the API must choose and document whether it
admits those encodings. If the deployment requires a unique wire encoding, add
canonical reserialization equality at this boundary. The reference already
requires exact equality for a claimed final response.

The context is owner-approved public data, not an attacker-supplied request.
Nonetheless, explicit enrollment bounds and safe native length arithmetic must
precede large allocations. Python private attributes and frozen dataclasses are
local programming conventions; they do not constitute a hardware trust boundary.

## Conditional product-check statement

In local-c2 mode, fix the complete proposed tile outputs and the enrolled query,
index and switching key. After canonical CRT and digit derivation, an incorrect
two-component output has a nonzero coefficient residual in at least one actual
native prime. One independently uniform batch-weight row annihilates that fixed
nonzero residual with probability at most `1/p`; the code compares the entire
polynomial rather than an arbitrary ring evaluation. Three independent rows
give at most `p^-3` for that block, conditional on correct arithmetic, true prime
moduli, uniform private entropy and output fixation.

Use the worst failing prime. Do not multiply by the probability of an honest
limb. For a complete attempt with `B` checked blocks, a conservative bound is
`B / min(primes)^3`, and for globally bounded attempts sum their block budgets.
Trusted suffix computation does not add another randomized-check term; it adds
an implementation-correctness obligation. This is not a deployed security level.
The current counters are local and nondurable, and the variable-time/checking
state interfaces have no private side-channel assurance.

The lower-level native functions accept caller-supplied weights. They are
arithmetic tests, not protocol gates. All-zero weights can make a false product
pass; this is a useful regression demonstrating why the one-use wrapper must
own entropy and why the lower-level API cannot authorize release.

## Meaningful adversarial tests

Keep the existing 89 tiny regressions; add the following native-specific tests.
They are correctness/admission tests, not a new performance cohort.

| Test | Expected evidence |
|---|---|
| Products at canonical limb endpoints, including zero and `p-1`; one residue equal to `p` | Endpoints compute correctly; equality to the modulus rejects before entropy. |
| Product/source coefficients near zero and `Q-1`; altered only one limb | Common-Q digit source agrees with independent CRT; the altered candidate rejects. |
| Maximum allowed batch with dense values near prime maxima | Fold sums and reduction agree with GMP/schoolbook truth; no 64-bit quotient assumption or overflow. |
| Wrong prime order, rotation schedule, key order, terminal modulus or layout | Enrollment rejects, or complete statement identity changes and old packets reject. |
| A full group, every possible tiny partial-group length, padded one, and a second ring geometry | The entire final packet matches independent replay, including shifts and missing-right behavior. |
| Every terminal coordinate, including unused tail lanes, independently mutated | Claimed final response rejects after authoritative construction; no partial release. |
| Terminal coefficients near zero and `Q-1` | Native wide/GMP lift matches the independent two-neighbor `round_lift`, including negative numerator floor division. |
| Wrong query seed, compressed tail bit, maximum compressed envelope and impossible final interval | Wrong query/context arithmetic rejects; malformed envelopes reject before entropy. |
| Invalid last block after valid earlier blocks | No challenge is sampled for any block. |
| Entropy failure in a later block after earlier arithmetic succeeded | Parent attempt stays consumed and no public release occurs. |
| Concurrent native calls sharing enrolled prepared context while the GIL is released | Immutable shared state and per-call scratch keep packets correct; one-use attempts still release at most once. |
| Replay, product evaluator and expected-oracle functions monkeypatched to fail | Checked admission remains successful for a valid immutable product packet. |
| Noncanonical outer claimed-response encoding with identical parsed values | Exact canonical response equality rejects it. |
| Fork, copy, pickle, malformed/repeated IDs and abandoned attempts | Local lifecycle policy is explicit and conservative; no durable-global assurance is inferred. |

Deterministic nonzero test challenges are appropriate for making arithmetic
mutation regressions reproducible. They do not test a cryptographic probability
claim. Include a separate test that verifies the wrapper calls its private
entropy source only after complete grammar validation.

## Q59/B4 dependency review

Q59 can proceed with a bounded static first component using the complete native
control even if H1 stops. It can identify the actual per-tile coefficient/NTT/GPU
buffers, authenticated snapshot identity and dependency closure, then verify that
replacement state equals a fresh enrollment for a single row, single tile,
dispersed 32-row edit and full snapshot. This supplies an engineering baseline
and an update-cost discriminator; it does not automatically establish H2 novelty.

An encrypted tile may contain several records. Updating one record usually
replaces the whole freshly encrypted tile, so account for tile-granularity
ciphertexts and prepared buffers, not a changed plaintext row's byte count.
Mutable cache and generic verifier controls receive the same local-update
opportunity. Full rebuild is a baseline weakness rather than an inherent BGV cost.

For reusable adjoint state, establish these prerequisites before claiming the
delta identity is a cheap secure update:

1. Identify every retained term and prove exactly which dependence on the edited
   encrypted index is linear. Normalized composed operators must be checked;
   linear factors do not imply that a product of two index-dependent factors is
   linear. In this search graph, a path with at most one index-dependent factor
   is a useful sufficient condition, but it must be established for the selected
   representation and cuts. Canonical digits are not a linear operation.
2. Derive `A(I + delta)^T r = A(I)^T r + A(delta)^T r` for those terms, and check
   the resulting retained state against a fresh construction under the same `r`.
   Equality tests alone do not establish secrecy or reusable-state soundness.
3. Couple the adaptive interaction to an ideal checker until its first false
   acceptance. Owner-authorized updates, graph selection and all public state
   evolution on that ideal branch must be independent of the secret checking
   randomness. Valid transitions cannot disclose linear measurements of it.
4. Bound all attempted submissions globally across epochs, retries, crashes,
   clones and rollback. A local request nonce or Python counter is insufficient.
5. Reveal only the modeled verdict. Dot products, challenge/state hashes,
   partial residuals and secret-dependent time/page/access observations need
   their own leakage argument. The first-false-accept proof does not cover them.
6. Atomically publish a single immutable owner-authorized snapshot identity for
   evaluator and checker state. Reject mixed epochs, stale/duplicate updates,
   rollback and interrupted publication; old requests either retain their old
   snapshot or are explicitly aborted.

The existing E117 first-false-accept argument is a starting point, not a proof
for state changes. Fresh independent epoch coins invalidate the old adjoints;
charge preparation/rebuild costs rather than simultaneously claiming fresh coins
and a free fixed-r update. A bounded static dependency screen can be completed
before implementing reusable private state. It should stop a nonlinear or large
dependency claim early without launching a new benchmark scan.

## Security boundary that the control does not settle

The checker holds no HE decryption key and performs only public computation.
That is useful containment, but a compromised attestation signer can authorize
malicious responses and reopen a secret-key-dependent client feedback channel.
Do not claim client privacy against signer/enclave compromise merely because the
HE secret stays on the client. Authentication, fixed approved parameters, private
client side channels, durable freshness/attempt accounting and actual protected
execution remain separate deployment obligations.

## Addendum: new native arithmetic reviewed

Reviewed the new `_native/complete_continuation.h` and conditional
`CUHEPY_BGV_COMPLETE` additions to `_native/bindings.cpp`, `_native/Makefile` and
the native type declarations. Also inspected their reused `bfv_residue.h`,
`rns_ntt.h` and thread-local profiling scope. The corresponding source/evidence
snapshot is `../research-data/native-verification-system-20261003/review/native-additions-review.json`.

No additional native source blocker was found in this scope. The continuation
binding constructs privately owned tensors only through full-range-validated
RNS/full-Q parsers; it computes the suffix directly instead of calling full
expected evaluation. The initial shift, missing-right branch, enrolled rotation
order, common full-Q reconstruction and full-coordinate GMP terminal conversion
are present. Separate native capsule names distinguish this module's prepared
handles from the older CPU and CUDA modules. Its `count`, `t` and `P` arguments
are still arithmetic parameters, so the Python controller must pin them to the
owner-approved context; direct native invocation is not an admission gate.

Reviewed, but did not rerun, the native worker's retained smoke script/results:
8 frozen original-query full packets, 35 arbitrary canonical algebra cases
across N8/16/64 and full/partial/multiple-group layouts, and 28 parser negatives.
The algebra fixtures do not claim valid encryptions or noise/security parameters.
An independent hash check here confirmed all seven preexisting extension binaries
remain unchanged. These are correctness and preservation observations, with no
performance measurement. The new Python complete controller and its integrated
tests were not yet present at this snapshot and require a separate final review.

## Addendum: integrated Python controller reviewed

Reviewed `native_complete_checked_bgv.py`, its on-disk integrated test source,
and the new native `complete_profile` export. This closes the pending controller
source-review item in the preceding snapshot. Corresponding hashes and scope
are retained in `../research-data/native-verification-system-20261003/review/controller-review.json`.

One enrollment inconsistency was reported and corrected: the original validator
did not enforce the terminal native interface's plaintext upper bound, `P > 4t`
and probable-prime requirement. The reviewed corrected source checks those
conditions and requires exactly two exact-integer native primes before preparing
any backend state. A probable-prime check is not a cryptographic parameter
approval or an unconditional primality certificate.

No remaining controller blocker was found in this scope. Enrollment binds full
fixed-width index/key bodies, ordered IDs, layout, query drop, terminal parameters
and epoch. Native profile equality additionally checks actual prime order and
gadget layout. Parent attempts are consumed before parsing, malformed/duplicate
IDs spend the cap, process guards precede locks, and copying/serialization and
concurrent repeated completion are rejected. The counts remain nondurable local
state.

All immutable block positions, packet headers, complete lengths and native RNS
ranges are checked across all blocks before any product weights. A claimed final
packet is also fully parsed before weights. The native trusted continuation is
called only after every local-c2 product block succeeds; its inputs are the same
immutable validated body bytes in enrolled order. Checked admission does not
enter native product production, prepared full replay or the expected schoolbook
oracle. The optional sentinel remains public test instrumentation after complete
packet construction, not a protected signer/client authorization API.

The response grammar admits at most 64 groups and separately checks the complete
header, every pair, and every coefficient of both components. `max_array_len=64`
is compatible with the largest body array and with all smaller fixed arrays.
Every admitted N is divisible by eight, so the full packed polynomial contains
no unused byte-tail bits. Exact final byte equality also rejects alternate outer
MsgPack encodings with identical parsed values.

Public SHAKE expansion uses the same domain, key ID, seed and 120-bit rejection
rule as the owner codec, with a budget of `4*N*15` bytes. Exhaustion fails before
child construction and cannot reopen the parent attempt. This budget is an
explicit public-input denial bound; it does not establish a universal success
claim for every possible seed. Recommended boundary regressions are exactly
64 response groups and a mocked all-`0xff` rejection stream; runtime test results
belong to the root worker's retained test receipt, not this source review.

The Q57 typed graph source also confirms a useful bounded Q59 first component:
canonical digit cuts prevent index-to-key factor composition. In this admitted
family, each normalized affine term has at most one fixed polynomial factor;
only original-query maps depend on index components. Their fixed-coins adjoint
update is therefore linear, while fixed key/digit operator state has no index
invalidation. Descendant canonical values may still change. The equally
specialized generic control gets the same identity, and reusable-state soundness,
actual state-update execution and H2 originality remain separate obligations.

## Final retained execution scope

The root worker reports 116 passing integrated native-controller tests, including
the requested exact-64-group, over-64-group enrollment, malformed last-polynomial
and SHAKE rejection-budget regressions. The test source was reviewed here; this
reviewer did not rerun it. These tests overlap the earlier 89 tiny-controller
regressions, so the two counts must not be added as independent evidence.

Reviewed the retained source-sized cohort and runner: one fresh key, 8,192 rows,
512 dimensions, N16,384, three fresh owner-seeded original query packets and
unrounded query format. Checked admission, new prepared replay and the historical
public CPU evaluator produced identical complete packets for all three queries.
Six owner decryptions occur outside the verifier. The three unique query results
contain 24,576 correct distances and stable top three results, and checked native
continuation covers 98,304 terminal polynomial coordinates including unused
score positions. The older CPU and new native evaluator share low-level RNS
primitives; the retained plaintext Hamming truth is an independent semantic check.

Per query, the implemented complete path actually consumes a 134,217,728-byte
(128 MiB) product body and performs 511 trusted rotations. The final packed body
is 102,400 bytes (102,488 bytes with its complete response framing). This confirms
the earlier traffic/rotation model at this geometry; it is not a measured
transport, residency, latency or protected-service cost. The cohort explicitly
does not approve parameters or claim attestation/authentication deployment.

An independent hash pass in this review confirmed all 20 preregistered source
and library inputs unchanged, verified the retained public-fixture digest, and
verified all three query and reference-response digests. No cohort or heavy
execution was repeated. The final controller review therefore closes the source
and retained correctness review, while security deployment, source-independent
primitive assurance and measured complete-service performance remain open work.
