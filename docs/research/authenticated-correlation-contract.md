# Research contract for authenticated offline search correlations

2026-09-29. This specifies the missing functionality behind E29–E31; it does
**not** implement a new correlation generator or change the production Nitro
path. The working reference remains fresh, independently owner-encrypted,
one-use answers. The [E30 report](shared-query-basis-results.md) retains the
failed deterministic-cache and public-linear mask-bank constructions.

## What must be produced

Fix an owner-approved epoch containing the key identifier, full encryption
parameters, ordered stable IDs, exact private coordinate matrix `M`, response
embedding `Phi`, encrypted coordinate columns `C`, and public query schedule.
All plaintext coordinates use `F_t`; ciphertext coefficients use `F_Q`.
The owner retains its private query transform `w(q)` and anchors. The public
schedule may reveal ranks, partitions, replicas and equality of query forms.

For each never-before-used token ID, the reference produces:

1. In the ideal functionality, **independent uniform coordinates**
   `r in F_t^h`. The implementation instead expands a private seed using
   SHAKE and rejection sampling, requiring the corresponding pseudorandomness
   assumption. The declared coordinate space is the whole public space, even
   if the private transform has a smaller image; a short seed is not an
   information-theoretically uniform sample of an arbitrarily larger space.
2. A fresh encryption `T_r = Enc(Phi(M*r))` with independently sampled
   encryption randomness, canonical ciphertext coefficients and an approved
   phase bound. The server receives this ciphertext, not `r` or its seed.
3. Private verification material for this exact ciphertext and epoch, plus
   one-use state. Hidden checker challenges and their evaluations must not
   become public correlation tags.

Online the owner consumes the token before releasing `delta=w(q)-r mod t`.
The server evaluates the prescribed full-ciphertext circuit
`Z = T_r + sum_j C_j * lift(alpha_j(delta)) mod Q`.
The owner checks those exact coefficients before private HE decryption and
adds its private anchor offsets only after decoding. The centered CRT lift
and each column's subring degree are part of the pinned circuit.

Correctness means every distance and stable top-k matches the pinned index.
Execution integrity means a modified, substituted, stale, truncated or
out-of-context `Z` is rejected before decryption. The existing fingerprint
checker establishes this **conditionally on trusted C, T_r and setup**; it
does not establish that a maliciously generated `T_r` encrypts the right
plaintext. Fresh encryption alone also does not authenticate a token.

## Parties, secrets and corruption cases

| Party | Reference knowledge | Required restriction |
|---|---|---|
| Data owner / trusted preprocessing service | `M`, private maps, mask seeds, encryption capability and epoch state | Can compute fresh answers; may not expose seeds, query forms or the plaintext index to the search server |
| Online client / verifier | HE secret key, private transform/anchors, stable IDs, pending seed, hidden checking material | Needs authenticated setup and durable token consumption; online private state is separately priced from the preprocessing service |
| Search server | Encrypted columns, public schedule, encrypted token answers, token IDs, deltas and response sizes | May choose malformed ciphertexts, replay/reorder messages, corrupt storage and observe acceptance/failure behavior |
| Proposed helper | Must be specified for each construction | If it learns `r` and later colludes with the server, `r+delta` reveals `w(q)`; calling it an offline service does not remove this issue |

The baseline trusts owner preparation and the verifier's process/state.
Side-channel compromise of the owner, approved-service compromise, client
rollback, colluding helpers, and unreviewed lattice parameters are separate
obligations, not consequences of the algebraic tests. A deployment model must
declare which parties can collude and whether compromise reveals old tokens.

## Why standard correlations are not a drop-in replacement

The PCG literature provides ways to expand short setup into specific
correlated values under explicit assumptions; the abstract/overview of
[Boyle et al., *Efficient Pseudorandom Correlation Generators: Silent OT
Extension and More*](https://eprint.iacr.org/2019/448) is a starting point.
It does not by itself provide our private-matrix, fresh-BGV-ciphertext and
hidden-full-coefficient-check functionality. A candidate needs an explicit
reduction from its output shares to **all three** token outputs above.

There are two different arithmetic domains. `M*r` and `delta` live modulo
`t`; the verification equation uses actual centered lifts modulo `Q`.
CRT interpolation followed by centering is not a linear map into `F_Q`:
in general `lift(a+b mod t) != lift(a)+lift(b) mod Q`. A MAC/VOLE relation
over `F_t` cannot simply be reused as the current full-ciphertext check over
`F_Q`. Ciphertext conversion, small lifts/carries, fresh randomness and
phase bounds must be accounted for, including adversarial inputs.

Likewise, a public linear expansion from `b` independent masks to more than
`b` requests has a public left-kernel relation. For `Delta=W-LR`,
`z^T L=0` implies `z^T Delta=z^T W`. Individually uniform requests are not
enough. Computational generators with appropriate setup are not ruled out
by this simple rank argument; this shortcut is.

## Candidate tracks and concrete gates

| Track | Potential benefit | First necessary experiment / missing argument |
|---|---|---|
| Trusted or attested owner preparation | Established reference functionality; move offline work off the online client | Implement authenticated epoch/token output and durable consumption on the actual trust boundary; measure fresh encryption, complete checks, expiry and storage |
| Two-helper or two-server correlations | Distribute offline work without giving one untrusted helper the complete mask | Specify noncollusion, shares, malicious setup and recovery; prove what each transcript reveals and cost the BGV conversion. Never give one colluding helper both `r` and the server transcript |
| Computational PCG / VOLE conversion | Amortize correlation preparation/communication | Produce a small complete conversion with fresh encrypted output and hidden `F_Q` checking; include field-conversion/carry constraints, setup assumptions and private-matrix handling |
| Rerandomized encrypted-index preprocessing | Potentially avoid retaining plaintext `M` at the helper | Prove mask hiding of the actual correlated ciphertext distribution, bound multiplied index noise and authenticate the new computation. Adding an `Enc(0)` and declaring the earlier attack fixed is insufficient |
| Incremental epoch correlations | Avoid rebuilding everything for small index changes | Define which rows/maps/columns change, whether pending tokens are invalidated, and how old/new verification state is separated. A change of basis is an epoch change unless a proved migration preserves all bindings |

These are competing research tracks. None is silently enabled by E31, and
none inherits production authorization from the experimental fingerprint API.

## Token lifetime and crash semantics

The required state machine is `prepared -> reserved -> consumed`, with
`expired` and `revoked` terminal states. A reservation/consumption transition
must become durable **before** the corresponding delta leaves the client.
No timeout, server rejection, crash, retry or rollback may restore a released
mask to the available pool. A retry either resends an identical already-bound
request under explicitly defined response semantics, or uses a fresh token.
The existing in-memory locks do not implement this crash-safe state machine.

Every token binds the epoch/key/schedule, query request and permitted response
count. Index updates, key changes or checker-budget exhaustion revoke pending
tokens unless a separately verified migration is defined. Checker attempts
consume the soundness budget even on malformed or rejected responses.
Pool preparation must not inspect future queries. Unused tokens still incur
their preparation, upload, storage and eventual deletion costs.

For `U` completed queries at utilization `u`, with `P=ceil(U/u)` tokens:

```
CPU work = measured setup + P*(answer preparation + trusted answer checking)
           + U*(request + server + packing + verification + decode/selection)
bytes    = seeded index upload + P*seeded answer packet
           + U*(query body + response body)
```

This is a serial work/byte model, not network latency or pipelined throughput.
Keys, authenticated envelopes, provisioning, journaling, idle pool storage,
update churn and unused capacity must be added for a deployment comparison.
The offline service's plaintext coordinates and the online client's retained
state are different storage budgets. Complete plaintext caching remains a
separate control with a different storage/privacy contract.

## Acceptance tests before a new implementation replaces the reference

Specify and test malicious setup/index/token substitution, zero-plaintext
claims, wrong field lifts, noise-bound violations, stale epochs, changed
schedules, token-ID collisions, concurrent consumption, crash/restart replay,
pool expiry, interrupted updates and conditional accept/reject leakage.
Require exact full-coefficient agreement with an independent arithmetic
reference and complete distance/top-k agreement, not selected score samples.
For any proposed generator, retain explicit transcript-leakage tests and the
assumption/reduction its tests cannot establish. Security review and parameter
assurance remain prerequisites for a production claim.
