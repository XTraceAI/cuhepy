# Q76.2 owner-authenticated native factory return

2026-10-04. Parent `7efab9f87ca441b650b94b3fae3dfe11ba42aa54`, branch
`experiment/native-shared-query-service-20261004`.
Read the [receipt](native-shared-query-auth-return-20261004.json),
[registration](native-shared-query-auth-registration-20261004.json),
[core return](native-shared-query-core-20261004.md), and
[ledger](research-contribution-progress-20261004.json).

The factory authenticates an immutable owner snapshot, the original seeded
query and every response context field before using the public native reply
predicate. It holds an owner **public verification key**, with no HE secret
or owner signing secret. The owner signing helpers use standard Ed25519; all
HE arithmetic remains homemade. This is a trusted local prototype, not an
attested service or private-release authority.

| Boundary | Binding/check |
| --- | --- |
| Enrollment | Owner signature covers exact canonical profile/origin law, ordered actual primes, complete evaluation keys, seeded feature-major index, ordered IDs, epoch and policy digest. The verifier anchor comes from trusted configuration. |
| Original request | Owner signature covers exact seeded query, snapshot, epoch, policy and 32-byte nonce. Seed expansion reconstructs the existing common-Q components; query uploads remain seeded. |
| Public reply | Complete source/output body and compact frame plus snapshot, epoch, policy, exact signed-request digest, nonce and IDs digest. Every context field must match; integer fields reject booleans/floats even when Python equality would match. |
| Native graph | Compiled internally from authenticated metadata; no supplied graph, bound, digest-only replacement or private/producer hook approves a packet. |

Signatures cover a domain-separated message containing SHA256 of the exact
payload. This uses ordinary Ed25519 with an additional hash-binding assumption;
it is not a homegrown signature scheme or an Ed25519ph claim. The policy digest
pins the isolated native binary and adapter/parser source under a trusted
local filesystem assumption. It is a reproducibility binding, **not hardware
attestation or evidence that a hostile host ran the pinned code**.

The signature does not prove valid binary plaintexts, correctly generated HE
keys or error support. The honest owner encoder and samplers supply those
facts. Arbitrary third-party ciphertext origin is outside this selected
contract. Public deterministic phase/terminal guards still precede native
preparation; neither sampled noise nor successful decryption approves a profile.

The retained gate passes 16 owner-canonical N16/N32 cases from the same two
Q74 HE key contexts. Native bodies/frames match the retained GMP tapes. It
rejects 112 context/type faults, 48 body/frame/grammar faults and 16 invalid
request signatures. The final 68-case unit suite includes foreign signing
anchors, late malformed key/index/query values, noncanonical encoding,
cross-request nonce binding, full uint64 epochs/IDs and ownership. Its earlier
65-case invocation overlaps it and is not added. No new HE keys, private HE
work, callbacks, timing panels or source-scale runs occurred. Standard ephemeral
signature keys were generated for tests/cohort and were not serialized.

The public acceptance predicate intentionally remains repeatable. It cannot
prove that a snapshot is still current or a nonce has not already authorized
private work. **Q76.3 must add the durable at-most-once controller before any
private callback/release or performance panel.** Local SQLite then requires
trusted non-rollback storage; actual freshness/attestation is still Q78.

Implementation: `experiments/bfv_search_lab/authenticated_shared_query.py`,
`test_authenticated_shared_query.py`, and
`benchmarks/authenticated_shared_query_lab.py`. Raw signed public envelopes,
all attempt logs, source archive and dependency/registration hashes are at
`/home/pete/yavor-projects/xtrace-work/research-data/q76-authenticated-factory-20261004`.
Wire, expanded input, prepared state, witness and compact-client bytes are
recorded separately. They are structural counts, not new latency measurements.

**Ledger return: Q76.2 is complete in its bounded local factory scope. Next is
Q76.3 lifecycle, followed by the registered one-key/six-search source-scale
correctness gate.** Production source/libraries and local main/staging refs
remain unchanged. No main originality or security/parameter approval follows
from these gates.
