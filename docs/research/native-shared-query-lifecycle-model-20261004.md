# Q76.3a local lifecycle specification

Implementation baseline `8da05b201fdab706eb486a83f1aacfbb8b894e4f`.
Read the [registration](native-shared-query-lifecycle-registration-20261004.json)
before changing the implementation or running its cohort. This is a prototype
state model, not a completed formal proof or production security approval.

One journal is provisioned by a trusted caller for one owner anchor, index scope,
native/authentication policy and lifecycle code digest. Its random public journal
identity distinguishes independently created journals. A database clone retains
that identity; clone/rollback resistance is explicitly outside this local model.
Authentication binds honest owner-origin inputs; it does not prove their plaintext
encoding or sampler supports.

```text
unseen signed nonce -> reserved -> rejected
                              -> authorized -> rejected (snapshot retired)
                                            -> dispatch_started -> delivered
                                                                -> callback_failed
```

Signature/required-context syntax is checked before a nonce can be trusted.
A nonce authenticated this way is inserted durably before seed preparation or
public arithmetic admission. Signed stale snapshots consume it as rejected.
A malformed signed seed consumes it before parsing fails. Unauthenticated
packets cannot consume a genuine owner's nonce. Duplicate identities never
create another attempt, even when re-signed for a new query or snapshot.

Snapshot epochs are exactly UInt64, stored as eight-byte blobs rather than
SQLite signed integers. Installing the identical snapshot is idempotent;
changing it requires a strictly higher epoch. Authorization checks the snapshot
again after complete native admission. Its row records the bound original query,
ordered-ID digest, response digest and complete compact-frame digest.

The public authorizer has no callback argument. A separate local callback guard
requires an authorization matching that row and frame. It checks the snapshot
again and commits its claim before invoking the callback. A snapshot change
after that commit is ordered after dispatch: it cannot recall work already
started. It prevents subsequent old-snapshot claims. Callback values are
discarded; failures produce a generic local exception and stay consumed.
Private callback errors must not be connected to a server-visible channel.

The two irreversible flags satisfy `callback_once <= authorized_once <= 1`.
Their history remains even if an authorized attempt is later rejected because
its snapshot was retired. A crash after reservation or dispatch can lose the
answer; the normal API never resumes a consumed attempt. This is **at-most-once
authorization/callback**, not exactly-once delivery. Crash tests exercise real
process exits; they do not emulate faulty disks or prove power-loss behavior.

Short `BEGIN IMMEDIATE` transactions serialize state changes; no database lock
is held across native checking or a callback. The implementation uses rollback
journaling and `synchronous=FULL`. These rely on SQLite's documented filesystem
locking and flush assumptions. ([Atomic commit](https://www.sqlite.org/atomiccommit.html),
[synchronous settings](https://www.sqlite.org/pragma.html#pragma_synchronous))
The trusted local runtime/storage can always alter the database. Q78 must
replace that trust with actual protected execution, freshness/revocation and
client checks; this journal or a code hash is not hardware attestation.

Ownership is process-bound. Inherited objects fail before any SQLite/native
operation after fork; closed objects reject new work. Each operation opens a
short-lived connection, so threads and separate processes sharing the same
trusted database use its transaction ordering. Independent databases do not
provide a global authorization budget or replay guarantee.
