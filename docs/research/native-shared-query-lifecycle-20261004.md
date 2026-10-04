# Q76.3a retained local lifecycle return

The local durable lifecycle gate passed. This adds a trusted local controller
around the homemade native BGV predicate; it does not complete source-scale
correctness, protected remote release or a security proof. Read the
[state model](native-shared-query-lifecycle-model-20261004.md),
[registration](native-shared-query-lifecycle-registration-20261004.json) and
[machine-readable return](native-shared-query-lifecycle-return-20261004.json).
The execution parent is `8da05b201fdab706eb486a83f1aacfbb8b894e4f`.

## Behavior and boundary

An authenticated original request consumes its nonce before seed preparation
or arithmetic admission. Complete public acceptance can authorize its bound
response once. A separate local guard commits its callback claim before
calling the hook. Rejections, crashes and callback failures never reset the
nonce. Authorization and dispatch recheck the current snapshot; installing a
replacement requires a strictly increasing UInt64 epoch. Snapshot replacement
after dispatch's commit is ordered after that already-started callback.

The public authorizer has no HE secret or callback argument. Callback values
are discarded, and callback failure produces a generic local exception with
no private diagnostic attached. These are **at-most-once authorization and
callback claims**: a crash can lose delivery. They are not exactly-once delivery.

The SQLite journal assumes trusted code, correct filesystem locking/flushes
and non-rollback storage. Independent databases do not provide global replay
or soundness-budget coordination. A journal clone retains its identity. Code
hashes and the unsigned local authorization record are not attestation or a
remote client-release protocol. Q78 must implement and review that boundary.

## Evidence, with overlapping runs kept separate

| Check | Final evidence | Scope |
| --- | --- | --- |
| Retained cohort | 16 cases from two retained HE contexts; 112 signed protocol requests | All native tapes and complete compact frames match retained independent GMP values. |
| Altered replies | 80 rejected and consumed | Body, frame, snapshot, Boolean epoch and trailing grammar; none authorizes a hook. |
| Accepted replies | 32 authorizations and 32 public test hooks | Sixteen successful and sixteen deliberately failed hooks; request/callback replays and post-restart dispatch deny. |
| Lifecycle unit cases | 71 passed | Threads, independent spawned-process races, two actual process exits, restart, a fork with a parent-held SQLite lock, stale races, malformed seeds, forged records, UInt64 limits and database errors. |
| Selected regression invocation | 197 passed | The same 71 lifecycle cases plus 58 native and 68 authenticated-factory cases. Two intentional fork deprecation warnings, no skips. |

The first 64-test invocation overlaps the final 71 cases; do not add them.
The first retained cohort passed, but Ruff flagged loop-variable capture in
its runner. After explicitly binding public frame/list/hook defaults, one
registered corrective repeat also passed with frozen sources. Both cohorts
are preserved; their overlapping 16 cases/112 requests are not summed into
32 cases/224 requests. Ruff passes on all four changed Python files.

No fresh HE key, HE encryption/decryption, private HE callback, source-scale
search or timing panel ran. Supporting standard ephemeral Ed25519 contexts
were generated: two in the first test invocation, four in the final combined
invocation, and one in each cohort (eight total). No authentication secret or
HE secret was serialized. Public test hooks inspect ciphertext hashes only.

The native ABI1202 source/library is unchanged. The authentication adapter
now exposes `checked_frame()`, factoring the existing complete acceptance
predicate so the journal need not parse the witness a second time. This
changes its file-based policy digest: retained public inputs are re-signed
under the current policy. Earlier signed packets/source snapshots stay in
their separate checkpoints; there is no silent policy migration.

## Reproduce and continue

Use the repository `.venv/bin/python` and the isolated library from
`/home/pete/yavor-projects/xtrace-work/research-data/q76-native-core-20261004/build/`.
Set `CUHEPY_SHARED_QUERY_LIBRARY` to `libshared_query_native.so` and
`CUHEPY_SHARED_QUERY_FIXTURES` to the retained Q74 directory before running:

```sh
.venv/bin/python -m pytest -q experiments/bfv_search_lab/test_native_shared_query.py experiments/bfv_search_lab/test_authenticated_shared_query.py experiments/bfv_search_lab/test_lifecycle_shared_query.py
.venv/bin/python -m ruff check --no-force-exclude experiments/bfv_search_lab/authenticated_shared_query.py experiments/bfv_search_lab/lifecycle_shared_query.py experiments/bfv_search_lab/test_lifecycle_shared_query.py benchmarks/lifecycle_shared_query_lab.py
```

The standalone runner is `benchmarks/lifecycle_shared_query_lab.py`; supply
the retained fixture directory, explicit isolated library and a new output
directory. Executed sources, signed public artifacts, databases, logs and
hash receipts live in
`/home/pete/yavor-projects/xtrace-work/research-data/q76-lifecycle-20261004/`.

Return to the [execution plan](system-contribution-execution-plan-20261004.md):
next is **Q76.3b bounded independent GMP producer, then the registered one-key,
six-search N16384/d512 correctness cohort**. Matched controls and certificate
handoff still precede Q77. This local lifecycle is supporting system work;
the main originality and production-security decisions remain open.
