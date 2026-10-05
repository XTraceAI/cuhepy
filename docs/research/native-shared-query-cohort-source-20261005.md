# Q77 public source preservation and attempt accounting

2026-10-05. The first subgate of the
[coordinator registration](native-shared-query-owner-coordinator-registration-20261005.json)
passes **23 distinct public cases**. The preceding 320 cases remain retained;
they were not rerun. There are 343 distinct retained cases across gates, not
one 343-case invocation. Nine cases remain in this registration's 32-case cap.

The implementation is
[complete_cost_cohort.py](../../experiments/bfv_search_lab/complete_cost_cohort.py),
with [public tests](../../experiments/bfv_search_lab/test_complete_cost_cohort.py).
All 435 preceding runtime sources, 66 company files, six isolated libraries
and the owner private extension remain unchanged. No SEAL implementation is
introduced. The company Paillier/BFV/BGV/CUDA paths remain preserved.

## What this finishes

The finite cohort will create fresh encrypted inputs during honest owner
updates. Retaining a complete duplicate enrollment for every update/mode would
exceed its artifact budget. Keeping only hashes would lose the exact public
inputs needed to reproduce those native executions.

`PublicArchive` retains each immutable public blob once by digest. A signed
`EnrollmentRecord` references complete evaluation keys and feature groups,
including unchanged groups reused by an update. It reconstructs the **existing**
canonical MessagePack enrollment envelope and signature law byte for byte.
The record, payload, packet and snapshot digests are checked before a complete
scratch enrollment is published. Old complete scratch may be retired after
its recovery record and source blobs are retained. Partial failures remain
present and consumed. Read-only recovery requires no private HE/signing key.

`ResourceLedger` records and fsyncs a named attempt before the caller starts
expensive work. Attempts cannot be refunded, retried under the same label or
resumed from a new holder. Persistence failure disables the holder. The
coordinator must still enforce the committed global registration; caller-supplied
limits alone are not external authority or rollback protection.

The archive counts retained plus live/partial logical file bytes. It does not
measure allocated filesystem blocks or RSS. The final runner must guard the
whole additional-artifact budget, including logs, witness, queries and metadata.
The current module does not make arbitrary caller bytes safe for public release:
the fixed owner code must supply only specifically public outputs.

## Evidence and limits

The frozen invocation was `source-run01` in
`/home/pete/yavor-projects/xtrace-work/research-data/q77-owner-coordinator-20261005`.
Its terminal receipt, collected inventory and JUnit report confirm 23 passes;
the guarded HE/private observation reports zero attempts. The run took 2.51s;
that is test-run duration, not a search latency measurement.

Cases cover one/two-group byte equality with `auth.sign_enrollment`, changed
group reuse, canonical binary/array boundaries, duplicate retention and byte
caps, modified/truncated inputs, foreign owner/signature rejection, bounded
partial writes, scratch retirement, read-only public recovery, process/copy
custody, consumed mock resource limits and persistence failure.

Fixtures use the existing UNIT-ONLY Ed25519 signing material and opaque small
packet grammar. They are not valid encrypted search inputs. Mock ledger entries
named `HE_keys` or `feature_encryptions` are not actual cryptographic work.
No fresh HE key, encryption, private decoder, native search, CUDA build, large
timing cohort or author artifact was executed. These tests do not approve
parameters, prove honest encryption, protect a remote filesystem, establish
nonrollback authority or provide attestation.

## Return to the plan

This is an experimental reproducibility prerequisite, not a paper contribution
by itself. The [current system plan](paper-system-build-plan-after-roles-20261004.md)
still selects the homemade BGV exact owner-data path and keeps all three
systems hypotheses open.

Next finish the separately registered multi-phase upload relay and executable
cohort coordinator. Freeze their sources/dependencies, event order, initial
state, warmup, affinity/telemetry, limits and cleanup before fresh HE/private
execution. The latest prefetch budget remains a **proposal**: 702 query
encryptions, 72 protected signers and 31,744 feature encryptions. Historical
540/54/31,744 limits have not been amended or consumed. The two-key,
18-block/144-observation, 48-calibration/96-held-out cohort is unchanged.

After R2, execute that finite Q77 cohort and its decision protocol. There are
no new broad preliminary experiment queues. Q78 deployment/security and Q79
originality/paper selection remain unfinished. The goal remains active.
