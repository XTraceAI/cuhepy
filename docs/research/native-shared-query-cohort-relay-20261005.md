# Q77 owner-bound cohort upload relay

2026-10-05. The separately
[registered six-case subgate](native-shared-query-cohort-relay-registration-20261005.json)
passes: **6 passed, 23 deselected**. The preceding 343 distinct public cases
remain retained; none were rerun. There are now 349 distinct retained cases
across gates. The parent coordinator component has used 29 of its 32 cases,
leaving three. The complete owner cohort and actual HE timing remain unexecuted.

[complete_cost_cohort_relay.py](../../experiments/bfv_search_lab/complete_cost_cohort_relay.py)
adds the missing initial/update upload phases. It composes with the existing
shared relay and serves through its bounded concurrent loopback worker.
Configuration fixes the owner verification anchor, public lifetime namespace,
two phase destinations and byte limits. The received signature covers the
namespace, phase, whole body, length and digest. No peer supplies a filesystem
path, port, library, owner key, policy or current epoch.

A valid owner phase is consumed before writing. A failed size/digest or disk
operation disables the upload lifetime; complete and partial files cannot be
replaced through a second request. Foreign signatures/namespaces and out-of-order
phases do not write a file. This is a local experimental lifetime rule; a fresh
process or trusted filesystem is not rollback-resistant remote authority.

All commands continue to share the existing relay's single download budget,
and owner threads use the existing shared upload endpoint. Setup/update are
real transferred bytes, not modeled stage sums. Upload records include actual
wall/thread-CPU intervals and completion status. Their acknowledgement does
not authorize decryption or advance the owner snapshot; the existing descriptor,
complete native predicate, consumed receipt and fixed private callback remain
necessary on the eventual search path.

The gate checks exact two-phase delivery and replay rejection, foreign roots,
namespace/order/config rejection, signed-digest and fsync failures, deadline/
process/copy guards, and a separately supervised public TCP worker. The latter
checks process ancestry, complete handler/child cleanup and equality between
download credits and actual sent frame bytes across setup/cache/update/control.
It uses opaque grammar and the existing UNIT-ONLY signing fixtures. Parent
HE/private profiling reports zero attempts; that guard is not inherited through
exec. The child follows the inspected fixed public-only relay entry and receives
only public configuration. This is not a real HE custody experiment.

All 436 other preceding runtime files, 66 company files, six isolated libraries
and the private extension remain unchanged. The prior test file is archived;
every existing fixture/test function body has the same AST. Six cases are
appended to it. The new relay brings the current runtime inventory to 438.
No new HE key, encryption, private decoder, native search, CUDA build, large
timing or generated signing context ran. All production/fallback schemes remain
preserved. Test duration 4.19s is not a search-performance result.

Return to the [current plan](paper-system-build-plan-after-roles-20261004.md):
finish owner orchestration, independent remote/cache/prefetch lifetimes,
actual refresh and guarded telemetry. Also separate actual native evaluation/
construction clocks from forwarding/verification waits. The old frontend
`produce-forward` wall interval includes both and cannot be presented as bare
evaluation latency. Define the precise computational projection and its limits
in the exact pre-HE addendum; no old BGV timing is a replacement. Then execute
the finite Q77 calibration/held-out cohort. Q78 and Q79 remain required.
