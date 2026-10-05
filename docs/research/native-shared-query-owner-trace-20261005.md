# Shared relay and owner event trace

2026-10-05. This additive R2 component follows the committed
[registration](native-shared-query-owner-trace-registration-20261005.json).
The [execution return](native-shared-query-owner-trace-return-20261005.json)
pins sources, both successful public invocations and the retained failed
invocation. The complete HE/timing cohort has not started.

[`complete_cost_relay.py`](../../experiments/bfv_search_lab/complete_cost_relay.py)
provides fixed public search, snapshot, compact patch and setup-upload routing.
One owner upload budget and one relay download budget cover all competing
connections, including framing headers. The relay-to-backend dispatch is an
explicit unshaped local hop with separately recorded bytes, copies and CPU.
Public packets cannot choose code, libraries, paths, backends or trust anchors.
Uploads consume one fixed destination before writing and never overwrite it.
Each request has an absolute deadline and closes its owned connection without
a transport retry. Local TCP/userspace pacing is not deployed AWS latency.

[`complete_cost_trace.py`](../../experiments/bfv_search_lab/complete_cost_trace.py)
connects the existing owner receipt/private adapter and authenticated cache to
that endpoint. Its fixed owner query source consumes an attempt budget before
encryption and signing. Frozen per-lifetime domains provide public request
nonces; existing independent OS-backed sampling still provides encryption
entropy. The coordinator must allocate those domains and pay preparation.

The event log records actual arrival, start, completion and thread CPU times,
with parent intervals and completed dependency edges. Concurrent acquisition
and search are real operations sharing the endpoint, rather than a sum of
stage samples. Cache-only operation carries no HE receipt or query capability.
Prefetch switches to a fully published current cache; its remote lifetime can
then be explicitly closed. A failed acquisition or query disables that
trajectory. It cannot silently become a new remote fallback or retry.

Owner-supplied revision advances validate the complete next descriptor before
changing pins. Publication holds the descriptor lock across cache invalidation.
Late acquisition and old in-flight receipts cannot publish or enter private
finish after that advance. A compact authenticated patch restores the current
cache. Background acquisition applies and records its own CPU affinity, even
when the owner thread has a narrower CPU mask. No server response can invoke
the trusted pin-advance operation.

The [relay tests](../../experiments/bfv_search_lab/test_complete_cost_relay.py)
passed **28 new public cases**; the
[trace tests](../../experiments/bfv_search_lab/test_complete_cost_trace.py)
passed **36 new public cases**. These 64 distinct cases exhaust this component's
registered public ceiling. The preceding 256 cases have unchanged sources and
were retained, not rerun. Thus 320 distinct public cases are retained across
components; there was no 320-case combined invocation.

The first trace invocation passed 35 cases and failed one test assertion: it
counted messages rather than separate header/body bandwidth reservations. The
original source archive, freeze and failed result are retained. The corrected
test checks four reservations and exact total wire bytes in both directions;
all 36 cases then pass. A final review also corrected the raw absolute-deadline
bound at the endpoint API maximum and extended the existing deadline regression.
The same 36 cases pass again; earlier results/sources are retained and this adds
no distinct case. Encryption, private decoding and native popcount are
explicit public stubs. Cache authentication uses existing public UNIT-ONLY
signing/AES material and public fixture nonces. Parent/thread guards and the
relay child's guard record zero real private/native/HE attempts. This public
gate establishes neither HE correctness nor actual secret custody in HE workers.
Both owned relay/supervisor processes were absent at the return.

All 431 earlier runtime files, 66 company files, six isolated libraries and the
private extension remain byte-exact. Four additive files bring the source
inventory to 435. Main/staging are untouched. There is no new cryptographic key,
large timing sample, native build, attestation or security/originality approval.

Return to [R2 in the build plan](paper-system-build-plan-after-roles-20261004.md):
`benchmarks/complete_cost_owner_lab.py` remains unimplemented. It must coordinate
tenant/device/process preparation, paid metadata/state provisioning, public
upload, independent policy state, actual affected-group encryption/native
refresh, arrivals, telemetry and cleanup. Warmup/private-handle lifetimes,
frozen exact sources/dependencies and encryption/worker budgets must be
committed before either HE key or timing work. The 720/72/40,960 draft is still
a proposal; the historical 540/54/31,744 caps remain unchanged and unconsumed.
The finite 18-block/144-query evaluation, Q78 deployment/security and Q79
originality/paper decision remain open.
