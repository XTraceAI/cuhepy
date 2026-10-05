# Q77 native clocks and public telemetry

2026-10-05. The separately [registered public subgate](native-shared-query-runtime-registration-20261005.json)
passes **3 cases, with 29 deselected**, in one retained invocation. The preceding
349 distinct cases remain retained, giving 352 across separate gates. This
exhausts the parent coordinator's 32-case ceiling. It is not a combined
352-case run or a fresh cryptographic experiment.

[complete_cost_owner_lab.py](../../benchmarks/complete_cost_owner_lab.py)
now supplies two real worker services. `TimedLocalRole` uses the existing role
arithmetic and authorization, adding clocks around configured native callables
before enrollment. It also replaces the factory's cached replay/aggregate
references with the same proxies. Configured argument/return types, arguments,
results and exceptions pass through; none are serialized by the clocks.
Actual native intervals, thread CPU and operation phases are recorded.

The explicitly named computational projection includes selected query
construction, evaluation and witness/terminal native calls. It excludes Python
parsing, allocation, authentication/framing, network/admission waits, signing,
initial preparation and cleanup. It is not an independently run unverified
evaluator, nor owner-visible latency. A returned native call does not assert
protocol success. The worker's final native close occurs after its inventory
and is explicitly outside that report; owned shutdown and telemetry must pay
it separately. No earlier `produce-forward` interval becomes bare evaluation
time: that interval still includes the protected round trip.

`PublicTelemetry` runs in a clean supervisor-descended process at its specified
affinity. It reads system CPU, memory, swap, clock/temperature counters and
public process metadata for a trusted local PID/birth registry. It does not
read process memory, argv, environment or keys. Birth mismatch prevents following
a reused PID; values are discarded if birth changes during a sample. Registry
updates must be atomic trusted-local writes, not received commands. The only
accepted RPC is the fixed stop command.

Sampling has fixed interval, attempt, byte and absolute-lifetime bounds.
Observed gaps longer than one second are flagged rather than fabricated or
filled in. A frozen available-memory minimum produces a cooperative failure
record; it is not a hard RSS/PSS limit or instantaneous peak guarantee. Guard
persistence failure stops the owned sampler and remains explicitly uncompleted.
The sampler never kills other programs. The future coordinator must check
the guard/final inventory, stop and retain a failed consumed trajectory, and
account for telemetry artifacts and CPU. These enforcement/HE integrations
remain unexecuted.

The public tests cover direct and cached-call identities/signatures/results,
failure forwarding, excluded public waits and process/copy guards; telemetry
birth binding and real resource/persistence failure paths; and a real clean
worker's ancestry, affinity and complete owned shutdown. Native arithmetic is
replaced by labeled public callables. Parent/thread profiling reports zero
HE/private/native-search attempts; it is not inherited through exec. The
exec child follows the inspected fixed public telemetry branch. No generated
signing context, HE key, encryption, private decode, native search, CUDA or
large timing ran. Test duration 4.96s is not a search benchmark.

All 437 other preceding runtime sources, 66 company files, six isolated
libraries and the private extension remain byte unchanged. The prior test
file is archived; its 27 top-level function ASTs are unchanged. The new worker
entry brings the registered runtime inventory to 439.

Return to the [build plan](paper-system-build-plan-after-roles-20261004.md):
the file provides worker services, **not yet the owner cohort run action**.
Finish owner preparation, exact source/query retention, independent policy
lifetimes, actual cache/remote races, updates, guarded accounting and the
committed pre-HE execution addendum. The public parent cap is exhausted; any
necessary new orchestration integration cases need a separate finite registration.
Historical HE caps and the 18-block/144-observation cohort remain untouched.

One startup law must be explicit: the existing supervisor validates new worker
CPUs against its current affinity. Pinning it permanently to CPU3 before later
starts would reject workers on other CPUs. Either retain and report its wider
startup mask or restore the captured allowed mask during starts and repin
afterward, charging those actual intervals. Do not claim permanent CPU3 affinity
without implementing and freezing that behavior. The local services are not
attestation, nonrollback authority, parameter approval or private-side-channel
assurance; Q78 and Q79 remain required.
