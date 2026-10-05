# Owner trajectory orchestration and compact public update preparation

2026-10-05. This is an implementation return to R2 of the
[current research plan](research-system-decision-plan-20261005.md), not the
reserved HE timing study. The [machine receipt](native-shared-query-owner-runner-return-20261005.json)
records **66 passing public cases: 24 new and 42 repeated compatibility cases**.
There are 376 distinct retained public cases across earlier gates. These are
control/grammar fixtures, not 376 encrypted searches.

The full cohort launcher is still absent. The new code executes a complete
trajectory once honest provisioning and the actual independent worker/update
operations are connected. It accepts actual owner adapters and fixed trusted
operations, not stage-cost samples. R2 is not marked complete; two HE keys,
18 matched blocks and the 144 observations per implementation remain unconsumed.

## What now executes

[complete_cost_coordinator.py](../../experiments/bfv_search_lab/complete_cost_coordinator.py)
persists an attempt before preparation, runs an excluded warmup and eight actual
query paths, records completion minus causal arrival, checks every distance
and ordinal/ID top3 outside the completion interval, performs the fixed row
update, and retains a separate complete post-update check and owned cleanup.
It records errors even when preparation never produces a usable owner trace.
Its deadline/memory/artifact guard is cooperative, not native preemption or an
OS hard limit.

The direct `CacheOwnerTrace` uses the existing authenticated cache. It requires
no HE key, encrypted index, certificate or HE descriptor. A fresh acquisition
occurs after the first measured arrival; a returning cache acquires before
its excluded warmup. Fresh-cache code warmup is a caller-supplied fixed public
operation without cache acquisition. The exact executable warmup and complete
device/setup/event law must still be frozen in the HE addendum.

[complete_cost_trace.py](../../experiments/bfv_search_lab/complete_cost_trace.py)
now permits cache publication to win while a remote query is in flight. It
keeps remote work, its authentication/private finish and its failures paid.
The runner joins acquisition and losing remote work, shuts down the remote
workers, then uses the cache-only update path. A failed acquisition or losing
remote is not silently converted into a successful fallback trajectory.
Polling/scheduling overhead remains in the observed completion metric.

Trusted query-source hooks consume the global ledger before encryption and
retain the actual signed original before any send/receipt begins. Persistence
failures poison the trace; no budget is refunded. These hooks still need to be
bound to the actual global ledger/archive by tenant provisioning.

[complete_cost_owner_cohort.py](../../benchmarks/complete_cost_owner_cohort.py)
implements a clean public **assembly worker**, not a full `run` command.
Its initial input carries the selected complete enrollment. A later update
carries only the changed feature group and the owner's signed recovery record
and descriptor. The worker reconstructs the existing enrollment bytes with
the old evaluation keys and unaffected group, authenticates the complete
signature/record relation, and publishes distinct fixed files. Old full
enrollment scratch is retired only after the new packet validates; the owner
archive is the recovery premise. Actual query admission remains the protected
role's responsibility. Opaque descriptor fixtures here are not HE validity or
descriptor equivalence evidence.

The public supervisor can pin its manager while preserving the captured
startup CPU availability for workers on other cores. It also closes the
parent copy of the child control socket before waiting for readiness, so an
early child exit is observable rather than hidden until timeout.

## Verification and preserved failures

The first source revision's invocation retained 50 passes and eight subprocess
failures. A fixed public manager probe confirmed that the execution sandbox
denied wrapping the inherited socket. No HE/private work was attempted.
With local socket permission the second revision passed 58 cases. The final
revision, including actual public assembly subprocesses, passed 66 cases in
10.58 seconds. That duration is a test-run duration, not a search benchmark.
All invocations, source archives, collected node IDs and JUnit/guard reports
remain in `/home/pete/yavor-projects/xtrace-work/research-data/q77-owner-runner-20261005`.

The parent/thread function guard observed zero actual HE/private/native-search
or generated-key attempts. Echo exec workers have their own guard. The assembly
exec worker follows an inspected pinned public-only branch; the parent function
guard is not inherited through exec. Existing UNIT-ONLY roots and labelled
arithmetic stubs provide no valid encrypted-search correctness claim.

All 437 other preceding runtime sources, 66 company files, six isolated libraries
and the private extension retain their baseline bytes. Only two experimental
control modules changed, with previous versions retained; three experimental
files were added. Main and staging are unchanged. No SEAL dependency, native
build, CUDA execution, new HE context or complete-cost measurement was added.

## Return to the execution dependency

Next connect honest selected-profile tenant/evaluation-key/index provisioning,
source retention and global resource hooks to the real independent role
preparations and these trajectories. Implement the complete cohort `run`
action, its trusted PID/birth telemetry registry, calibration-policy freeze,
held-out execution and whole-artifact cleanup/guard ownership.

Commit the exact event, arrival, warmup, update, source/dependency/library,
traffic/retention, affinity, deadline and resolved budget addendum before any
fresh HE/private/timing work. Current 702-query/72-signer prefetch accounting
remains a proposal; historical caps are unchanged. Eight new public cases
remain under this component registration. Do not substitute another clock or
literature-only milestone for the missing cohort action.

After that, return to R3 and select one creative extension from its measured
bottleneck. Row overlays, a mixed common-Q cut or streamed state remain
conditional alternatives; no new grid or accepted originality claim is added.
Q78 deployment/security and Q79 paper review remain required.
