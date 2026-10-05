# Shared public link and process-supervisor component

This is a bounded part of R2, registered before implementation at
`da5e20c` in the [component registration](native-shared-query-coordinator-component-registration-20261004.json).
The [return receipt](native-shared-query-coordinator-component-return-20261004.json)
retains the source archive, invocation, public subprocess artifacts and scope.

[`complete_cost_network.py`](../../experiments/bfv_search_lab/complete_cost_network.py)
adds one process-owned budget per full-duplex direction. Competing streams share
header/body reservations and actual chunk delivery; a late thread cannot deliver
an old reservation in a burst alongside another active chunk. Partial writes
keep their original credit. Waiting for shared delivery uses the message's
absolute deadline; failed credits are not refunded. Backpressure and scheduling
delay occupy the lane. This declared userspace link has no fairness guarantee
and is not an AWS network measurement. The full runner must shape each direction
once and charge relay copies/work.

[`complete_cost_supervisor.py`](../../experiments/bfv_search_lab/complete_cost_supervisor.py)
starts a clean manager before future HE-key generation. Only bounded public
specifications cross its trusted local control socket. The manager launches
pinned child entries with a restricted environment, explicit affinity and
bounded readiness; it never replaces a consumed label. Stops/errors retain logs
and exit receipts and clean the exact owned children. A fresh process session
provides a bounded cleanup fallback for an unresponsive manager. This supervisor
is not a remote trust root. Its API cannot prove that the caller has no HE key
already: the real runner's creation order and custody still need inspection.

The native-role wrapper reuses `LocalRole` and `serve`. It removes frontend
per-connection pacing only inside the future shared-relay topology; protected
internal traffic keeps its declared link. That real-role wrapper has not been
executed in this public gate. Calling it directly without the shared relay would
omit the client link cost and is not an eligible cohort path.

The [network tests](../../experiments/bfv_search_lab/test_complete_cost_network.py)
and [supervisor tests](../../experiments/bfv_search_lab/test_complete_cost_supervisor.py)
passed **20 distinct public cases**. Actual small TCP streams cover contention,
partial delivery and deadlines. Six managers launch four echo children: two
complete normally and two intentional startup failures terminate with exit143.
All ten owned processes were absent at the return. The echo child's parent is
the manager, and an arbitrary public owner-environment marker is absent.
Parent and four echo-function guards record zero private attempts; child imports
precede their guards. These are public process controls, not HE-custody or private
side-channel assurance.

The preceding 236 public cases are retained with unchanged sources, not rerun
or added as new experiments. The 256 distinct retained public cases exhaust the
initial implementation unit ceiling. Any necessary additional integration gate
needs its own bounded registration before execution; the actual HE cohort cap
remains unconsumed. All 427 earlier runtime files, 66 company files, six isolated
libraries and the private extension remain unchanged. Four additive runtime
files bring the inventory to 431. No fresh HE/standard crypto context, native
build, CUDA, large timing or paper/security approval is added.

The next dependency is the whole owner trace and shared relay: tenant setup,
public upload, private/native preparation, device metadata/cache acquisition,
prefetch, requests, complete private finish and 32-row updates. Resolve initial
warmup/private-preparation state and the query/update/worker-context budgets in
the exact execution addendum before any real HE work. In particular, a separate
cold prefetch remote trajectory cannot silently reuse a warm worker or exceed
the initial 54 protected signing contexts; either its reuse/state law or an
explicit budget addendum is required. The historical 18-block/144-observation
cap and 48/96 calibration/held-out split are unchanged. Q78/Q79 remain open.
