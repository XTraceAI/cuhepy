# Q77 local public role and owner callback handoff

The additive [implementation registration](native-shared-query-complete-cost-registration-20261004.json)
was committed at `2d892992113b1fd5cb9a660d512e7c8bfa8239f9` before new code.
The [bounded return](native-shared-query-complete-cost-public-return-20261004.json)
records 158 final distinct passing tests, six retained small native mode paths,
and two corrupted native results rejected without a signature or callback.
This completes the public role/transport component. The owner HE decoder,
private-context custody, whole cohort coordinator and exact execution addendum
remain unfinished. Neither reserved HE key nor any large measurement was used.

## Implemented execution path

| Component | Code and behavior |
| --- | --- |
| Public frontend and protected role | [Runner](../../benchmarks/complete_cost_shared_query_lab.py) uses fixed trusted config, owner anchor, mode and pinned native library. Its worker CLI can run a role in another process. Network commands cannot choose those roots. |
| Full common-Q / exact aggregate | Frontend creates the actual native result; protected role executes complete existing admission, journal authorization and claim. The same complete compact frame reaches the result signer. |
| Prepared replay | Frontend forwards only the signed original; it creates no native preparation and computes no proposed answer. The existing protected replay computes once, then uses the same journal and receipt seam. |
| Local result bridge | [Protocol](../../experiments/bfv_search_lab/complete_cost_protocol.py) signs only from the existing durable journal's claimed callback. The signed payload binds logical owner pin, HE key, selected mode/code/certificate, complete request identity and full frame. |
| Owner callback seam | A separately trusted verifier anchor and the current owner descriptor precede signature/payload/frame checks. The local identity is consumed before a private callback; rejection, private failure, duplicate or stale delivery cannot retry that callback. Real HE decoding is the next component. |
| Actual bounded transport | [Transport](../../experiments/bfv_search_lab/complete_cost_transport.py) uses length-framed IPv4 loopback TCP, checks length before allocation, enforces absolute IO/pacing deadlines and serializes complete messages. It records both directions, bytes, hashes and intervals without payloads. |

The frontend/protected link carries the original plus the actual complete claim
for delegated modes, then the signed compact receipt back. The frontend forwards
that receipt to the owner. Replay gets the same proxy topology, without a
redundant producer computation or witness. Separate links and directions must
remain charged in the cohort.

The declared local link conditions are 100 Mbps plus 10 ms one-way delay for
the client link and 10 Gbps plus 0.1 ms one-way delay for the internal link.
Userspace pacing is a controlled prototype condition, not measured AWS
networking or secure transport. Pacing happens before chunk delivery, including
the last chunk; the receiver cannot finish before the declared envelope.

## What the bounded evidence covers

The [receipt tests](../../experiments/bfv_search_lab/test_complete_cost_protocol.py)
cover exact signed context/request/mode bindings, boolean/integer encoding
aliases, complete compact-coordinate grammar, wrong anchors, stale pins,
duplicate/concurrent delivery, callback failure, journal-claim failure and
process/copy ownership. The [transport tests](../../experiments/bfv_search_lab/test_complete_cost_transport.py)
cover oversized/truncated frames, EOF, terminal timeouts, actual paced receive
completion, concurrent senders, full duplex and fork/close behavior.

The six actual native handoffs use saved Q74 owner-canonical cases at N=16,
17 records and N=32, 33 records, through all three modes. They compare the
entire received frame to the retained frame, including both physical groups.
The callback in these tests handles public frame bytes; it performs no new HE
decryption or score-semantic check. The tests instantiate the role classes in
one process and exchange actual TCP messages across threads. Separate-process
cohort behavior and role affinity are not measured by this gate.

Two bad-result controls execute the real full/aggregate predicates. Their
attempts become rejected, with zero authorizations and zero callback claims;
retrying the same original is consumed. The preserved unit role files include
six delivered and two rejected journal attempts. They contain public small
fixtures/configuration and local state, never an HE secret.

All five test invocations and four source archives are retained. Final cases
are **158 distinct tests**, not the sum of overlapping runs. The initial
sandbox run could not create sockets; later integration failures exposed text
RPC verbs against a binary-only parser, then an overbroad correction of two
trusted JSON keys. Final code uses binary RPC verbs and string JSON field names.
The parser and admission predicate were not weakened. Explicit-file Ruff
validation passes; the first default Ruff invocation excluded research paths
and is not counted as validation.

The gate uses two deterministic public unit-only Ed25519 contexts. Main and
future test threads were monitored for repository HE key generation,
encryption/decryption, evaluation-key generation and private ring operations:
zero calls were observed. No native build, CUDA, Nsight, Lean, author artifact
or new literature execution occurred. Existing 420 runtime files, 66 company
files and six isolated libraries keep their original pins; five runtime files
were added.

## Boundary and next action

The local protected worker/runtime, config path, current-pin provisioning and
journal storage are trusted. A code digest or local key announcement supplies
no attestation. Client attempt state is process-local; it is not a crash- or
host-rollback authority. The journal/descriptor must have the same owner
anchor, and current-pin advance linearizes with already claimed private work.
Public complete-frame syntax does not prove private phase correctness.
Honest-origin, primitive/native correctness and the Q76 security-card premises
remain explicit. No originality, parameter or deployment approval follows.

Return to the [roadmap](paper-system-roadmap-20261004.md): implement the owner
coordinator with retained in-memory keys, real complete compact-P private finish,
fresh spawned public/protected workers, all cache policies, acquisition and
32-row updates. Then commit the exact event DAG, initial states, warmup/arrival
semantics, deadlines, telemetry, preservation and calibration freeze before
consuming either HE key or measuring the cohort.

The execution addendum must resolve encryption accounting explicitly: the
initial reservation of 540 fresh query encryptions covers the three standalone
remote trajectories. Background acquisition can add up to 180 remote component
calls. Account for those before execution; keep 18 matched blocks, 144 measured
observations per implementation, six calibration and twelve held-out blocks.
Do not silently reuse ciphertexts or call extra components independent trials.

Q77 remains incomplete. Q78 actual deployment/security and Q79 originality/paper
remain required. This handoff adds no claim of a new protocol or speedup.
