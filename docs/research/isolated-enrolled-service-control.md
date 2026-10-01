# E79: actual private bootstrap and independent endpoint measurements

2026-10-01. [Preregistration](isolated-enrolled-preregistration-20261001.md).
Retained runs: [smoke](../../benchmarks/results/publication-isolated-enrolled-smoke-20261001.json),
[pilot](../../benchmarks/results/publication-isolated-enrolled-pilot-20261001.json),
[final panel](../../benchmarks/results/publication-isolated-enrolled-final-20261001.json),
[direct first release](../../benchmarks/results/publication-isolated-enrolled-first-release-20261001.json).
Code: [private provisioning](../../experiments/bfv_search_lab/private_provision.py),
[three-process harness](../../experiments/bfv_search_lab/isolated_enrolled.py),
[tests](../../experiments/bfv_search_lab/test_private_provision.py),
[runner](../../benchmarks/isolated_enrolled_lab.py).
Sources `c4e654b` (smoke/pilot), `7f336e4` (final), `6390ffb` (first-release).
Production paths and E75/E76 raws remain unchanged.

**Return decision:** the finite private-acquisition/resource gap is now closed
for this local panel. Keep the stronger company controls and contrary cache
results. Do not infer an outsourced deployment advantage, universal failure,
production assurance or new cryptographic contribution. Full R2/P packages
remain open for updates, WAN, scale/concurrency and approved-parameter systems.

## What actually crosses the boundaries

Owner, compute server and querying client are three freshly spawned Linux
processes with different PIDs. No owner/private state is a compute-server
argument. The owner loads the pinned dataset, discovers the strong E76 global
map, generates keys/index/checker, and sends **actual public bootstrap and
seeded index packets** over TCP. The server reconstructs its index and native
evaluator solely from received bytes.

A new client acquires the secret/public keys, private maps, row positions/IDs,
checker seeds/fingerprints/bounds and ternary factory coordinates over a
separate owner socket. AES-GCM authenticates the envelope **before** a bounded
whitelisted MessagePack decoder or private-key constructor sees its payload.
There are no remotely supplied pickle objects or dynamic class imports.
Public bootstrap refuses private record types/extra fields.

The trusted local controller relays a64-byte owner key/context root plus its
public padding bound through actual framed IPC: **204 bytes across two hops**
in these runs. This is an explicitly paid local trust root, not an implemented
AWS identity/remote enrollment service. Private HE envelopes are padded to a
fixed public-geometry function; their whole padding cost is measured. Cache
bootstrap is a fixed1,121-byte envelope containing its separate key/manifest.
Snapshot compression length remains declared leakage as in E58.

The client restores the exact seeded checker without retaining the encrypted
index, reconstructs its owner-private factory, prepares every independent
answer, uploads it and sends the actual masked query. Response parse/bounds and
complete checking precede inner secret decryption. Scores/IDs/top-3 match the
independent plaintext oracle. Caches deliver authenticated raw/zlib1/zlib9
snapshots with either raw or compressed retention. Already-owned raw searching
is also timed in the isolated owner before HE setup; all owned plaintext remains
permitted. HE's retained coordinates are not excluded from the state ledger.

## Sampling and measured results

Smoke:2 trials/6 queries. Pilot:36 trials/216 queries, three independent process
repetitions per dataset/mode. A preregistered normal-approximation pilot rule
with10% relative precision, floor5/cap12 selected **eight** repetitions because
Semeion/raw-cache variability requested eight. This rule does not guarantee
precision. Final:96 trials/**864 exact mode queries**, nine queries each (first
marked warmup). Intervals resample independent **process means**, not individual
queries as independent trials; they are provisional with eight processes.
No p95 is reported. Mode order rotates between repetitions.

Mean returning wall time; parentheses are the process-cluster95% mean interval.
Acquisition includes actual private bootstrap/authentication/construction,
snapshot download when applicable, and the first query; excludes Python startup.

| Dataset / mode | Returning ms | Acquire + first query ms | Owner setup ms | Private envelope B |
|---|---:|---:|---:|---:|
| Mushroom homemade HE |47.580 (47.509–47.658)|128.863|3,187.733|1,162,809|
| Mushroom raw snapshot / raw retained |0.717 (0.705–0.732)|12.020|8.515|1,121|
| Mushroom zlib1 / raw retained |0.730 (0.704–0.768)|12.148|9.560|1,121|
| Mushroom zlib9 / raw retained |0.720 (0.707–0.740)|12.436|65.953|1,121|
| Mushroom zlib1 / compressed retained |3.562 (3.530–3.601)|15.191|9.574|1,121|
| Mushroom zlib9 / compressed retained |3.508 (3.485–3.534)|14.880|66.079|1,121|
| Semeion homemade HE |17.205 (16.842–17.413)|95.627|2,158.783|1,588,921|
| Semeion raw snapshot / raw retained |0.145 (0.139–0.154)|8.686|6.817|1,121|
| Semeion zlib1 / raw retained |0.141 (0.140–0.142)|8.881|7.589|1,121|
| Semeion zlib9 / raw retained |0.140 (0.139–0.141)|8.755|19.154|1,121|
| Semeion zlib1 / compressed retained |0.811 (0.807–0.816)|9.892|7.713|1,121|
| Semeion zlib9 / compressed retained |0.796 (0.793–0.800)|9.401|19.193|1,121|

These are **means**, not the medians in E76; direct subtraction is not a paired
speedup. Same strong geometry/fixtures but separate-process, sampler, query-count
and provisioning differences are explicit. Fixed padding is conservative;
unpadded encodings are also retained, and neither is a claimed lower bound.

Mean HE client query CPU is35.274/11.431 ms; server query-command CPU is
10.521/5.263 ms (answer parsing is separately recorded). Mean peak RSS in MiB:

| Dataset / mode | Owner | Compute server | Client |
|---|---:|---:|---:|
| Mushroom HE |180.50|188.32|60.73|
| Mushroom zlib1/raw cache |42.60|41.87|43.17|
| Semeion HE |148.13|151.81|52.70|
| Semeion zlib1/raw cache |48.53|41.98|41.98|

Each process reports its post-import baseline, current RSS and `ru_maxrss`
throughout. Baselines are about40MiB; peak includes allocations/imports and is
not serialized state or an object-size model. Owner raw-control RSS is recorded
**before** expensive HE setup. Parent/controller memory is not mislabeled client
memory. No timing/RSS from a shared-GIL endpoint is used here.

## Direct cold and new-client first result

The main panel's controller duration covers the **whole nine-query trial**.
Its legacy `controller_new_client_wall_including_process_startup_s` field covers
the whole client session; neither is treated as first-result latency. A retained
follow-up adds a direct `first_done` IPC observation and clearer full-session
names. It runs another48 independent process trials/**432 exact queries**,
eight repetitions for HE and the two strongest acquisition controls.

| Dataset / mode | Cold first result s | Enrolled server / new client first result s |
|---|---:|---:|
| Mushroom HE |4.391|0.299|
| Mushroom raw snapshot/raw |0.584|0.184|
| Mushroom zlib1/raw |0.581|0.182|
| Semeion HE |3.239|0.270|
| Semeion raw snapshot/raw |0.642|0.177|
| Semeion zlib1/raw |0.640|0.177|

These are directly observed controller means, including spawned interpreter
startup and local validation/first-result instrumentation. Cold includes
fixture parse, owner raw-control/oracle instrumentation, discovery, keys,
index/checker creation, enrollment and private acquisition. They are not
minimal production service latency or sums of overlapping substage timers.
Returning timings in the preceding table exclude startup and first query.

Across smoke/pilot/final/follow-up: **182 process trials /1,518 exact mode
queries**, including repeated workload queries with new keys/epochs. This is
not1,518 distinct holdout queries. Every emitted score hash and stable top-3
matches the owner oracle. Eight new provisioning tests plus eight existing
wire/release tests pass, including actual loopback tests outside the socket-
restricted sandbox. Four explicit Ruff paths pass. A fixture-string/path bug
and relative-pilot metadata path bug were fixed before their successful runs;
no failed run is counted or retained raw overwritten.

## Remaining boundary and next action

This is a bounded research measurement service. Epoch/attempt state is volatile;
authenticated owner-root distribution, crash/rollback, private timing and
approved BGV/Paillier/related-key parameters remain unresolved. AES-GCM setup
does not repair arbitrary FHE decryption or make the underlying protocol
production ready. Socket permissions were used only for local loopback.

IP/TCP headers, TLS, WAN, network loss, updates, larger distinct datasets,
concurrency and GPU service are excluded. The existing permitted-cache winner
survives both returning and acquired-client panels; no artificial memory cap
or forbidden plaintext retention explains it away. Retain this contrary result
and return to R6's construction/resource selection rather than tune a losing
protocol's kernel and announce a paper contribution.
