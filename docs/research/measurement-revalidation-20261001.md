# Measurement revalidation, 2026-10-01

Status: finite audit completed with explicit historical-reproduction limits.
This follows the owner's request to check whether
earlier competing workloads affected measurements. It supersedes no historical
receipt and attributes no observed difference to interference without evidence.

The main conclusions survive: large CPU reductions reproduce, the tiny E27
CUDA allocation/repair ordering remains unresolved, and strong NumPy/cache
controls retain their negative results. A stronger Paillier lookup hybrid
baseline changes the local-latency comparison: 344.524 ms versus prepared
BFV's 395.213 ms in the matched 8k block. BFV retains its much smaller payload.
Fresh layout-model costs change 25/63 choices at 8k and 17/63 at 32k; saved
routing reports must be refreshed from compatible measured inputs.
The research plan carries these findings forward and keeps E82 as the next
unimplemented construction screen.

## Frozen evidence and execution

The construction checkpoint `66c04dc69423438220ed4eb87a09a7831bac80ab`
and all original raws remain unchanged. New results, per-process resource
telemetry, inventories and execution receipts go to
`../research-data/revalidation-20261001/` relative to the repository.
The isolated source copy is `../cuhepy-revalidation-20261001/`. Three documented
copy-only changes accept fresh metadata paths and isolate the external author
adapter's cache; arithmetic and delivered native binaries are unchanged.
The twelve copied runtime libraries were subsequently made local, byte-identical
files to satisfy benchmark path-provenance checks. Separate metadata/profile
adapters record actual compiler and NVTX paths; they do not change arithmetic.

The initial queue had 209 jobs: 113 earlier-experiment jobs, 80 publication
jobs and 16 additional process blocks for sensitive contrasts. It completed
with 205 successful artifacts and four retained metadata/tool-path failures.
One successful block had 312 KiB of host swap activity and is qualified.
The inventories
also account for superseded runs, derived reports, diagnostic failures and
tool-dependent standalone targets. The immutable `main209-completion.json`
records this cohort; `followup9-completion.json` separately records the nine
fresh-ID retries and controller-matched followups. `final-three-completion-01.json`
records three further whole-block repeats, all successful and without detected
resource qualification (265, 216 and 113 samples). Additional declared phase receipts retain
the repeated CPU reference, new native binaries, historical SEAL checks,
parameter models and bounded upstream PIR timing control.

Every timed workload runs serially, with a 30-second resource preflight and
two-second CPU/GPU, swap, pressure, clock/temperature and competing-process
sampling. No unrelated process is stopped; the desktop still shares the GPU.
There is no machine-exclusive assurance. Qualifying conditions remain in the
receipt, and affected whole blocks require repeat/sensitivity analysis.

The owner provided an idle window for the complete eight-variant, 8,192-vector
comparison. Its fresh block03 passed all 377 measured resource samples with
no competing GPU compute process, high foreign CPU activity or new swap activity.
The earlier resource-qualified block02 remains retained. The repeated BFV CPU/
GPU scaling study also completed cleanly at all three declared sizes, with five
measured calls per mode, and all nineteen new native configurations completed
under their common monitored phase. These are additional studies, not nineteen
independent process blocks or exact historical-binary reproductions.

Independent process/key blocks repeat E26/E27's small GPU differences,
E49's vectorized factory comparison, the vectorized complete update lifecycles
and E77's client-plus-factory cost. Within-process query repetitions are not
independent host-load samples. Pairwise process-block ratios retain units and
timed boundaries; a stage sum is not an end-to-end service measurement.

Fresh tile measurements feed lifetime prices, then causal rules. Fresh cache,
BGV and external measurements feed communication/acquisition models. Failed
prerequisites cannot silently reuse copied historical measurements. Counts,
correctness, modeled security costs, timeout coverage and timings are reported
separately. Current-source checks do not reproduce historical code when its
recorded hashes differ.

## Tests already completed

The full native/CUDA-enabled pytest invocation collected 1,966 cases:
1,960 passed, six skipped, zero failed. Rebuilding the optional independent
Microsoft SEAL v4.1.2 BGV oracle in a separate directory allowed its five
skipped tests to pass. Combined coverage is therefore **1,965 unique passing
tests**, with one live AWS Nitro check unavailable. The oracle used installed
GCC 13 instead of the absent historical GCC 12; its correctness result is not
a fair historical timing comparison.

Separate native diagnostics passed all ten standalone families, all seven
dedicated CPU bindings (675 passing executions and two documented ASan mlock
admission skips; overlapping scopes), eleven supplemental CUDA memory/race/
synchronization checks, and four positive/four deliberate-negative private
taint controls under GCC 13 and Clang 18. These finite checks establish no
constant-time proof. Rust 78, two Go groups of three, and actual uncached
Bazel XML with 59 cases also pass. The legacy integer-versus-hex assertion
failure is retained beside the representation-aware control and six unchanged
legacy assertion programs that pass. No delivered extension was replaced.

All environment/tool setup failures remain: the sandbox's ptrace/device
limitations, initial Clang header selection, official sanitizer launcher
ambiguity and current Nsight wrapper/NVTX layout differences. Fresh host
retries and explicit adapters are separate receipts. Current Nsight Systems
capture/export/summary succeeded as instrumented, resource-qualified
diagnostics; Nsight Compute counters were denied with `ERR_NVGPUCTRPERM`.
Neither is a quiet latency measurement or exact old-profiler reproduction.

## Comparison and coverage

The final comparison contains **272 successful measurement/model outer receipts,
290 normalized observations, 297 historical/fresh pairs and one separate new
study**. Its compared identities intersect **215 of the 224 primary historical
JSONs**; three separately listed supplemental artifacts bring the distinct
compared total to 218. Nine primary identities instead require explicit
instrumented, model/derived, known-negative or profiler accounting. The 29
additional JSONs are six historical manifests, 22 incomplete progress records
and one recipe alias; they are preserved and do not add independent timing
blocks. These counts describe different units and do not assert exact historical
replay. The earlier main-only snapshot remains 205 successful jobs/210 pairs/
175 primary identities. All 253 historical JSONs, 59 protected
paths, twelve original/copied runtime libraries, protected refs and historical
validation receipts remain unchanged. The active research plan is explicitly
revised separately.

The main analysis preserves earlier analyzer attempts. Corrected comparisons
separate Python/NumPy arithmetic, update traces, vectorized factory controls,
driver versions, process repetitions, adaptive trial counts, actual serialized
payload observations and deterministic models. Different trial sequences
cannot be compared by the same array index. Matching recorded hashes do not
prove complete historical-source replication; changed and missing maps remain
qualified.

Twenty-two retired configurations completed with their original
explicit geometries and repetition flags. Twenty have recoverable recorded
nonbinary source inputs in isolated retained-commit contexts; two dirty source
versions were not recoverable. All thirteen setup contexts have passed;
38 archived extensions were freshly built using the available GCC 13/CUDA 12.9
toolchain, while the current controls retain delivered
libraries. All 42 current/recovered jobs passed their common final integrity
accounting. One current radix-8k job had eight busy-CPU samples among 85;
the one predeclared whole-workload repeat passed all 84 samples without a
resource flag. Its original strict final bookkeeping check remains a failed
receipt: the plan omitted a declared `PYTHONOPTIMIZE` field even though the
captured same-interpreter worker confirms assertions enabled. A separate
metadata-only all-gate review accounts for this declaration discrepancy without
rerunning or modifying the timing. Source recovery does not recover the original compiler, binary or
host conditions, and these strata cannot establish a pure algorithm or
background-interference causal effect.

The exact historical SEAL/Paillier sanity runner also completed at 256, 2,048
and 8,192 vectors, with all 61 pinned source/archive identities unchanged.
These single-query references use the existing SDK environment, with NumPy
2.4.4 and msgpack 1.1.2; the research environment uses 2.4.3 and 1.2.2.
The failed research-environment attempts remain retained. These are separate
runtime epochs rather than an exact historical environment replay.

Large CPU benefits reproduce. Complete local GPU benefits are much smaller
than server-stage gains, with E27 allocation comparisons near a tie. Strong
NumPy update/factory and paid client-plus-factory controls retain their negative
results. Cache-versus-remote model winner flags do not change, although eight
compression-control choices do. Per-attack estimator completion and timeout
coverage remain separate from heuristic operation costs. These assessments
are reconciled with the completed fresh timing blocks in the final analysis.

In the five matching-controller E27 blocks (02–06), allocated-versus-repair32
CUDA local-total ratios are 1.00153 [0.99966, 1.00340] and 1.00075
[0.99980, 1.00171] for the two fixed splits. Both provisional paired-bootstrap
intervals cross a tie. The all-six sensitivity view slightly excludes one for
the second split, but includes the first controller version whose exact helper
bytes were not retained. Prefer the matching-controller result: neither variant
has an established complete-query CUDA advantage, and the possible differences
are also far below the two-percent practical margin.

The targeted N=2,048/q40 BKW followup completes within a 180-second budget
(111.36 seconds observed) and reproduces the historical heuristic cost
380.8607384947615 exactly. The earlier 45/60-second timeouts remain retained.
This restores that attack's finite coverage; it does not replace the lower
minimum across the full set of attacks or provide parameter approval.

All four derived checks completed separately from the frozen timing comparison.
The two layout planners retain every geometry/payload plan and all 63 scenario
formulas each, but preferred options change in 25 scenarios at 8k vectors and
17 at 32k. They choose BGV owner-index radix layout, terminal precision and
query/response drops over the existing all-precision CUDA-server panels;
24/15 changes concern precision and 1/2 concern layout. They do not select
BFV versus Paillier, CPU versus GPU, or public-index mode. Recompute saved
experimental routing reports from these matching fresh panel costs; no
production/runtime consumer uses the reports. These are analytical rankings
with nominal links and incomplete setup floors, not measured WAN
latency or new independent blocks. The frontier oracle's JSON semantics remain
exact; 203 source checks pass with nine specifically documented metadata-only
adaptations. Fresh exports have 96 stage rows, 96 scenario rows and four
figure files (two figures, each exported as SVG and PDF). Original exports and
the prelaunch schema-check failure remain retained. This result does not license
changing the unrelated publication
model calibration graph.

## Matched 8,192-vector BFV/Paillier comparison

The final clean block03 uses one common 8,192 × 512 corpus/query fixture,
one excluded warmup and three measured queries per variant. The table reports
the median **complete local elapsed** boundary, plus stage medians and measured
serialized bytes. It excludes setup, network transit, authentication/attestation
and content retrieval; unequal parameters are not asserted to provide equal
security. Repetitions share one process/context and do not supply an independent
process confidence interval. Stage medians need not add to the elapsed median.
Paillier uses `key_len=1024` prime generation; the lookup hybrid's actual
modulus is 2,047 bits, with alpha 280 and a 279-bit decryption exponent.
BFV uses degree 16,384, plaintext modulus 65,537, 180-bit coefficient modulus,
30-bit decomposition, error eta 21 and a 50-bit response modulus. Its client
remains on CPU; the Paillier CUDA/hybrid rows require a GPU client. These
experimental profiles are disclosed inputs, not parameter assurance.

| Variant | Client prepare ms | Server ms | Client finish ms | Local elapsed ms | Response bytes | Query + response bytes |
|---|---:|---:|---:|---:|---:|---:|
| Paillier CPU | 10.339 | 48.743 | 56,257.209 | 56,316.163 | 4,227,019 | 4,227,563 |
| Paillier CUDA | 141.861 | 86.124 | 1,919.666 | 2,147.631 | 4,227,002 | 4,227,546 |
| Paillier lookup CPU | 0.720 | 48.984 | 8,561.928 | 8,611.322 | 4,227,029 | 4,227,573 |
| Paillier lookup CUDA | 3.790 | 343.160 | 285.179 | 632.319 | 4,226,954 | 4,227,498 |
| Paillier lookup hybrid | 3.794 | 48.843 | 291.524 | 344.524 | 4,226,953 | 4,227,497 |
| BFV CPU | 198.851 | 19,626.889 | 27.493 | 19,853.807 | 204,900 | 942,294 |
| BFV CUDA | 198.312 | 260.134 | 27.650 | 486.336 | 204,900 | 942,294 |
| BFV CUDA prepared | 197.114 | 171.007 | 27.157 | 395.213 | 204,900 | 942,294 |

The lookup hybrid uses a CPU server and GPU client. Prepared BFV's local elapsed
time is about 14.7% longer than this stronger baseline, while its response is
20.63× smaller and query plus response is 4.49× smaller. BFV beats the slower
all-CUDA lookup's local latency in this block; it does not beat every Paillier
configuration. The difference motivates a matched large-workload hybrid control,
without extrapolating an 8k result to larger sizes.

The separate clean eight-variant BGV study uses a different fixture/order seed
and five measured queries. Its BGV owner CUDA workspace median is 60.047 ms,
with 102,488 response bytes and 348,354 query-plus-response bytes. Keep this in
its own study; it is not a ninth paired row in the table above.

A separate BFV server-API study excludes a first CPU call and measures five
CPU/GPU calls per mode. At 1,024/8,192/32,768 vectors, CPU medians are
2.441/19.570/78.381 s and prepared GPU medians 0.03445/0.17104/0.64635 s,
respectively: 70.87×/114.42×/121.27× server arithmetic speedups. It excludes
owner crypto, persistent-index preparation and network, and its calls are
within one process rather than independent blocks. This large arithmetic gain
does not contradict the complete-query tradeoff above.

## Return to the research plan

The finite coverage accounting and fresh paired comparisons retain contrary
outcomes. Carry the Paillier lookup hybrid into the next larger-workload panel;
keep E27's allocation choice unresolved at the complete CUDA boundary. Reopen
a hypothesis only if a specifically matched complete-cost control supports it;
qualify a small improvement when independent blocks do not resolve it.
Retain exact algebra/body counts when they reproduce, without treating them
as evidence about wall-clock latency. This task adds no originality, parameter
approval or private-side-channel assurance.

The next proposed experiment remains **E82: a paid authenticated
fixed-private-matrix correlation/token interface**. It is unimplemented.
First check the contract, negative cases and full owner/helper, refresh,
field-size and authentication costs; implement a primitive adapter only if
that screen survives. No complete original paper mechanism is selected by
the audit. The publication models retain their matching dependency graph;
unrelated attractive synthetic 8k/scaling results are not substituted as
calibrations.

The [typed coverage ledger](../../../research-data/revalidation-20261001/final-typed-coverage-04.json)
and [readable coverage](../../../research-data/revalidation-20261001/final-typed-coverage-04-summary.md)
account for all 224 primary identities, 29 extras and three supplemental
artifacts separately. The complete
[comparison](../../../research-data/revalidation-20261001/comparison-final-extended-03.md)
retains 272/290/297 receipt/observation/pair counts. The
[final numerical analysis](../../../research-data/revalidation-20261001/analysis-final-followups-04.md)
and source/evidence manifest are retained with the checkpoint below. Historical
documents are superseded by this dated assessment rather than rewritten.

The audit branch is `audit/measurement-revalidation-20261001`; checkpoint tag
`checkpoint/measurement-revalidation-2026-10-01`. The verified Git bundle and
selected source/binary/raw/log evidence archive live in
`../checkpoints/measurement-revalidation-2026-10-01/` relative to the repository.
The archive's `checkpoint-retention.json` verifies every selected member.
Main, staging, earlier optimization checkpoints, original ciphertext code and
historical result bytes are unchanged. Tools/cache/environment exclusions and
remaining source/runtime limits are explicit in the member ledger; this is
not a complete historical environment image.
