# SB01: one matched larger-workload arithmetic and acquisition cohort

Status: proposed bounded measurement, not activated. This contract closes the
BGV/BFV/Paillier-hybrid/cache pairing gap. It does not activate Q30's full
verified-service evaluation or approve parameters, a paper claim, or GPU release.
The baseline is commit `11e1690d4c4a90a718e5f2b8a98e79b4757a59bd`.

## Question and fixed scope

On one identical 32,768-vector, 512-bit owner-authorized corpus, how do current
ordinary BGV CUDA, prepared BFV CUDA, Paillier-Lookup CUDA, the stronger
GPU-client/CPU-server Lookup hybrid, and an authenticated full plaintext cache
compare when setup, recurring local phases, actual packets and one small
snapshot replacement are accounted for separately?

The user permits the client to retain its full plaintext index. Cache is a
required control. Existing 8k BGV/BFV and BFV/hybrid measurements came from
different panels; their latency numbers must not be divided to produce a paired
BGV/hybrid speedup. This cohort measures the missing pairing at the already
supported larger size; it is not another ring/count/layout grid.

| Variant | Fixed implementation/parameters | Client / server |
|---|---|---|
| `bgv-public-index-cuda-workspace` | Homemade shallow BGV; N=16,384, t=1,031, Q120 two-prime RNS, eta=21, gadget30, terminal25; public-key-encrypted index; owner-seeded queries; CUDA level4, baseline NTT, persistent workspace | CPU RNS owner / GPU |
| `bfv-cuda-prepared` | Homemade BFV; N=16,384, t=65,537, Q180 three-prime RNS, gadget30, terminal50; current default fused CUDA server and batch32; native private decoder | CPU / GPU |
| `paillier-lookup-cuda` | Existing Lookup, key_len1,024 (prime size), alpha_len280; actual modulus/exponent lengths recorded; requested GPU must load | GPU / GPU |
| `paillier-lookup-hybrid` | Same API/profile as Lookup CUDA; independently generated keys; batched client CUDA, GMP public multiplication | GPU / CPU |
| `authenticated-raw-cache` | Existing AES-256-GCM raw snapshot, pinned owner manifest/epoch, authorized full retention, CPU XOR/popcount and heap top3 | CPU / storage only |

Ordinary BGV is explicitly a **public-index reference**, not the best of every
BGV experiment. [E16's owner-index/radix/precision controls](bgv-layout-planning.md)
remain mandatory before claiming a best HE system: they change index law,
plaintext modulus, rounding or assurance premises. SB01 does not silently
activate those profiles or bypass guards. CPU-only Paillier, BFV CPU and
standard CUDA Paillier remain separately revalidated implementation baselines;
their expensive repeated calls would add little to this selection question.

## Corpus, query and update declaration

Use the unchanged `bfv_client_matrix.make_data(32768,512,1701)` corpus and its
known equal/complement/equal rows. IDs are zero-based positions. Record a
canonical packed corpus digest, not the vectors. One excluded warmup uses the
returned query, so zero/max distances and stable ties are exercised.

The five measured plaintext queries, in order, are all-zero, all-one,
alternating `j % 2`, then two binary words from `random.Random(20261003)`.
All variants receive each identical query; every encryption uses fresh OS
randomness. Variant ordering uses a separate `random.Random(2026100301)` and
is shuffled before each round. There is one process/key/index block, not five
independent setups or five independent datasets.

After the five warm measurements, replace rows0..31 with their complements,
keeping IDs, keys, count and dimension. This aligns to one 32-row packed tile
in both HE layouts. Use public client encryption and public immutable-index
preparation APIs; do not create an in-place native mutation API. A single
fresh post-update query uses the warmup plaintext. Check every score/top3
against the updated corpus outside measured phases. This is one observed
snapshot transition, not an update-rate/lifetime sweep.

The update panel separately reports owner encoding/encryption of replacement
rows, actual serialized delta bytes with positions and explicit snapshot
metadata, server delta parsing/host replacement, and full resident-snapshot
re-preparation required by the present APIs. Cache pays complete resealing and
acquisition with fresh nonce/manifest under its retained key. Old resident
handles are released before allocating new ones; timing includes required
release/repair. Logical snapshot metadata is synthetic trusted harness data,
not a deployed freshness protocol. If the implementation review cannot close
these public-API handles, freeze a no-update revision **before** any main and
retain the update gap; do not silently drop a failed update after timings.

## Timing and byte boundaries

Report these units separately, with each original sample retained:

* Common input acquisition: corpus/query creation, encoding into local packed
  integers, expected scores and correctness work, outside crypto timings.
* Initial owner preparation: key generation, evaluation-key generation,
  private context/terminal cache, index encoding/encryption and serialization.
* Initial server preparation: public import, index parsing, public plan,
  immutable resident-index preparation and BGV workspace preparation.
* Recurring client preparation: input encoding, fresh query encryption and
  request framing; BGV's seeded owner API includes its internal framing.
* Recurring server: query parsing/seed expansion, actual public evaluation,
  compaction and response framing; native API conversion costs remain included.
* Recurring client finish: response parsing, native decryption/decoding and
  stable top3. BGV native finishing includes selection; no fictitious extra
  top3 timing is added. Cache has local query only and no per-query transfer.
* Complete local elapsed: one sequential locally simulated request; independently
  measured stage medians are not summed to replace the elapsed median.
* Actual setup, query, response and update packets: materialize canonical
  serializers and record `len(packet)`. BGV index framing reuses `Case.pack`
  and its fixture decoder; BGV public/evaluation-key bytes use a newly declared
  local canonical fixed-width coefficient frame, labeled benchmark framing.
  Existing BFV and Paillier setup exports remain their normal formats. Keys
  and snapshots are never written into result files. Logical candidate order
  is implicit for HE; cache carries explicit IDs and pays them.
* Retained resources: declared native index/workspace byte counts where APIs
  expose them, canonical client cache-body bytes and actual worker RSS/GPU
  telemetry. Body counts are not complete Python RSS estimates.

No actual network, WAN, TLS, attestation, proof, authorized content fetch or
EC2 is measured. Any transfer-time model is explicitly a post-run model with
separate directional link assumptions, not included in local medians. A cold
session model may combine each variant's own paid setup and its observed
queries; do not omit setup for HE while charging it to cache. Do not extrapolate
observed session length into an unbounded epoch or certify a lifetime budget.

## Controller proposal and bounded activation

Implement one NEW runner `benchmarks/system_selection_measurement.py`; do not
edit old runners or library/native arithmetic. Its named states are created,
setup, warmup, measured, update, complete or failed. It writes a new progress
JSON after each setup/round/state and append-only phase events with monotonic
start/end boundaries, preserving partial cohorts. New pure-controller tests
cover plan validation, ordering, setup separation and summaries without HE,
GPU or full-size data. Separately declared intrinsic compatibility work uses
one16-row fixture in all five variants and a16-row replacement, outside timing
claims; it is not a selectable pilot and must be reviewed before main.

Activation requires root's explicit GO after contract, source/binary/argv
freeze, independent review and intrinsic correctness. No main, HE/keygen,
timing, profiler, build or test is authorized by this document alone. Runtime
dependency availability is inspected without importing CUDA/creating contexts;
existing local extensions are present. No rebuild or CPU fallback is planned.

The main performs one30-second idle preflight, then exactly one cohort. The
worker wall cap is1,200 seconds, aggregate CPU cap3,600 seconds and telemetry
terminates only the owned worker on observed RSS above16GiB or per-process GPU
usage above8GiB. CUDA virtual reservations make RLIMIT_AS inappropriate; RSS
and GPU caps are sampled limits, not instantaneous allocation guarantees.
Host includes a shared RTX3080/10GiB and Ryzen5800X; worker uses
`OMP_NUM_THREADS=8`, `OPENBLAS_NUM_THREADS=1`, `OMP_WAIT_POLICY=PASSIVE`,
`PYTHONOPTIMIZE=0`, `PYTHONNOUSERSITE=1`, `PYTHONHASHSEED=0`, explicit interpreter,
and explicit repo/src PYTHONPATH. No user process, GPU clock or power setting is
changed. The supervisor owns its fresh process group and retains cleanup logs.

No heavy test, build, proof, symbolic scan or other benchmark runs concurrently.
Use the existing serial research lock. Every two seconds record CPU process
activity, foreign compute PIDs, swap, pressure, RAM, GPU memory, clocks,
temperature and power; correlate with phase/sample boundaries. Missing GPU
telemetry, new swap, foreign GPU compute or at least three foreign-CPU samples
above0.75 cores qualify the cohort. Preserve qualified/failed samples rather
than cherry-picking them. No retry or alternate profile is automatic: return
to the research plan with the retained evidence. Sampling and a quiet window
do not prove machine exclusivity.

## Interpretation and next decision

Check every distance and the stable top3 for every warmup, measured query and
update-validation request. Record medians, full ranges and paired per-query
ratios for the five common query rounds. Five trials in one process support a
bounded implementation comparison, not a population confidence interval.
Correctness/resource failure stops interpretation; no partial subset is called
a complete matched cohort.

SB01 may choose an implementation reference for the next verifier prototype.
It cannot select a production scheme or establish original cryptography.
All local HE replies are generated by trusted harness code; untrusted GPU
responses may not reach private decryption under this diagnostic contract.
The paired verifier package must price safe release, and prior-work comparison
must distinguish a surviving complete construction. Cache uses standard AEAD,
with key/current-manifest delivery trusted and freshness persistence unbuilt.
HE profiles have unequal, unapproved security and private-side-channel scope;
client hardware also differs. Preserve these assumptions even if BGV is much
faster or cache dominates this corpus.

Return to the three-package system selection after completion: use SB01's
matched arithmetic/acquisition result with the complete GPU-verifier screen
and bounded Fourier certificate attempt. Successful timing is not a reason to
resume the retired experiment grid.

## Pre-execution clarifications

The first frozen contract and unexecuted source drafts are retained in the new
measurement-design evidence directory. Before any intrinsic or main activation:

* Separately record common dependency-import/startup time; setup timings alone
  are not a whole cold-process cost.
* All measured top3 paths use heap selection or existing native heap selection;
  the independent correctness oracle keeps stable full sorting. The result
  contract remains `(distance, ID)` and exports every score for validation.
* Phase-event dictionaries are buffered during requests and flushed between
  samples. Complete local elapsed includes small scheduler bookkeeping, with no
  JSON writing/fsync in the request. Progress JSON uses atomic replacement.
* The intrinsic includes a cheap largest-group public-metadata admission guard,
  not512 zero ciphertext tiles: for the exact frozen Q120 profile, apply the
  unchanged full512-input butterfly recurrence and unchanged P25 reduction.
  Require terminal bound8,446,469, matching the retained revalidation32k owner
  pipeline artifact. This covers the largest conservative bound absent from
  the16-row arithmetic fixture. No secret/noise sample or larger trial is added.
* Pure-controller scope is19 unique cases, separately registered before the
  first test invocation. The intrinsic is a distinct correctness-only component.

The new external supervisor uses the existing revalidation `runs/serial.lock`
inode read-only, one30-second preflight, a60-second lock-acquisition cap, the
declared main limits, an absolute wall alarm and owned-group cleanup. It imports
the existing resource monitor and adds sampled descendant RSS/compute-memory
caps. The intrinsic has a separately frozen wall/CPU cap within the main maxima.
No main activation or automatic retry follows from these clarifications.

The final execution environment is a complete minimal map: the registered
Python/thread flags plus `PATH=/usr/bin:/bin`, `LANG=C.UTF-8`, `LC_ALL=C.UTF-8`
and `TZ=UTC`. No inherited Git, preload, CUDA/Python tuning or credential
variables enter the owned launcher/worker or resource monitor. Read-only ELF
inspection found only standard GMP/C++/libc dynamic dependencies in the three
delivered CUDA extensions; intrinsic compatibility still must confirm loading
under this explicit map. The resource receipt qualifies fewer than three
worker telemetry observations as insufficient timing assurance even when the
preflight itself was quiet. Setup begin/end events flush outside the measured
setup function so a hard stop retains the last entered stage.
