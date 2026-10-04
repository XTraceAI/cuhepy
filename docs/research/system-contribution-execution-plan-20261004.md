# Execution plan for an original, complete encrypted-search system

2026-10-04. Evidence baseline: `3ecef8eeb86bdc1e2c33ce568557debdea8949e9`.
This is the current execution plan. Read the
[contract-level closest comparison](closest-work-contract-matrix-20261004.md),
[Q74/Q75 return](shared-query-gates-20261004.md),
[claim cards](system-contribution-claim-cards-20261004.json), and
[progress ledger](research-contribution-progress-20261004.json).
The [planning integrity receipt](system-contribution-plan-validation-20261004.json)
preserves the reviewed planning baseline. The [Q76.1 core return](native-shared-query-core-20261004.md)
records subsequent small native correctness, and the ledger controls the next step.
The [earlier derivation and plan](research-contribution-plan-20261004.md)
remains intact as a technical reference. Registrations and negative results
are preserved; this document changes priorities and clarifies acceptance.

**Build one complete homemade BGV system to answer a specific research
question: when does jointly compiling evaluation, public admission, and
retained state improve the complete cost of exact encrypted search?**
The intended contribution is a certified compiler/runtime and a demonstrated
operating frontier, with known cryptography. No original main result has yet
been established. A compiler that merely renames known transformations, or a
fast evaluator with an expensive verifier, does not meet the paper gate.

There are **zero remaining preliminary gates in the selected Q74/Q75 plan**.
There are four system packages: Q76 implementation/control, Q77 evaluation,
Q78 deployment/security, and Q79 final originality/paper decision. Optional
ideas below are conditional branches inside these packages, not a new
unbounded experiment queue. Completing a prototype is distinct from obtaining
a publishable result.

## 1. What the evidence actually says

| Evidence | Result we can use | Consequence for the system |
| --- | --- | --- |
| Homemade BFV/BGV CPU, native, RNS, CUDA and compact IO | Working company assets, including significant arithmetic improvements. | Build on homemade BGV; retain Paillier, BFV, SEAL sanity controls and all earlier optimizations. |
| Retained 32,768 x 512 matched local panel | Median BGV 117.298 ms, BFV 892.813 ms, Paillier lookup CUDA 2,599.103 ms, lookup hybrid 1,418.960 ms; permitted retained cache 4.384 ms. | These experimental profiles exclude complete protected admission/network and retain setup-swap qualifications. They select an HE foundation, not a secure-service speedup. |
| Q74 small encrypted gate | 64 complete relations, 320 source mutations and 192 output-component mutations; full-ring, actual-limb, frame, score and coverage checks pass. | The packed-query/feature-major graph is a sound reference within the recorded small scope. Native/source-scale/controller assurance is unfinished. |
| Q74 source-profile public bounds | Owner canonical Q120 passes. Public-key-index canonical Q120 and both derived Q120 modes fail. One Q180 rescue passes its algebra screens. | Start owner canonical Q120. Do not silently substitute an input law, approve parameters from successful decryptions, or use the Q120 parser for three primes. |
| Q75 finite resource screen | 60 cards, nine exact finite frontiers, zero compiler-cap failures; known composition has identical algebra/resources. | New expansion/gadget/asymptotic claims are closed. Models are sufficient schedules, not measured time, peaks or lower bounds. |
| Q180 derived versus owner canonical Q120, one full group | Witness body 90.703125 versus 120.468750 MiB; modeled pointwise work about 2.81x, keys 2.25x, query/index about 1.5x. | Preserve the tradeoff, but select no larger-Q variant from bytes alone. Client response bodies remain 102,400 bytes/group. |
| Current Q76 work | Q76.1 passes 16 retained N16/N32 native cases, 304 source/output faults and a 58-case boundary suite on normal/UBSan builds. No fresh keys or private work. | Next Q76.2 authenticates enrollment/requests. Large native correctness, lifecycle and release remain unfinished; no timing or completed-service claim. |

The final Q74/Q75 regression invocation passed 157 cases; that is not 157
independent encrypted experiments. Neither those tests nor the large earlier
measurement panel establishes equal-security parameters. Current model cards
and the qualified raw measurements remain separate tables.

The earlier public-index BGV panel uses a different circuit with its own
recorded guard. Q74's public-index failure concerns the new shared-query
graph, whose expanded-query noise is multiplied by the index noise.

The evidence also points to a useful reversal: reducing client replies can
move the bottleneck to **server-to-verifier** traffic. In the selected full-group
model the latter is approximately 120 MiB while the client coefficient reply
is 100 KiB. They are different links and cannot be added to one ambiguous
"response reduction" number.

## 2. Exact contract and the claim worth pursuing

One honest owner controls the plaintext binary index, encoding, HE keys and
queries. The owner is allowed to retain any plaintext. The untrusted server
may alter computation, reorder or omit records, substitute inputs, replay old
responses, and observe public admission outcomes. It may deny service.

The primary result is every exact Hamming distance, with complete ordered
record IDs and stable local top-k. Approximate retrieval, encrypted top-k-only
selection, content fetching and multi-owner/private-server-data protocols are
different contracts. Their implementations are preserved but are not quietly
substituted into this comparison.

The protected verifier has public ciphertext inputs and authentication keys;
it has **no HE decryption secret**. Owner origin and public bounds are necessary
assumptions. An owner signature binds bytes; it does not prove valid binary
encoding, sampler support or an RLWE parameter estimate. The trusted owner
encoder supplies those origin facts in the first implementation. A malicious
owner or arbitrary third-party encrypted index requires a separate validity
protocol.

The primary claim to attempt is:

> A compiler for exact encrypted search can select and certify a complete
> evaluation/admission plan, including representation boundaries and state
> lifetimes, that gives a useful paid resource advantage over the best
> compatible fixed-policy protected execution.

This is a **systems hypothesis**, not a new gadget, DP algorithm, TEE primitive
or asymptotic source-count result. Its distinctive artifact would include:

1. A small, independently checkable certificate connecting original owner
   inputs, common-Q integers, both actual prime limbs, all output coordinates,
   noise/terminal conditions and the authorized response frame.
2. An executable choice among full replay, complete public relation checking,
   and protected-prefix/product/suffix placement, with the same compatible
   optimizations and charged conversions for every choice.
3. A real operating-region result: latency, trusted state or update/acquisition
   cost improves under explicitly fixed budgets, and the failure/tie regions
   are explained and reproduced.

Ablating to an evaluator-only cost objective must change a choice and harm the
complete cost on held-out instances. This alone does not establish priority:
if the strongest applicable prior compiler reproduces the same design result,
the algorithmic claim is contained. A systems contribution then needs an
independently defensible artifact, finding and closest-system distinction.

## 3. Architecture and certificate

```mermaid
flowchart LR
    O[Owner encoder, keys, IDs and signed snapshot] --> E[Enrollment and independent plan-certificate check]
    Q[Signed original query, snapshot and fresh request ID] --> R[Bound request]
    E --> R
    R --> U[Untrusted homemade CPU or CUDA evaluator]
    R --> V[Protected admission or matched replay]
    U --> V
    V --> A[Authorization of the complete bound frame]
    A --> C[Client checks context before private decode and local top-k]
```

The first selected graph expands one pre-normalized signed query once,
contracts it with the owner's encrypted feature-major index, and accumulates
three tensor components before one relinearization per record group. It uses
ordinary negacyclic products; no full scalar-SIMD batching premise is assumed.

The source profile remains N=16,384, d=D=512, t=1031, eta=21, actual ordered
primes `1152921504606748673,1152921504606683137`, Q their product, P=33,548,413,
canonical radix30 and owner-origin index. These are experimental, unapproved
cryptographic parameters. Change them only through an explicit paid profile
revision and security review.

Each certificate must include these independently checked obligations:

| Obligation | Implementation rule | Failure that must be rejected |
| --- | --- | --- |
| Input and plan authority | Copy/authenticate profile, actual primes, index/key schedule, IDs, count, epoch and code/plan digest; compile the graph internally. | Correct digest accompanying a weakened peer-supplied graph; foreign key/index; changed source ordering. |
| Common integer | Parse canonical whole-Q coefficients before any transform; derive the same radix digits for both actual limbs. | Independent per-prime digit membership or a noncanonical late coefficient. |
| Complete arithmetic | Check every source recomposition and both tensor cross terms, using every physical coordinate in both prime NTTs. | A scalar evaluation, sampled coefficient, unconstrained expanded query or unchecked branch. |
| Correct plaintext semantics | Prove signed feature/query encoding, zero padding, coefficient coverage and the public phase induction for every admitted source. | Honest-run noise samples being used to accept arbitrary witnesses. |
| Terminal and response | Bind both full terminal-Q components and independently reconstruct all rounded P coefficients and headers. | A correct prefix/top-three answer with a changed unused tail, wrong IDs/count or different compact frame. |
| Release and lifetime | Bind original query, fresh request identity, snapshot and complete frame; authorize before private work. | Stale snapshot, cross-request frame, replay, duplicate callback or hidden retry after a failure. |

The certificate is compilation evidence, not a succinct proof sent to the
client and not hardware attestation. Its checker must be separate from the
optimizer and producer. A native implementation is not correct merely because
two code paths share the same bug.

Current owner-seeded query/index wire formats should be retained. The native
draft consumes expanded two-component buffers: preparing those buffers is a
paid step, not a reason to double query uploads or label expanded resident
state as the compact wire size. Every byte category is measured at its actual
interface.

## 4. Q76: finish one authoritative native prototype

The existing [registration](native-shared-query-registration-20261004.json)
caps source-scale correctness at one fresh key context and six searches.
No timing panel or CUDA port precedes this gate.

| Milestone | Concrete next work | Completion evidence |
| --- | --- | --- |
| Q76.1: public native core — complete bounded gate | Reviewed C++ core, bounded ctypes adapter and frozen isolated build/source/dependencies. Reused the 16 retained owner-canonical N16/N32 cases. | Exact GMP tapes/frames, both whole-limb schoolbook vectors, 208 source/96 output faults and 58 boundary cases on normal/UBSan builds. No source-scale or service approval. |
| Q76.2: enrollment/request authority | Add an owner-authenticated immutable factory, seed-to-common-Q preparation, signed original request and strict complete packet grammar. Never admit arbitrary graphs or peer-provided bounds. | Signature/context/coverage/ID/key/nonce faults; producer/private-decode hooks cannot approve a packet; native handles have explicit ownership and bounds. |
| Q76.3: lifecycle and source scale | Add the fail-closed local journal; test concurrency, process/fork/restart, epoch changes, races and failed callbacks. Then run the registered N16k d512 counts 8,224/16,384/32,768 with two queries. | At most six large searches, exact independent GMP source/output/frame equality, every distance/tail/stable tie checked privately only after public acceptance. No secret key serialized. |
| Q76.4: matched controls | Build prepared replay and checked-product/trusted-prefix/suffix in the same native backend, plus the permitted authenticated cache. Grant layout, expansion, lazy relinearization, Karatsuba, fusion, preparation and streaming equally. | Same source/terminal/snapshot contract and full correctness gates. Count protected work, duplicate work and transfers in both directions, not just the control's return packet. |
| Q76.5: certificate and handoff | Validate the high-level certificate independently, publish owned/resident/scratch accounting and source/codec commands, and audit the boundary. | No free input or approval-by-oracle path; full test/mutation/lifecycle report, honest limitations, ledger return selecting or stopping Q77. |

**Next executable task is Q76.2.** Source belongs in
`experiments/bfv_search_lab/_shared_query/`; Python adapter/tests beside the
other research implementations; reproducible runners in `benchmarks/`.
Keep isolated libraries and outer evidence. Migrate a reviewed selected
interface into `src/cuhepy/` only later. Main/staging and delivered libraries
remain preservation baselines.

Local lifecycle semantics are **at-most-once authorization/callback**, with
possible lost delivery after a crash. A failed attempt consumes its request
identity before admission. This is not an exactly-once delivery claim.
SQLite durability is a prototype control under trusted non-rollback storage;
it does not resist an adversarial host restoring a snapshot. Q78 must supply
real freshness/revocation and protected-release assumptions, including
owner-side request/snapshot binding. Actual attestation remains unimplemented
for this selected service.

## 5. Q77: decisive complete-cost evaluation

Freeze methods, actual deployment budgets and the primary success metric
before measurement. Use the existing three sizes and one selected profile,
two independent key contexts, and three fresh process blocks **per key and
size**. Each block has one excluded warmup, eight measured queries and one
separate post-32-row-update correctness check per distinct implementation.
Thus there are 18 matched blocks and 144 measured queries per implementation;
these are dependent within a key/corpus and are not 144 independent setups.
Identical candidate/known-composition code is an alias, not another experiment.

Primary protected-contract controls are complete deterministic admission,
equally prepared replay and checked-product/trusted-suffix. Also report the
allowed retained and newly acquired cache. A protected plaintext-search
control is relevant when the owner accepts secret/plaintext custody inside
the TEE; label that extra trust separately. Paillier/BFV and bare BGV CUDA
remain engineering context, with their actual profiles and assurance scope.

Q77 initially measures native prototype roles under the declared local
storage/authority assumptions. It must label that placement as a prototype,
not measured enclave or secure remote-service latency. Q78's real protected
deployment must rerun the relevant frozen comparison before a deployed
performance claim. Attestation and transport overhead cannot be inferred from
an ordinary-process microbenchmark.

For each method measure the full elapsed path and its dependency graph:
owner preparation, encryption, expansion, evaluation, source extraction,
serialization, transport, parsing, checking/replay, terminal, authorization,
client checks/decode/selection. Do not sum medians of overlapped stages.
Separate startup/setup, tenant reuse, per-device acquisition, all network
links, peak CPU/GPU/trusted memory, retained state, 32-row updates and actual
invalidation. Distinguish structural word/transform counts from latency.

Use a declared idle window, paired/alternating order and recorded activity,
clocks, thermal state, swap and synchronization. Preserve slow/contaminated
runs with their preregistered qualification. Never delete observations to
improve a ratio. The old swap-qualified panel is retained, not promoted to a
clean secure-service baseline by this review.

Separate lifetimes explicitly:

```text
amortized cost = tenant setup / tenant queries
              + device acquisition / device queries
              + update frequency * paid update
              + complete query critical-path cost
```

For actual overlap, use the measured scheduling DAG rather than this
sequential illustration. Derive device lifetimes 1/8/128 from the same paid
stages. A returning device's allowed plaintext cache pays no invented download.
A new device may acquire an owner-authenticated compact encrypted vector
backup; it must not be forced to download the HE index.

Transfer-only accounting on the **old** 32k public-index measurements puts one
2,359,388-byte cache acquisition at about 5.23 exchanges of 450,761 bytes.
That is an illustration, not a new selected-profile break-even result: it
excludes setup, private-key delivery, checking, CPU work and actual transport.
It motivates measuring cold-device and returning-device regimes fairly.

Before the main cohort, freeze actual prototype memory/link/update budgets and
the project's 20% amortized complete-cost improvement threshold against the
best compatible remote control. Report cache wins, reversals and ties. The
threshold is a project decision, not a conference acceptance criterion.

Required ablations isolate evaluator-only selection, verified-cost selection,
the known combined versus old layout, canonical admission versus replay,
compatible fusion/streaming, and each expensive representation boundary.
Held-out queries and fresh process blocks must reproduce the selected rule.
An unknown prior artifact cost is not a defeated competitor. Public-proof
systems with different trust/leakage contracts belong in separate comparable
scope rows, not misleading cross-paper speed ratios.

## 6. Creative extensions, with finite triggers

| Direction | What would make it interesting | Trigger and bounded first action | Stop rule |
| --- | --- | --- | --- |
| Mixed verification placement | A certified split avoids more trusted canonicalization than it adds in witness/transfer/state costs; the optimizer-only and complete-cost choices differ. | Q77 identifies normalization or the witness link as decisive. Add at most one mixed prefix/suffix placement to the same backend and grammar, using existing keys/fixtures. | Generic specialized replay/checking gets the identical paid frontier, or no useful operating region survives. This is not a new min-cut/DP claim. |
| Noise/state/communication selection | An all-witness-safe representation is selected for a genuine link/memory constraint rather than its small tape alone. | Only a measured source-witness bottleneck justifies reopening retained Q180 derived, with its larger keys/moduli/state and separate assurance charged. | Added producer/verification/setup costs remove the advantage. No new radix or ring-size grid. |
| GPU execution of the complete public relation | Offloading the actual admission bottleneck may make the protected path competitive while keeping complete common-integer and terminal checks. | CPU-native gate passes and Q77 identifies a substantial parallel public-check bottleneck. Port that bounded kernel; charge both transfer directions and the protected checker. | A fast GPU checker is accepted as its own untrusted evidence, or complete cost fails to improve. GPU attestation is a separately implemented/reviewed path. |
| Smaller trusted state through streaming | A compilation certificate remains valid with less trusted memory at an acceptable complete cost. | Native measured state exceeds a declared budget. Compare one existing cached and one streamed schedule with the same replay choices. | Saving modeled arrays only hides preparation, wire buffers or scratch, or controls obtain the same advantage with no distinct system result. |
| Proof backend for the same public relation | Removing a trusted verifier without losing source/common-Q/noise/frame binding would be a meaningful later system extension. | Main native contract stabilizes; an actual ring-proof adapter or corrected blind-proof contract passes the comparison gate. Start with one small complete relation, not a free microbenchmark. | Missing range/oracle commitment/input/release binding, unmatched feedback assumptions, or no paid advantage. Do not call the TEE tape a cryptographic proof. |

Ordinary private randomized adjoints/Freivalds/Slalom are controls, not a new
contribution. A randomized implementation remains conditional on a proved
adaptive soundness/challenge-lifetime budget and charged preprocessing; it
does not enter Q76 by default. Earlier E101/E110/Q57/H1/Q59/H2 containment,
failed mask/reuse laws and Fourier/root/selection screens remain closed unless
a precise changed premise supplies a new bounded question.

## 7. Q78: proof and actual security closure

Start the semantic/certificate and public-bound proofs during Q76. Develop
the threat/state model alongside Q77, then close the argument for the actual
selected deployment in Q78. Do not wait for a promising timing result to
check whether the design's assumptions are valid.

Prove in layers, keeping assumptions separate from tests:

| Proof obligation | Planned argument | What cannot stand in for it |
| --- | --- | --- |
| Graph semantics | Induct through signed query expansion, feature contraction and delayed relinearization; prove all coefficients, padding, IDs and stable score decoding. | Top-three agreement alone. |
| Compiler/admission correctness | Exact common-Q recomposition and actual-prime NTT invertibility imply the intended full-ring relations. Canonical sources determine the canonical graph; relaxed variants require their own every-witness bounds. | Sampled/scalar residuals or a supplied graph with the correct hash. |
| No-wrap and terminal correctness | Derive phases from actual origin/sampler supports, then prove Q and Q-to-P conditions for every accepted input/witness, including all unused coordinates. | Empirical noise, ideal independent errors, or syntax equality without a noise proof. |
| Stateful authorization | Model signed original request, snapshot, epoch, response hash, client acceptance, crash/race/replay and the actual freshness authority. | A PID check, mutex or rollbackable local journal. |
| Confidentiality composition | Couple authorized private outputs to ideal exact search; simulate public admission from public ciphertext data. Then reduce to the correctly stated augmented-HE/key, authentication and protected-execution assumptions. | Claiming plain IND-CPA implies raw BGV CCA security. |
| Implementation/deployment | Review actual samplers/seed expansion, concrete parameters, constant-time private operations, attestation/channel policy, private error feedback and measured release code. | Successful decryptions, code hashes, fake attestations or tests alone. |

A prospective game-hopping bound separates augmented-HE advantage,
signature/hash failure, origin failure, admission soundness, correctness
failure, freshness failure, TEE failure and permitted/private leakage.
It is an **unproved agenda**, not a finished reduction with numerical security.
For the exact deterministic relation, modeled algebraic checking has no
statistical equality error; implementation bugs and the other assumptions
do not disappear. Related-secret evaluation keys require the appropriate
explicit HE/KDM/circular assumptions or a reviewed alternative construction.

The allowed leakage must list dimensions/counts, lengths, request/update
timing and public admission outcomes. Private decode errors or result-dependent
client behavior must not become an unmodeled server oracle. Keeping the HE
secret out of the TEE reduces secret custody; it does not prove confidentiality
against a compromised verifier that authorizes malicious ciphertexts.

For the first 32-row update, re-encrypt affected owner feature groups and
re-certify the new snapshot under the original fresh-origin law. Charge the
refresh and invalidated preparation. An encrypted delta changes phase/noise
supports after repeated updates; use it only with a revised certificate and
explicit lifetime/refresh bound. A faster affine update alone does not reopen
the earlier contained update claim.

Mechanize the certificate/semantic and state-machine core if tractable; use
existing formal-methods ideas and do not claim the first verified HE compiler
or accelerator. Native NTT/CRT/packing code needs a clearly stated assurance
boundary. An AWS/NVIDIA deployment is a separate tested artifact, with real
attestation/freshness and the same complete cost measurements.

## 8. Q79: paper selection, not an automatic publication promise

A main system paper needs all of the following:

1. A precise result left after the strongest compatible known constructions
   and compiler controls are specialized, with prior-separated claim cards.
2. A complete artifact and independently checked invariant from owner inputs
   to authorized private output, including updates and stated trust/leakage.
3. A useful complete-cost region and held-out ablations explaining why it
   exists, alongside cache/control wins and limits.
4. Correct profile/security scope, reproducible source/build/data receipts
   and external cryptographic/systems review.

If only a faster implementation of known methods remains, keep it for the
company and present it honestly as engineering/supporting evidence. If a
rigorous negative finding survives, consider a scoped measurement/security
paper with its own originality review. Do not disguise either as a new
cryptographic primitive or keep expanding experiments to avoid a decision.

The paper outline follows the result: exact contract and motivation; closest
systems and threat models; compilation/certificate and design rule; native/CUDA
runtime; conditional proofs; paid evaluation/ablations; limits and artifact.
CSF/FHE.org or another venue is chosen after this evidence, not used to invent
a claim or promise acceptance.

## 9. Execution discipline and handoff

Complete or stop one milestone, record exact units/source/build/registration,
write limitations and return to the ledger. Preserve failed attempts, negative
controls and changed registrations. Do not add overlapping test counts or
silently relabel models as measurements. Freeze a revised registration before
new keys, timing cohorts or protocol changes.

For Q76.1, inspect the isolated draft and registration; build only its isolated
library; add the public adapter and retained-fixture gate; run via
`.venv/bin/python -m pytest`; lint new experimental files with
`ruff --no-force-exclude`. The public-native gate precedes new large keys.
The registry retains primary PDFs/text/version/hash/scope outside Git; no
author artifact is executed merely to download or review it.

Checkpoint this plan and unvalidated draft separately from successful evidence.
Preserve the 54 production source files, 12 delivered libraries, main/staging
refs and earlier evidence archives. Approval of an original main, secure
parameters or production deployment is never inferred from a checkpoint.
