# Research roadmap after E99: complete verification and sound reuse

Planning revision, 2026-10-02. Evidence base: `8e7cd6b` / checkpoint
`gadget-dependency-controls-2026-10-02`. Read the
[closest-work audit](closest-work-roadmap-refresh-20261002.md) first, then use
the [machine-readable handoff](contribution-roadmap-refresh-20261002.json),
[canonical queue](publication-work-packages.json), and
[progress log](publication-progress.md).
The original planning checkpoint `07ef3f7` ran no experiment. Earlier
[E101–E103/E105 return](boundary-reuse-selection-20261003.md) and113-test scope
remain historical. The [current E108 return](native-proof-interface-selection-20261003.md) completes
one scalar interface and three transparent native toy relations,103 final tests
and a29,247-constraint strongest generic control. The earlier
[E106/E107 return](native-opening-selection-20261003.md) and227-test separate-run
inventory remain unchanged. No cryptographic backend, original main, timing,
parameter or broad gate passes. **Next Q35/E109** is the proposed
[bounded backend/control pilot](native-proof-backend-plan-20261003.md), with
three precise creative leads retained rather than promoted without a protocol.
E100/E104 remain unimplemented and conditional.

## 1. Recommendation and intended paper

Aim for **compact, correctly verified encrypted search on an untrusted
accelerator, with explicit guarantees across repeated queries**. The central
question is whether we can protect the fast homemade evaluator without a
trusted party repeating its full computation, while retaining its small
client response and accounting for all setup and private state.

Start with a short full-trace verification discriminator. Develop a restricted
finite-lifetime correctness analysis as a second route and a possible
supporting theorem. Test owner-summary-assisted exact retrieval separately
only after its privacy and coverage contract is explicit. These are research
hypotheses; the available evidence does not justify calling any one original.

The eventual contribution must be one of the following, with a precise scope:

| Candidate claim | New result that would be required | Result that would **not** establish it |
| --- | --- | --- |
| **A: a cheaper complete authenticated HE boundary** | A specific witness/check representation or restricted algorithm that beats the strongest fused complete verifier, with full-error sensitivity and original-query binding | Freivalds, a quotient identity, generic circuit fusion, a TEE signer, or a faster unchecked GPU kernel |
| **B: a useful finite bound for adaptive reused-key search** | A nonheuristic bound for a specified real reuse/decomposition graph, closing a distribution or lifecycle case absent from the closest controls and changing a useful resource choice | A covariance table, a fitted Gaussian, a standard conditional union bound, or another version of E94/E97/E99 |
| **C: exact retrieval using small owner state** | A distinct summary/retrieval/certification mechanism with a measured useful frontier, all omitted rows covered, and the declared traffic privacy | Ordinary clustering plus PIR, a triangle lower bound, authenticating fetched rows alone, or forbidding the owner to cache data |

A and B may become one coherent paper if the new boundary permits the new
finite bound and that combination gives a complete effect. They may also
separate into different papers. Do not bundle unrelated optimizations into a
novelty claim. If all routes fail their mechanism gates, retain the engineering
artifact and negatives, then make a fresh research decision rather than
promising a conference paper.

## 2. What the existing evidence changes

1. **Keep the fast homemade server.** Strong native/CPU/CUDA improvements are
   real engineering assets. Communication gains do not imply lower total
   elapsed: matched BFV CUDA is slower locally than the Paillier lookup hybrid.
   A matched BGV/hybrid service comparison is still missing.
2. **Stop treating tiny GPU ratios as findings.** E27 intervals include a tie.
   New GPU work should follow a surviving complete protocol and its profile.
3. **Do not restart defeated preparation recipes.** Vectorized owner work and
   permitted caches beat several proposals; E77's factoring retains factory
   work. E83's literal coded-row fetch is very expensive. All are controls.
4. **Stop extending generic terminal-conversion sketches as the main claim.**
   E85–E99 provide valuable exact interfaces, but standard switching, rounding,
   basis, and compiler controls contain the generic mechanisms. Target
   precision stays unchanged in E99's 720 cards.
5. **Treat parameter changes as new cryptographic transcripts.** Known-prefix
   failures and sample-budget corrections remain. Hidden sparse support is
   full-N security, and its assurance is open. No numerical correctness
   improvement licenses a smaller-Q or sparse-key production setting.
6. **Measure why outsourcing helps.** The owner may keep everything. Small
   measured acquisitions favor caches. Larger data, updates, multiple devices,
   concurrency, or client resource differences are hypotheses to measure,
   not new restrictions on the client.

The [comparison's evidence table](closest-work-roadmap-refresh-20261002.md#8-what-the-accumulated-results-actually-justify)
preserves numbers and their boundaries. Frozen raw observations and all prior
negative decisions remain unchanged.

## 3. Contract, implementation, and assurance boundaries

Use [exact-search-contract.md](exact-search-contract.md). Primary mode:
owner-private registered index, adaptive private binary queries, one malicious
compute server, all exact scores and stable IDs, observable accept/abort.
The owner is trusted to generate the first authenticated epoch; outsourced
malicious enrollment is an additional protocol. The owner/client can retain
any plaintext. Availability is not promised against a malicious server.

In A's first deployment mode, a protected owner-approved checker can hold
verification secrets, index/key commitments and public encrypted material,
but **no HE secret key, plaintext index, or decrypted score witness**. The
untrusted GPU does the expensive HE work. The client verifies the complete
receipt before HE secret use. A fully attested accelerator running the full
evaluator and the existing full trusted recomputation are mandatory known
controls. A no-key checker avoids provisioning the HE secret; its compromise
can nevertheless permit forged receipts and recreate a decryption-feedback
oracle. Do not claim HE privacy remains intact against that compromise.

Public proof mode, a plaintext-owning TEE mode, two noncolluding servers,
approximate results, and exact-top-three-only mode are separately named
contracts. Extra trust or leakage cannot silently improve the primary curve.
Plaintext-owning TEE search is a particularly strong comparison if a proposed
helper gains access to owner plaintext or HE key information.

Keep deliverable arithmetic/protocol code homemade. SEAL and author libraries
remain pinned controls. New reference code belongs in
`experiments/bfv_search_lab/`, runners in `benchmarks/`, reports here.
Native/CUDA follows surviving reference relations; `src/cuhepy/` promotion and
production readiness are separate work. Preserve production/main/staging,
historical sources, raws, checkpoints, and earlier test scopes.

## 4. Route A: choose the verified boundary jointly with the native trace

### A.1 Concrete question

Can a restricted search trace share **canonical nonlinear witnesses** across
packing, expansion, multiplication, key maintenance, reduction, and terminal
conversion, so that a whole-query check avoids repeated index work or dense
provisioning without paying more proof traffic or client work?

The new step, if one exists, must be in that shared representation and its
sound construction. Basic linear aggregation is the strongest known control.
The [closest audit](closest-work-roadmap-refresh-20261002.md#3-closest-complete-mechanisms-for-verification)
includes Slalom, specialized vFHE, modern small-field proofs, and our E13/E72.

### A.2 Start from the actual graph

Record each node's **real** input/output grammar, ring, RNS limbs, coefficient
or NTT domain, layout, canonical interval, key/epoch/row-ID binding, and honest
phase bound. Identify what the chosen backend actually executes: a depth-one
three-component path, or a maintenance/rotation path. Do not attach a proof
to an imaginary linear evaluator.

For fixed index tile `A=(a0,a1)` and original encrypted query `u=(u0,u1)`, the
pre-switch relation is known:

```
v0 = a0*u0
v1 = a0*u1 + a1*u0
v2 = a1*u1                       in R_Q.
```

A fused complete control uses `v2` (or its trusted recomputation), its unique
canonical digits, and the two final components. E13 already removes v0/v1
intermediate witnesses. E72 already applies the operator transpose once at
registration. These must not be recreated as new results.

For a **specified prime limb**, write the full affine constraints between
nonlinear cuts as

```
e = L_y*y + L_w*w + L_u*u + c.
```

Here `w` contains all paid nonlinear/cross-domain witnesses. Canonical digit,
range, carry, quotient, coin, and rounding constraints accompany this relation.
Checking `e=0` does not enforce those constraints by itself. For a hidden
uniform row r, compiling `r*L_u` and `r*L_w` is a known adjoint control; compare
the full size and construction cost of these hints.

### A.3 Three bounded alternatives to discriminate

| Alternative | Proposed experiment | Strong control / early stop |
| --- | --- | --- |
| **Canonical cut elimination** | Independently expand the whole graph, then eliminate intermediate affine nodes while keeping each canonical digit/remainder witness only once. Search for a shared representation across signed views and mixed layouts. | Give a generic compiler the identical elimination, common-subexpression reuse, and E100 remainder rewrite. Stop the originality claim if it produces the same relation/cost. |
| **Factored protected checks** | Test whether repeated public switching-key/operator structure lets the complete check use fewer independent stored adjoint vectors, with a proved all-error bound. Price private seeds, compiled hints and reconstruction reads. | Compare ordinary uniform-vector and geometric/polynomial batching controls. Publicly linked challenges can create cancelling errors; retained E99 rank/primitive-map tools help expose these. A PRG seed does not compress an arbitrary index-dependent hint. |
| **Point/quotient boundary** | Test ordinary unreduced product plus quotient witnesses as a low-state control; assess whether one shared trace serves all required checks and is actually cheap on the existing GPU. | Generic polynomial verification gets the same quotient/NTT reuse. Never treat NTT roots as arbitrary polynomial-check points or assume quotient generation costs zero. |

For the third control, `AB = Y+(X^N+1)W` with `deg(Y)<N` and
`deg(W)<=N-2` has a residual degree at most `2N-2`. Once all coefficients are
fixed, uniform secret points over a prime field give the **known** root-count
bound. Restricting points to NTT roots permits an error localized to one
spectral coordinate to be missed almost always. Quotient witnesses may double
internal coefficient traffic or require additional cyclic/negacyclic work.
Any compressed opening needs its own binding and complete cost; a hash does
not supply a free polynomial opening.

Geometric batching, for example, also loses degree-dependent soundness compared
with uniform independent weights. Use the actual degree and attempt budget.
Over RNS, an error in one limb receives only that limb's guarantee. Over a
composite modulus, field rank is insufficient. Check every decoder dependency,
including required C1/C2 coordinates; omitted C0 support is a proved layout
property, not permission to omit arbitrary components.

### A.4 First packet and acceptance

**Q27/E101: bounded whole-trace/cost discriminator, proposed.** Begin with
preregistration and a graph/claim comparison, then a tiny independent exact
oracle only if a specific distinction remains. Proposed files:

- `experiments/bfv_search_lab/joint_binding_oracle.py` and its meaningful
  mutation/cancellation tests;
- `benchmarks/joint_binding_lab.py` for exact traces and counts initially;
- `docs/research/joint-binding-preregistration.md`, `joint-binding-screen.md`,
  and a lemma/cost table for each retained variant.

First prove the independent expanded graph matches original encrypted inputs,
final wire grammar, every score, IDs and stable ties. Exhaust a declared small
field/error space, including non-basis errors. Treat larger random/mutation
checks as differential tests, not exhaustive proofs. Mutate one RNS limb,
an original query, digit reconstruction, range, dropped support, row order,
epoch, coin source/order and response body. Include **true output with false
witness**: the first accepted false *trace*, not only the first wrong score,
is the checking failure event.

Record local and client/server transport boundaries separately. Compare
existing fused native recomputation, E13, E72, equally optimized generic
elimination, the relevant specialized proof, and permitted caches. No complete
baseline adaptation means the comparison remains open.

Initial cap: two algebra/graph sessions and one exact/count session. A session
is a bounded work component, not a timing promise. Stop a literal variant on
known containment, a soundness counterexample, missing original binding, or
an optimistic complete ledger that already loses. Advance only one variant
with a precise remaining algorithm/theorem difference and a plausible useful
complete effect. Do not write a new GPU kernel before this return.

**E100's status changes only in priority:** retain its existing plan and all
originality cautions; make the remainder-first identity a conditional A/B
control when a measured/priced canonicalization bottleneck requires it. It is
not the automatic next main-paper candidate and is not marked executed.

## 5. Route B: a finite certificate across adaptive reuse

### B.1 Restricted theorem target

Specify one real search circuit, actual CBD/ternary distributions, full key
dimension, same-key index/query graph, gadget keys, canonical decomposition,
and approved release boundary. Begin with a degree-two source and its exact
decoder; maintenance and stochastic terminal switching are explicit extensions.
Do not claim a theorem for arbitrary BGV/CKKS/TFHE circuits.

Let Z contain all once-sampled keys/index/errors. Seek a good-setup event
`G(Z)` with unconditional failure at most `epsilon_epoch`. For every fixed
`z in G`, every permitted query history and next legal query, require

```
Pr[honest decode fails at query i | Z=z, history, next query] <= delta_i.

Pr[any honest failure in the lifetime]
    <= epsilon_epoch + sum_i delta_i.
```

The conditional union is **known**; its use is not the contribution. The
research step would be proving a substantially useful finite bound for G and
the conditional failures in a real dependency case not covered by the closest
results. G is not an observed absence of failures or an unpriced rejection
sampler. Conditioning key generation on G changes its law and requires its
own assurance if actually used as a sampler.

### B.2 Proposed mathematical method and falsifiers

Construct an exact dependency graph with shared atom identity and draw order.
After fixing Z and appropriate public randomness, express legitimate fresh
noise as affine forms of still-fresh CBD/rounding coins where justified.
Combine exact finite MGFs or certified concentration bounds with deterministic
norm bounds on fixed source/key residuals. Use shared aliases before computing
norms. RNS views and signed orbit copies do not create independent samples.

The difficult case is a coefficient depending on the **same fresh randomness**
being bounded: adaptive digits, key-switch errors and source products may have
this property. It is invalid to plug such a coefficient into an independent
MGF formula. Derive a valid conditioning/filtration or use a conservative
bound and record the lost precision. Do not assume that posterior secrets,
setup annihilator errors, or Gaussian approximations become IID after reuse.

Compare the closest BGV/CKKS/CLT analyses, deterministic canonical-embedding
bounds, E94's fixed-source adaptive control, and E97/E99's exact fixed-input
rounding controls. An unchanged standard Hoeffding/Chernoff result is a control.
Novelty needs an additional dependency handled rigorously, with a quantitative
effect after all old residuals and lifetime losses are paid.

**Q28/E102: finite-tail theorem discriminator, proposed.** Produce a precise
restricted theorem statement and independent tiny finite-distribution oracle.
Proposed `finite_lifetime_noise.py`, meaningful freshness/reuse falsifier tests,
`benchmarks/finite_lifetime_noise_lab.py`, and a preregistration/lemma/report.
Verify exact conditional laws at small sizes; compare certified tails with
complete finite enumerations. If optimizing MGFs numerically, use outward
rounded/certified bounds and account for numerical error. Monte Carlo can
falsify a model, not validate a 2^-128 tail.

Price at least: current dense full-ring controls; changing Q with fresh
enrollment; terminal precision; key/response/proof bytes; setup/update/query
lifetimes; and the binding mechanism. Keep lattice hardness separate. Fixed
weights/hidden sparse supports require the matching full transcript analysis;
old prefix costs cannot be reused. A correctness-only smaller Q is a model,
not an approved setting or a measured speedup.

Initial cap: two theorem/dependency components and one finite/count component.
Advance if a restricted nonheuristic result is both distinct and useful, or a
new sharply scoped impossibility/limitation is established. Stop if it merely
restates E94/E97/E99 or if all meaningful finite bounds are vacuous. This route
can become the main paper if A is ordinary engineering; it does not depend
on a new public proof backend to state its restricted theorem.

## 6. Route C: owner summaries and exact private candidate retrieval

This is an explicitly separate **exact-top-three plus records** mode, not an
all-score replacement. It is lower priority because high-dimensional geometry
and hidden stopping costs may defeat it.

An owner builds a complete authenticated partition/hierarchy. For group j
retain centroid `c_j`, a proved maximum Hamming radius `r_j`, count, minimum
stable ID and epoch/coverage commitment. The client computes

```
LB_j = max(0, Hamming(query,c_j)-r_j).
```

These are known metric lower bounds. Fetch authenticated candidate blocks
privately, compute exact local distances and update stable top-three. Terminate
only when every unfetched group's lexicographic lower bound exceeds the current
kth `(distance,ID)`; ties and fewer than k live rows need explicit handling.
An owner-generated radius/coverage commitment is essential. A server's
self-declared radius or Merkle membership of a fetched row is insufficient.

The potential new step is a **joint summary/block/certificate representation**
that remains useful after privacy and complete coverage are charged. Compare
PANTHER/SANNS-style private candidate retrieval, strong exact selection, verified
PIR/updates and raw/compressed mutable owner caches. Standard triangle bounds
plus these primitives alone do not pass the mechanism gate.

**Q29/E103: exactness/privacy/count discriminator, proposed and conditional.**
First enumerate all queries in a small binary universe and compare with a
full exact scan, including far queries, equal distances, uneven/empty groups,
duplicates, deletions, stale summaries and adversarial omitted blocks. Then
use held-out corpora plus uniform and adversarial geometry. Proposed
`owner_summary_oracle.py`, tests, `benchmarks/owner_summary_lab.py`, and a
separate contract/preregistration/report.

Early stopping, candidate count, retries, fallback and message timing may
reveal the query even when each PIR address is private. In the primary privacy
comparison use a public fixed schedule/padding or a proved traffic-hiding
mechanism, and pay dummy work. Variable-work/leakage-budget variants are
separate experimental modes, never called equivalent privacy. A fixed budget
with an unpriced query-dependent fallback does not solve this problem.

Inner BFV/BGV PIR responses also need a safe release gate or a separately
reviewed key-lifetime protocol. AEAD integrity of recovered owner records
does not authenticate a malicious outer HE reply before HE secret use.
Measure summaries, records, PIR proofs/hints, all query rounds, updates,
multi-device enrollment, and the cost of eventually acquiring a full cache.
Stop early on known containment, dense worst-case candidate sets, or padding
that erases the proposed useful effect. Initial cap: one contract/coverage
component and one exact/count component before any large retrieval service.

## 7. Execution order and concrete handoffs

| Step | Status / prerequisites | Deliverable and return decision |
| --- | --- | --- |
| **D0: evidence and closest-work revision** | Completed planning in this revision | This plan, comparison, 9 newly pinned sources, targeted complete-page review, append-only registry/queue updates; no new benchmark/proof result |
| **D1 / Q27 / E101** | Completed bounded literal stop | Complete tiny BGV graph and false-witness oracle retained; generic elimination contains recipe; full native/terminal proof remains open |
| **D2 / Q28 / E102** | Completed bounded literal stop | Known restricted conditioning/setup-cap certificate retained; toy model geometry qualified; honest full-N nonlinear maintenance theorem remains open after E105's fixed-setup law |
| **D3 / Q29 / E103** | Completed bounded literal stop; separate top-three contract | Exact owner coverage retained; ordinary metric recipe and fixed-padding limits stop originality; PIR/failure padding unimplemented |
| **D4: select main mechanism** | Bounded returns complete; no original main selected | [Current R6 return](native-opening-selection-20261003.md) retains native/terminal known controls and stops contained literal claims; next complete specialized-opening comparison. Broad gates and old P/Q6 remain unmet. |
| D9 / Q31 / E105 | Complete bounded literal stop | 26,244 weighted states and full joint law match actual API; injectivity and matched grouped controls stop carry representation; no general theorem |
| D10 / Q32 / E106 | Complete selected tiny BGV known control | Actual CPU/RNS original-query-to-full-wire oracle and complete affine count compiler; strict canonical checks; full proof/BFV/CUDA adapters deferred |
| D11 / Q33 / E107 | Complete finite known-control/literal stop |180,978 rich/60,326 reduced tuples; centered terminal relation survives, shared generic compiler contains saving |
| **D12 / Q34 / E108** | Next, proposed | Applicable specialized-opening interface/premise audit then complete tiny native relation and fair proof budget; known comparison prerequisite |
| **D5: homemade complete reference** | Selected mechanism and credible useful ledger | All protocol roles, canonical messages, safe release, persistent epochs/budget, updates, matched strong baseline adapter; toy oracle first, then real ring arithmetic |
| **D6 / Q30 / E104: matched service evaluation** | Complete reference and stated parameter scope | One matched BGV/BFV/Paillier/hybrid fixture plus cache controls; measured full service/lifecycle costs, not multiplied cross-study ratios |
| **D7: theorem and assurance package** | Start lemmas at D1; finish before security claims | Actual transcript reduction, correctness/soundness/lifetime budgets, full auxiliary-key parameter analysis, private implementation review; independent review remains an explicit external requirement |
| **D8: native/CUDA optimization and paper artifact** | Surviving full protocol, measured profile | Homemade fast path, complete ablations, held-out evaluation, reproducibility archives, manuscript claims that match demonstrated scope |

E104 is conditional, not a request to rerun every historical panel now. A
separate engineering BGV/hybrid comparison is useful but cannot select an
original research contribution by itself. If a primitive's adaptation is
missing, name the missing work and keep the relevant comparison open.

After **every component**, return to R6 / the earliest unmet applicable gate:
record hypothesis, exact scope, immutable sources/results, strongest-control
difference, costs, pass/stop and the next action. Stop individual recipes,
not entire families without a proof. A new proposal must state why the
earlier negative does not already cover it. Do not keep generating small
variants of a recipe after its originality is contained by a complete control.

## 8. Full-cost evaluation preregistration

Retain project gates: at least **20% complete-cost improvement**, or at least
**2× binding state/preparation reduction** with at most **10% extra complete
elapsed and 10% extra per-query traffic**, versus the strongest matched valid
control. These are screening thresholds, not conference acceptance criteria.
Always report the Pareto curve and regressions. Define the chosen cost
objective before running; do not switch it after seeing a losing latency.

The first small proof/count experiment should be cheap enough to stop a bad
idea. Real evaluation follows only a viable mechanism:

- Same binary corpora, dimensions, query samples, stable tie rule, output/trust/
  leakage contract, enrollment state, hardware, and declared security scope.
  Preserve production Paillier and the stronger CPU-server/GPU-client lookup
  hybrid. External artifacts require pinned versions and explicit adaptations.
- Distinct cold owner enrollment, enrolled-server/new-client, returning-client,
  and multi-device state. Charge owner, server, client and any protected helper;
  do not count a helper's work as eliminated.
- Setup/evaluation keys, encrypted index, original/expanded query, response,
  proof/internal witness, attestation/provisioning, private checker state,
  plaintext caches, unused tokens, updates, invalidation, retries and expiry.
  Measure bytes on each link and RSS/device memory as well as canonical bodies.
- Begin with existing 8k/32k fixtures. Add a preregistered, distinct larger
  workload only when memory estimates permit, e.g. 2^17/2^20 rows at d=512.
  Model-only/out-of-memory cases remain labeled. Do not extrapolate a GPU
  throughput ratio into a full-service or approved-parameter claim.
- Sweep actual query lifetime and update rates, cold acquisition, sequential
  latency and concurrent throughput. Separate cold-start cost from amortized
  owner/company/server expenditure. Include full and compressed local caches
  without imposing a storage ban; measure acquisition, residency and updates.
- Use serial monitored whole-process blocks with warmups, predeclared run
  counts and resource qualification. Pair all variants within a block and
  use process blocks, not within-process repetitions, for uncertainty. Freeze
  seeds/corpora before training a router; evaluate held-out decisions.
- For network claims, measure a real RPC/transport boundary and payloads;
  a bandwidth equation is a sensitivity model. Genuine WAN/cloud/TEE costs
  remain unknown until measured. Instrumented Nsight diagnostics do not replace
  quiet elapsed measurements or unavailable hardware counters.
- Ablate the new representation, verification boundary, lifetime rule,
  precision, packing, batching, native arithmetic and CUDA independently.
  Report checked service versus checked service; unchecked arithmetic is a
  lower-bound control with a different contract.

## 9. Security and proof work planned alongside construction

Prove circuit/encoding correctness and stable-ID coverage first. Then show
that any accepted false complete trace lies in the checker's failure event.
Sample fresh challenges only after a complete immutable statement is fixed,
or justify a reusable protected-check construction with a global finite
attempt bound. No independently probeable stage decisions or uncounted
false-witness retries. Include malformed, replayed, cross-epoch and true-answer/
false-proof attempts, crash, restart, fork, concurrency and rollback.

For a surviving protected-check mode, the reduction should separately identify
HE privacy assumptions (including the **actual** evaluation/auxiliary-key
graph), commitment/signature/attestation and checker assumptions, the probability
of a false trace acceptance, honest decryption-failure probability over the
lifetime, and implementation leakage. A suggested hybrid is to replace release
with an ideal correct-result/abort functionality up to the binding and honest
failure events, then reduce the remaining ciphertext view to the appropriate
HE assumption. This is a **proof task**, not an achieved reduction or a claim
that IND-CPA alone handles malicious release.

Do not transfer a small toy rank or an estimator number into 128-bit security.
Model setup-only, per-query, reused and transformed public samples with the
real available counts and distributions. Sparse/derived secrets, correlated
gadget rows, auxiliary keys and seeded masks each need matching arguments.
Existing finite taint/sanitizer checks do not establish constant time.
The selected private decoder/sampler/receipt implementation needs its own
side-channel and lifecycle review. Live hardware attestation and independent
cryptographic review remain explicit deployment requirements.

## 10. Publication and preservation decision

A strong system paper would demonstrate a new authenticated representation,
a clear paid-resource improvement, a complete malicious-server contract, and
a reproducible homemade artifact. A stronger formal route could center on a
new restricted finite theorem and its concrete cryptographic consequence.
Venue selection follows the demonstrated contribution; dates or a venue name
must not force unsupported novelty/security claims.

At selection, write the paper's claim in one paragraph and the closest-work
delta in one table. At completion, each claimed theorem must have a proof and
each numerical claim a matching immutable experiment. Keep the many known
controls and negative attempts in the artifact/appendix; the main story should
be the surviving mechanism, not the chronology of every optimization.

This planning branch preserves company sources and all earlier checkpoint
refs. The literature archive now contains **77 PDF/text pairs**, with hashes,
acquisition records and targeted reading scopes. Earlier 68 records remain
unchanged. New planning validation checks links, dependencies, original raw
and source identities, protected refs, and historical governance documents at
their original commit. It does not rerun or rename the earlier experiments.

## 2026-10-03: E108 return

See the [complete screen](native-proof-interface-screen.md) and [R6 selection](native-proof-interface-selection-20261003.md).
The interface/count component is complete as a known control. Next [Q35/E109](native-proof-backend-plan-20261003.md) is proposed; full proof and publication gates remain open.
