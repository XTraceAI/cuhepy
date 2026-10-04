# Q74–Q75 return: shared query works, but smaller witness is not a system result

2026-10-04. Parent `50473fc665572e2548fb95d1de4d817238771901`.
Branch `experiment/shared-query-admission-20261004`.
This executes the two finite preliminary gates of the
[contribution plan](research-contribution-plan-20261004.md). See the
[Q74 registration](shared-query-admission-registration-20261004.json),
[Q75 registration](shared-query-cost-registration-20261004.json), and
[current execution ledger](research-contribution-progress-20261004.json).
Raw evidence is in
`/home/pete/yavor-projects/xtrace-work/research-data/shared-query-admission-20261004`.

**Decision:** advance one owner-encrypted, canonical Q120 shared-query design
to a complete native admission-versus-replay discriminator. Preserve the
Q180 bounded-state alternative as supporting resource tradeoff evidence.
Do not select it from witness bytes alone. The strongest known composition
has identical algebra, so a new expansion/gadget/asymptotic claim is rejected.
An original complete system result remains a hypothesis, not an accepted claim.
The correctness and resource gates are complete within their registered scope;
there is no measured new service, approved parameter set, or security theorem.

## What was implemented and checked

The homemade [reference](../../experiments/bfv_search_lab/shared_query_bgv.py)
encrypts one predivided packed query, expands it once, contracts the expanded
features with an encrypted feature-major index, and relinearizes once per
record group. It imports our arithmetic, not Microsoft SEAL. The historical
SEAL example and company BFV/BGV/CUDA implementations remain unchanged.

For binary dimension d, D=next_power_of_two(d), ring degree N >= 2D,
the query plaintext is `D^-1 * sum_j (1-2*q[j])*X^j mod t`. Expansion uses
`sigma_l: X -> X^(1+N/2^l)` and returns constants `1-2*q[j]`, with zero
padded features. The two branches are `C+Rotate(C)` and
`X^(-2^l)*(C-Rotate(C))`. Signed feature polynomials contain records across
coefficients and zero unused record positions. Their product sum has plaintext
`d-2*Hamming`. The owner decodes distances and selects stable-ID top-k locally.
This uses ordinary negacyclic products, without assuming full SIMD batching.

The complete public relation is affine in the owner's original ciphertext
and canonical source digits because the enrolled encrypted index is a fixed
public multiplier. Every source recomposition, both tensor cross terms, and
both complete terminal-Q components are linked to those inputs. It copies
keys, ciphertexts, origin envelopes, profile, ordered IDs and coverage; its
statement digest binds that context. Terminal checking independently rounds
and packs **all** coefficients, including unused coordinates and headers.
No private key, HE replay, sampled noise or private budget approves a response.

Two policies were fixed before fresh experimental keys:

* `canonical30`: canonical common-Q radix-30 source at every expansion switch.
* `derived_last30`: canonical anchors until the penultimate level, then derive
  the last level's signed integer representations from both anchor siblings.
  One canonical relinearization source per group remains in either policy.

Let `d_a` be the canonical digits of `sigma(C1)`, `A[a,j]` the canonical
common-Q digit j of public switch-key column `K_A[a]`, and `h=-2^l`.
The retained sibling states are

```text
Eplus[j]  = sigma^-1(d_j) + sum_a d_a * A[a,j]
Eminus[j] = X^h * (sigma^-1(d_j) - sum_a d_a * A[a,j]).
```

Their recomposition gives the corresponding child's C1 modulo Q. The next
switch uses the automorph of this **same signed integer state**. Every radix
and convolution cross term is included. These identities are known gadget
algebra; their occurrence in this query tree does not make them new. No
independent per-prime digit witness or free expanded-query witness is allowed.

The final small public checker also recompiles the expected graph before
comparison. A supplied correct digest cannot authorize a weakened graph.
All 64 retained tapes were rechecked and 64 same-digest weakened graphs rejected
after this hardening. A native service must compile and cache its authoritative
graph inside enrollment; this diagnostic recompilation is not an efficient
production controller. The executed-source archives preserve the earlier
exact versions, with a separate final-source follow-up receipt.

## Public bounds change which profiles are usable

The noise module uses exact deterministic public supports, not sampled errors.
With `B=2^30-1`, `ell=ceil(bitlength(Q)/30)`, and `s=t*eta*N*ell`:

```text
canonical switch contribution <= s*B
retained sibling digit bound M <= B + N*ell*B^2
fresh owner phase Fq = t//2 + t*eta
index phase Fi = Fq                       (owner)
              = t//2+t*eta*(2N+1)         (public-key)
F_(l+1) = 2*F_l + s*(B or M)
F_output = N*d*Fi*F_expanded + s*B
F_terminal = ceil(P*F_output/Q) + ceil((N+1)*t/2).
```

Every stage and output must satisfy `2*F < Q`; the terminal must satisfy
`2*F_terminal < P`. The bound on M follows from the infinity norm of every
integer convolution and holds for every canonical source admitted by the
relation. It accounts for both signed siblings. No response-supplied envelope
can weaken these inequalities. Authenticated owner origin is a future service
requirement, not something a ciphertext metadata field proves by itself.

For the source geometry N16,384/d512/t1031/eta21:

| Q / index origin / policy | Output-bound bits | Q guard | Terminal bound | P guard |
| --- | ---: | --- | ---: | --- |
| Q120 / owner / canonical | 107 | pass | 8,450,122 | pass |
| Q120 / public-key / canonical | 122 | fail | 125,391,702 | fail |
| Q120 / owner / derived | 144 | fail | 503,138,207,122,545 | fail |
| Q120 / public-key / derived | 159 | fail | 16,104,284,169,169,280,522 | fail |
| Q180 / owner / canonical | 108 | pass | 8,446,469 | pass |
| Q180 / public-key / canonical | 123 | pass | 8,446,469 | pass |
| Q180 / owner / derived | 146 | pass | 8,446,469 | pass |
| Q180 / public-key / derived | 160 | pass | 8,446,500 | pass |

Q120 is the actual product of primes
`1152921504606748673, 1152921504606683137`; P=33,548,413.
The only registered larger-Q rescue adds prime `1152921504606584833`;
P=33,548,579. The exploratory design calculation that motivated this rescue
is archived and explicitly distinguished from preregistered fresh-key outcomes.
These are public algebra screens. No large key generation or encryption was
performed, and neither source profile is concrete-security approved. A
two-prime native parser is not assumed to support the three-prime profile.

## Actual correctness evidence, with units separated

Q74 used two fresh experimental key contexts: N16/d3/t11 and N32/d5/t19,
eta1, actual two-prime Q120. Each had two queries, counts N-1/N/N+1/2N-1,
both index origins and both policies: **64 complete relations**.

* Independent schoolbook whole-Q residuals and every actual prime limb agreed;
  limb checks used the same common-Q integer digits.
* Independent complete terminal rounding/framing and private diagnostics after
  public acceptance matched exact scores, stable-ID top-3, all zero feature
  padding and all unused record positions.
* One final-coordinate mutation in each canonical source slot was rejected:
  **320 source mutations**. Each complete output component was independently
  changed with a correspondingly rebuilt frame: **192 output mutations**.
* Q75 reused eight of those contexts: both geometries, modes and policies at
  N+1 records. Paired Karatsuba and the same bounded generic fusion preserved
  all independent residuals for honest, source-fault and unused-output-fault
  cases: **48 whole-vector rewrite/fault cases**, also checked per actual limb.
  Q75 generated **zero** new HE keys and ran no timing panel.

The final test invocation passed **157 tests**: 82 new regression cases and
75 selected existing expansion/gadget/relation/fusion cases. Test-fixture
keys are separate from the two registered experimental contexts. These are
test cases, not 157 independent encrypted experiments. Earlier runs of 64 and
80 new tests are development validations, not added to the final count or to
the historical 186-test checkpoint. A direct pytest entry point initially
failed collection because it did not put the repository on the import path;
`python -m pytest` resolved that without changing scientific inputs.

## Paid resource screen: witness savings add costs

Q75 compiled **60 resource cards** with zero compiler-cap failures: records
8,224/16,384/32,768; Q180's two policies in each origin mode; retained Q120
owner canonical control; direct versus identically bounded generic fusion;
cached versus per-use public recipe preparation. The caps and grammar were
registered. Nine finite frontier panels matched an independent all-pairs
oracle. This is a Pareto set within that grammar, not global compiler optimality
or a deployment winner. Residency changes have charged preparation/state costs.

For one full group of 16,384 records, owner index, direct paired Karatsuba
relation with cached public multipliers:

| Resource model | Q120 canonical | Q180 canonical | Q180 derived |
| --- | ---: | ---: | ---: |
| Source + terminal-Q coefficient body, MiB | 120.468750 | 180.703125 | 90.703125 |
| Evaluation-key Q coefficient body, MiB | 18.750000 | 42.187500 | 42.187500 |
| Owner seeded index coefficient + seed body, MiB | 120.015625 | 180.015625 | 180.015625 |
| Verifier input prime NTTs | 4,104 | 9,228 | 4,620 |
| Verifier DAG word products | 268,369,920 | 553,549,824 | 754,876,416 |
| Additional producer integer-state ring products | 0 | 0 | 4,608 |
| Sufficient cached multiplier RNS bytes | 423,624,704 | 651,165,696 | 665,321,472 |
| Sufficient scheduled dynamic live RNS bytes | 403,177,472 | 604,766,208 | 808,058,880 |

These witness bodies are **server-to-verifier**, not response download to the
owner. In all three rows the compact response coefficient body is 102,400
bytes for one group (headers additional). The Q180 query body is 368,672 bytes
including its seed versus 245,792 at Q120. Public-key index bodies have two
Q components per feature; the owner/public-key controls are matched separately.

Against the same-Q canonical control, deriving the final level approximately
halves witness traffic and forward NTTs but increases pointwise word products
by about 36%. Against the smaller admissible Q120 owner control, the witness
body falls by about **24.7%**, while word products grow by about **2.81x**,
keys grow **2.25x**, and index/query bodies grow about **1.5x**. The additional
integer products have larger signed intermediates and are not assigned a fake
equivalence to one modular product. Partial-group storage and old-layout
rotations are counted from actual occupied records.

Generic fusion is not an automatic win: for Q120/full-group/cached, this
sufficient adapter increases word products from 268,369,920 to 469,434,368
and scheduled live dynamic bytes from 403,177,472 to 739,508,224. Some other
resource coordinates/partial or multi-group tradeoffs keep fused variants on
a finite frontier. Do not reinterpret these schedules as memory lower bounds
or native measurements; better scheduling is equally available to controls.

## Closest-work return and claim decisions

The [primary-source closest comparison](closest-work-contribution-design-20261004.md)
and its PDF/source cache remain the reference. No new author artifact was
imported/executed. The strongest known-method adapter receives the exact same
program, propagation, lazy relinearization, Karatsuba, pairing, fusion, and
cache/streaming choices. Its resources and residuals are identical.

| Claim | Result of these gates | What remains useful to investigate |
| --- | --- | --- |
| A new packed-query/feature-layout/gadget primitive or O(D+G) inventory | **Rejected/contained.** HERS/E07, SealPIR/MulPIR/E73, gadget propagation and noise-aware relaxed relations cover the ingredients. | Preserve the correct homemade implementation and negative comparison. |
| C1 complete compilation/admission invariant | Supported in a copied-context small public reference, including full frame; native enrollment/lifecycle not yet built. | A typed native compiler/certificate and conditional correctness/composition proof. PEEV and prior ring verifiers are applicable controls. |
| C2 useful verified-cost design | A real modeled byte/transform/state tradeoff exists, but the selector and identities are known; originality unaccepted. | Determine whether admission removes costly replay normalization stages enough to pay for the witness and extra checks in a complete system. |
| C3 original system frontier | **Unmeasured and conditional.** | A useful complete regime plus an identifiable distinction from vFHE/PEEV/BioZKFHE and the compatible known composition; a faster isolated kernel is insufficient. |

Equally prepared replay gets the same graph/layout and **zero source witness**.
Its sufficient canonical stage model counts source reconstruction inverse
NTTs, common-Q CRT/digit extraction, forward digit NTTs and terminal inverse
NTTs. At Q120/full group that is 1,024 source inverse prime NTTs, plus four
terminal inverse NTTs; no claim of an optimal or measured replay schedule.
Admission may avoid these stage conversions by checking supplied canonical
sources, while adding source/output parsing, residual work and 120 MiB of
traffic. This explicit tradeoff is the remaining bounded systems question.

The checked-product/trusted-suffix control moves expansion and final maintenance
inside the protected side and pays their work. Its raw product packet model
has three Q components per group; its full cost remains unknown. Plaintext
cache is allowed: packed features are 1 MiB for this full group, plus 128 KiB
of ordered IDs, with zero remote online query/response bytes. Acquisition,
authenticated updates and client constraints must be measured fairly. No
cross-paper timing, unavailable adapter, or optimistic model is a winner.

## Next build and finite stop rule

Q76 now has one selected engineering/scientific-discriminator build:
**owner origin, actual Q120/t1031/eta21/N16k/d512, canonical30 shared expansion,
direct paired Karatsuba**, retaining streamed versus cached state as a lifetime
choice. CPU native comes first; existing company libraries stay intact.

1. Internally compile and copy enrollment: actual ordered primes, origin
   assurance, key schedule, feature coverage, IDs, epoch and code/profile hash.
   Requests bind the original owner query and one fresh request identity.
2. Build the matched native producer and full bounded packet/codec; preserve
   common-Q digits and complete output/terminal coverage. No peer graph or
   claimed bound can enter the controller.
3. Complete full mutation and exactly-once lifecycle gates, including request,
   epoch, restart/rollback/concurrency and response-frame binding. Integrate
   protected release only under the actual attestation/freshness contract.
4. Build equally rewritten prepared replay and checked-product controls in
   that same backend. Price their preparation, state and all conversions.
5. Only then run Q77's two-key/three-process-block matched panel at the three
   registered sizes. Measure actual complete elapsed critical path, IO, peaks,
   setup and 32-row updates, plus the permitted cache and applicable prior
   adapters. Keep unknown artifact costs unknown until reproduced.

The primary discriminator is a useful reduction in complete verified cost
under an explicitly fixed memory/link/update budget; witness size alone fails.
No weights calibrated from isolated historical stages choose the headline.
Keep two lifetimes separate: tenant-wide index/key/preparation reuse and
queries on each owner device. A fresh device making a few queries is a
legitimate acquisition scenario to test, while a device already retaining
the plaintext cache pays no invented download cost. Give the fresh-device
cache control an owner-authenticated compact encrypted vector backup; do not
force it to acquire the bulky HE index. Derive amortization at device query
counts 1/8/128 from the same measured stages, without adding timing cohorts.
Before Q77 timings, freeze the actual prototype resource/link budgets and
the existing project threshold of 20% amortized complete-cost improvement
against the best compatible remote control, then report the allowed cache
even when it wins. This is an execution decision threshold, not a conference
criterion or an assumption that such an improvement exists. Workloads and
budgets cannot be chosen solely to exclude the cache.
If replay/cache or an equally specialized prior adapter eliminates useful
regimes, classify this as supporting company/negative research work and stop
the main-performance claim. If a useful regime survives, the paper still needs
an original complete design result, formal assumptions, strongest controls and
external review. The derived Q180 option reopens only when a measured resource
constraint specifically justifies its additional costs; no new radix grid.

Q78's reduction agenda remains: authenticated owner origins and augmented
HE/key assumptions; every-admitted-witness correctness; complete public
admission before private work; ideal-output coupling; signature/TEE/request
composition and explicit failure/leakage/lifetime budgets. Samplers, concrete
parameters, private timing and actual hardware assurance remain unclosed.
Tests do not prove raw BGV CCA security or production safety. Q79 selects the
paper only after the complete evidence and closest-system distinction exist.
