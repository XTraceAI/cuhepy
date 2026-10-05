# Concrete delegation controls and the paper-selection decision

2026-10-05. Planning baseline `ccd8e38b319641b7cf2de5572a6ffa15955d8a80`;
preserved implementation `73b552f2cbcc7a4b0add092c41d0171d236a826a`.
Read with the [canonical plan](research-system-decision-plan-20261005.md),
[closest-work matrix](closest-work-contract-matrix-20261004.md) and
[execution handoff](research-mechanism-execution-handoff-20261005.md).
The [review receipt](research-delegation-frontier-review-20261005.json) pins
the calculations and retained evidence. This is a planning return, not another
HE experiment, completed launcher, new parameter approval or enlarged queue.

## Recommended research position

Build the complete owner-data service around our homemade BGV arithmetic.
Aim for **one demonstrated design result about where exact encrypted computation
is constructed, checked and retained**, rather than presenting all earlier
optimizations as independent inventions. The performance question includes
both client-visible latency and the resources required to deliver it safely.
The engineering selection is already justified; the original paper mechanism
has not been selected by evidence yet.

Three discoveries would support that research position:

1. A precise admission/representation boundary changes the complete execution
   enough to win where equally optimized protected replay or known delegation
   loses. Identify the work removed, not just a smaller message.
2. A current snapshot can safely preserve expensive physical computation state
   across updates, with an actual paid advantage over selective refresh and
   permitted owner correction. The ordinary immutable-base template is a
   control; the new result must be an additional execution or assurance finding.
3. A concrete bounded-state execution enables a useful scale or latency regime
   beyond equally streamed replay and maintained sketches. Streaming by itself
   does not constitute that finding.

These are the existing conditional R4 choices, **not three new experiment
queues**. R3's measured bottleneck chooses one. A systems contribution can use
known cryptography; it still needs a generalizable and previously unestablished
design result. A new primitive, a first use of a TEE, and a first packed-search
claim are unnecessary and unsupported. If the result is only an equally
specialized implementation of a known execution, preserve the company system
and describe the narrower engineering/evaluation contribution honestly.

## Closest work: the comparison that matters for this decision

The larger matrix retains the full versioned source archive. This table names
the strongest objection to each potential paper claim, rather than listing
papers solely because they contain “encrypted search.”

| Claim being considered | Strongest applicable predecessors/control | Obligation before making the claim |
| --- | --- | --- |
| Fast exact encrypted similarity | [HERS](https://arxiv.org/abs/2003.12197v3), [EMVP](https://eprint.iacr.org/2025/858), [BNTM](https://arxiv.org/abs/2502.13060v3), the company Paillier implementation | Align output, input ownership, preprocessing, updates and complete transport. EMVP/BNTM's retained small-fixture advantages cannot be discarded. |
| Packed-query expansion and reusable encrypted index state | [SealPIR](https://eprint.iacr.org/2017/1142), [MulPIR](https://www.usenix.org/system/files/sec21-ali.pdf), [PPMI v3](https://arxiv.org/html/2506.17336v3) | Give the reference expansion once per request, cached transforms, compact uploads and selective refresh. No new expansion/cache primitive is claimed. |
| Secure acceleration outside a TEE | [vFHE](https://arxiv.org/html/2301.07041v2), Appendix D, and [Slalom](https://arxiv.org/html/1806.03287v2), §3.2 | Supply real checked delegation with its preparation, randomness, input binding, maintenance and attempt lifetime. Our exact aggregate control recomputes products. |
| Integrity-only attested FHE | [Argos](https://petsymposium.org/popets/2025/popets-2025-0099.php) | Match optimized protected execution and its hardware/attestation custody assumptions. A local Ed25519 signer is not the deployed control. |
| Verified encrypted matching and complete release | [BioZKFHE](https://arxiv.org/html/2607.22065v1), §§III/V–VI | Credit ordered block coverage and verified-output release. Its committee opening, threshold recovery and application output differ from an owner receiving all exact distances. No cross-contract runtime ratio. |
| Function-dependent verification preparation | [Additive-homomorphic FCs](https://eprint.iacr.org/2022/1331), Definition 8/Appendix A.4; [homomorphic signatures](https://eprint.iacr.org/2025/110), Definitions 2.5/A.9 | Preparation and authenticated streaming are known. Pay the actual arithmetic-domain, origin, update and release adapters. |
| Current results over incremental snapshots | [IntegriDB](https://integridb.github.io/IntegriDB.pdf), §2.1/4.5; [Inc-VDB](https://www.cnsr.ictas.vt.edu/publication/07366556.pdf); [model-generic IVC](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.ITCS.2026.6) | Grant authenticated current recipes and state transitions. Prove the precise HE/private-consumption refinement; signatures alone are insufficient. |
| Efficient maintenance relations or representation selection | [Corrected Cascudo](https://eprint.iacr.org/2025/286), [Laminate](https://eprint.iacr.org/2025/2285), [ILA](https://arxiv.org/html/2509.11559v1), [Silph](https://eprint.iacr.org/2023/060)/[CirC](https://eprint.iacr.org/2020/1586) | Specify common-Q/range/rounding obligations and a literal changed execution. Generic typing, relaxed maintenance or conversion-aware planning is not new. |
| A small verifier with polynomial certificates | Our [E70 quotient control](convolution-certificate-results.md) and [E71 encrypted-query control](encrypted-query-certificate-control.md), plus the preceding verification work | These ideas were already implemented/screened. Account for quotient generation, one-use hints, challenge order, feedback and all maintenance before revisiting a different scope. |
| Outsourcing is useful to this owner | Returning, fresh and racing authenticated cache; partial owner replacement; a separately scoped plaintext-in-TEE control | Respect the owner's permission to retain its data. Charge acquisition where it occurs; do not force it on returning users. State stronger plaintext/key custody explicitly. |

The strongest reference is a compatible construction from these ingredients,
not an intentionally incomplete individual paper. Unknown adaptation cost
stays unknown. Likewise, adapting a known technique does not inherit its proof
or reported performance automatically.

## What the retained results actually say

The 32k local panel supports BGV as an engineering foundation: 117.298 ms median
and a 204,895-byte first reply, versus 892.813 ms/409,770 B for prepared BFV,
1,418.960 ms/16,907,985 B for Paillier hybrid, and 2,599.103 ms/16,908,071 B
for Paillier lookup CUDA. Returning raw cache took 4.384 ms and no returning
query transfer. This is one key/index/process block per variant, five measured
requests, unequal unapproved profiles, setup-swap-qualified and without WAN or
complete protected admission. These are not secure-service speedup ratios.

The BGV update's 7.1466 s re-preparation out of 7.2788 s total, after an already
compact upload, motivates state reuse. The selected graph's 127,057,920-byte
internal witness, of which 125,583,360 B is query-expansion sources, motivates
construction/admission placement. The exact aggregate control already moves
that whole prefix inside the protected role; it does not avoid contraction
products. Its 1,474,560-byte claim is an internal-link reduction, not an owner
response or a measured compute saving.

The original gated EMVP and unified BNTM records remain direct publication
controls. The [canonical plan](research-system-decision-plan-20261005.md)
retains their Mushroom/Semeion means, reply counts and preprocessing differences.
No ratio between these fixtures and 32k/Q77 is meaningful. The historical
revalidation's receipts, normalized observations and paired comparisons are
different units; none becomes an independent replicate through this review.

Q77 still has zero actual HE keys, complete-cost blocks or timings, and 376
distinct retained public cases. R2 provisioning and whole-cohort launch remain
unfinished. This review recalculates the 25 old panel medians and checks the six
retained reference input reports; it generates no new measurement evidence.

## A concrete known-delegation control that the main claim must survive

The canonical profile has `N=16384`, `d=512`, two approximately 60-bit primes
and `G=ceil(rows/N)` groups. Its protected prefix already constructs the genuine
expanded query. In each prime's NTT coordinates, denote query components by
`a0[j,k], a1[j,k]` and fixed enrolled index components by
`b0[g,j,k], b1[g,j,k]`. The contracted claim consists of

```text
z0[g,k] = sum_j a0[j,k]*b0[g,j,k]
z1[g,k] = sum_j (a0[j,k]*b1[g,j,k] + a1[j,k]*b0[g,j,k])
z2[g,k] = sum_j a1[j,k]*b1[g,j,k].
```

This is a fixed **linear operator in the expanded query**, although producing
that query and finishing its result require non-linear maintenance. The native
three-product contraction uses the cached `b0+b1` row. A standard preprocessed
Freivalds control chooses uniform weights `r0,r1,r2` over every group/frequency
and stores

```text
m0[j,k] = sum_g (r0[g,k]*b0[g,j,k] + r1[g,k]*b1[g,j,k])
m1[j,k] = sum_g (r1[g,k]*b0[g,j,k] + r2[g,k]*b1[g,j,k]).

sum_(g,k,c) rc[g,k]*zc[g,k]
    = sum_(j,k) (a0[j,k]*m0[j,k] + a1[j,k]*m1[j,k]).
```

For a fixed false claim independent of the uniform weights, one field check
misses with probability at most `1/p`. Check both actual primes. A forgery can
alter only one limb, so do not multiply their soundness probabilities. As an
**illustrative algebraic target**, `2*B/p_min^r <= 2^-128` for `B=1024` attempts
requires three rounds. That example is neither a Q77 budget amendment nor
cryptographic parameter approval. Reuse, public feedback, durable consumption,
crashes and challenge confidentiality require the actual protocol argument.

Counting only field multiplications, both limbs:

```text
exact native contraction:                  6*d*G*N
dense preprocessed check, r rounds:         r*(4*d*N + 6*G*N)
stored input projections, one check set:    r*2*2*d*N*8 bytes.
```

For three rounds the input projections occupy **805,306,368 bytes** before
weights, keys, prefix state and scratch. If independent one-use check sets
are provisioned in a pool, multiply their hint cost by the pool depth. That is
not a compulsory cost for the strongest reference: Slalom §3.2 explicitly
permits reusing hidden randomness across inputs with an attempt-dependent loss.
Give its compatible adapter that freedom when the actual bounded transcript
argument applies. Review challenge confidentiality, feedback, crashes,
concurrency and durable consumption; do not silently credit safe reuse in our
implementation. This is the standard Slalom-style control, not a new primitive
or a claim that its whole BGV adapter is complete.

The ratio simplifies to `2*r/(3*G)+r/d`. This known count law is only an early
resource screen; a complete execution may be limited by the shared prefix,
maintenance, secret state, updates or transport. The fixed projection body is
per check set, not necessarily per request. Its confidentiality is an explicit
premise: leaking checking weights can allow false admission. Argos instead
keeps attestation secrets out of the evaluator CPU/memory hierarchy. Our
secret-state checker and local signing process cannot inherit that architecture's
assurance by sharing its integrity-only HE goal. Public modular arithmetic
used on private weights also needs its own side-channel review.

| Full groups | Rows | Dense check / exact contraction count | Dense projection bytes, one check set |
| --- | ---: | ---: | ---: |
| 1 | 16,384 | 2.0059 | 805,306,368 |
| 2 | 32,768 | 1.0059 | 805,306,368 |
| 4 | 65,536 | 0.5059 | 805,306,368 |
| 8 | 131,072 | 0.2559 | 805,306,368 |

This explains why a lightweight-looking random checker is **not automatically
faster at our reserved one/two-group sizes**. The table omits preprocessing,
prefix, terminal, reductions, additions and all network/private work. It is not
a latency prediction. The larger rows are analytical examples, not registered
future runs. A useful many-group regime must pay for its actual scale and
capacity before entering a future experiment.

### Small point hints move the cost elsewhere

The E70/E71 alternative uses ordinary polynomial evaluation with the necessary
negacyclic quotient:

```text
sum_j aj(X)*bj(X) = z(X) + (X^N+1)*h(X),  deg h <= N-2.
```

An arbitrary off-root evaluation without `h` is invalid. Sampling only NTT
roots instead can miss an error concentrated in one coordinate. These are
retained counterexamples, not new discoveries in this review. At this profile,
the conservative off-root error bound uses degree `2*N-2`; four independent
rounds satisfy the example two-limb/1024-attempt/128-bit algebraic target.

For all three aggregate components separately, the fixed-index hints need
`4*2*2*d*G*8` bytes: **131,072 B at two groups**, before all other state.
Query evaluations from the current NTT prefix can use Lagrange weights at the
negacyclic roots, avoiding a free assumed inverse NTT; materializing all such
weights needs **1,048,576 B per check set**. Generation, inverses, retained
secrets and side channels must be paid/reviewed. This interpolation observation
is standard, not a new conversion algorithm.

The unbatched quotient body is **1,474,470 B at two groups**, in addition to the
1,474,560-byte aggregate body. Ordinary cyclic/negacyclic decomposition is a
known quotient-generation control and adds producer transforms/products/state.
Post-output batching has a different interaction/order/quotient cost law;
E70/E71 already implement its tiny control. Do not mix its lower body count
with the unbatched single-stage operation counts here. After matched repetitions,
the unbatched point check's modeled multiply count is about **1.3492 times**
the exact contraction at two groups, before all excluded work.

Small verifier hints therefore identify a **state/work/traffic tradeoff**, not a
free improvement. E71's actual tiny encrypted-query variant already stopped
its literal wire/preparation claim and retained a quotient-feedback predicate.
Moving its preparation from the owner to a TEE or replacing its tiny layout
with the current packed query needs a complete new adapter; it cannot be
reported as an already original or faster protocol.

### A literal conversion ablation, if R3 selects that cost

The exact aggregate wire currently converts NTT results to canonical common-Q
coefficients; the receiver converts them back. A strict two-limb NTT packet
could remove `12*G` aggregate-wire NTTs and `3*G*N` producer CRT compositions,
while growing coefficient bodies from 15 to 16 bytes per element. At two
groups that is 24 transforms and 98,304 compositions removed, versus
**98,304 additional internal bytes**. Maintenance's canonical source/digit
and terminal obligations remain. Nothing here permits independent per-limb
digits or an unchecked result.

This is an exact, same-output engineering ablation of conversion-aware
placement. It cannot establish a new conversion primitive, and it does not
remove the aggregate checker's recomputed products. Credit the same native
representation to applicable replay/delegation controls. Implement it only
if R3 attributes a meaningful complete cost to that boundary and the selected
R4 mechanism needs it; this document does not add an experiment slot.

## The executable decision and the contribution bar

The immediate task remains R2, then the existing R3 cohort. Do not launch a
new quotient or sketch sweep to postpone that dependency. On the R3 return:

| Observed limiting paid cost | One R4 route to specify | Mandatory control and early stop |
| --- | --- | --- |
| Update-to-next-answer / preparation | Current-recipe reuse of physically admitted base state, with exact owner replacements and paid compaction | Selective refresh plus ordinary partial-owner correction. If graph, protocol and costs coincide, close the new-algorithm claim. |
| Construction / admission | One precise native representation or maintained arithmetic boundary | Protected replay, exact aggregate and applicable vFHE/Slalom specialization. Removing a known conversion or changing the cut name alone is supporting engineering. |
| Verified execution capacity at a justified scale | One complete bounded-state execution with query-prefix reuse and explicit admission-state lifetime | Equally streamed replay and maintained dense/point hints with identical attempt targets. No free verifier sketches, hidden hints or missing quotient/maintenance. |

R4's eligibility specification must name **what remains after these controls**.
It must give the changed source-to-release graph, a necessary invariant, actual
setup/update/per-query resource vectors, a same-output ablation, a calibration
prediction and a losing regime. A favorable body/count model is only an early
feasibility screen. The paid implementation and held-out traces decide utility;
closest-construction and external review decide the scope of originality.

There is one reserved selection cohort, then at most one separately registered
extension cohort. R3 has 18 process blocks and 144 measured queries per
trajectory; its six trajectories total 864 measured queries. Six blocks
calibrate, twelve are held out. The proposed R4 cohort has 32 observations per
surviving variant. Exact auxiliary attempts and freeze requirements remain
in their controlling registrations. No broad preliminary search is reopened.

## Security and paper obligations after selection

Keep the proof work tied to the implemented winning mechanism. Define a game
in which the owner pins currentness, signs the original query and can receive
arbitrary malformed/replayed/interleaved server traffic. State the permitted
public leakage and authorized owner outputs explicitly.

The reduction should separately account for authenticated origin/code/context,
arithmetic false admission, noise/terminal failure, freshness/rollback and
implementation/private-side leakage. It must show that only a complete,
correctly bound authorized frame can trigger private decoding, and that attempts
are consumed through failure/crash/concurrency paths. For randomized checking,
prove the actual adaptive challenge/state lifetime rather than borrowing a
fixed-witness calculation. For composite updates, prove exactly one current
value per ordinal and atomic recipe/compaction behavior. These are obligations,
not an asserted completed or original reduction.

Real attestation must bind the verifier key to approved code and configuration;
source/native refinement, concrete parameters and private constant-time work
remain necessary. A secure local authorization prototype does not establish
AWS deployment or private-key side-channel assurance.

Write the paper around one precise execution change or substantive assurance
result, its strongest prior objection, its paid winning/losing regimes and its
actual artifact. Include early failed/contained experiments where they explain
the final design. Venue selection follows that result. Do not promise a
conference-worthy original contribution before the missing evidence exists.
