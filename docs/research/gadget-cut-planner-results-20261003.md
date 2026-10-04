# Q70: per-node cut planning, encrypted correctness and full gate return

The finite planner/reference component is complete within its declared caps.
It shows that a whole-group half-fill cutoff loses valid opportunities: at
8,224 vectors, a per-node14-bit schedule removes190 source cuts where the
earlier mixed whole-group policy falls back. Every fresh toy encrypted
comparison agrees with the complete canonical plaintext and independent search
truth. This is a useful semantic-boundary result. The DP, gadget identities and
suffix-key lowering are known methods; no original main contribution, complete
native admission or latency win is accepted.

Code and evidence are on `experiment/gadget-cut-planner-20261003`, parent
`3d6ea4efbce6e8c49d8276aebe02328404d40637`. The current
[progress ledger](gadget-cut-planner-progress-20261003.json) and
[native construction gate](gadget-cut-native-admission-plan-20261003.md) are the
return to the research plan. The preceding company/research checkpoints and all
earlier raw evidence remain unchanged.

## What is implemented and what was run

| Component | Scope and result |
| --- | --- |
| [Finite planner](../../experiments/bfv_search_lab/noise_cut_planner.py) and [registration](gadget-cut-planner-registration-20261003.json) | Exact Pareto DP within a uniform-rotation-radix grammar, with explicit resource caps and clean no-optimum outcomes |
| [Independent oracle](../../experiments/bfv_search_lab/noise_cut_oracle.py) |72 distinct tiny inputs match unpruned generic enumeration and every coordinate of the preserved signed-symbolic butterfly. The original/refined executions repeat the same inputs, not144 independent cases |
| Registered large screen |42 cases;37 complete, five hit declared limits. No private key, HE execution, timing or approximate optimum. The initial interrupted run retains six completed one-tile cards separately |
| [Small encrypted reference](../../experiments/bfv_search_lab/noise_cut_reference.py) and [registration](gadget-cut-planner-encrypted-registration-20261003.json) | Two fresh homemade toy keys, four query/context pairs,16 half/half-plus-one/full/tail base cases and96 variant comparisons; all complete Q/P plaintexts, distances, stable IDs and top3 agree |
| [Suffix lowering](../../experiments/bfv_search_lab/noise_cut_lowering.py) and [registration](gadget-cut-suffix-lowering-registration-20261003.json) | All37 completed large schedules can switch their discarded-state suffix to canonical30 keys while keeping the complete public Q/P guard. Five parent limits remain ineligible. This is a matched cost control, not37 new encrypted trials |

Runners are [planner](../../benchmarks/noise_cut_planner_lab.py),
[encrypted](../../benchmarks/noise_cut_encrypted_lab.py) and
[lowering](../../benchmarks/noise_cut_lowering_lab.py).
Immutable evidence is under
`../research-data/gadget-cut-planner-20261003/`: `tiny/`, `tiny-refined/`,
`large/`, `large-refined/`, `encrypted/`, `suffix-lowering/` and `primary/`.
Every execution pins registration/source hashes and archives its exact code.
The encrypted runner pins synthetic data before key creation, stores all public
contexts, complete traces/frames and plans, and retains no HE secret/error coins.

The96 comparisons include1,800 distance checks and2,880 physical-coordinate
checks **with nested-prefix/variant overlap**. There are100 distinct max-prefix
query distances. Ninety-two variant outputs have different whole-Q bytes;
four canonical fallbacks do not. All frame lengths stay equal to their baseline.
Private diagnostics follow strict complete public replay. This reference
recomputes the circuit and retains even derived diagnostic cuts; it does not
implement the smaller modeled admission tape.

The five incomplete large cases are `(tiles,radix,allow_seed)`:
`(32,14,false)`, `(32,14,true)`, `(256,14,true)`, `(257,14,true)` and
`(257,18,true)`. The first two reach the distinct-transition cap; the other
three reach the dominance-comparison cap. They have no exact reported optimum.
The first large run was interrupted after its six one-tile cards because of
frontier growth. That process termination and partial evidence remain retained;
it is not another completed cohort or a measured cryptographic failure.

## Legal grammar and conditional correctness

Keep canonical30 product relinearization. Within an original profile every
rotation uses one radix `B=2^b`, with `ell=ceil(bitlen(Q)/b)`. Leaves either have
opaque C1 or the previously checked public tensor seed. Each active packing node
chooses canonical or derived switching and separately retains/discards its
output common C1 representation. A derived source requires both active child
states; a missing branch has known zero state. Canonical unary switching can
reset its state from its own source. Canonical binary minus digits alone cannot
supply the plus state. No radix conversion, independent limb lift, paid extra
C1 anchor, changed secret basis or enlarged modulus is hidden in this grammar.

With a common state bound L, let
`F=1+N*ell*(B-1)`, `C=N*ell*(B-1)^2`, `S=t*eta*N*ell`.
Canonical source norm is `B-1`; a derived source has norm `L_left+L_right`.
Its switch-error box is S times that source norm. Retained unary canonical
output has bound `(B-1)*F`; retained binary canonical output has bound
`L_left+L_right+C`; retained derived output has bound
`(L_left+L_right)*F`. These follow the known integer gadget equations and
negacyclic convolution bound. A single integer recipe exists across all RNS
limbs. The private key/error realization never chooses an admitted bound.

The packing suffix has nested residue supports. In the independent declared
coefficient boxes, an input i contributes `D*B_product` only at residues i
mod D; switch error at level j,node i contributes
`(D/2^(j+1))*B_switch` only at residue i modulo that suffix weight. A subtree
therefore combines peaks as `max(left,right)+weight*B_switch`. The oracle
explicitly reconstructs every residue and uses independent symbolic signed
aliases for every physical coordinate. This is an exact envelope for these
boxes, not a tight bound on actual correlated cryptographic noise. Summing
unrelated per-level maxima can overestimate a heterogeneous schedule.

For rounding allowance `R=ceil((N+1)*t/2)`, the largest safe integer peak is

`U=min(floor((Q-1)/2), floor(Q*(floor((P-1)/2)-R)/P))`.

Partial envelopes can only grow. A retained state L at peak Z cannot help a
later derived switch if `Z+S*L>U`: even suffix weight1 is unsafe. Binary
transitions never reduce either quantity; a unary canonical reset needs no
old state and remains available after discarding it. Removing such dead
retention choices is exact within this grammar. The refined execution adds
that rule, exact-label deduplication and declared transition/comparison caps;
it does not truncate an exact frontier into a claimed optimum.

Pareto labels track common-state availability/norm, envelope, removed cuts,
seeds, charged direct work and the set of shared public digit-key levels.
Dominance is preserved by every legal transition. Memoization uses subtree
level and prefix count. The selected objective minimizes source cuts, then
direct work, seeds, digit-key level count and peak. Generic enumeration gets
the identical rules and objective. This is not an optimum over all HE systems,
mixed-radix plans, carry normalization, memory schedules or proof protocols.

## Matched resource consequences

Fix N16384/Q120/P25/t1031/eta21/D512 and the earlier owner-query/encrypted-index
phase assumptions. One packed Q polynomial is245,760 bytes. The body below
contains remaining source-cut Q polynomials and both complete terminal-Q
polynomials per response group. It is a **verification-boundary body model**,
not the client response or the historical product-only/trusted-suffix traffic.

| Selected rule | Vectors | Removed cuts | Canonical body → selected body | Extra selected rotation-key body | Direct work with three-product tensor control |
| --- | ---: | ---: | ---: | ---: | ---: |
| Per-node14, no seed, lowered suffix |8,192 |192 |180.234375 →135.234375 MiB |7.03125 MiB |42,488 versus6,904 canonical ring-product equivalents |
| Per-node14, no seed, lowered suffix |8,224 |190 |180.46875 →135.9375 MiB |7.03125 MiB |42,175 versus6,915 canonical |
| Tensor18 seed, lowered suffix |8,192 |256 |180.234375 →120.234375 MiB |1.40625 MiB |40,696 versus6,904 canonical |
| Tensor18 seed, two full groups, lowered suffix |32,768 |512 |480.46875 →360.46875 MiB |1.40625 MiB shared |151,536 versus19,440 canonical |

The32k row is an explicit two-group aggregation of the single full-group
model, not a newly encrypted/timed32k cohort. Common keys are charged once.
The8,224-vector body reduction is24.68%. It has one first-stage binary node;
unaffected unary subtrees still supply common states for127 second-stage and
63 third-stage derived switches. At384 tiles the unseeded screen removes no
cuts: there are no two usable sibling states at the needed next stage. The
advantage depends on geometry and cannot be advertised for every fill ratio.

The original uniform14 plan pays21.09375 MiB of extra rotation keys. After the
last retained/derived level, every node is canonical and discards state, so
canonical30 keys can replace that suffix without a radix conversion. Replaying
the changed complete envelope reduces the extra key body to7.03125 MiB above.
The mixed rule uses14 bits at levels0–2 and30 thereafter. Its shared public
A-digit packed body is4,644,864 bytes, additional to ciphertext/key state and
scratch. These are sufficient representation prices, not measured memory.

Raw direct models charge four tensor products plus canonical30 relinearization.
The actual small evaluator uses Karatsuba's three tensor products. The table
gives both controls that opportunity by subtracting one product per tile;
[the cost addendum](../../../research-data/gadget-cut-planner-20261003/review/cost-accounting-addendum.json)
preserves the arithmetic. Direct integer-state formation and modular correction
products need not have identical wall-clock costs. Their counts predict no
latency ratio. The stronger [factorized/streamed/expanded known controls](gadget-cut-factorization-20261003.md)
remain mandatory: eliminating explicit integer-state materialization may change
the producer/checker tradeoff substantially.

Original index/query, key origin, digit preprocessing, transforms/permutations,
allocations/scratch, complete checking/proof, terminal conversion, protected
execution, network and lifetime/update costs remain additional. The smaller
source body alone is insufficient to establish a useful complete system.

## Closest work and the precise return

Two more primary PDF/text pairs and one official design HTML/text pair are
archived with hashes. The registry preserves its earlier106 source records;
it now has109 primary records, **not109 papers or full proof audits**. Rendered
Chen page9 and CiFlow page4 were visually inspected. No author artifact or
performance result was reproduced.

| Primary control | Relevant established method | Decision here |
| --- | --- | --- |
| Hao Chen, [relinearization placement](https://arxiv.org/pdf/1711.06319v1), §4 | State DP for circuits with at most one outgoing edge per vertex; general hardness result in its own model | Tree placement DP is known. Neither its polynomial bound nor hardness automatically transfers to our multi-resource grammar |
| [HEIR relinearization ILP](https://heir.dev/docs/design/relinearization_ilp/) | Explicit eager/lazy maintenance placement and key-degree constraints | An optimizer for maintenance locations is not a contribution by itself; our semantic rules must be supplied equally to generic controls |
| Neda et al., [CiFlow](https://arxiv.org/pdf/2311.01598v4), §IV | Dataflow changes reduce working state and improve reuse in key switching | Streaming/fusing public digit families is an established control, not originality inferred from a large expanded matrix |
| [Homomorphic gadgets2022/347](https://eprint.iacr.org/2022/347.pdf), [bivariate2023/771](https://eprint.iacr.org/2023/771.pdf), [relaxed maintenance2025/286](https://eprint.iacr.org/2025/286.pdf) | Bounded noncanonical representations, public decomposition products and noise-controlled relation relaxation | Supply explicit compatible adaptations under the same Q/P, key origin, complete relation and preprocessing/state prices; no theorem or author timing is transferred unchanged |

**Q70 return:** exact finite planning, bounded encrypted correctness and a
matched key-suffix cost control are complete. The literal claim of a novel
tree DP/ILP, gadget propagation or public factorization is rejected as a main
contribution. This does not refute the remaining systems hypothesis: a complete
verified evaluator can spend deterministic noise slack to reduce paid
canonical source boundaries. Its prior separation and complete usefulness are
still unresolved. Do not turn another parameter sweep or a larger correctness
cohort into originality evidence.

Q71's [construction design](gadget-cut-native-admission-plan-20261003.md) and
[first complete generic relation component](gadget-cut-relation-results-20261003.md)
are now complete. The next component is its full-resource matrix-free/fused
residual adapter. It must permit the strongest generic gadget and
matrix-free/fused controls to use this same per-node rule. Only a precise,
useful surviving systems difference activates the isolated native build and
Q72 lifecycle timings. Retain prepared full replay, checked-products/trusted
suffix and the explicitly permitted plaintext cache. Keep no accepted original
main or production assurance until those gates are actually met.
