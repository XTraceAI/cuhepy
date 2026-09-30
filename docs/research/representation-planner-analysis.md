# P02/P04: finite exact boundary-state planner

2026-09-30. Implemented in `representation_oracle.py` and
`representation_planner.py`; research-only, bounded owner-side code.

## Grammar and exactness scope

Fix an index-order median discovery tree, a profile, and elementary slot counts
from `{1,2,4,8}`. Every node may use raw binary coordinates, a certified affine
map, or the two recursively chosen children. Exact identical maps are grouped
in first-occurrence order. Every positive contiguous slot allocation is tried,
and its equal-map dyadic regions coalesce. Final CRT geometry is independent
of discovery paths. Existing CRT/rank/phase gates reject infeasible candidates.
This is not an optimum over arbitrary partitions, reordered groups, fields,
public leakage or encryption security parameters.

The DP boundary state records each exact map and all assigned row positions,
in first-occurrence group order. By induction, every grammar choice occurs in
the node's cross product. Two choices with the same state induce the same
complete map groups, feature counts, column-sharing identities and final
allocation choices. Their circuit, restoration, maps/IDs/checker bodies and
static resource vector are identical. Retaining one representative therefore
preserves every complete static resource vector. No partial rank or scalar
cost dominance is used. Hard work caps apply before exponential allocation.

The planner computes Pareto dominance only after complete compilation and
only within one identical profile. It keeps cost ties because their provenance
may matter for later update policies. Equivalence for arbitrary future refits
is **not** proved: a lifetime DP must additionally retain source node/mode,
capacity, noise and pad-history state. The current E43 implementation freezes
the exact maps and geometry.

Independent exhaustive grammar tests compare all complete resource vectors
and all-pairs Pareto frontiers against the DP on six sharing/fixture settings.
Tiny score tests cover every binary query across accepted layouts, plus native
encrypted adaptive queries and phase checks. Stable IDs, duplicate vectors,
row coverage, field mismatch, work caps and invalid budgets are exercised.

## Controls and results

Four retained fixtures compare raw/global affine, local affine, exact form
sharing, a rank-first beam of width one, and the exact static frontier. All
selected plans match all 256 binary queries. Counts include ID/permutation
state, seeded offline answer bodies, owner coordinates and complete checking.
They are not measured request time or RSS.

For random data, a minimum-column plan has `F=7, h=20, W=26`, while raw global
has `F=h=W=8`. Both return one 512-byte reply. The rank-first choice saves
12.5% of index/server product counts but grows the client audit body model
from 721 to 1,171 bytes and checker products from 680 to 770. This is a precise
counterexample to treating rank as the whole objective, not a new primitive.

For shared affine planes, equality merging yields `F=h=W=2`, and global affine
has `F=h=W=4`. The local plan's audit body is 676 bytes versus the global
645 bytes, so a slightly larger state budget can buy much less index work.
The gain is explained by ordinary affine/equality merging; it does **not**
pass the plan's originality gate by itself. Constant and unrelated-plane
negative controls are retained, as are beam misses and rejected geometries.

An allocator correction deserves nuance: with common padded D and elementary
capacity c, old input-tile minimization minimizes L with constraints
`m_i <= L*a_i*c`. Response minimization minimizes R under
`m_i <= R*a_i*(D*c)`. Since `ceil(ceil(x)/D)=ceil(x/D)` for positive integer D,
minimizing L can already minimize R over the same allocation set. One must
not claim that changing the objective inherently lowers reply count. Tied
allocations, redistribution across coalesced leaves, W, checking and state
are the dimensions to examine. The new oracle independently enumerates them.

## Decision

Static tradeoffs and exact finite optimization are implemented. A standalone
claim of novel affine compression, equality merging, packing DP or fingerprinting
would be unsupported. Gate B remains open. Move the stronger hypothesis to
joint lifetime/noise/pending-work planning, while completing the low-state
baseline comparison. E43's retained measured positive and negative cases are
the first follow-on, not proof that the final contribution is novel.

Raw evidence: [finite-frontier artifact](../../benchmarks/results/publication-joint-oracle-20260930.json).
