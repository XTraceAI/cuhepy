# E52: finite lifetime planning with exact span and noise state

2026-09-30. [Oracle/DP](../../experiments/bfv_search_lab/lifetime_planner.py),
[tests](../../experiments/bfv_search_lab/test_lifetime_planner.py),
[raw model](../../benchmarks/results/publication-lifetime-oracle-20260930.json).
This advances P04/P05 after the E49 stronger control fails and E50 exposes
cache limits. It is **a hindsight model**, not a learned online algorithm or
measured deployment improvement.

## Domain and boundary

The owner supplies a finite catalog of exact maps, positions, alignment and
field context. Reserved directions are explicit owner-approved bit positions:
initial rows plus anchor-XOR-direction rows generate an ordinary affine span.
Initially unused directions still cost encrypted columns, masks and state.
Every map is certified against every candidate revision; an edit outside its
span is rejected, not interpreted approximately. Stable IDs and row count stay
fixed. Insertions, deletion and arbitrary partition migration are outside this
first oracle.

A trace records revisions, query counts and the initial number of prepared
tokens. All prepared tokens are charged, including those never used. Each
query burns one abstract token; refresh/migration processes only remaining
never-exposed pads. Migration may regenerate unused pads for a new coordinate
domain; it does not recycle a released pad. This is a model of that permitted
transition, not a durable implementation of it.

State is `(exact catalog entry, ciphertext noise age, revision)`. The revision
fixes current owner rows and the consumed-prefix/pending count. With the fixed
trace and profile, this state determines every future feasible action and
incremental cost. The noise envelope is `age * B_fresh_circuit`; repair raises
age, while complete reencryption resets it. Repair is disallowed before a
universal response bound reaches Q/2. This conservative envelope covers all
query values, not sampled requests.

## Exact restricted DP and independently enumerated schedules

Start with each feasible catalog entry, enrolling its full index and pool.
At each revision enumerate same-entry sparse repair, fresh refresh or a
feasible catalog migration. Keep non-dominated additive work / peak-state
vectors **only within identical boundary states**. At the final revision,
take the complete cost Pareto frontier across states. No rank beam or estimated
time objective silently discards alternatives.

Conditional optimality within this finite model follows by induction: every
legal first choice is enumerated; every legal successor is enumerated; states
with identical boundary semantics admit identical future costs/actions.
Adding the same nonnegative work and taking the same peak-state maxima
preserves dominance, so pruning a dominated prefix cannot remove a better final
vector. Equal-cost prefixes at the same boundary require one witness. Distinct
noise ages and exact map catalogs remain separate. This does not prove global
partition optimality, polynomial complexity or real service optimality.

The exhaustive reference never prunes intermediate prefixes. It shares the
explicit transition/pricing definitions, so hand-counted token-cost tests,
independent exact score oracles and a phase-forced-refresh test audit those
definitions. Two reported traces and twelve bounded randomized traces give
identical DP/exhaustive final cost sets. Reported prefix counts are 4/4/4 versus
4/10/15 for the span trap, and 4/6/9 versus 4/10/15 for repeated sparse edits.
State count can grow exponentially; the hard cap rejects before materializing
an unbounded next frontier.

An integration regression also enrolls a reserved map with an initially zero
column, performs two genuine encrypted E43 repairs, consumes all six original
tokens exactly once, and compares every adaptive score plus full native/GMP
coefficients and independent integer phases. An unreserved-bit edit is rejected
without changing the index. This exercises the mathematical transition; the
per-epoch local checker test is not a global durable malicious-attempt budget.

## A concrete static-state counterexample

Initial d=3 rows are `{000,001}`. Reserving bit 1 versus bit 2 produces maps
of rank two with **identical static resource vectors**. After the approved
second row becomes `011`, the bit-1 reserve still certifies it and admits
repair; the bit-2 reserve does not. A rank-only/static-vector merge therefore
forgets information necessary to decide future feasibility. This is a stronger
algorithmic obligation than observing a rank/payload correlation.

It is also ordinary subspace mathematics. The counterexample proves the
required state distinction; it does not by itself establish an original
publishable algorithm. Closest dynamic HE/compiler/PIR planning comparisons,
a deployable policy and workload evidence remain mandatory.

## Cost scope and next execution

The eleven-axis model retains fresh/additive ciphertext coefficients, private
dot terms, modeled certification terms, public evaluation products, complete
check products, response bytes and peak client/owner/pending/server bodies.
The current client's public-key/secret-key bodies, IDs, private maps and checker
are included. Native word arrays, int8 coordinates and unused answer/pad/check
state are charged. Catalog fitting/certification and both oracle runtimes are
reported separately. Counts are **not calibrated milliseconds or RSS**;
framing, provisioning, compiler scratch and durable execution remain additional
costs. Do not read the model frontier as a Gate C result.

Next return to P05/P06: run reserved-span encrypted transitions against fresh
reencryption and ordinary delta indexing; record real-data span failures;
calibrate prices from complete native traces; train a reserve/rebase policy on
one trace family and assess it on held-out traces. Compare no-reserve, raw,
static-affine, hindsight oracle, compact caches and vectorized owner production.
Only then decide whether joint lifetime planning adds more than established
incremental linear algebra and automatic HE layouts. Authentication, durable
one-use state and private timing remain P07/P08 work; new GPU kernels remain
behind their practical-effect gate.
