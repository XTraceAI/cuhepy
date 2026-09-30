# E55: exact finite checkpoint and private-exception frontier

2026-09-30. `overlay_lifetime.py` extends the existing lifetime count oracle
with E54's known private client delta control. It is a finite hindsight model,
not a measured online policy or a new encryption protocol.

At each revision keep a frozen encrypted base and privately correct current
scores, or rebuild/migrate to a feasible current catalog entry. An unchanged
base can answer rows outside its old affine span because the client adds
exact private bitmask corrections after the full base response gate. Every
unused original token is charged on a rebuild. Corrections, range scans,
private owner-to-client bodies and peak base/current row bodies are charged
in addition to encrypted work/state. Refreshes do not grant a new mask-use
budget, and frozen bases do not accumulate HE noise from edits.

The exact boundary is `(catalog entry, base revision)`, with current revision
and remaining original tokens implicit in the trace level. Merely retaining
current rank, cost or exception count is insufficient: two bases with the
same current exception count and identical current incremental cost can have
different cancellation behavior on the next edit. A regression constructs
that counterexample. Retaining base revision distinguishes every needed old
row pattern without inventing a count-only Markov assumption.

For equivalent boundaries every future action has the same feasibility and
nonnegative additive work/traffic; peak resources compose by maximum. A
dominated cost vector can therefore be removed. Exhaustive successor
enumeration followed by this pruning preserves the complete Pareto frontier
inside the stated catalog/trace grammar. This ordinary DP argument does not
prove polynomial state size, optimal arbitrary partitions, a cryptographic
reduction or originality. Work caps explicitly reject rather than silently
substitute a beam search.

`test_overlay_lifetime.py` compares DP with exhaustive schedules, ten random
traces, all-unused-token rebuild counts, out-of-span updates, cancellation,
peak retention and caps. Two retained tiny four-revision traces yield six and
seventeen frontier points with exact oracle agreement:
`benchmarks/results/publication-overlay-frontier-20260930.json`.

Return to P04/P06: measured prices, causal policy evaluation and complete
encrypted migrations are still required. The frontier now includes a stronger
simple control; it does not demonstrate a new dependency-aware algorithm beats
that control. E54's composition premises remain necessary.
