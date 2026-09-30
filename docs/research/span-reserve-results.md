# P05: held-out replacement spans versus known schema controls

2026-09-30. `benchmarks/span_reserve_lab.py` is an exact finite-field screen,
not an HE/update-time measurement. Raw:
`benchmarks/results/publication-span-reserve-20260930.json`.

Enroll the seed3001 index split. Fit each block using enrolled rows plus zero,
four or sixteen training replacement examples. Test 32 disjoint source rows
as hypothetical replacements at uniformly chosen stable IDs. The training
and evaluation slices are disjoint for this experiment; these public datasets
were explored earlier and are not a blinded publication test set. They are
not actual customer edit traces. Every enrolled row is certified, and a
separate batch reconstruction tests replacements with API spot controls.

| Dataset / block size | Index-only fit | Reserve4 | Reserve16 | Public schema / raw |
|---|---:|---:|---:|---:|
| Semeion / 128 | 0% | 0% | 0% | 100% |
| Semeion / 512 or global | 100% | 100% | 100% | 100% |
| Mushroom / 128 | 87.07% | 87.27% | 88.38% | 100% |
| Mushroom / 512 | 95.07% | 95.07% | 95.07% | 100% |
| Mushroom / global | 100% | 100% | 100% | 100% |

Semeion's 128-row blocks have maximum initial affine rank127; reserve16 raises
this to143 yet accepts none of the tested replacements. A 512-row or global
block already has full rank256. Mushroom's global fitted rank85 accepts all
tested rows; its fixed public one-hot schema has rank104. The schema anchor
selects one category in each of 22 published attributes and its basis has one
`e_j-e_anchor` vector for every other category: rank126−22. It contains every
schema-valid one-hot row independent of enrollment. This is known categorical
algebra, not a novel reserve mechanism. A public schema may avoid private
data-derived discovery/leakage, but its extra query columns still cost work.

All candidate fitting/certification and catalog exploration are timed. Separate
map bodies, maximum rank and sum of ranks are recorded; the sums do not account
for equality sharing, CRT allocation or HE parameter thresholds. No latency,
noise, online-policy or security claim is inferred from acceptance fractions.

Return to the plan: reject the premise that a handful of learned directions
solves arbitrary local span changes on these fixtures. Keep global/schema/raw
maps and private client deltas as controls. A learned reserve policy needs a
justified structured edit distribution, complete migration costs and held-out
evidence before promotion. Do not invent such a distribution to force a win.
