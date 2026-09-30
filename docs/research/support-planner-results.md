# E65: exact support-aware static grammar and stronger simple controls

2026-09-30. **No new optimizer speed/contribution claim survives this screen.**
The homemade static supplement is retained for correctness and future falsifiers.
It is deliberately narrower than the full lifecycle proposal: no base-revision,
noise-age, mask-exposure, seed-visibility or global-allowance optimization has
been implemented by this module. Existing lifecycle oracles remain separate.

`experiments/bfv_search_lab/support_planner.py` retains the original exact
private-map/row boundary state and parameter profile. For every final contiguous
CRT cover, it enumerates all capacity-valid distributions of a map's ordered
rows over that map's leaves. It prices the actual supported-C0/full-C1 body,
while retaining full index, answers, checker work and owner/client state charges.
No partial plan is discarded on rank or the old full-body vector. The reported
frontier is final **static** dominance; all full candidates remain available.

Independent Cartesian count traversal agrees with the bounded composition
generator; exhaustive raw/affine grammar agrees with the boundary search.
Every decoder basis column and all binary queries of the named workloads pass
all-score, stable-ID and tie references. The restricted-domain completeness
argument is simple: the original boundary grammar enumerates exact map/position
states; each complete cover fixes leaf capacities; bounded compositions list
every nonnegative per-map allocation with the required sum; canonical slicing
preserves all original positions. This says nothing about arbitrary partitions,
score permutations, online/lifecycle optima or security.

## Executed sequence and decision

| Retained raw suffix (`publication-support-planner-…-20260930.json`) | Scope | Result |
|---|---|---|
| `oracle` | 16 named cases,624 candidates,6,336 full-score query checks | Ordinary proportional balancing matches exhaustive wire optima |
| `expanded-oracle` | 20 cases,792 candidates,9,024 checks; unequal12/4 fixed discovery split added | Six fixed geometries improve224→192 B, entirely explained by balancing |
| `random-oracle` | Same20 named cases plus32 bounded irregular catalogs, seed67501;1,115 additional candidates | Balancing misses one static frontier point; minimum overall wire size remains equal |
| `refinement-oracle` | Same declared catalogs; one-row strict-descent control added **after** the irregular screen | Refined controls recover every tested static frontier; no remaining catalog advantage |

The irregular catalogs certify every decoder matrix and independently traverse
row allocations. The9,024 exhaustive binary-query checks apply to the named
cases; they are not claimed for all random catalogs. The follow-up is a stronger
control on the same instances, not a held-out performance evaluation.

The instructive irregular example is N16/t17, rows
`7,4,6,2,7,1,0,0,7,0,6`, fixed split1/10, allocation1/3. Splitting off the
singleton affine block gives ranks0/3. Proportional allocation `(1,4,6)` has
128 B projected reply and132 B query+reply. Moving one row to `(1,3,7)` omits
two unused C0 coordinates:120 B reply and124 B query+reply, a6.06% body saving
at this fixed geometry. This single-row control takes four modeled candidate
evaluations and one accepted move; it matches the exhaustive result.

The point survives the initial static frontier only because its modeled owner
coordinate body is31 B versus33 B for the111 B global query+reply control.
Its client audit body is559 B versus364 B. This two-byte count-model tradeoff
is not a useful system improvement, RSS saving, deployment advantage or paper
contribution. A singleton known to the owner also motivates a stronger local
constant-row control; full plaintext caching is already permitted.

For any fixed full-rank linear score decoder in this deletion-only domain,
`rank(D_t)=m` implies at least m kept phase coordinates. Keeping all C1 therefore
costs at least `m+R*N` coefficients. A full-ring score-only leaf attains this
count. This is a **restricted coefficient-deletion** floor, not a lower bound
against public reconstruction, extra preprocessing, key switching, local
known scores or different output functionality. E48 already changes the domain
by reconstructing C1 locally. The [relation specification](supported-decoder-relation.md)
states the exact omission/minimality scope.

Seven tests retain Cartesian/exhaustive agreement, every score/ID/tie,
cross-profile isolation, invalid membership/counts, work limits and the
irregular example with its stronger control. The final runner's immediate
refinement call was later moved to a named helper for lint; executed source
versions remain committed and hash-resolvable. Old raws are never rewritten.

Return to plan: preserve the relation/codec and count oracle, decline a
native/GPU implementation of a purported novel exhaustive optimizer. Any next
compiler candidate must beat global/raw/affine, proportional allocation,
single-row refinement and permitted caches, and demonstrate a new protocol
consequence. A dependency/recipe/lifetime composition is still a hypothesis;
the current E65 screen has not implemented or validated it.
