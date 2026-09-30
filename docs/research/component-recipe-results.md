# E48: a public component recipe trades bytes for client work

2026-09-30. Homemade implementation:
[`component_recipe.py`](../../experiments/bfv_search_lab/component_recipe.py);
paired benchmark:
[`component_recipe_lab.py`](../../benchmarks/component_recipe_lab.py).
This is a known seed-recomputation technique applied to the current masked
linear circuit, not a new encryption or compression primitive.

## Exact mechanism and verification boundary

For the authorized index, the response is
`T_r + sum_j C_j * alpha_j(delta)`. Its second component depends only on
the public encryption seeds of C_j and T_r, and the public masked correction
delta. The client reconstructs that component; the server sends only the
first component. The prescribed result is exactly the original two-component
ciphertext, not a rounded or lower-modulus substitute.

The existing complete ciphertext check still runs before secret decryption.
Index and answer seeds come from trusted owner preprocessing, bound to the
same context, epoch and token. Neither a private mask seed nor a checker seed
is exported. Mutated first components, index/answer seeds, truncated bodies
and stale epochs are rejected; failed attempts consume the old check budget.
These tests do not implement authenticated remote setup or durability.
The encryption proof still requires the seeded-XOF premise in P07.

The cached implementation retains a public native index. The streaming version
expands one public column at a time through the existing native ABI. Both
implementations use homemade arithmetic. Fresh fixed indices are supported;
additive update seeds require an authenticated expression graph and rebasing
policy, which is not implemented.

## Matched CPU pilot

N=16,384, Q32, eta=21; same index, request, full ciphertext, complete vector
check, exact full scores and stable top-3. Three measured adaptive queries per
fixture, plus a warmup. Both serializers charge validation and GMP conversion.
Times are paired measured stage sums, not elapsed network requests.

| Public fixture | Full reply / local work | Cached recipe / local work | Streaming recipe / local work |
|---|---:|---:|---:|
| Mushroom, 7,996 rows, d=126, t=193 | 131,072 B / 56.50 ms | 65,536 B / 67.84 ms | 65,536 B / 229.49 ms |
| Semeion, 1,465 rows, d=256, t=257 | 131,072 B / 58.45 ms | 65,536 B / 70.53 ms | 65,536 B / 190.09 ms |

At the paired median extra work, saving 65,536 bytes pays for cached
reconstruction below roughly **46.2 / 43.4 Mbps** respectively. Streaming
crosses over near **3.0 / 4.0 Mbps**. These are directional bandwidth models:
no overlap, equal omitted RTT/query upload, no contention or measured sockets.
The 50% reduction is response coefficient body size, not complete authenticated
transport, provisioning traffic or lifetime cost.

Cached public native arrays cost **8 MiB / 5.75 MiB** respectively, in addition
to common client state. Public index seed bodies are 1,024 / 736 bytes and
public answer seeds cost 32 bytes per token. Streaming's one-column native
array is 256 KiB of scratch; Python/GMP buffers and other transient objects
make actual peak memory larger. This is not a low-RSS measurement.

The full plaintext-cache control remains decisive: scan plus stable selection
takes about **2.8 ms / 0.4 ms** in these runs. Packed rows plus IDs need only
191,904 / 58,600 bytes before object overhead, much less than the public native
cache. Thus cached E48 is a poor small-client-state answer for these fixtures
when plaintext caching is permitted. Even the public author BNTM reference
has smaller response bodies: 63,968 / 11,720 bytes. Its state/protocol costs
are separately documented in [P01](baseline-reproduction.md); timings from
different harnesses are not combined here.

Raw matched results:
[`Mushroom`](../../benchmarks/results/publication-component-recipe-mushroom-20260930-matched.json),
[`Semeion`](../../benchmarks/results/publication-component-recipe-semeion-20260930-matched.json).
The [first pilot](../../benchmarks/results/publication-component-recipe-mushroom-20260930.json)
at `d2c198d` omitted full-codec integer conversion from its timer. It is retained
as preliminary evidence and superseded by the matched scope, not overwritten.

## Decision after returning to the plan

P10 screening passes exactness and falsification requirements for this bounded
candidate; the whole alternate-hypothesis package remains open. E48 does not
pass originality Gate B or full-lifetime Gate C. Retain it as an optional slow-link
tradeoff and a compiler cost dimension, including its adverse state/time costs.
Do not invest in a new GPU kernel yet. Possible next tests are amortized client
setup, seed-expression growth over updates, and complete authenticated wire
traffic. Any outsourced reconstruction remains inside the complete verifier
boundary; the current experiment trusts the local reconstruction code.
