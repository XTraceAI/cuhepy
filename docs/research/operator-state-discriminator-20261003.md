# Q57 / B2: complete native butterfly operator/state discriminator

2026-10-03. The bounded static discriminator is complete. A real native
butterfly gives non-additive shared-state costs, but the equally specialized
generic affine/adjoint control obtains the identical dictionary and cut choice.
**Stop the literal normalized-operator/set-union proposal as an original H1
mechanism; it does not qualify an original Q58 compiler implementation.** Keep
the exact representation, negative result and index-dependency invariant for
native controls and the separate bounded Q59 update control. E101/E110 remain
closed; this report neither reverses them nor concludes every compiler is known.

[Blueprint](system-research-blueprint-20261003.md),
[typed oracle](../../experiments/bfv_search_lab/operator_state_discriminator.py),
[31-test suite](../../experiments/bfv_search_lab/test_operator_state_discriminator.py),
[static runner](../../benchmarks/operator_state_discriminator_lab.py).
Raw dictionaries, result JSON, exploratory objective cards, source snapshots,
primary readings and validation are retained under
`../research-data/native-verification-system-20261003/operator-state/`.
**No HE/GPU timing, real key/index enrollment, admission protocol, TEE,
security-profile change, or production client change was performed.**

## Actual graph and nonlinear boundaries

The source schedule is `_native/trace_server.h`, its persistent-RNS equivalent
`_native/residue_trace.h`, and the independent `butterfly_bgv.py` reference.
For each tile, fix enrolled encrypted components `(A0,A1)` and public query
components `(q0,q1)`. Tensoring gives

`t0 = A0*q0; t1 = A1*q0 + A0*q1; t2 = A1*q1`.

The source `t2` is a mandatory canonical full-Q polynomial. The checker derives
all radix digits from that single source; digit variables are typed independent
inputs to the following affine segment, never linear functions substituted
through a carry. Shift the two relinearized components by `X^(1-D)`.

At a butterfly node let `H=X^h`, `a=1+2N/D` raised by successive squarings,
`plus=A+H*B` and `minus=A-H*B`; omit B if absent. The exact equations are

`r = sigma_a(minus1)` (mandatory canonical source),
`out0 = plus0 + sigma_a(minus0) + sum_j K[j,0]*digit_j(r)`,
`out1 = plus1 + sum_j K[j,1]*digit_j(r)`.

In particular, **out1 does not add `sigma_a(minus1)`**: that value is the
switching source. A one-tile partial group still takes all `log2(D)` stages.
Both complete final full-Q polynomials are constrained. Subsequent terminal
rounding remains trusted, over every coefficient; its compact response and all
context/ID/epoch/packet bindings are separate obligations, not omitted checks.

## Exact normalized family and dependency lemma

Operators normalize to integer-weighted sums

`X^h * sigma_b(k) * sigma_a(x)`.

Here `k` is either one fixed encrypted-index component, one fixed switching-key
polynomial, or absent. Exponents reduce modulo `2N`, `X^N=-1` gives the sign,
like terms combine and zero coefficients disappear. The code applies
`sigma_a M_k = M_(sigma_a(k)) sigma_a` and composes shifts/automorphisms exactly.
The dictionary is a sufficient **formal generating dictionary**; independence,
minimum state, and accidental numerical equalities between actual keys are not
claimed. Numeric enrolled-key matrices were not instantiated at large sizes.

Every path in an affine segment contains at most one fixed convolution factor.
To see this, tensor edges introduce their one index factor, whereas switching
edges introduce one key factor on a fresh opaque digit input. Their intervening
edges are only additions, shifts and automorphisms. Mandatory canonical digit
cuts break every potential tensor-to-key or key-to-key composition. Induction
therefore gives degree one in a single index/key symbol per term; the typed
normalizer rejects a proposed composition containing two fixed factors.

Consequently all **query-input coefficient maps** are linear in the encrypted
index. Every coefficient map multiplying a canonical value, derived digit, or
retained optional value is index-independent. A tile update can change many
descendant canonical **values**, but does not thereby invalidate their checking
coefficient maps. This distinction is useful for Q59; it is known affine
factorization, and the generic control receives it too. Fresh epoch coins still
require rebuilding their adjoints.

## Six exact static cards

Use the existing `N=16384, D=512, four Q120 radix digits` shape. Each tile holds
32 records. The 8k geometry has one **partial** 256-tile group and 511 rotations;
32k has two full 512-tile groups and 1,022 rotations. Keys are shared between
groups, but their enrolled encrypted-index symbols are distinct.

Three complete streaming policies are counted:

- **Every local cut:** transmit all three tensor components, both shifted
  product components and all rotation source/output components.
- **Product cut:** retain both shifted product components and all mandatory
  rotation sources/final values; eliminate tensor0/1 and rotation outputs.
- **Maximal affine elimination:** keep only the tile C2 sources, rotation
  sources and complete final values.

Every transmitted polynomial in this deliberately uniform body model uses
canonical Q120 integers, 15 bytes per coefficient. Digit strings are derived,
not transmitted. This is one serialization model, not a lower bound or the
existing native packet ABI. RNS-only optional cuts could use different bodies.

| Geometry | Streaming policy | Full-Q witnessed polynomials including terminal | Canonical body MiB | Distinct fixed-key/pure atoms | Distinct tile-index atoms |
| --- | --- | ---: | ---: | ---: | ---: |
| 8k | Every local |2,813|659.296875|107|512|
| 8k | Product cut |1,281|300.234375|486,664|768|
| 8k | Maximal affine |769|180.234375|882,941|135,681|
| 32k | Every local |8,186|1,918.59375|109|2,048|
| 32k | Product cut |4,098|960.46875|617,736|3,072|
| 32k | Maximal affine |2,050|480.46875|1,410,297|542,722|

The large key dictionary is concrete evidence against a small atomic operator
family after eliminating cuts. It is **not** evidence that verification must
store all those vectors. One uint64 coefficient vector per atom, per two primes
and three check rounds, would cost about 356/647 GiB for the 8k product/maximal
cards and 452/1,033 GiB for the 32k cards. These infeasible **models** defeat that
literal materialization policy, not the generic verifier.

The stronger generic control can instead precombine weighted operators into
one vector per used input source, or choose atomic vectors where their dictionary
is small. All index contributions can be summed into just **two query adjoints
per prime/round**. For non-query sources, a simple fully bundled control charges
`4*(T+V)+optional_cuts` vectors, plus those two query vectors; canonical target
terms share `v` and row scalars `u`. Its modeled large-vector state is 3.75/2.62/
2.25 GiB at 8k, and 10.49/7.50/6.00 GiB at 32k for local/product/maximal policies.
This is another sufficient policy, not a minimum. The local atomic fixed-key
dictionary alone is about 80 MiB; online folds, v/u, original query state,
enrollment, memory access and all repeated combinations must additionally be
charged. The static oracle does **not** decide which policy has lower latency.

The same terminal compact body model is 102,400 bytes per group (P25 bit packing),
so 102,400/204,800 bytes at 8k/32k before framing. It does not absorb verifier
witness traffic. The 767/2,046-source figures in the blueprint exclude two/four
terminal full-Q values; this complete model includes them.

### Product-only continuation is a different row

The known product-only checker followed by trusted continuation returns two
product components per tile over two uint64 limbs: 128 MiB at 8k and512 MiB at
32k. Witness-C2 mode adds64/256 MiB, making192/768 MiB total arithmetic bodies
before framing. Local-C2 mode omits that witness but computes256/1,024 trusted
products. Both then execute511/1,022 trusted rotations and complete terminal
conversion. This is distinct from the complete streaming **product-cut** policy
above. No product output, C2 witness, trusted suffix, or canonical terminal work
is free because the final client packet is compact.

## Minimal actual-graph non-additivity and strongest control

Take `N8,D4,two tiles,two digits`; vary the two optional components of the first
product, retaining every mandatory source/final value. The exact dictionaries
are:

| Optional cuts | Fixed atoms | Index atoms | Total atoms | Exact illustrative cost (atoms +3 per cut) | Baseline-marginal additive prediction |
| --- | ---: | ---: | ---: | ---: | ---: |
| Neither |47|17|64|64|64|
| C1 only |47|15|62|65|65|
| C0 only |44|16|60|63|63|
| Both |42|12|54|60|64|

The fixed-state mixed difference is `47+42-44-47=-2`. Set-aware enumeration picks
both cuts, whereas a predictor using independently computed baseline marginals
picks only C0. Thus the blueprint's non-additivity distinction **does occur in
the real graph**; a per-edge additive objective can choose differently.

The penalty3 was selected **after inspecting the four dictionaries** to exhibit
the choice difference. The initial penalty1 card is retained separately and
both rules choose both cuts there. These units are illustrative, not serialized
bytes, physical latency, a preregistered workload weight, or a practical win.
The strongest generic sparse compiler normalizes and counts the same exact
relation and obtains **every exact cost and choice**. This leaves no new rewrite,
compact sufficient state, recurrence or approximation guarantee to carry into
Q58. Generic set memoization/exhaustive enumeration is not claimed original.

## Oracles, adversarial scope and evidence lineage

31 tests pass. Nine tiny full/partial geometries compare typed execution with
an independent literal schoolbook butterfly and check all three policies.
Every retained target polynomial, including terminal coordinates, is mutated
and participates in the complete residual relation. Sixteen tiny product-cut
subsets match the generic full-expression oracle. The matrix-free census matches
that oracle's entire formal dictionary; negacyclic word identities, wrong rings,
nonunit automorphisms, geometry, digit carries and missing mandatory cuts are
covered. Index-update exact linear differences are also checked as algebra.

These tests do not authorize a client decrypt, implement field challenges,
parse an untrusted wire tape, or prove a malicious-server protocol. Uniform
bilinear checking has the known worst-case `(2/p-1/p^2)^tau` bound only under
the blueprint's fixation/challenge hypotheses, per worst affected prime, and
the corresponding lifetime/error budget. No fresh or reusable production coins
are introduced by this count oracle.

The six large cards are direct matrix-free symbolic propagation, not HE runs.
Dictionary files and hashes allow exact reconstruction. The initial execution
sources are archived; adding `strict=True` to equal-length tuple zips during
the static census did not change the dictionaries. A later **separate** tiny
objective artifact adds the disclosed penalty3 discriminator and preserves
the original penalty1 result. No large raw result was overwritten. Ruff checks
use `force-exclude=false`, since experiments are excluded by the repository's
default configuration.

## Targeted primary comparison and return

[Structured matrix-vector verification](https://arxiv.org/abs/1704.02768v1)
already considers structure-aware probabilistic/cryptographic checking; a
dense independent-matrix control would be weak. [vFHE §V-B/Appendix D](https://arxiv.org/html/2301.07041v2)
already delegates expensive FHE tensoring to untrusted hardware with randomized
equality checks and TEE execution. Its tensor argument is not silently treated
as our complete canonical-maintenance/terminal verifier.

[KeyMemRT v1](https://arxiv.org/abs/2601.18445v1), §4.1/4.2.1–4.2.10, explicitly
types rotation-key identities, merges repeated key lifetimes with dataflow
analysis, hoists common-input work, clears at last use and inserts prefetch
hints. Its lifetime scheduling is a concrete shared-state control; it does not
itself establish our complete verification relation. The new PDF/text pair and
rendered pages6/7 are pinned with hashes. Fhelipe remains the existing layout
compiler control. No competitor speedup is transferred to this static census.

**Return:** retain these known-control building blocks for Q56 and Q59. Close
this literal H1 originality gate and do not start a new Q58 native compiler or
Q60 timing campaign solely because non-additivity exists. A future H1 proposal
must specify an additional exact transformation or algorithmic guarantee and
survive the same generic normalization/sharing control. Q59 may independently
test the known update factorization, with state reuse/lifecycle security and
authenticated GPU tile replacement still explicit unfinished obligations.
