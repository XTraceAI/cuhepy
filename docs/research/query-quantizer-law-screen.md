# E114: exact ideal query-quantizer law, two-card return

2026-10-03. **Conditional ideal-mask fact; known control matches; literal recipe
stops. No deployed sampler, protocol or parameter approval.**

The [frozen specification](query-quantizer-law-preregistration.md) preceded all
new implementation/tests/card execution. The selected
[raw receipt](../../benchmarks/results/publication-query-quantizer-law-20261003.json)
records exactly two cards: N16384, d512, count8192, t1031, CBD_eta21, radix15,
query drops22 and23. Q1152921504606748673 is the actual source-selected60-bit
NTT prime; P4294953991 is the existing compact32 prime. There was no new key
setup, native/GPU execution, timing benchmark, additional profile/drop grid,
proof backend or production change.

## 1. Result and return to the plan

| Registered query drop | Complete deterministic common-digit bound | Ideal conditional lifetime upper bound | Declared query packet | Declared query+response |
| ---: | --- | ---: | ---: | ---: |
|22|passes|2^-2722|100460 B|231624 B|
|23|rejects|2^-2595|98412 B|229576 B|

The statistical bounds assume a **unit secret and a genuinely uniform fresh
full-ring mask**, independent of fresh CBD errors, with the query chosen before
its own mask. They apply to the sufficient complete correctness event described
below, including all unused output coefficients and all2^32 query invocations.
They are exact conservative rational upper bounds on that IDEAL conditional
statistical component. They are neither observed failure probabilities nor
an actual SHAKE/ROM, secret-sampler, security or2^-128 deployment forecast.

The response model is131164 B for both cards. The conditional extra query bit
saves2048 B in the coefficient body and complete packet. These are exact counts
of the existing declared coefficient/MessagePack schema, not measured large
packet execution, proof/receipt bytes or an end-to-end performance improvement.
The owner can retain the plaintext index: its binary coefficient body is524288 B
(plus65536 B for uint64 stable IDs). Full-cache use remains a permitted control.

The equally informed generic control receives the **same exact PMF, bias,
endpoint domination, maintenance envelope, fixed base, outward rounding,
terminal margin, lifetime union and byte choices**. Its certificate equals the
candidate certificate on both cards, ratio1. This is ordinary exact counting
and Chernoff concentration, not a surviving novel mechanism. Stop this literal
recipe and retain the conditional parameter/body fact. Any actual owner-only
interface or pseudorandom-mask composition is a separately specified task.

## 2. Exact codec law and its bias

The existing rounded-query codec writes canonical c=R*h+r, R2^drop, and transmits
`t*h+(r modt)`. Reconstruction adds `t*floor(K/2)`, Kfloor((R-1)/t), before
reducing modulo Q. The unique small added lift is

```
delta = t*(floor(K/2)-floor(r/t)).
```

For Q=F*R+T, each bin k has mass

```
F*length([k*t,(k+1)*t) intersect [0,R))
  +length([k*t,(k+1)*t) intersect [0,T)),
```

with denominator Q. This accounts for the short last plaintext bin in every
radix cycle and the last incomplete Q cycle. Q is not enumerated.

| Drop | Full cycles F | Tail T | PMF bins | delta/t support | delta radius |
| ---: | ---: | ---: | ---: | --- | ---: |
|22|274877906943|4096001|4069|[-2034,2034]|2097054|
|23|137438953471|8290305|8137|[-4068,4068]|4194108|

Both laws have positive, nonzero signed bias. Exact means of delta/t are
466849888569851550/Q (drop22) and357265962875895818/Q (drop23).
The calculation does not replace these distributions with symmetric rounding
noise or discard the bias.

Full weighted PMFs and exact positive/negative MGF rationals are archived in
`research-data/query-quantizer-law-20261003/drop{22,23}-exact-{law,mgf}.json`
outside Git, with raw hashes. The largest numerator/denominator has114592 bits;
the finite geometric sum avoids one MGF term per source-Q coefficient and no
N-fold giant rational product is materialized. These are size inventories of
the exact representation, not time or memory benchmarks.

## 3. Conditioning and complete graph coverage

Condition on an owner-enrolled index and supported fixed setup/key errors.
Let s be a unit in R_Q. A genuinely uniform full-ring mask a has a*s uniform
because multiplication by s is a permutation. Conditional on any query chosen
before that mask and any fresh error vector E, c0=m+tE-a*s is therefore uniform
over the whole coefficient vector. Consequently its deterministic delta_i are
IID with the exact scalar law above and independent of E. This conclusion is
about an ideal full-Q vector, not a256-bit seeded implementation.

Write Z_i=E_i+delta_i/t. Each fixed owner-index phase coefficient has magnitude
at most W=1+t*eta=21652. Negacyclic product coefficients are weighted sums
`t*sum_i a_i*Z_i`, with fixed |a_i|<=W, plus a message contribution bounded by
d*W=11085824.

E15's established disjoint-support identity is essential: an input contribution
to each final joint butterfly coefficient is D times **one** shifted product
coefficient (or zero), D512. It is not a sum over every tile. Thus the same
per-output tail bound applies without a union over input products. Complete
output cardinality U=N*ceil(count/N)=16384 includes unused positions.

All relinearization/rotation maintenance remains pointwise. Common bounded
radix15 digits yield

```
S = t*eta*N*ceil(bit_length(Q)/15)*(2^15-1)
  = 46493749542912,
maintenance = (2D-1)*S = 47563105782398976.
```

This contains canonical digits and bounded common alternative recompositions.
It assumes neither independent reused key errors nor independent digit states,
and requires no digit-state probability union. It is only a mathematical bound
for the stated honest/checked relation; no malicious-server admission or private
release verifier is implemented by E114.

Compact-v1 terminal rounding has C=ceil((N+1)*t/2)=8446468. With strict raw-Q and
terminal-P centering, the greatest sufficient integer final phase radius is

```
B = min((Q-1)/2 floored,
        floor(Q*((P-1)/2 floored-C)/P))
  = 574193413656199173.
```

Only a random pretrace magnitude at least

```
h = floor((B-maintenance)/D)-d*W+1
  = 1028574808980193
```

can escape that sufficient envelope. The +1 and all integer floor/ceil guards
are retained. At drop22 the complete deterministic final phase/terminal bounds
are432383798108422144/1619196647; at drop23 they are
813272010588356608/3038111414. The latter **bound rejects** at both Q and P; this
is not an observed wrong decryption or an attack.

## 4. Outward rational certificate

Use only the frozen base z16385/16384. The CBD MGF is
`((1+z)*(1+1/z)/4)^eta`. Multiplication by the exact quantizer MGF is justified
only by the preceding conditional independence. Finite geometric sums give
both signs exactly. Convexity of `x -> E[z^(x*Z)]` over[-1,1] bounds arbitrary
fixed signed weights by the larger endpoint MGF. This retains the bias.

Each exact endpoint MGF is rounded **upward** to a2^-32 dyadic rational. The
larger resulting values are538264385/536870912 (drop22) and
1084829195/1073741824 (drop23). Let Jfloor(h/(t*W))=46076470. The standard
inequalities `log(M)<=M-1` and `log(z)>=(z-1)/z` give

```
A = J*(z-1)/z - N*(M-1).
```

Exact A values are297400342771/107380736 and567600192817/214761472, with
floors2769 and2642. Hence two-sided per-output bounds are respectively
2^-2768 and2^-2641, using `2*exp(-A)<=2^(1-floor(A))`. The complete lifetime
union factor is2^32*16384=2^46, giving the table's2^-2722 and2^-2595.
No floating logs, Gaussian approximation, optimized base search or observed
tail frequency enters this certificate. The union itself requires no output,
reused-key or query independence; every invocation must satisfy the stated
conditional fresh-mask premise given its history.

## 5. Validation, provenance and limitations

58 distinct scoped tests pass, with JUnit, collected IDs and exact argv/exit
receipts in the external cache. They independently check tiny literal PMFs,
mass/bias/partial cycles; exhaust the smallest16-bit actual coefficient-codec
domain; compare geometric and direct rational MGFs; enumerate CBD coins and
moments; exhaust unit-mask permutations in R_17/(X^2+1); falsify uniformity with
a supported nonunit secret and with a post-mask signed-query choice; compare
exact endpoint weights and tiny true tails; test greatest strict terminal
radius, outward rounding, sign/union/floor accounting and malformed inputs.
These tiny algebra tests do not instantiate the selected large security profile.
Nonempty Ruff over all three new Python paths passes. Main/card exit code is0.

An independent read-only review found no derivation blocker. It requested the
compact-v1 helper explicitly reject P>=Q. The original57-test source, raw,
law/MGF artifacts and logs were preserved before this guard-only correction.
A new regression gives58 tests. The same two-card rerun has **exactly identical
scientific card fields, summary, profile, scope and law/MGF hashes**; only source,
run metadata and the correction record change. No experiment/test failure was
hidden. The comparison receipt is
`research-data/query-quantizer-law-20261003/guard-only-scientific-comparison.json`.

The receipt pins source bytes, the frozen preregistration and the E113 raw
anchor. The normal result directory is ignored by default; root may include the
selected final raw in the branch checkpoint. Full exact-law caches stay outside
Git. E113's current large general key-generation guard still refuses both cards;
no owner-only API admission or native large execution is implied.

Unsettled premises include actual secret-unit probability, seeded SHAKE/ROM
composition, rejection-sampling truncation, owner setup/index authentication,
accepted-query/trace binding, adaptive epoch and feedback composition, private
side channels, approved RLWE parameters, and complete proof/receipt costs.
No setup-failure or computational-advantage budget has been assigned. A marginal
correctness argument for the public-seeded protocol is a separate conditional
proof task; E114 does not establish it. Return to the contribution plan with
this known conditional law fact and the ratio1 stop, without another drop grid.
