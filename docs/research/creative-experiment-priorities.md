# Creative experiment priorities

**Current execution plan:** [publication research plan](publication-research-plan.md),
with a [closest-work comparison](closest-work-comparison-20260930.md) and
[machine-readable work packages](publication-work-packages.json). Proposed
E41–E47 are not implemented. The E01–E40 results below remain the evidence.

Priority update, 2026-09-30, following the project's research direction.
This supersedes the execution order in earlier plans; it does not change their
results. The implementation baseline is `7dd927f` on
`experiment/bgv-verification-packing`, preserved in the pushed tag
`checkpoint/bgv-product-checks-2026-09-27`. The original company baseline remains
in [PR #14](https://github.com/XTraceAI/cuhepy/pull/14).

**First cycle implemented:** [algebra, encrypted pilots and filter results](creative-algebra-results.md)
are on the descendant branch `experiment/creative-search-algebra` (`b972353`,
`a23d813`). E20's ordinary deferral does not save switches; E21's literal answer
polynomial loses to packed scores. E19's coupled syndrome/weight bound improves
selectivity on favorable fixtures, and public rank factorization halves its
modeled encrypted lookup cost, but that lookup still needs 8× the original
scan's ciphertext products. These are useful limits and experiment controls,
not an established novel contribution or a new production speedup.

**Second cycle implemented:** [certified filters and coordinate folding](certified-folding-results.md)
test a one-sided low-rank lookup, an owner-derived coordinate dictionary (E22),
and exact threshold discovery with whole-ciphertext-tile refinement. The lookup
loses selectivity after certification. Exact folding wins a paired full-size
CPU/CUDA experiment on deliberately redundant columns; it does not compress
uniform random data. No general-data speedup or novelty is established.

**Third cycle implemented:** [dictionaries, hints and exact residuals](dictionary-witness-results.md)
tests E22 layouts on two public datasets, E23 two-round interval refinement,
E24 exact witnesses sharing response coefficients, and E25 owner-held exact
residuals. All use homemade encrypted arithmetic. Complete native CPU/CUDA
measurements charge subset preparation: the two-round variants lose there.
E25 preserves one query/response and reduces server work, but retains private
residual data; on the measured fixture its compressed hint is almost as large
as the compressed full database. This is a changed-state reference, not an
established practical protocol win.

**Fourth cycle implemented:** [exact affine dictionaries and CRT components](affine-component-results.md)
replace per-row residuals with private block maps and multiplex their different
queries inside one full-size homemade BGV ciphertext (E26). Public categorical
data gives about 1.85× CPU local improvement, with CUDA total nearly unchanged.
A deliberately block-structured 8,192-vector fixture gives 7.10× CPU and 1.31×
CUDA local improvement. Binary-mask query contractions rescue the initial CUDA
regression. Traffic equals full scan; separate block queries cost much more.
Dense map blowup on digit/random data and a rank-64→65 padding boundary are
retained counterexamples. A scalar encrypted residual lookup also works but is
expensive; its cost is not a lower bound for better packed constructions.

**Fifth cycle implemented:** [rank repair and unequal CRT capacity](dyadic-rank-results.md)
(E27) splits only blocks that exceed a chosen padded rank, then optionally
allocates component capacity independently. Public Mushroom CPU local time is
206–214 ms versus the previous 347–348 ms and full scan's 639–640 ms; CUDA remains
about 51 ms. Three public index splits, rejected digit/random controls, exact
fixed-map allocation and a one-row update that doubles fixed-layout work are
retained. A complete affine plaintext cache is now implemented and measured,
not just modeled: it answers these public queries in about 2.5 ms with extra
per-row client state. The state/deployment justification remains central.

**Sixth cycle implemented:** [matrix arithmetic, query masks and a conditional
linear check](matrix-arithmetic-results.md) builds homemade E28 matrix-BGV
oracles, projected/symmetric secret-source expansions and opposite input
orientations. An E17 owner-prepared gadget query trades fewer server sources
for larger upload. One-use preprocessing then preserves the constant query
subspace: online corrections use scalar coefficients and admit an E14 linear
fingerprint under trusted offline inputs. All 234 tiny encrypted searches are
exact; 148 count/state models retain costs and failures. These are known
ingredients and new local experiments, not an established novel primitive.

**Seventh cycle implemented:** [CRT response columns and masked search](crt-masked-query-results.md)
(E29) extend the idea to actual E26/E27 maps and full-degree homemade BGV.
Transposing the index into the reply layout removes online ciphertext products,
switching and terminal rounding; one-use independently encrypted answers and
public scalar/subring corrections preserve a complete linear verification
relation. A public linear-solve regression rejects deterministic ciphertext
mask caches. Two full-size public splits compare affine/40-bit and raw/32-bit
representations, including token upload, enrollment, verification and full-cache
controls. All 16 encrypted queries and 336 regressions pass. The separate C++
subring evaluator is exact against GMP; no CUDA or production path changed.

**Eighth cycle implemented:** [common and local query directions](shared-query-basis-results.md)
(E30) share private affine query forms across blocks. Common directions require
scalar corrections; residual directions retain CRT subring corrections. At
equal encrypted index size, query coordinates decrease by 12–16% and private
map/check bodies by 7–12%. More aggressive sharing trades about 41% smaller
map/check bodies for 41–44% more index storage, with similar native online time.
A global affine control is competitive; Semeion and a missed-intersection
counterexample retain failures. All 48 encrypted comparisons are exact. Two
additional pool tests show why public linear expansion cannot turn a small
one-use mask bank into arbitrarily many independent private requests.

**Ninth cycle implemented:** [hierarchical sharing and geometry](hierarchical-query-basis-results.md)
(E31) reduce query bodies by 69–71% with unchanged local encrypted index size,
but only 0.4–0.5% of total online traffic. Full hierarchy increases private
state and native latency. Exact small optima and Semeion's lack of sharing are
retained. The [authenticated-correlation contract](authenticated-correlation-contract.md)
specifies setup, field conversion, collusion and lifetime obligations.

**Tenth cycle implemented:** [fixed-batch CBD correctness](fixed-batch-noise-results.md)
(E32) enables same-capacity q32 execution from the previous q40 local circuit.
Response/index coefficient bodies shrink by 20%, but another verification
round raises checked native local time by 4.4–7.9 ms. All 72 full encrypted
searches and 387 regressions pass, with unreduced integer-phase auditing.
The separate probabilistic type leaves old deterministic APIs intact. Queries
must be fixed before enrollment; there is no adaptive or production assurance.

**Eleventh cycle implemented:** [adaptive transcripts and field/geometry selection](adaptive-field-frontier-results.md)
(E34/E35) retain exact ideal fresh-mask independence and three failure models;
the real encrypted-transcript argument remains open. Separating private rank
discovery from final CRT factors enables a smaller plaintext field. The old
deterministic API then achieves the same 20% response/index reduction as E32,
with adaptive queries chosen after preprocessing. Mushroom query bodies also
halve. All 72 full encrypted searches and 405 regressions pass. Refitting the
original memberships reproduces the selected layouts, and another checking
round leaves native local time 4.3–6.0 ms higher. Full frontier setup, unused
tokens and plaintext-cache alternatives are charged.

**Twelfth cycle implemented:** [complete verification and competing limits](verification-frontier-results.md)
(E36–E40) test uniform Lee-norm bounds, a native same-family verifier control,
known polynomial fingerprints, exact bit bodies, schema range, moment/ID
counterexamples, contract/pool selection and fixed-map ring fragmentation.
All 108 full encrypted searches are exact; 478 selected regressions pass.
Native checking accounts for most of the 1.58–1.76× local stage-total gain;
the different known hash family has a smaller additional benefit. Norm
tightening does not cross a byte boundary. Small-ring models retain both
unchanged-payload and spare-capacity cases; changed N needs new assurance.

**Current next cycle:** follow section11 of the
[publication plan](publication-research-plan.md) after the E54–E65 execution.
The first causal lifetime policy lost to ordinary deltas, and full authorized
cache retention is expressly permitted. Prioritize supported-coordinate
verification/decoder semantics are specified and E64's separate prototype
passes toy encrypted oracles. E65's static optimizer is matched by ordinary
balancing plus single-row refinement; retain its exact oracle, but reject a
novelty/effect headline. Next test recipe/decoder admissibility and complete
cold/ready costs against known extraction/compiler and cache controls. The
lifecycle extension remains unimplemented. New CUDA/service work remains
behind the practical-effect/protocol gates.

**Historical next cycle (before E41 execution):** execute P00–P04 of the [publication plan](publication-research-plan.md):
freeze the functionality/leakage, reproduce closest compatible protocols,
build an exact joint-representation oracle, test the backend/security-dimension
tradeoff and E47's proposed vLHE layer over public ciphertext coefficients, then
develop the surviving algorithm. E43 investigates sharing versus
update/token invalidation. Begin the E34 transcript proof alongside this work;
defer E33 service deployment and new GPU kernels until the mechanism/full-cost
gates pass. The [E01–E40 synthesis](research-synthesis-and-system-roadmap.md)
remains the complete results ledger. Preserve the general BGV/CUDA path and
all failed constructions. Exact certified refinement and output-only selection
remain bounded alternate hypotheses, not established contributions.
Previous checkpoints include `checkpoint/dyadic-rank-capacity-2026-09-27`
(`10a9125`) and `checkpoint/matrix-query-space-2026-09-28` (`cee16cf`). E29 source
is committed at `26e8ffb` and `b6e41c8`, checkpointed at `15c6737`. E30 source
is committed at `fc5aa84` and `185ffc7`.

## Objective and working method

Prioritize experiments that could lead to a new algorithm, representation,
bound or protocol. Routine speed tuning, completing the current verifier and
deployment work remain useful, but are no longer the default next task.
Correctness and a clear security contract are necessary to interpret an
experiment; full production integration is not a prerequisite for exploring it.

Recent work provides homemade implementations, measurements and reference
oracles. It has **not established an original research contribution**. The
[literature agenda](encrypted-search-literature-agenda.md) identifies related
work, not an exhaustive novelty search. The proposals below are speculative:
their equations, individual ingredients or complete constructions may already
be known. Check the closest work before presenting a contribution claim.

For the next research cycle:

1. Investigate several competing hypotheses with small independent algebraic
   models. Use the completed E19–E40 results above to choose the next competing
   questions. A plausible but uncertain idea deserves
   a cheap test.
2. For each, write the claimed difference from its closest known construction,
   one falsifiable prediction, and the assumptions needed for correctness and
   privacy. Derive an identity or counterexample before building a fast backend.
3. Compare operation counts, dependent rounds, live ciphertexts, setup and total
   bytes. Use exhaustive tiny examples and adversarial cases, including ties,
   wraparound, empty inputs and worst-case data. Record what fails and why.
4. Implement the most informative survivors with independent homemade
   references. Use other libraries as explicitly labeled oracles or baselines.
   BFV/BGV are options, not restrictions; mixed protocols and other schemes are
   welcome when their different contracts are stated.
5. Optimize native/CUDA code when doing so tests a surviving hypothesis. Choose
   the paper direction after comparing the evidence, rather than treating the
   next completed engineering milestone as the contribution.

Do not require an early prototype to beat optimized CUDA. First establish
whether the idea changes a meaningful cost or enables a useful tradeoff. A
negative result or a proved obstruction can justify retaining the experiment.

## Research priority reaffirmed, 2026-09-28

The user's highest priority is now the originality and scientific value of the
question being tested. Use that priority to choose between tasks, including
when the easier task would produce a more reliable benchmark improvement.
Correctness and honest comparisons remain requirements; production hardening
and maximal performance can follow a promising research result.

The latest CPU improvement supports the usefulness of the E27 representation
on the measured data. It does not by itself establish novelty. The small CUDA
improvement identifies a bottleneck, but that is not an instruction to spend
the next cycle on conversions, kernels or client tuning. Those measurements
are controls for a new idea when relevant, not the research agenda themselves.

The following was the initial order for this cycle. The sixth-cycle results
above now determine the next probes; retain these questions and their failure
criteria without rerunning the completed first experiments. They are not
novelty claims:

| Priority / direction | Difference to investigate | First discriminating experiment |
|---|---|---|
| 1. E28: a different arithmetic model | Can an exact-search representation use matrix-valued arithmetic to avoid enough rearrangement/switching to pay for its extra secret terms and keys? Implementing the published scheme alone is not the contribution. | Read the complete construction, derive rectangular Hamming products with a homemade tiny secret-expression oracle, and count useful output capacity, switches and keys against scalar-ring packing. Separate one-query latency from batched throughput; hold effective lattice dimension fixed as an initial accounting control, not a security proof. |
| 2. E17: query conversion fused with matching | Can conversion directly produce the private map's required linear forms, eliminating an intermediate full query representation? | Derive one complete small conversion-and-score identity and compare with separate conversion plus matching. Charge conversion keys, owner work, noise and bytes; neither the query secret nor a private dictionary becomes public for convenience. |
| 3. E25/E26: exact exceptions without a rank cliff | Can structured encrypted exceptions preserve a small exact core without per-row owner hints or a scalar lookup for every residual? | Try shared support classes or factored selectors on tiny exact instances, including one out-of-span insertion and unrelated residual supports. Count the full encrypted selector cost and record any exposed structure; compare with full-rank scoring and complete local caching. |
| 4. E14: arithmetic chosen for complete verification | Can changing the representation reduce both search work and the integer relations needed to authenticate its result? | Compare complete tiny circuits, including carries, canonical ranges and output binding. Find counterexamples to omitted checks before implementing a fast verifier. |

For each probe, keep a short contribution ledger: what is already known, the
precise proposed difference, an identity or falsifiable prediction, the
cheapest counterexample, and the evidence needed to advance or abandon it.
Assess novelty against the closest primary work; neither an unfamiliar idea
nor a fast implementation establishes it. A new tradeoff, useful bound or
well-scoped obstruction is worth exploring even before a latency win appears.

Avoid letting one successful implementation consume the whole exploration
cycle: test the first alternatives cheaply before committing to a native/CUDA
backend. Preserve failed constructions and adversarial controls. Keep homemade
implementations as the default, with external schemes and libraries clearly
labeled as prior work or reference implementations. BFV/BGV are not constraints
on the eventual design. The follow-ups inside older experiment cards are local
options; the current **Next cycle** paragraph governs the execution order.

## E20 — Can reduction happen before expensive ciphertext transformations?

**Question:** can a search-specific representation reduce the number or size of
key switches and canonical digit decompositions, rather than accelerating each
one in the existing schedule?

A product initially decrypts through the formal expression
`c0 + c1*s + c2*s^2`. Combining products under the same secret can precede
relinearization algebraically. The difficulty in our reduction is that an
automorphism also changes the secret: applying `sigma` produces terms in
`sigma(s)` and `sigma(s)^2`. A proposed delayed schedule must track those terms;
pretending that every transformed ciphertext still uses `s` is incorrect.

**First experiment:** build a tiny exact polynomial oracle that tracks secret
expressions through alternative product, automorphism, sum and projection
schedules. Compare immediate relinearization, delayed relinearization and
switching only the result components that a proposed projection needs. Count
distinct secret terms, evaluation keys and coefficient conversions. Include
integer rounding/carry relations separately: these operations cannot simply be
commuted through a linear sum.

**Possible contribution:** a justified search-specific schedule or representation
with fewer expensive conversion boundaries. Delayed relinearization, trace and
ring switching themselves are prior-art search targets, not novelty claims.
Compare against an equally delayed/hoisted conventional schedule.

**Falsification:** the number of secret terms, key bytes, noise or required
projection work cancels the saving. Never treat a smaller output polynomial as
permission to use an inadequately secured encryption ring. Any changed key or
ring distribution needs its own parameter and security assessment.

## E21 — Can we compute answer summaries without a full distance vector?

**Question:** can exact Hamming search exploit its small integer score domain to
compute a useful answer aggregate directly, avoiding some per-vector result
construction, packing or selection?

For binary data define `b_ij = x_ij + q_j - 2*x_ij*q_j`. The elementary identity

```text
G(z) = sum_i product_j (1 + (z - 1)*b_ij)
     = sum_i z^Hamming(x_i, q)
```

encodes the distance histogram. This is an algebraic starting point, **not** an
efficient encrypted algorithm or a novel identity. Weighted versions could
encode information about IDs, but a histogram alone cannot return the winners.
In particular, a fixed number of moments cannot be assumed to identify the
smallest IDs in an arbitrarily large tied bucket.

**First experiment:** compare direct score-and-select with polynomial, factored
and evaluation-point representations of these aggregates on exhaustive tiny
databases. Include a complete stable-ID recovery strategy, such as recursively
counting ID prefixes at the selected distance. Account for its worst-case
rounds, encrypted comparisons, multiplication depth, degree, field size and
output conversion. Counts and IDs must not silently wrap modulo the field.

**Possible contribution:** a new selection/aggregation circuit or a proved
regime in which the score structure lowers total work or communication. E18's
sparse encoding and existing secure selection/histogram methods are comparison
targets; encoding already-known winners is not the missing algorithm.

**Falsification:** products, prefix refinement or representation growth cost
more than constructing and returning the scores. Test all-equal distances as
well as separated winners. Any adaptive query schedule needs a stated leakage
contract and authenticated replies before observable decryption-dependent
behavior; a plaintext oracle is not that protocol.

## E19 — Can a cheap certificate replace most of an exhaustive scan?

Promote the [private indexing proposal](encrypted-search-literature-agenda.md#9-e19--exact-private-indexing-with-a-coverage-certificate)
to an early experiment. Compare substring coverage, blockwise syndrome lower
bounds and simpler prefix/popcount bounds. Explore which public or
owner-committed code/block choices strengthen a deterministic lower bound for a
given data distribution, while retaining correctness for every query.

**First experiment:** measure exactness, selectivity and a lower-bound cost for
private retrieval and complete coverage on uniform, clustered, duplicate and
adversarial data. Include index construction, maintenance and a full-scan
fallback. Search for omitted-winner counterexamples, including boundary ties.

**Possible contribution:** a useful combination of a stronger cheap bound and
private, authenticated coverage. Multi-index hashing, syndrome decoding and
plaintext pruning are established ingredients. Distribution-dependent design
choices and accessed buckets may reveal information: charge protection for
that information, or label the changed leakage contract explicitly.

**Falsification:** the bound is weak, or hiding/verifying routing erases the
pruning gain. A fast plaintext filter alone is not a private-search result.

## E22 — Can an index-specific representation avoid most score arithmetic?

The [implemented first probe](certified-folding-results.md) groups equal or
complementary database columns and folds query weights on the owner. Near
groups add exact per-row residual budgets, yielding safe Hamming lower bounds.
The ring and security parameters stay fixed. This uses standard factorization
and triangle-inequality ideas; the proposed research question is their joint
optimization for ciphertext padding, coverage and refinement.

**Implemented follow-up:** fixed representative budgets, row-tail medoid
sweeps, signature/metric physical orders and stable original IDs are in the
[third-cycle report](dictionary-witness-results.md). Smaller worst residuals
did not reliably help search. Signature order often beats the more complicated
metric partition; neither helps uniform random data enough to rescue pruning.

**Implemented per-block follow-up:** E26 below replaces coordinate grouping
with exact local affine relations and shares their query ciphertext through
polynomial CRT. Common worst-block padding and map memory determine whether it
wins. The next layout experiment must optimize those costs jointly, retaining
the one-map/full-scan controls and separate query holdouts.

**Falsifiable prediction:** an HE-aware dictionary/layout reduces complete
search work on a real binary distribution after charging queries, keys,
fallback index, authenticated private refinement and epoch updates. Compare
ordinary coordinate sampling, full scoring and row deduplication. Failure on
unrelated queries or loss after padding/routing charges is an informative result.

**Protocol scope:** only the owner holds the data-dependent map; sharing it
changes the contract. Adaptive tile IDs and schedule length are currently
visible. PIR alone does not solve integrity or selective-failure privacy.
Model authenticated PIR and padded/attested routing separately before adopting
either, and charge offline hints rather than treating retrieval as free.

## E23 — Can trusted intervals remove threshold-discovery rounds?

**Implemented:** owner-retained exact radii turn encrypted template distances
into lower and upper bounds. The kth upper score/ID pair supplies a safe cutoff
before exact refinement. All qualifying original tiles are requested in one
batch, preserving ties. Point intervals are already exact. No oracle radius is
used. This removes the encrypted radius feature and can avoid a padding doubling.

**Observed limit:** it fetches more tiles than adaptive discovery, often loses
on digit data, doubles query/reply traffic on the measured native workload,
and per-query selected-index preparation overwhelms the CUDA saving. Routing
and round counts remain exposed; mathematical bounds do not authenticate replies.

**Next gate:** compare a fixed private/attested schedule and its complete cost
before treating lower product counts as a protocol improvement. A resident
subset API is engineering follow-up only if that protocol survives the cost model.

## E24 — Can unused response support pay for useful exact side information?

**Implemented:** two honest butterfly outputs with different trace scales share
one ciphertext after a certified disjoint monomial shift. Fixed exact witness
scores tighten interval thresholds. A separate query and prepacked witness
index are charged, and phase bounds add. Placement can fail despite sufficient
total empty coefficients; no arbitrary free scatter is assumed.

**Observed limit:** the arithmetic is correct, but witness sampling mostly
adds work or saves too few tiles. It saves a reply relative to separate filter
and witness outputs, not relative to the single-response full scan. Python
fusion is also charged in the native benchmark.

**Next experiment:** ask whether a different fixed exact statistic buys a much
stronger bound per product/switch. Compare with no statistic, include complete
coverage and ties, and stop if it only fills coefficients without improving
complete work. Linear addition and mixed coefficient layouts alone are not novelty.

## E25 — Where should an exact sparse correction live?

**Implemented reference:** the owner retains differing positions and original
bits between every row and its folded template. Two AND/popcounts recover the
exact score correction after one encrypted template evaluation. This removes
refinement and its routing, but gives private residual information to the hint
holder and grows owner state linearly with residuals. It is an owner-only
reference, with variable-time private Python correction, not a general reader API.

**Observed tradeoff:** on 7,996 categorical vectors, local CPU time improves
3.31× and CUDA local time 1.09×, with unchanged traffic. Canonical hints are
60,514 B versus 127,936 B of raw rows; lossless compression narrows that to
21,319 versus 23,466 B, and full plaintext local search is much faster. The
expanded hint uses more Python memory than the raw row integers. Uniform-data
hints exceed raw data by 6.86×. Preserve these unfavorable controls.

**Priority experiment:** evaluate sparse corrections while keeping their support
and values encrypted and owner state bounded. Derive the encrypted selection/
lookup cost instead of assuming plaintext sparsity makes HE cheap. In parallel,
measure map/hint/ID storage and updates against a compressed full-data cache.
The question is whether a useful exact outsourced-search tradeoff survives an
equal storage/privacy contract; the elementary signed correction is not a new
cryptographic identity. Compare hint-bearing and hintless PIR literature without
transferring their different security or retrieval guarantees.

**Fourth-cycle probe:** a homemade encrypted scalar multiplexer selects a query
bit at an encrypted residual position, then applies an encrypted sign. It is
exact but needs `d` products per residual before any output packing. This rules
out the literal scalar construction at our dimensions, not better SIMD lookup
or nonlinear/multiround methods. A narrow bilinear rank obstruction prevents
assuming a tiny exact linear feature encoding for unrestricted addresses. E26
avoids those per-row lookups by exploiting exact restricted affine structure.

## E26 — Can private local representations share one encrypted query?

**Implemented:** an exact modular affine basis per block represents binary rows
as `a + uB`. The owner computes the query-only offset and `B(1-2q)`; the server
evaluates encrypted `u`. Polynomial CRT components of the same full-size ring
carry different blocks' queries. The existing butterfly preserves components
when common padded rank divides component degree. Equal-coefficient bit masks
contract binary queries; no new CUDA kernel or external HE implementation is
needed. Independent polynomial and homemade encrypted tests establish exactness.

**Observed tradeoff:** Mushroom local affine rank crosses padding 128→64 on one
split with 8 blocks, but needs 16 on the other. Canonical maps are 4,527/8,271 B;
stable IDs add 15,992 B. Maps have no per-row residual array, but contain private
anchors/relations and compiled Python objects exceed compressed full data on
this fixture. Semeion and finely partitioned uniform data reduce rank only with
maps much larger than the full database. Preserve those failures. Components
save traffic versus separate queries, not versus the existing full scan.

**Next experiments, in order:**

1. Plan blocks from index data under a fixed map-byte/update budget, scoring
   actual padded products, switches and imbalance. Include an out-of-span row
   that raises rank 64→65; prove exact epoch rejection and charge re-enrollment.
2. Test unequal capacities and mixed rank classes. Derive the trace/CRT schedule
   before implementing it, and charge every key, query, product and fusion.
   Common worst-block padding is the current control, not a free assumption.
3. Combine a low-rank exact core with encrypted support-class exceptions,
   testing tiny-domain or factored private lookup and alternative schemes.
   Compare complete affine/plaintext caching and bound owner state explicitly.
4. Couple E17 query conversion with the required component linear forms; price
   privacy of the data-derived maps instead of making them public for convenience.

**Possible contribution:** a useful exact-search representation/schedule with
measured state/update/compute tradeoffs. Affine algebra, CRT, SIMD and bit masks
are established ingredients. Compare tensor-ring matrix methods, encrypted
lookup and dictionary/compression work before claiming a new construction.

**Falsification:** a single outlier doubles work, maps effectively retain the
database, or a second query/reply and map processing erase the reduction in
encrypted products. The current GPU tie on public data is already informative.
Fixed scheduling removes adaptive tile requests, but does not authenticate the
server or establish private side-channel/parameter assurance.

## E27 — Can rank-boundary repair and unequal capacity make small maps useful?

**Implemented:** dyadic plaintext CRT factors have unequal degrees while the
full encryption ring remains fixed. All leaves still use a common padded rank;
there is no unpriced mixed-rank trace. Median and hybrid coordinate cuts repair
only over-rank blocks. An exact slot-feasibility test minimizes the maximum
tile count for fixed maps/common padding. Replicated components share private
maps; complete coverage, zero tails, stable IDs and public geometry are charged.

**Evidence:** hybrid rank-32 maps reduce Mushroom products 63→18/20/18 across
three splits with 9,542/11,386/13,983 B of canonical maps. Median-only and input-
order fits fail that target within the depth budget. The 8 KiB selector instead
chooses 32-product layouts; 4 KiB selects full scan. Semeion's reductions exceed
32 KiB; the uniform control does not save work. Allocation saves one product
on one public split and none on the others. It strongly helps given unequal
synthetic groups, but those favorable generative boundaries are explicit.

**Update/state limit:** one new direction doubles a fixed synthetic layout's
products 32→64; targeted repair restores 32 with one extra map. This takes a
full owner rebuild, not incremental HE updates. Complete maps plus all pivot
bits compress to about 22 kB on the public fixture and support ~2.5 ms local
search. Compiled maps/IDs occupy additional memory in both approaches. The
question is where a fixed-state outsourced design pays off as distinct data
and updates grow; current small-index measurements do not establish that.

**Next experiments:** keep a stable main representation and a bounded encrypted
delta for inserts/replacements/deletions; derive a shared-query/reply schedule
with charged reserve capacity and correct stable-ID replacement semantics.
Compare it with full rebuild and complete local caches at fixed working-memory
budgets. Try a bounded beam/Pareto search over rank, maps and allocated work;
the current greedy splitter is the control, not an optimal algorithm. Epoch
hashes do not authorize server output, hide update locations or bind external IDs.

## E28 — Is matrix-valued HE a better arithmetic model for exact search?

**Primary lead:** [Bence Mali's generalized BGV/BFV/CKKS preprint](https://eprint.iacr.org/2025/972)
studies matrix-ring plaintext/ciphertext spaces, Module-LWE and a superoperator
approach to noncommutative relinearization. This is existing work to understand
and compare, not our construction. The sixth cycle read the construction and
built a separate tiny matrix-BGV oracle, with independent entrywise expansion
and compact output under another module key. It does not implement every
operation or the full generalized ciphertext format from the paper.

**Implemented evidence:** right/right, commuting-entry combination,
independent right/left and transposed-secret right/left products agree with
direct noisy phase evaluation and exact search. Modeled rank-eight sources per
output fall 576→548→192→100, with an owner-gadget alternative using 16. All
switching work, keys, query bodies and the changed output format are charged;
this is not a measured speedup over scalar-ring BGV. Seeded-mask controls keep
ordinary query upload smaller than the gadget query. Masking a query in its
constant subspace supports a separate offline/online experiment below.

**Possible direction:** combine index-specific affine structure with an
arithmetic representation that needs fewer slot moves. Test the existing
scalar-ring pipeline as the full control. A lower polynomial degree alone is
not a security-preserving improvement; parameter and related-key assumptions
must be assessed before any practical comparison. Reject the idea if matrix
key/switch expansion or unused query capacity erases the useful-work saving.

## E17 — Can query conversion and matching share work?

**Sixth-cycle probe implemented:** the owner directly encrypts private affine
query weights and their product with the matrix secret in gadget form. This
specializes an external product; it is not an arbitrary-reader LWE conversion.
One-use offline random-query answers plus a converted index reduce the online
step to a public correction. Restricting the mask to the constant query space
keeps the correction scalar and drastically reduces its online body. Offline
traffic and total index/token state increase. Tests reject a query outside the
mask space and demonstrate leakage after token rollback/reuse. This does not
establish a complete secure preprocessing protocol.

**Seventh-cycle result:** E29 now implements that CRT extension and a raw-column
control. Fresh encrypted offline answers are necessary in the tested design;
deterministic combinations of the public index disclose their masks by solving
a public linear system. Independent owner encryption blocks that exact relation
but requires access to the plaintext coordinates. The next discriminating test
is trusted/verified preprocessing with lower total cost and useful update
lifetime. No general ciphertext-only upload conversion is implemented.

Extend the [query-upload proposal](encrypted-search-literature-agenda.md#7-e17--make-query-upload-proportional-to-useful-input):
instead of converting a short encrypted query into a general-purpose full-ring
query first, ask whether conversion can directly produce the linear forms or
packed correlations required by the encrypted index.

**First experiment:** specify a toy short-LWE/MLWE or established-cipher query
format, derive the exact conversion-plus-search relation and compare it with
separate conversion and matching. Count all key material and amortization,
noise/depth, refresh work and batch-one latency. No plaintext query or symmetric
secret key may be given to the evaluator under the encrypted-only contract.

**Possible contribution:** a search-specific conversion with less intermediate
work or communication. Ring packing and transciphering are already represented
in the literature agenda; a smaller upload alone is not enough.

**Falsification:** conversion must reconstruct the full query anyway, extra
keys/noise dominate, or saving bytes requires enough batching to harm latency.

## E14 — Can changing the arithmetic make verification cheaper?

**Sixth-cycle probe implemented:** constant-mask online computation is a scalar
linear relation over all public ciphertext coefficients. A private one-use
fingerprint checks that complete online relation, canonical coefficients and
derived bounds, assuming trusted converted-index and offline-answer inputs.
Prime-field collision probabilities are exhaustively checked on a tiny field;
composite-modulus and poisoned-offline-state controls retain the limits. It is
not a proof of preprocessing or a replacement for existing response authority.
Next test whether compact output and updates preserve a useful verifiable
relation after all offline trust and private arithmetic costs are charged.

**Seventh-cycle result:** E29's linear-circuit correctness bound permits full-Q
40-bit or 32-bit replies, avoiding terminal rounding in this experiment. It
implements complete output fingerprints with adjoint preprocessing and bounded
epoch reuse of hidden challenges, following known Freivalds/Slalom ideas. Raw
query coordinates have larger encrypted index storage but much smaller checking
hints. Trusted preprocessing, durable lifetime budgets and private arithmetic
are still obligations; poisoned trusted-state and rounded-output failures are
retained. The next question is a representation that reduces complete owner
state and trusted token work together, not just a faster field check.

## E29 — Can query space, reply layout and verification be designed together?

**Implemented probe:** encrypted coordinate columns already occupy the final
reply positions. Public correction polynomials are constant inside CRT leaves
and use a short subring, while encryption retains the full degree. A separate
homemade C++ implementation contracts prepared short NTT fibers; the raw-column
case uses scalar products. Exact full-size encrypted experiments compare both
representations and charge their offline answers, private checking state and
expired-token costs. See the [report](crt-masked-query-results.md).

**Possible contribution:** a useful joint search/state/verification tradeoff,
with a new bound or protocol if subsequent work establishes one. Transposition,
CRT, NTT, input blinding and secret Freivalds preprocessing are known tools.
The lower online bytes and standalone arithmetic timings alone are insufficient.

**Next experiments:** mixed raw/affine public spaces, index-size/client-state
Pareto curves, alternative ways of preparing authenticated correlations, and
update/expiry workloads. Derive the token and epoch invariants first. Test
complete caching and ordinary seeded BGV at equal contracts. A GPU backend is
useful when it tests the new contraction, not as a substitute for this analysis.

**Falsification:** retaining the index or paying for fresh tokens dominates;
the mask leaks through a proposed shortcut; verification state becomes another
database cache; or consumed/expired token costs erase the apparent IO benefit.

Use the current checked-product stage as a measured control, not a mandatory
path to extend layer by layer. Ask whether a different representation or
schedule reduces the integer carry, decomposition and rounding relations that
a verifier must establish. Explore it alongside E20 rather than assuming the
current BGV circuit is fixed.

**First experiment:** compare exact constraint and witness counts for one
small complete computation, including canonical ranges and terminal bytes.
Construct malicious carry, digit and output mutations against each model.
Field equations alone do not establish the intended integer computation.

**Possible contribution:** an arithmetic/protocol design that reduces complete
verification cost. Randomized checks and ordinary batching are known tools.
**Falsification:** omitted range constraints explain the gain, or restoring
them, binding the index/query and covering every output erases it.

## E30 — Can common query directions buy a better state/index tradeoff?

**Implemented:** exact quotient-space factorization `x=a_g+cC+vR_g`, a greedy
overlap trajectory and raw-coordinate control. The mixed scalar/subring
evaluator and conditional checker run at full encryption degree. The
[report](shared-query-basis-results.md) prices `F=K+max r_g`, `h=K+sum r_g`
and `W=K+S*max r_g`, complete modeled owner bodies, token work and expired pools.
Global affine compression is an essential simpler control. The basis-row
candidate pool provably misses a better intersection in a retained tiny case.

**Candidate contribution:** an exact search representation with a useful
frontier or a bound/selection algorithm for that frontier. Common/individual
subspaces, common-subexpression elimination and rank-aware HE are prior ideas;
the current measurements do not establish originality.

**Rejected preprocessing shortcuts:** restricting masks to a private image
reveals its relations; publishing linearly mixed requests beyond the rank of a
fixed mask bank reveals relations among queries, even when every marginal looks
uniform. Fresh independent owner-encrypted tokens remain the working reference.

## E31 — Can a hierarchy of query subspaces improve the frontier?

**Implemented:** exact intersections, per-column subring degrees, fixed-tree
coordinate-count bound, exhaustive small optima and capacity-preserving greedy
regrouping. The [report](hierarchical-query-basis-results.md) retains 64 complete
encrypted searches and an explicit equal-row-deduplication control. Query bodies
shrink by 69–71% after regrouping at unchanged local index size, but total online
bytes shrink only 0.4–0.5%; owner state and native latency do not improve.
Semeion has no useful sharing. Geometry chosen for fewer coordinates can worsen
the correction-degree sum. These negative results redirect the next experiment.

The fixed-tree laminar coordinate optimum and `h <= sum S_j` are restricted
algebraic bounds, not a new cryptographic primitive or a global memory/time
optimum. Hierarchical partial sharing has prior statistical formulations; the
report records targeted primary reading and makes no originality claim.

The [correlation contract](authenticated-correlation-contract.md) now specifies
who knows the matrix, query masks, encrypted outputs and authentication material,
the two arithmetic fields, malicious setup, collusion, updates, expiry and durable
consumption. No PCG or new production protocol has been implemented.

## E32 — Can a lifetime noise bound change the IO frontier?

**Implemented:** [a separate fixed-batch profile](fixed-batch-noise-results.md)
uses the exact CBD MGF, an integer-rounded union bound over every coefficient
and the full declared lifetime, and separately bounded message/carry terms.
Mushroom and Semeion both execute at q32 without extra encrypted columns.
The same full-degree GMP/C++ ciphertexts agree, every score is exact, and the
independent audit reconstructs integer phases before Q reduction. Response,
index and seeded-answer bodies shrink; checked native time increases because
q32 uses a fifth checking round. Fresh OS errors and explicit fixed-before-index
corrections enforce the narrow assumptions. Exact dependent/correlated-error
counterexamples are retained.

The prototype has its own context/certificate/output type. Existing deterministic
`phase_bound` semantics and rejecting key gates are unchanged. This is not a
public-key, product, rounded-response or adaptive-circuit bound. Tests do not
establish 128 correctness bits empirically; RLWE assurance and an independent
proof review remain separate. The scheduling limitation motivates E34.

**Possible contribution:** a useful search/verification/parameter schedule with
a rigorously scoped lifetime guarantee; noise concentration itself is known.
**Falsification:** message carries, adversarial dependence, seed assumptions,
epoch lifetime or complete-circuit checks invalidate the apparent smaller Q.
Keep the deterministic profile as the control and fallback.

## E33 — Can authenticated correlations cross the two fields cheaply?

Use the explicit correlation contract before selecting a PCG or helper model.
The exact server check is over `F_Q`, but masks and query geometry are over
`F_t`; centered CRT lifts are nonlinear between those fields. Explore whether
the lift/carry relations admit a cheaper complete checked conversion or a
different arithmetic representation, with public rank/geometry kept explicit.

Start with a tiny end-to-end oracle covering every coefficient, carry/range
constraint, fresh output encryption and malicious setup. Compare its complete
work/state with fresh owner preparation and full-coefficient fingerprints.
Noncolluding helpers, trusted attestation and a single malicious server are
different contracts. A deterministic rerandomization slogan or a public linear
mask bank is not a solution. Query reuse, expiry and crash semantics belong in
the experiment, not in a later footnote.

**Falsification:** the allegedly saved work is merely shifted to a trusted
party, discarded correlations dominate, or restoring authentication/field
conversion costs erases the gain. A new assumption must appear beside the
performance comparison.

## E34 — Can fresh masks support adaptive correctness without a fixed epoch batch?

**Ideal model implemented:** [exact transcript oracles](adaptive-field-frontier-results.md#e34-which-adaptive-transcript-admits-the-ideal-argument)
enumerate the joint error/correction distribution. A policy may see reused
errors and earlier toy phases, but commits w before the current independent
uniform r. The correction transcript is then independent of errors; reuse,
early disclosure of just one linear form, and error-dependent token selection
are exact failure controls. Their TV distances are model dependence measures,
not HE attack advantages. The production-view replacement is not proved.

**Next protocol gate:** model encrypted offline answers and SHAKE expansion,
including trusted-owner/caller boundaries, first-failure histories and token
selection. Do not promote the ideal lemma to a real-transcript noise theorem.

The target is a reviewed adaptive correctness statement for a useful scheduling
contract, not simply changing E32's immutable-batch API. A caller or server that
selects corrections from enrollment errors violates the current proof. E29's
one-use masking, a hidden HE key and exact verification alone are not a proof
of error independence under every adaptive transcript.

**Falsification:** exposure of r-related ciphertexts, caller access to owner
state, conditional failure history or discarded correlations prevents the
ideal argument or makes the needed scheduling too expensive. Keep E32 and its
counterexamples as the fixed-query control.

## E35 — Can search geometry and both fields be selected jointly?

**Implemented:** [joint field/geometry frontier](adaptive-field-frontier-results.md#e35-private-discovery-cuts-are-not-polynomial-factors)
refits and certifies maps independently per field, then separates private
discovery cuts from the final allocated CRT cover. At unchanged full N and
column/reply capacity, t=193 on Mushroom and t=257 on Semeion let the old
absolute phase bound fit q32. Queries are chosen after the index and entire
answer pool exist. Fixed-membership controls match, while global affine maps
exceed the local index cap. Native server time changes little; the fifth
checking round raises total time. The full selection search, state and unused
tokens are retained costs. Below-32-bit moduli and fixed-CBD frontier entries
are models, not implemented adaptive profiles.

Tiny controls include exhaustive field/score/CRT identities, characteristic-
dependent rank and invalid cross-field map reuse, followed by 72 full-size
encrypted searches. A scalar independent-checking-field shortcut has both
false acceptance and false rejection without integer Q-carry relations.

**Possible contribution:** a useful jointly optimized representation and
verification/correctness frontier. Modulus tuning, CRT and concentration are
known; their combination is not automatically novel. A larger independent
verification field requires complete integer Q-reduction carry relations.
**Falsification:** map rank, score capacity, extra rounds/carry checks or setup
costs cancel the apparent bit reduction.

## E36 — Can the correction image give a uniform adaptive norm bound?

**Implemented in the twelfth cycle; no new byte boundary on the measured layouts.**
See the [E36–E40 report](verification-frontier-results.md). The original
hypothesis and falsifier below are retained as history. The universal phase gate uses
`sum |alpha_j| <= W*floor(t/2)` even though alpha is a linear image of only h
masked coordinates over F_t. Can duplicated forms, zero coordinates or code
constraints lower the maximum centered-lift L1 norm enough to change a byte
boundary, verifier rounds or response capacity? This would preserve absolute
correctness for arbitrary correction choices, avoiding a concentration claim.

Begin with exact tiny generator matrices and enumerate every delta. Check
independent upper bounds and adversarial maximizers before trying branch bounds
or finite-field support arguments on a real CRT/map image. Charge certification
work, private state, message/error terms, carries and full lifetime costs.

**Obstruction control:** if Z coefficient forms are nonzero, a uniform delta
makes each individually uniform. With b=floor(t/2), expectation implies
`max_delta sum |center(alpha_j(delta))| >= Z*b*(b+1)/t`, without coefficient
independence. Establish Z rather than assuming Z=W. Do not mistake typical
norms for a universal upper bound or relabel a probabilistic estimate adaptive.

**Possible contribution:** a useful representation-specific bound or a sharp
obstruction that changes the search/verification tradeoff. Linear codes, CRT
and worst-case norm analysis are known ingredients. **Falsification:** the
maximum stays near the full coefficient cube, checking/certification costs
erase the savings, or the bound fails on characteristic/carry counterexamples.

## E37 — Can a known complete fingerprint family improve the joint frontier?

**Implemented:** compare the existing seeded uniform-vector check in GMP and
native code before attributing a gain to a new family. A separate secret
irreducible-polynomial remainder check uses the same F_Q and complete formal
coefficient sequence. Its exact factor-count bound includes length and the
attempt budget. Full negacyclic adjoint preprocessing handles every wrap term.
Q35/Q36 need degree five where the vector check uses four rounds, so setup
and fingerprint state can lose even when native online hashing wins.

**Follow-up:** independently review the verification-only transcript and
private implementation; do not expose keys/tags or silently extend length or
lifetime. The family is established prior art. Evaluate any parallel/native
variant against the equally optimized exact vector control.

## E38 — Can application range and CRT geometry be selected together?

**Implemented:** validated one-hot diameter, exact tiny pairs and invalid-query
wrap controls. Mushroom's score range permits t=47, but the chosen 32-slot
geometry still needs t>=193. Raw scalar columns avoid those roots with much
more index storage. No general small-field affine API is enabled.

**Follow-up:** prove a query-language restriction and exact representation
before shrinking its field. Compare scalar, CRT and raw/global maps including
storage and authenticated query validation; schema range alone is insufficient.

## E39 — Which output and cost shortcuts survive exactness and contracts?

**Implemented:** classical equal-moment partitions embedded as valid Hamming
indices, histogram/ID ambiguity, exact omitted-row coverage with stable ties,
and a measured-candidate contract/pool planner. All nine tokens are charged;
online-only and amortized objectives choose different candidates. The default
contract rejects the current unreviewed research candidates.

**Follow-up:** ID-aware summaries or a complete exact selection protocol must
beat full-score transfer with conversion, verification and coverage included.
Distance-only counterexamples are not general top-k impossibility results.
Canonical state models are not resident-memory or deployed-network benchmarks.

## E40 — Does a smaller encryption ring improve the physical reply frontier?

**Implemented model:** reuse certified fixed maps, allocate final geometry
afresh, and retain every feasible/rejected ring degree. Mushroom N=8192 needs
two replies instead of one at N=16384, leaving body size unchanged. Semeion's
much smaller index has spare capacity and can have substantially smaller body
models. No lower-degree encryption profile, latency or security is claimed.

**Follow-up:** review lattice parameters/distributions, then perform complete
encrypted same-data comparisons at any justified degree. Include all replies,
token headers, checker length, key/setup costs and private map/full-cache state.
Never infer an admissible smaller encryption ring from plaintext CRT roots.

## Evidence and deferred work

Each experiment report should state: hypothesis, closest prior work and claimed
difference, exact assumptions, independent oracle, positive and negative cases,
costs omitted, and the next discriminating test. Keep mathematical evidence,
cost projections and measured encrypted execution distinguishable. Compare
exactness, output privacy, adversaries and leakage on equal terms.

Defer routine kernel fusion, serialization tuning, large benchmark sweeps,
full verifier integration and deployment unless needed to test a hypothesis or
fix a correctness problem. Preserve the current Paillier/BFV/BGV implementations
and checkpoints. Before promoting a prototype to the protected service, the
existing complete-response authentication, private-arithmetic and parameter
review obligations still apply.
