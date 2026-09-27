# Creative experiment priorities

Priority update, 2026-09-27, following the project's research direction.
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

**Next cycle:** prioritize encrypted exact residual evaluation with bounded
owner state, block-dependent dictionaries with shared query work, and the
state/update-rate tradeoff. Compare compressed full data and direct local search
whenever owner hints are proposed. Keep simple signature ordering as a strong
control: it often beat the metric partition. Preserve E17 and the separate
private-refinement question. Do not default to resident-gather/kernel tuning
merely because this cycle exposed an implementation bottleneck.

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
   models. The first cycle tested E20, E21 and E19; use the results above to
   choose the next E19/E17/E14 questions. A plausible but uncertain idea deserves
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

**Next experiment:** compare small families of per-block dictionaries, optimizing
padded products, complete tile work, owner state and query/key duplication
together. Test whether common query transformations can be shared rather than
charging one full query ciphertext per dictionary. Include the existing one-map
layout and exact full scoring. Keep query fitting separate from index enrollment.

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

## E17 — Can query conversion and matching share work?

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
