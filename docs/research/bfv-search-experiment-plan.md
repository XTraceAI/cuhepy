# Experimental plan: exact encrypted Hamming search across the whole system

Drafted 2026-09-24. Branch: `research/bfv-search-lab`, based on the accepted
CUDA implementation in `staging` at `8d4c12c` (PR #12). These are hypotheses,
operation counts, and proposed experiments. No new encrypted performance
results or production-security approval are claimed by this original plan.

**Implementation update, 2026-09-24:** E01, E02, E06 and a restricted E08 now
have encrypted implementations and tests; E11 has a measured-variant network
planner. See [the first results](search-lab-first-results.md) for the experiments,
including losses, exact scope and raw data. The implementation directory is
[`experiments/bfv_search_lab`](../../experiments/bfv_search_lab). The portfolio
now also includes proposed CKKS, TFHE and mixed-protocol alternatives below.

**Public-pipeline follow-up:** the homemade BGV path now includes GPU query
transforms, key-read sharing, two fusion strategies, native terminal reduction,
and experiments on concurrent requests and terminal precision. See the
[paired pipeline results](bgv-public-pipeline-results.md). External libraries
remain independent correctness/performance references; developing our own
scheme and arithmetic implementations is the primary objective.

**Service/arithmetic follow-up, 2026-09-25:** E04 now has explicitly leased
persistent GPU workspaces and individual completion; the owner has an opt-in
private RNS/NTT backend. Nsight Systems captures and loopback TCP measurements
cover conversion, allocation and communication. E05 has a standalone narrow-limb
NTT comparison, E07 an encrypted feature-major reference, and E10 a plaintext
exact-filter bound study. See [results and remaining work](bgv-service-results.md).
The old system sanitizer issue is resolved using NVIDIA's verified 12.9.79
redistributable; the public oracle passes memcheck/racecheck. These advances do
not by themselves authenticate BGV responses or establish private constant-time
behavior; the subsequent, separate protected path is described below.

**Communication follow-up, 2026-09-25:** the query accounts for 70.6% of BGV
traffic at 8,192 vectors. A separate plaintext-congruent c0 rounding experiment
now reduces total traffic by 27.6% with the existing public-key index and 36.4%
with a new owner-encrypted index. It preserves N/Q and uses the complete public
correctness-bound schedule to select precision. A native public codec retains
the Python/GMP oracle and original seeded query. See the
[derivation, tradeoffs and measurements](bgv-query-compression.md).

**Compute/precision follow-up:** indexed NTTs, exact GPU terminal rounding,
packed owner finishing and bounded word codecs now have paired measurements.
The joint query/response planner measures complete framed traffic, including
229,583 bytes at 8,192 vectors with the public-key index. See
[compute and joint precision](bgv-compute-followup.md).

**Authentication/private-arithmetic follow-up:** an opt-in BGV Nitro protocol
now verifies an owner-authorized CPU evaluator's receipt before parsing or
decryption, and a separate native terminal decoder has fixed-work arithmetic
and compiled secret-taint checks. The GPU remains outside this authenticated
execution path. Local tests use synthetic enrollment; real AWS testing, private
encryption/key-generation assurance and parameter review remain open. See
[BGV authentication](bgv-authentication.md).

**Literature/agenda update, 2026-09-26:** the
[related-work review and E13–E19 proposals](encrypted-search-literature-agenda.md)
cover the supplied BioZKFHE paper, encrypted search/packing, verifiable FHE,
TEE-assisted verification, conversion and private indexing. The next priority
is a complete verified GPU path alongside stronger noise/packing models.
The [current execution order](#7-next-experiments-after-the-literature-review)
supersedes the initial ordering below. These proposals add no new performance
measurements or security/novelty claims.

## Expanded scheme portfolio after the first implementations

The objective is exact/private search under a declared contract, not adherence
to BFV. Each new scheme needs its own key/index format, correctness assumptions,
parameter assessment and protocol binding. A faster experiment must report any
change in privacy, interaction, preprocessing or approximation alongside speed.

| Track | Concrete experiment | First decision criterion |
| --- | --- | --- |
| BGV-style depth-one RLWE (implemented reference) | Coefficient correlations, no scale-and-round; compare four tensor products against three; try smaller plaintext modulus because this layout needs no batching roots | Full search compute **and** unrepacked response bytes, plus a public no-wrap correctness bound |
| BGV with sparse-result conversion (reference, native RNS and CUDA implemented) | Joint trace/packing butterfly, bounded terminal reduction and seeded owner queries; see the [measured follow-up](bgv-butterfly-results.md) | Compare complete search cost, setup, payloads and parameter/security differences; preserve the independent trace reference |
| CKKS with exactness gate | Signed inner products or coarse scores, followed by certified integer rounding or exact refinement of **all** ambiguous candidates | A proved error interval or measured recall labeled approximate; near-tie/tie fixtures must be included |
| RLWE-to-TFHE selection | Compute distances in an arithmetic scheme, then convert to Boolean/torus ciphertexts for encrypted comparisons and stable top-k | Conversion + comparisons + key distribution must beat sending packed distances and sorting on the owner |
| Mixed-protocol secure computation | Secret-shared Hamming followed by Boolean/garbled-circuit top-k; compare offline correlations and online traffic | State who holds each share, which parties may collude, interaction rounds, and whether security is semi-honest or malicious |
| Attested plaintext kernel | A separately labeled trust-model baseline: keep plaintext/key material inside an approved confidential execution boundary and perform XOR/popcount/top-k there | Trusted memory and attestation coverage, actual end-to-end cost, and explicit loss of the HE-only confidentiality assumption |

CKKS supports approximate arithmetic; that feature does not by itself guarantee
exact binary top-k. Our proposed gate would require a **proven** distance error
below one half for direct integer rounding, or intervals that retain every
candidate able to enter the exact top-k. Empirical accuracy alone belongs to
the approximate track. See the [original CKKS paper](https://eprint.iacr.org/2016/421).

TFHE supplies encrypted Boolean computation. Applying it only to selection is
a hypothesis for this workload, not an existing result here; scheme conversion
and tie-breaking can dominate. See the
[TFHE paper](https://eprint.iacr.org/2018/421) and its
[original implementation](https://tfhe.github.io/tfhe/).

ABY2.0 is a useful counterpoint for preprocessing and mixed arithmetic/Boolean
computation, but its stated security model is semi-honest. It cannot be used as
a drop-in answer to our malicious-evaluator problem. Our proposed experiment
must explicitly select and justify the parties and adversary model before
implementation. See [ABY2.0](https://eprint.iacr.org/2020/1225).

Historical order after the first measurements: preserve the winning query and
partial-reduction variants; optimize and compare sparse coefficient-result conversion;
then compare a reviewed library's shallow BGV and scheme-conversion path as an
independent oracle before optimizing a new native implementation. Seeded RLWE,
precomputed zero encryptions, coefficient dot products and three-product
multiplication are established techniques. Any paper contribution must be
supported by a prior-art review and the measured combination, layout/cost model
or new conversion algorithm, rather than renaming these ingredients.

Trace-packing prior art needs particular attention: the August 2026
[algebraic trace analysis](https://eprint.iacr.org/2026/1604) discusses
coefficient-dependent noise and non-recursive packing. Our first implementation
uses a simple worst-case coefficient bound, not that paper's refined variance
analysis. [HERMES](https://eprint.iacr.org/2023/1244) is another relevant
conversion baseline, using MLWE formats for ring packing; reproducing it would
require a different representation and cannot be assumed to be a small patch.

The research question is: **which representation and division of work minimize
end-to-end cost when both the database and query are encrypted?** Our strongest
opportunity is to jointly choose the Hamming circuit, packing, client work,
resident server representation, and communication budget. Faster generic GPU
arithmetic is an important baseline, but is already an active research area.

## 1. What the accepted implementation tells us

The [complete-search benchmark](bfv-paillier-performance.md) and its
[raw measurements](../../benchmarks/results/bfv_cuda_paillier_comparison_8192.json)
give this starting point for 8,192 vectors of 512 bits, N=16,384, t=65,537,
Q approximately 180 bits, and 50-bit terminal responses:

| Recurring cost | Measured warm median |
| --- | ---: |
| Client query encryption | 197 ms |
| GPU server, resident index, including framing | 180 ms |
| Client response decoding | 25.5 ms |
| Local complete search | 405 ms |
| Query upload | 737,394 bytes |
| Response download | 204,900 bytes |
| Query + response | 942,294 bytes |

These are existing measurements on a Ryzen 7 5800X / RTX 3080, not fresh runs.
The phase medians need not add to the total median. They exclude network,
attestation, setup, and content retrieval. The resident index uses 192 MiB;
larger-index tests reach about 49,000 vectors/second. Adding concurrent objects
gave only about 4% additional throughput, so concurrency alone has little
support as the next major improvement. See [the CUDA study](bfv-cuda-fused.md).

Two consequences guide the plan:

1. Even eliminating server time entirely would leave roughly 225 ms of client
   work. Eliminating query-encryption time alone would leave roughly 208 ms
   locally. These are illustrative limits, not achievable performance forecasts.
2. Query upload is about 78% of recurring BFV traffic. Optimizing only the
   download would miss most of the remaining communication cost at this size.

The current circuit squares encrypted differences, relinearizes each tile,
performs nine rotation/add stages over dimensions, masks the useful lanes,
then rotates/adds tiles into packed responses. For this workload there are
256 input tiles, 2,304 dimension-reduction rotations, 255 packing rotations,
and 256 relinearizations: **2,815 key-switch operations**. One operation here
means one ciphertext operation, not one CUDA launch.

## 2. Research contracts

The primary track keeps exact integer Hamming distances and stable top-k by
`(distance, original_index)`. The owner holds the secret key; the evaluator
holds encrypted data and public evaluation material. Index preprocessing is
allowed and must be charged separately. Never give the server a secret key to
accelerate a nominally homomorphic baseline.

Record changes to the contract explicitly:

| Track | Allowed result / observability |
| --- | --- |
| Exact, fixed scan | Same top-k; server execution shape depends on public sizes |
| Exact, owner sees intermediate scores | Same top-k, but client learns partial distances/correlations; appropriate only for an owner already authorized for the underlying data |
| Exact, selective execution | Same top-k with a proven bound, but access patterns need a declared leakage model or an oblivious/attested execution mechanism |
| Approximate | Measure recall against exact binary Hamming top-k; exact reranking of a candidate set does not restore missed candidates |

Performance work must preserve the existing requirement to authenticate the
intended computation before releasing decryption-dependent feedback. The
[CUDA evaluator currently cannot use the Nitro receipt path](bfv-cuda-server.md).
A CPU enclave must not sign an unchecked host-GPU result. Adaptive search needs
particular care: server-controlled results followed by client-selected branches
could reintroduce the decryption-feedback problem. Intermediate messages need
query/index/epoch/circuit binding and a reviewed execution-verification path.
GPU attestation, trusted recomputation, and proofs remain separate options.

## 3. Portfolio and recommended order

Each row is independently switchable. Combine winners only after measuring
them separately; keep unsuccessful results and their reasons.

| ID | Experiment | Primary target | First-stage uncertainty | Priority |
| --- | --- | --- | --- | --- |
| E01 | Stop dimension reduction early; use spare response slots for partial sums | Fewer key switches at a chosen download budget | Layout, client-output contract, noise | First |
| E02 | Native client encryption, one-use offline zero encryptions, seeded owner encryption | Online client time and query upload | Correct randomness lifecycle and private arithmetic | First |
| E03 | Bilinear Hamming circuit with an index cached in transform form | Repeated forward transforms | Memory cost and changed noise behavior | First |
| E04 | GPU terminal compaction, persistent scratch, graph replay, query microbatches | Transfers, allocation, launch overhead | Real profile and tail latency | Supporting |
| E05 | 30/31-bit residues and alternative key switching | Integer throughput and key traffic | More limbs/base-conversion work | Second |
| E06 | Coefficient-packed correlation with efficient result collection | Eliminate dimension-sum rotations | Repacking may consume all savings | High-upside research |
| E07 | Feature-major index and accumulate before relinearizing | Amortize key switches over many products | Query expansion and noise | High-upside research |
| E08 | A shallow BGV evaluator for the same binary circuit | Avoid BFV tensor scale-and-round | Different noise/parameter tradeoff | High-upside research |
| E09 | Bounded-range top-k plus encrypted sparse-output encoding | Download only selected IDs/distances | Comparisons and fixed ciphertext overhead | Later |
| E10 | Certified filtering, followed by exact evaluation | Avoid most expensive scores | Bound quality, access leakage, extra rounds | Separate protocol track |
| E11 | Joint circuit/layout/parameter planner | Workload-specific compute/traffic frontier | Security and correctness constraints | Starts with E01; expands later |
| E12 | Exact factorization, approximate sketches, and oblivious chunk lookup | Reduce arithmetic through data structure | Rank/recall/lookup cost may defeat the idea | Deliberately speculative |

### E01. Spend empty slots to save encrypted operations

Let M be the candidate count, d the dimension, D its next power of two,
N the ring degree, and C a power-of-two number of partial sums per vector.
Each partial covers D/C coordinates, including zero padding. Keep C disjoint
partial sums, pack them, and let the owner add them after decryption.

For the existing dimension-major layout:

```
vectors per input tile = N / D
T = ceil(M / (N/D))                         input tiles
R = ceil(T / (D/C)) = ceil(M*C/N)            response ciphertexts
dimension rotations = T * log2(D/C)
packing rotations   = T - R
relinearizations    = T
```

For M=8,192, d=512, N=16,384:

| Partial sums/vector | Rotations | All key switches | Responses | Coefficient bytes |
| ---: | ---: | ---: | ---: | ---: |
| 1, current schedule | 2,559 | 2,815 | 1 | 204,800 |
| 2 | 2,303 | 2,559 | 1 | 204,800 |
| 4 | 2,046 | 2,302 | 2 | 409,600 |
| 8 | 1,788 | 2,044 | 4 | 819,200 |
| 512, no dimension reduction | 0 | 256 | 256 | 52,428,800 |

Thus C=2 removes **256 key switches, about 9.1%**, without another ciphertext.
These are counts, not a 9.1% latency prediction. Byte counts exclude framing;
the measured current response is 204,900 bytes. A new layout identifier must be
authenticated and its actual serialized overhead measured.

Within each SIMD row, let B=N/(2D), G=D/C. After log2(G) rotate/add stages,
keep dimension starts `0,G,2G,...`. In a response, tile j occupies columns
offset by `j*B` within every partial-sum band. At most G tiles fit; bands do not
overlap. Decryption sums the C corresponding entries. This also handles partial
tiles and incomplete response groups.

**First experiment:** implement a CPU reference for C=1,2,4 before CUDA. Verify
every partial sum, final distance and stable top-k, including non-power-of-two
dimensions and response boundaries. Then shorten the CUDA rotation loop, change
mask/merge limits, and add a separate decoder. Existing ciphertext arithmetic
parameters and encrypted indexes can remain the starting point.

**Continue if:** C=2 produces a repeatable complete-search win at the same
coefficient payload, and the C sweep gives a useful bandwidth/compute frontier.
**Stop or narrow if:** client overhead or more complicated packing erases it.
The client learns sub-distances; do not describe this as a distance-only API for
third-party queriers. The possible contribution is an occupancy-aware execution
planner, not a claim that partial summation itself is new.

### E02. Make online query generation cheap

Treat these as three ablations:

1. Implement native CPU encoding/encryption with a persistent private context.
   The current `BFV.encrypt` performs public-key polynomial products through the
   Python/GMP path; the server already has substantially faster native machinery.
   Benchmark a normal CPU client first, without requiring a client GPU.
2. Generate fresh `Enc(0)` objects offline. Online, consume exactly one and add
   `floor(Q/t)*Encode(query)` to its first component. This preserves the public
   encryption distribution when the precomputed encryption is fresh. Charge
   refill work, memory, startup, pool depletion, and crash recovery. Two messages
   using the same zero encryption expose their difference: tokens must never be
   reused, including across forks, retries or restored snapshots. Start with an
   in-memory single-use pool; do not persist reusable randomness casually.
3. Since the owner has the secret key, try symmetric RLWE encryption whose
   uniform component is regenerated from a public seed. Send one full polynomial
   plus the seed instead of two polynomials. The noise/secret randomness must
   remain independent of that public seed. SEAL already implements
   [seeded symmetric encryption](https://github.com/microsoft/SEAL/blob/main/native/src/seal/util/rlwe.cpp);
   this is established technique, not a novelty claim.

At N=16,384 and 180 coefficient bits, the raw two-polynomial query contains
737,280 coefficient bytes. One polynomial contains 368,640. A seed and new
framing could therefore roughly halve query upload; measure regeneration cost
on the server. This is not arbitrary compression of evaluated responses, whose
components generally cannot be replaced by seeds.

**Continue if:** client preparation falls materially below the existing 197 ms
and the benefit survives accounting for offline refill. **Stop or narrow if:**
state management dominates, or symmetric encryption does not fit a caller that
has only a public key. Private arithmetic needs its own side-channel review;
server-side public CUDA routines cannot simply be relabeled private routines.

### E03. Cache the useful representation of an immutable encrypted index

For bits, `H(x,q) = sum(x + q - 2*x*q)`. Evaluate this bilinear circuit instead
of squaring `x-q`. Cache the encrypted index's lifted, NTT-transformed components
once; lift/transform the query once per request and reuse it across tiles.

The current prepared index retains six N-coefficient residue arrays per tile.
A two-component transform in the seven-prime multiplication base uses fourteen:
about **448 MiB instead of 192 MiB** for the existing 8,192-vector index, if it
replaces the six-array copy. Keeping both uses about 640 MiB. Add plan, scratch,
allocator and runtime memory to these array-only estimates.

This trades a general product's pointwise work and a larger resident index for
less repeated transformation. Binary inputs are essential to this identity.
Cache ownership must bind the exact key, parameters, index epoch and circuit.

**Important algebra check:** lifting a difference reduced modulo Q into a
larger RNS base is not interchangeable with subtracting independently lifted
operands. Do not substitute cached transforms into the old square kernel and
assume coefficient equality. Start with the explicit bilinear BFV circuit,
check its decoded output and noise against the reference, then optimize it.

**Continue if:** the warm-query saving amortizes index preparation within the
expected queries per epoch. Report the break-even query count and update cost.
**Stop or narrow if:** VRAM growth forces enough streaming to remove the gain.

### E04. Finish removing avoidable representation changes

Prototype exact terminal modulus switching and 50-bit packing on the GPU, so
the server downloads final packed coefficients. Today it downloads six residue
arrays, composes GMP integers on CPU, compacts, and exports. Then test bounded
scratch pools, pinned transfers, and CUDA Graph replay for public workload
shapes. Distinct in-flight queries must retain separate mutable buffers.

Add true query microbatching over a shared index to reuse evaluation-key/index
loads across queries. This is a different experiment from creating more Python
instances. Measure queue delay and single-query p95 as well as aggregate QPS.
Avoid unbounded request batches to manufacture throughput at unusable latency.

**Continue if:** an unsynchronized end-to-end profile improves. **Stop or narrow
if:** allocation/launch/transfer time was already negligible. Synchronized phase
profiles in the existing report are diagnostic and must not be added up as
shares of wall time. Run Compute Sanitizer memcheck/racecheck on a working
installation; the previous host's sanitizer failure remains an open validation
item.

### E05. Match residue arithmetic and switching to the GPU

Compare three approximately 60-bit primes with approximately six 30-bit primes
at comparable total Q, retaining the same N and declared security target.
Use 32-bit words and 64-bit products in the short-prime variant. This is not
halving the cryptographic modulus: more limbs and more base conversion can
erase the faster per-limb arithmetic.

Independently vary gadget decomposition and evaluate RNS/hybrid key switching.
Measure key bytes, digit transforms, noise, and steady-state memory traffic.
The existing rotation tree changes its input after each step, so a decomposition
cannot be hoisted once across all nine dependent rotations. Hoisting is most
useful when several automorphisms share one unchanged input, such as some
expansion/repacking schedules. See
[Halevi–Shoup's linear-transform work](https://www.iacr.org/archive/crypto2018/10993198/10993198.pdf).

GPU key switching already has dedicated
[comparative implementations](https://eprint.iacr.org/2025/124), and
[Cheddar](https://github.com/scale-snu/cheddar-fhe) studies short-word GPU
arithmetic for CKKS. Reproducing their principles is useful engineering; exact
BFV scale-and-round needs its own implementation and correctness argument.

A stretch experiment is limb-split integer Tensor Core arithmetic for blocked
NTT/base-conversion products. [TensorFHE](https://arxiv.org/abs/2212.14191) is
prior art. Derive accumulator bounds and reconstruct exact integers; do not
silently introduce approximate floating-point errors into exact BFV. Compare
with ordinary CUDA cores including repacking overhead.

### E06. Compute correlations in polynomial coefficients

Let `a_j=1-2*x_j`, `b_j=1-2*q_j`, pad unused coordinates with zero to length D,
and put B=N/D candidates into a tile:

```
A(X) = sum over r,j of a[r,j] * X^(r*D+j)
B(X) = sum over j of b[j] * X^(D-1-j)
```

In `Z_t[X]/(X^N+1)`, the coefficient of `X^(r*D+D-1)` in `A*B` is
`sum_j a[r,j]*b[j] = d - 2*H(x_r,q)`. Neighboring blocks cannot contaminate
this coefficient because `j-k` cannot equal a nonzero multiple of D. Terms
wrapping past N land below degree D-1, outside the selected positions.

This performs many dot products with one ciphertext multiplication and **no
dimension-sum rotations**. The owner recovers H from the signed correlation.
An odd plaintext modulus greater than 2d suffices for these selected values;
unlike full SIMD batching, coefficient packing does not require `t=1 mod 2N`.
For d=512, t=1031 is a candidate for a separate parameter study, not a reviewed
replacement for the current t=65,537. The existing parameter validator assumes
the batching path and must not be weakened globally for this experiment.

The problem is output collection. Sending all 256 tile results at the current
N/Q' would cost about **52.4 MB of coefficients**, versus about 0.205 MB now.
Explore trace/automorphism extraction, structured repacking, and a separately
reviewed small-output ring/key switch. Sampling a few coefficients from both
ciphertext components is not a valid shortcut: decryption includes convolution
with the secret polynomial. The public seed trick cannot generally compress
these computed ciphertexts either.

Forward/backward polynomial packing is established in
[earlier encrypted-inner-product work](https://link.springer.com/article/10.1186/s40736-014-0005-x).
The prospective contribution is collecting many exact encrypted correlations
efficiently enough to retain the compute saving and low communication.

**First experiment:** reproduce the coefficient identity, implement a CPU
encrypted tile, then benchmark repacking separately before writing CUDA.
Unselected coefficients expose additional correlations to the decrypting owner;
mask/repack them or explicitly require the owner-authorized intermediate-output
contract. **Stop if:** repacking costs at least the rotations it replaces and
the communication tradeoff has no useful regime. That negative result is useful.

### E07. Turn the index sideways and delay expensive normalization

Store each feature as a ciphertext containing that feature for up to N vectors.
Expand the encrypted query into replicated encrypted feature values once, then
evaluate all candidate dot products by feature-wise products and additions.
No per-vector dimension-reduction rotations are needed in this representation.

Accumulate the three-component products over features and relinearize the sum
once per output group. Separately investigate accumulating wide integer tensors
before BFV scale-and-round. The latter requires a new auxiliary-base bound with
the feature-count accumulation factor, and changes rounding/noise; it is not
just moving an existing call outside a loop.

The tradeoff is query expansion. At M=8,192, N=16,384, a feature-major index
uses 512 ciphertexts rather than 256 and underfills each one. For large M,
expansion amortizes across groups, so sweep M beyond N and vary query batches.
Measure both expansion and evaluation; do not benchmark only the dot product.

**Continue if:** saved rotations/switches beat query expansion at a reachable
database size and VRAM budget. Compare with E06 and the existing tile layout,
including key size and index construction. **Stop if:** the break-even size
requires an impractical encrypted index or a larger noise modulus that removes
the gain.

### E08. Ask whether BFV is the best scheme for this shallow circuit

Implement a minimal, experimental BGV path for the same encrypted binary
workload. The current BFV CUDA multiplication uses seven primes to reconstruct
an exact wide product and scale it back to three. BGV's different plaintext/noise
encoding may avoid that BFV-specific tensor scale-and-round at the cost of a
different noise evolution and modulus-switch procedure. This is a hypothesis,
not a claim that BGV is automatically cheaper. BGV is an
[existing scheme](https://eprint.iacr.org/2011/277).

Start from a reviewed library as a sanity baseline and a tiny CPU reference.
Compare equal exact outputs and separately assessed security, with full key,
parameter, and operation counts. Do not reuse BFV parameters, decoder or
attestation circuit identifier unchanged. Only port to CUDA if the operation
and noise measurements justify maintaining another backend.

### E09. Exploit the small distance range to return only top-k

For d=512, distances are integers from 0 to 512. Try a tournament selector,
a threshold/count circuit, and BFV-to-Boolean-scheme switching for comparison.
After identifying a small set, evaluate sparse-result encoding rather than
sorting/retransmitting the entire vector. Relevant prior work includes
[compressed oblivious encoding](https://arxiv.org/abs/2109.07708).

Selection and compaction are separate problems. Three occupied slots in an
N=16,384 ciphertext still have essentially the same coefficient payload as a
full ciphertext. A smaller output representation needs a real extraction,
packing, or ring/key-switch protocol. PIR composition work such as
[Spiral](https://eprint.iacr.org/2022/368) offers ideas, but PIR normally performs
different operations over a server-held database; it is not a drop-in solution
for our encrypted-encrypted distance computation.

The existing Q/depth budget cannot simply run a deep comparison circuit. Include
conversion keys, bootstrap costs if needed, setup and client decoding. Preserve
deterministic ties and original IDs.

At 100 Mbps, transmitting the current 204,900-byte response takes about 16.4 ms
in an ideal transfer model; at 10 Mbps it takes about 164 ms. These give a useful
ceiling on download-only savings at this size. A selector costing seconds needs
a different workload regime to pay off. Query upload, RTT and authentication
costs remain. **Stop early if:** selection plus compact output cannot beat the
existing response at any intended workload/network point.

### E10. Exact lower bounds before expensive full scores

For disjoint coordinate blocks B_j, the following are genuine lower bounds:

```
sum_j |popcount(x on B_j) - popcount(q on B_j)| <= H(x,q)
H(x on a chosen subset, q on that subset)      <= H(x,q)
|H(x,pivot) - H(q,pivot)|                       <= H(x,q)
```

Precompute encrypted block counts, pivot distances, or encrypted cluster
representatives/radii. Obtain an exact k-th candidate distance tau; discard a
candidate/group only when its certified lower bound is greater than tau.
Equality needs tie handling. Returning the best candidates from a rough sketch
alone is not an exact algorithm.

First measure bound selectivity with plaintext on random, clustered, biased,
near-duplicate and deliberately difficult binary data. Uniform random 512-bit
vectors are likely to make coarse bounds weak. For a query with genuinely close
neighbors, a short exact coordinate prefix may eliminate distant candidates.
Include the cost of finding tau, not just the later pruning rate.

The server cannot branch on an encrypted bound for free. Client-steered
candidates reveal access patterns; encrypted masks can leave full scan cost
unchanged. Evaluate explicit alternatives: accepted leakage, private retrieval
of surviving encrypted tiles, or trusted selection inside an attested boundary.
The last option requires a separate trusted-computation design. Authenticate
each round before decryption-dependent control flow; synthetic local tests do
not establish that protocol's security.

Recent [GPU encrypted ANN work](https://arxiv.org/abs/2608.21131) already studies
rank reduction, hierarchical routing, and access-pattern leakage. We must compare
its setting and warm/cold accounting, and identify what exact binary bounds and
pre-encrypted indexes add. No claim that encrypted hierarchical search is new.

### E11. A planner constrained by correctness and security

Search across public workload inputs `(M,d,k,bandwidth,RTT,queries_per_epoch,
VRAM)` and candidate circuits/layouts. Choose C for E01 first; subsequently add
N, coefficient-prime layout, switching parameters, and terminal response bits.
Measure the whole Pareto frontier instead of picking a ring solely by server
time or response size.

Try dropping a coefficient prime after multiplication and before rotations;
try narrower terminal responses; measure how E06's smaller plaintext modulus
changes feasible Q. Each choice needs new noise/correctness bounds and parameter
assessment. Fix the schedule by reviewed public configuration, never by exposing
a private per-response noise estimate. Merely passing random decryptions is not
a parameter proof.

Pin the version and full inputs of the
[lattice estimator](https://github.com/malb/lattice-estimator), including secret
and error distributions, and document its modeling limits. Do not describe the
current N/Q comparison or smaller rings as security-equivalent without that
work. Small-ring arithmetic fixtures are not deployment candidates. Related-key
material and ring-switch paths also need analysis, not only a scalar Q-bit check.

**Prospective contribution:** a reproducible, security-constrained plan selector
for an encrypted Hamming circuit, backed by measured cost/noise models. A planner
trained on one GPU must be validated on another or labeled hardware-specific.

### E12. Deliberately risky representations

- **Exact low-rank factorization over the plaintext field:** if the binary/signed
  index matrix factors as A*B with rank r much smaller than d, encrypt the factors
  and evaluate in two stages. Test exact rank before FHE. Random binary data may
  have full rank; larger intermediate coefficients, an extra multiplication
  stage and rotations may eliminate any savings. Keep data-dependent rank/index
  shape private or explicitly include it in leakage.
- **Sketch then rerank:** random coordinate sampling, binary projections, or
  quantization may reduce expensive candidate scoring. Measure recall@k against
  the full exact result; attach a rigorous bound/certificate if claiming exact
  output. This is a separate approximation track and overlaps prior ANN work.
- **Oblivious lookup per small bit chunk:** precompute a truth table and select
  it with encrypted query bits using an actual encrypted MUX/external product or
  programmable bootstrap. A plaintext lookup indexed by encrypted bits is not
  possible. Hamming is already a low-degree function; the exponential table and
  encrypted selection may be worse. Model 2-, 4-, and 8-bit chunks before code.

These are useful experiments even if they lose. A reasoned counterexample and
measured failure regime are better paper material than an unexplained omission.

## 4. Validation and comparisons that make this a paper

Use the accepted implementation and committed raw measurements as provenance,
then rerun fresh paired baselines before claiming improvements. The first local
baseline is the same RTX 3080. Validate leading candidates on an available AWS
GPU later, recording the actual instance/GPU rather than assuming portability.
No cloud provisioning is part of this planning change.

| Axis | Proposed sweep |
| --- | --- |
| Vectors M | 1,024; 8,192; 32,768; 131,072; 1,048,576 where memory/streaming permits |
| Dimensions d | 128; 256; 512, plus non-power-of-two correctness fixtures |
| Top-k | 1; 3; 10; stable tie cases |
| Workload | Random, clustered, biased bits, duplicates, query exact match/complement, real binarized embeddings with documented provenance |
| Index lifetime | One query/epoch; 10; 100; 1,000; incremental updates |
| Load | Single request; real microbatches; bounded concurrent requests |
| Network | Separate uplink/downlink rates, 10/100/1,000 Mbps, explicit RTT; real transport for finalists |
| Parameters | Published exact N/t/Q/primes/error/gadget/response settings; assessed security separately |

The current resident representation alone is about 24 GiB for a million
512-bit vectors, before keys/scratch; E03's fourteen-array form is about 56 GiB.
Such sizes require streaming, sharding or a larger GPU. Never silently benchmark
repeated copies of a small encrypted tile as if it were a distinct corpus.

Report key generation, index encryption, preprocessing, device preparation,
client query encoding/encryption/serialization, query upload, server execution,
response serialization/download, client decryption/decoding, top-k and optional
content retrieval separately. Record query, response, index and evaluation-key
bytes, peak host/VRAM use, and update cost. Charge one-use preprocessing to
throughput even when reporting its online latency benefit.

Use fresh query encryption; share identical inputs/keys for same-parameter
backend ablations; alternate execution order; record cold and warm separately.
For initial timing use at least ten measured requests; for p95 claims collect
enough independent requests (e.g. 100+) and report variation/confidence intervals.
Keep correctness checks, profilers, builds and other GPU jobs outside timed
regions. Model latency as a model until real transport is measured:

`L = client_prepare + server + client_finish + 8*U/b_up + 8*D/b_down + rounds*RTT`

That buffered model excludes overlap, queuing and transport overhead; measure
those for finalists. Amortization break-even for a preprocessing optimization is
`extra_setup_time / per_query_time_saved`, when the latter is positive.

Correctness checks include every distance, stable top-k, empty/tail batches,
cross-backend decoding, malformed ciphertexts, context/key/index mismatches,
concurrent lifetime/isolation, and randomness reuse regressions. Equal ciphertext
coefficients are expected for representation-only kernel changes, but changed
circuits such as E03/E06 need plaintext equivalence plus noise analysis instead.

External baselines should include current SEAL CPU and a BFV-capable GPU library
such as [HEonGPU](https://github.com/Alisah-Ozcan/HEonGPU), alongside our CPU BFV,
CUDA BFV, Paillier CPU/CUDA and Lookup CPU/CUDA/hybrid. Match the workload,
encrypted operands, output contract and security assessment. Cheddar/TensorFHE
are important related GPU work, but a CKKS kernel timing is not automatically
an exact BFV search baseline. Pin external versions and licenses before adapting
code; paper headline speedups on other hardware are not our results.

## 5. Implementation sequence and repository boundaries

1. **Model and falsify first:** the independent plaintext oracles below, a fresh
   baseline/profile, data selectivity/rank probes, and an initial related-work
   matrix. Distinguish a new contribution from adapting known techniques.
2. **First encrypted experiments:** E01's C=2 CPU reference and CUDA path; E02's
   native encryption ablation; E03's uncached bilinear reference and cached form.
   Compare each against the unchanged accepted implementation.
3. **Primitive experiments:** E04/E05, only where profiles justify them. Extend
   the planner with measured costs and add encrypted noise validation.
4. **Competing algorithm experiments:** E06/E07/E08. Reject losing cost models
   before expensive CUDA work. Retain a small CPU oracle for each surviving path.
5. **Protocol experiments:** E09/E10 and selected E12 ideas, with explicit output,
   accuracy, leakage and authenticity contracts. Evaluate real network break-even.
6. **Paper selection:** combine the strongest independent wins, run ablations,
   reproduce on another GPU, and include negative findings. Do not promise that
   every idea is novel or that their speedups multiply.

Start in `experiments/bfv_search_lab/`, using a CPU reference before optional
CUDA modules. Keep benchmark integration in `benchmarks/` and reports here in
`docs/research/`. Only promote a stable primitive into `src/cuhepy/bfv/` and its
Hamming adapter into `src/cuhepy/hamming/` after the experiment earns it. The
current clients remain the baseline; draft plans do not change their defaults.
Use descendant branches such as `experiment/bfv-partial-reduction` for separate
implementations, so failed ideas can remain inspectable without coupling them.

For each experiment, retain a short record: hypothesis, closest prior art,
contract, derivation, source/build hashes, parameters, full samples, correctness
and noise evidence, amortization/memory costs, outcome, and a reason to continue
or stop. Never store private keys in measurement artifacts.

## 6. What exists on this branch now

- This plan and its primary-source links.
- [A standard-library plaintext oracle](../../experiments/bfv_search_lab/layout_oracles.py)
  for E01's complete slot layout and E06's signed coefficient identity.
- [Analytical operation counts](../../experiments/bfv_search_lab/models/partial-reduction-8192.json)
  for the current 8,192-vector workload, clearly marked as a model.
- [Encrypted first results](search-lab-first-results.md): partial CPU/CUDA sums,
  query preprocessing, seeded uploads and the homemade coefficient-BGV reference.
- [BGV joint packing](bgv-butterfly-results.md): an isolated homemade public
  RNS/CUDA evaluator, terminal compaction and independent SEAL circuit checks.
- [Public pipeline ablations](bgv-public-pipeline-results.md): gathered/fused
  kernels, native terminal reduction, 32,768-vector scaling and concurrent service.
- [Fresh owner arithmetic](bgv-owner-results.md): bulk sampling/stream decoding,
  exact shifted-ternary products, a separate private C++/GMP owner, and paired
  client/server phase measurements. No secret arithmetic enters the public server.
- [Result handling and distinct-query GPU batches](bgv-finish-batch-results.md):
  exact distance lookup, fused private finishing, public batch kernels, and
  comparisons with the existing threaded server, including completion delays.
- [Service and algorithm studies](bgv-service-results.md): persistent GPU
  workspaces, private RNS arithmetic, local TCP pacing, fresh Paillier/BFV
  comparisons and negative narrow-limb/filter results.
- [Query communication](bgv-query-compression.md): bounded c0 rounding, native
  codecs and separately measured public-key/owner-encrypted index choices.
- [Compute and joint precision](bgv-compute-followup.md): indexed/warp NTT
  ablations, exact GPU terminal rounding, packed response processing, a public
  query/response precision frontier and bounded word codecs, with full-request
  measurements and retained baselines.
- [BGV authentication and private finishing](bgv-authentication.md): separate
  CPU enclave protocol, verification before decryption, fixed-work terminal
  arithmetic and local protocol benchmarks; no authenticated GPU claim.
- [Literature review and next experiments](encrypted-search-literature-agenda.md):
  primary-source comparisons, E13–E19 derivations, cost limits and decision gates.
- [Radix packing and client decoding](bgv-radix-results.md): balanced and
  direct-distance layouts, exact bytes, scalar controls and complete local/TCP
  measurements, including cases where fewer tiles still lose on the network.
- [Trusted digit-boundary costs](bgv-digit-boundary-results.md): exact CPU/GPU
  conversion, transfer layouts and radix-reduced schedules; no verifier claim.
- [Joint layout/precision/setup planning](bgv-layout-planning.md): all 12
  measured plans, separate paced-link checks and epoch break-even projections.
- [Complete key-switch stage checking](bgv-checked-switch.md): one-use
  reference/native checkers, conditional soundness, CPU/CUDA differential tests
  and actual trusted work; complete search authentication remains open.
- [Bound product/switch checking](bgv-checked-product.md): eliminates the trusted
  tensor prerequisite, compares witness/local-c2 partitions and measures a
  direct-RNS checked GPU subcircuit against native recomputation.

The oracle passes **1,131 partial-layout cases and 367 coefficient-layout cases**.
It exhausts all query/vector pairs up to four bits and adds deterministic random
fixtures, zero padding, tails, empty inputs, multiple responses and negacyclic
wraparound. It does not execute BFV, estimate security, measure noise or establish
speedup. Reproduce it with:

```bash
python3 experiments/bfv_search_lab/layout_oracles.py \
  --json-out experiments/bfv_search_lab/models/partial-reduction-8192.json
```

## 7. Next experiments after the literature review

The baseline is preserved in pushed checkpoint tags and
[PR #14 into staging](https://github.com/XTraceAI/cuhepy/pull/14), at `3c0a547`.
Follow-up work is on `experiment/bgv-verification-packing`:

- **E15 implemented and measured:** the [deterministic support bound](bgv-support-bounds.md)
  keeps the ciphertext circuit unchanged, saves 16/18 KiB of query traffic at
  8,192/32,768 vectors and reduces paced-link latency. Original bounds, codecs
  and Nitro policies remain available. Whole-polynomial symbolic tests and
  complete CPU/CUDA comparisons precede the precision measurements.
- **E16 implemented and measured:** [balanced/direct-distance packing](bgv-radix-results.md)
  uses the existing homemade BGV circuit with new t/layout contexts. At 32,768
  vectors, owner-index complete local requests fall from 86.36 ms to 61.20 ms
  (distance g=2) or 54.41 ms (g=3). Only g=2 also improves total traffic there;
  at 8,192, larger packets lose on both measured links. The scalar reference,
  negative initial results and packed/vectorized ablations are retained.
  The [joint planning follow-up](bgv-layout-planning.md) measures all 12
  layout/precision combinations and three directional links. Its local-sample
  model picks five of six paced winners, with a 1.64 ms miss. Setup amortization
  matters: switching a resident ordinary index to g=2 at 32,768 vectors needs
  a modeled 6,680-query epoch at symmetric 10 Mbps; full registration overhead
  is unmeasured, so this is a floor under the current representation.
- **E13/E14 specification/oracles and E13 boundary measurements implemented:** the
  [stage/constraint inventory](bgv-verification-relations.md) includes integer
  rounding, canonical CRT, digit ranges, coverage and exact response binding.
  Exhaustive toy field and integer mutation tests validate these arithmetic
  references. There is no complete proof or authenticated GPU protocol yet.
  The [measured digit boundary](bgv-digit-boundary-results.md) improves from
  130.53/348.84 ms to 43.95/121.41 ms at 8,192/32,768 vectors using aligned
  words and eight CPU workers. These omit the actual verification protocol
  and enclave transport. Radix g=3 reduces those schedule costs further to
  20.60/50.01 ms; substantial trusted/transfer work remains.
- **E13 complete stage check implemented:** [canonical batched key switching](bgv-checked-switch.md)
  binds trusted inputs and full output packets, samples fresh weights after
  output commitment, and checks both components in both limbs. The independent
  Python/GMP implementation and optional homemade C++/RNS checker pass mutation,
  lifecycle, toy exhaustive-soundness, CUDA and native sanitizer tests. Paired
  native costs including input binding are 9.29/23.15/90.73 ms for batches of
  1/8/32 at N=16,384. These verify one stage with already-trusted inputs, not
  the complete query or an untrusted preceding tensor product.
- **E13 product/switch composition implemented:** the
  [bound product checker](bgv-checked-product.md) pins the query/index and
  combines product and switch relations. A c2-only witness removes 40% of
  full-tensor/output coefficient traffic; local c2 removes 60%. After a retained
  negative export-heavy GPU run, direct RNS export and batching yield complete
  checked-stage medians of 61.27/155.85 ms at 32/64 tiles versus optimized native
  recomputation at 91.58/197.97 ms. One tile loses and eight are near parity.
  These are ciphertext tiles and an initial subcircuit, not complete searches.
- **Next:** extend the exact relation through butterfly/key-switch transitions,
  then terminal rounding/compression and final-byte binding. Benchmark matched
  CPU thread budgets, bound block coverage above 64 tiles, resident memory and
  actual enclave transfers before selecting a complete verifier partition.
  The trusted checks now dominate the 32-tile result. For E16, measure
  registration, epoch turnover, additional dimensions/tails and independent
  reruns; budget resident memory and switching margins. Extend protected client
  and receipt contracts only after the complete statement is established.
  E14 proofs and E17–E19 remain independent model-first experiments.

The strongest current paper direction is **exact encrypted search with
verification, client work and communication included in the optimization**.
The earlier E01–E12 descriptions retain their original hypotheses and dated
baselines; their follow-up reports record what was implemented and what lost.
Use the updated agenda for new decisions, rather than treating an old estimate
or a raw GPU fixture as today's authenticated service performance.

| ID | New experiment | First concrete deliverable | Main reason it may fail |
|---|---|---|---|
| E13 | Trusted CPU checks an untrusted GPU's public ciphertext arithmetic | Bound product/switch and direct-RNS checked GPU subcircuit done; next reduction/terminal/coverage chain | Intermediate traffic or trusted work approaches matched native recomputation |
| E14 | Design the HE circuit and its proof together | Canonical evaluation relation including integer rounding, compression and index coverage | Proof generation/bytes overwhelm the fast search |
| E15 | Coefficient-specific trace/noise bounds | Exact symbolic support model, then a justified deterministic or explicitly probabilistic bound | Shared errors/rounding invalidate optimistic independence assumptions |
| E16 | Balanced and direct-distance radix digits inside coefficient-packed correlations | Joint layout/precision/setup report done; next actual epochs, registration and memory costs | Larger t/Q, wider output or setup erase the reduction in tile count |
| E17 | Short LWE/MLWE or symmetric query upload with server conversion | Conversion+search cost model against the current rounded query | Conversion depth/setup costs exceed saved transfer time |
| E18 | Exact stable top-k followed by sparse output encoding | Selection and moment-encoding oracles, with real output-conversion costs | Comparisons cost more than the roughly 80 KB response they replace |
| E19 | Exact private substring indexing and coverage certificates | Bucket/selectivity model, omission tests and explicit leakage contract | Enumeration, padding, proof traffic and extra rounds erase pruning |

The [companion agenda](encrypted-search-literature-agenda.md) gives the equations,
closest literature, security boundaries, experiment sequence and stop criteria.
Use E13's measured boundary costs and E15/E16's mathematical references and
full-request measurements to choose the next complete verification experiment.
Proceed to new kernels or scheme implementations only after those models
leave a credible complete-request improvement. E17–E19 remain
independent exploratory tracks; BFV is not a restriction on the design space.

Keep the four original size categories and add authentication/proof bytes,
verifier/accelerator traffic and preprocessing refill. Compare exact with exact,
raw with raw, and protected with the same protection. The CPU protected path
and raw GPU path are different baselines; their timing components cannot be
combined into a claimed verified GPU result. Preserve all homemade/reference
implementations and record unsuccessful experiments as part of the evidence.

Packing, randomized verification, transciphering and sparse encoding are known
ingredients. Whether the proposed bound, protocol, conversion or measured
combination is a research contribution remains a literature-and-results question.
