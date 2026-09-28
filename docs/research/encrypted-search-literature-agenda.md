# Literature review and next experiments for encrypted search

**2026-09-28 sixth creative follow-up:**
[matrix arithmetic, query masks and conditional verification](matrix-arithmetic-results.md)
now implement the first E28 oracles and new E17/E14 probes. The matrix
construction has been read beyond its abstract; targeted new reading includes
[Park's CC-MM paper](https://eprint.iacr.org/2025/448),
[Bae et al.'s matrix formats/external products](https://arxiv.org/html/2503.16080v1),
and the overview of [Yang et al.'s preprocessing tradeoffs](https://arxiv.org/html/2606.25349v1).
The report distinguishes reading depth, established ingredients and our
experiments. A restricted query-mask space preserves scalar online arithmetic,
with larger preprocessing/state costs and a conditional linear check. The next
test is the actual private-map/CRT query space and its complete protocol costs,
not a claim that these algebraic ingredients are novel or production ready.

**2026-09-28 execution priority:** the user reaffirmed that creative, potentially
original experiments take precedence over completing or maximally tuning the
current pipeline. The updated
[research priorities](creative-experiment-priorities.md#research-priority-reaffirmed-2026-09-28)
put E28 alternative arithmetic, E17 conversion fused with matching, and E25/E26
encrypted exceptions ahead of further E27 layout tuning or packed-workspace
integration, with E14 co-design as another candidate. Each starts with a precise
difference from prior work and a cheap falsifiable model. This is a change of
execution order, not a new literature review or an established novelty claim.
The E27 implementation remains checkpointed at
`checkpoint/dyadic-rank-capacity-2026-09-27` (`10a9125`).

**2026-09-27 fifth creative follow-up:**
[rank repair, unequal CRT capacity and cache/update controls](dyadic-rank-results.md)
now implement E27. The interesting comparison is a joint owner-state/rank/
capacity/update tradeoff, with a complete plaintext affine cache as an explicit
alternative. Positive HE timings alone do not choose the paper direction.
Targeted new primary reading adds
[Mali, Generalized BGV, BFV, and CKKS for Homomorphic Encryption over Matrix Rings](https://eprint.iacr.org/2025/972)
as an alternative matrix-valued/Module-LWE arithmetic lead. Only the abstract
and available technical-overview excerpt were reviewed in this cycle. The
[E28 card](creative-experiment-priorities.md#e28--is-matrix-valued-he-a-better-arithmetic-model-for-exact-search)
requires a full read and homemade small oracle before implementation or timing
claims; charge noncommutative switching, keys and batch-one utilization. This
does not establish novelty, a scheme conversion or a security estimate.

**2026-09-27 fourth creative follow-up:**
[exact local affine maps and CRT query components](affine-component-results.md)
now test shared query work with bounded-per-map owner state. Targeted primary
reading adds [Smart and Vercauteren's homomorphic SIMD/lookup work](https://eprint.iacr.org/2011/133)
and [Zheng, Li and Wang's tensor-ring matrix framework](https://eprint.iacr.org/2023/1649)
to the comparison agenda. The latter was inspected at abstract/metadata level,
not reproduced. Polynomial CRT, affine factorization and binary-mask query
contractions are established ingredients; the open question is a useful joint
rank/padding/state/update tradeoff for exact encrypted search. An expensive
scalar encrypted residual lookup is retained as one control, not a lower bound
for optimized private lookup. The updated
[E26 experiment card](creative-experiment-priorities.md#e26--can-private-local-representations-share-one-encrypted-query)
prioritizes unequal capacities, bounded-state planning, exact exceptions and
query conversion fused with private component statistics. These measurements
do not establish novelty or close the authentication/side-channel boundary.

Reviewed 2026-09-26 on `research/bfv-search-lab`, after `5f4a550`.
This supplements the [main experiment plan](bfv-search-experiment-plan.md).
E13–E19 below began as **proposals**. The 2026-09-27 follow-up now records an
[E15 deterministic bound and measured precision improvement](bgv-support-bounds.md)
and [E13/E14 stage inventory and arithmetic oracles](bgv-verification-relations.md),
followed by [E16 radix/client measurements](bgv-radix-results.md),
[joint layout/precision/setup selection](bgv-layout-planning.md),
[E13 CPU/GPU boundary measurements](bgv-digit-boundary-results.md) and a
[complete reference/native key-switch stage check](bgv-checked-switch.md), then
[bound product/switch composition and direct RNS GPU output](bgv-checked-product.md). These do not
implement a complete GPU verification protocol or proof. None establishes
novelty or production security. Existing E01–E12,
implementations, negative results and independent oracles remain the baseline.

**Priority update, 2026-09-27:** the project prioritizes creative research over
incremental optimization and production completion. The
[creative experiment priorities](creative-experiment-priorities.md) add
speculative E20/E21 directions and move competing algebra, output, query and
indexing experiments ahead of completing the current verifier. The next paper
direction is deliberately open. Complete verified search remains one candidate;
it is not a prerequisite for investigating the others. This update is a research
plan, not a new literature review or a novelty claim.

**Creative follow-up:** [the first-cycle report](creative-algebra-results.md)
records implemented E20/E21 references and an E19 coupled filter with exact
public lookup factorization. Two literal circuits lose their cost comparisons;
the stronger filter's reduced candidate count does not yet pay for its
encrypted lookup. The next experiments target that representation/protocol gap
and E17 query statistics, rather than another round of routine kernel tuning.

**Second creative follow-up:** [certified filtering and E22 coordinate folding](certified-folding-results.md)
now include a failed one-sided lookup compression, a measured exact folding
win on structured data, and whole-tile adaptive refinement with discovered
thresholds. Index-specific dictionaries, binary matrix factorization and
authenticated PIR join the comparison agenda. The extra reading is targeted;
it does not establish novelty or implement a secure adaptive protocol.

**Third creative follow-up:** [dictionaries, hints and residuals](dictionary-witness-results.md)
tests public binary/categorical data, owner interval hints, exact witness
packing and owner-held sparse corrections through homemade CPU/CUDA BGV.
Hint-bearing search must be compared with compressed full-data retention and
local scan, not just the encrypted server baseline. SimplePIR/DoublePIR and
YPIR's offline-communication tradeoffs are related design questions, with
different retrieval/security contracts. E25's next question keeps correction
support encrypted and owner state bounded; the observed changed-state speedup
is not yet a paper contribution. See updated E22–E25 cards before continuing.

## 1. What the literature changes

The user-supplied [BioZKFHE, v1](https://arxiv.org/html/2607.22065v1)
combines BGV similarity evaluation, packing and verification, with a threshold
committee and blockchain-mediated release. Its §VII-E reports roughly 22–44 s
for proof-dominated runs at 10k–40k templates. Table IV's proof footprints are
object-size estimates, not canonical wire measurements. It is close prior art,
but its quantized biometric workload and release model differ from ours.

The [authors' artifact README](https://github.com/plan-lab-szu/BioZKFHE)
distinguishes measured from extrapolated rows, and says the core PVSC verifier
uses direct decryption unless changed to use its threshold-opening primitives.
Reproduction must preserve those distinctions. We inspected the paper's
architecture, threat model, packing, evaluation and relevant supplement sections,
plus the artifact README; we have not reproduced or audited that implementation.

Three consequences guide this agenda:

1. Packing, GPU FHE, private nearest-neighbor search and verifiable FHE already
   have substantial literature. A useful contribution needs a specific new
   algorithm, proof, cost model or demonstrated combination under a clear contract.
2. Optimize the **verified request**, including internal verifier traffic and
   preprocessing. A short result ciphertext can be overwhelmed by proof traffic.
3. Treat integrity as part of confidentiality. Our chosen-response regression
   illustrates an established class of FHE attacks, not a newly discovered
   cryptanalytic primitive. See
   [Viand–Knabenhans–Hithnawi](https://arxiv.org/abs/2301.07041v2) and
   [the CPAD analysis](https://eprint.iacr.org/2024/116).

### Closest work and the comparison it requires

These are primary papers, author/institution pages or author artifacts. This is
a targeted review, not an exhaustive novelty search. Entries based on abstracts
or artifact descriptions are leads for detailed reproduction, not endorsements
of every construction or security argument. Paper timings are **not** normalized
against our machine, parameters or workload.

| Work | Established result or relevant scope | Consequence for our experiments |
|---|---|---|
| [Litchev–Ouyang, batched Paillier Hamming, 2026](https://arxiv.org/abs/2609.21364v1) | Our existing carry-separated encoding, lookup/reduced-exponent arithmetic and CUDA batching | Preserve all CPU/GPU/lookup configurations; distinguish warm throughput from a complete request |
| [HERS, TBIOM 2022](https://hal.cse.msu.edu/papers/hers-encrypted-image-search/) | Encrypted representation search combined with learned dimensionality reduction | Compare exact binary scoring separately from accuracy-preserving or approximate embedding changes |
| [Bauspieß et al., coefficient packing, IWBF 2022](https://orbit.dtu.dk/en/publications/improved-homomorphically-encrypted-biometric-identification-using/) | Multiple encrypted biometric comparisons per polynomial product | E06's coefficient dot product is prior technique; collection, verification and complete cost need separate contributions |
| [Bassit et al., practical biometric search, TBIOM 2025](https://ris.utwente.nl/ws/portalfiles/portal/499572606/Practical_Biometric_Search_under_Encryption_Meeting_the_NIST_Runtime_Requirement_without_Loss_of_Accuracy.pdf) | Exhaustive search using vertical organization/chunking; stated honest-but-curious setting | Important E07 and lookup-style baseline; inspect preprocessing, decision mode and feature encoding before adapting |
| [SANNS, USENIX Security 2020](https://www.usenix.org/conference/usenixsecurity20/presentation/chen-hao) | Semi-honest secure search using HE, garbled circuits and distributed ORAM; approximate top-k | Benchmark a mixed-protocol alternative; its approximation/security contract does not establish our exact malicious-server goal |
| [Tiptoe, SOSP 2023](https://people.eecs.berkeley.edu/~henrycg/pubs/tiptoe/) | Private search with linearly homomorphic encryption and substantial preprocessing | Separate query privacy over a server-held corpus from our owner-encrypted corpus; charge offline traffic |
| [Isozaki–Bratina–Kim, GPU ANN, 2026](https://arxiv.org/abs/2608.21131v1) | Hierarchical approximate search; reports access-pattern leakage and warm server-only timings | E10/E19 must account for repeated-query leakage, client/network cost and exactness, not just scale |
| [HEonGPU, author implementation](https://github.com/Alisah-Ozcan/HEonGPU) | Existing GPU HE implementation and multi-stream execution | Pin a compatible backend as an arithmetic baseline; faster NTTs alone are not a new search algorithm |
| [Slalom, ICLR 2019](https://arxiv.org/html/1806.03287v2) | Trusted CPU delegates linear operations to an untrusted accelerator using randomized checks | E13 builds on established verification, but must also cover HE digit decomposition, rounding and wire bytes |
| [Verifiable FHE, 2023 preprint](https://arxiv.org/abs/2301.07041v2) | Active-server integrity failures can become interactive key-recovery attacks | Require verification before any attacker-observable decryption-dependent behavior |
| [VERITAS, CCS 2024](https://s-chtl.github.io/publication/veritas/) and [Cheon–Jang cryptanalysis, v3, 2025](https://arxiv.org/html/2502.12628v3) | Plaintext check encodings; later work attacks REP/PE in specified settings | Do not adopt hidden sentinels/check slots as a proven defense; restrictions on depth/keys require a new argument |
| [HELIOPOLIS](https://eprint.iacr.org/2023/1949) | Homomorphic IOP/FRI verification in the plaintext space | Alternative to proving every machine operation; check active-security and decryption requirements before composition |
| [Phalanx, CCS 2025, revised full version](https://eprint.iacr.org/2025/302) | FHE-friendly SNARK construction with reduced multiplicative depth | Include as a proof-system lead; cite the revised version rather than mixing earlier draft numbers |
| [Fherret, 2025 preprint](https://eprint.iacr.org/2025/700) | MPC-in-the-head proof of correct-and-honest evaluation, targeting reaction attacks and circuit privacy | Stronger proof objective worth comparing; account for repeated evaluations, verifier work and circuit-privacy assumptions |
| [Xia, algebraic trace analysis, 2026](https://eprint.iacr.org/2026/1604) | Coefficient-dependent noise cancellation and non-recursive packing | E15 needs a theorem for our actual trace/rounding schedule; variance alone is not a failure bound |
| [HERMES, CRYPTO 2023](https://eprint.iacr.org/2023/1244) | MLWE-based ring packing and conversion | E17/E18 should compare representations explicitly; this is not free extraction into a small ciphertext |
| [Compressed oblivious encoding, 2021](https://arxiv.org/abs/2109.07708v1) | Compact encoding of encrypted search matches | E18's sparse output is established territory; finding exact winners remains separate work |
| [PASTA, TCHES 2023](https://eprint.iacr.org/2021/731) | Integer-oriented hybrid homomorphic encryption trades bandwidth for server work | E17 can investigate tiny query uploads without giving the server a symmetric secret key |
| [Transciphering SoK, TCHES 2025](https://eprint.iacr.org/2025/669) and [subgroup PASTA packing, 2026](https://arxiv.org/abs/2609.12624v1) | Cipher/representation tradeoffs and recent packing improvements | Compare complete conversion plus search; generic transciphering or interleaving is not our novelty |
| [Norouzi–Punjani–Fleet, exact multi-index hashing](https://arxiv.org/abs/1307.2982) | Exact Hamming search using substring hash tables | E19 must contribute private, authenticated coverage or a useful cost/leakage tradeoff, not claim the indexing theorem |
| [HEIR, relinearization scheduling](https://heir.dev/docs/design/relinearization_ilp/) | Existing lazy relinearization and explicit key-basis/placement models | E20 must account for transformed secrets and compare against an equally delayed conventional circuit |
| [Azogagh–Killijian–Larose-Gervais, blind counting sort/top-k, PETS 2025](https://eprint.iacr.org/2024/1894.pdf) | TFHE counting/LUT selection and private k-NN with an honest-but-curious server and plaintext corpus | Counting/selection are established; adapt the corpus, output and integrity contracts explicitly |
| [Alman–Williams, probabilistic polynomials and Hamming neighbors, FOCS 2015](https://arxiv.org/abs/1507.05106) | Randomized polynomial constructions and batch Hamming-neighbor algorithms | E21 does not establish a new polynomial-search primitive; any probabilistic variant needs its own exactness/error contract |
| [Kumar et al., binary matrix factorization, ICML 2019](https://proceedings.mlr.press/v97/kumar19a.html) | Approximation algorithms for binary factorizations over integer and binary-field arithmetic | E22's signed column dictionary is a restricted representation; factorization and residual bounds are established ingredients |
| [SimplePIR/DoublePIR, USENIX Security 2023](https://eprint.iacr.org/2022/949) and [Piano, author implementation](https://github.com/wuwuz/Piano-PIR-new) | Different single-server PIR preprocessing, storage and online-computation tradeoffs | Compare private refinement of owner-encrypted raw records with encrypted distance reranking; charge client state and updates |
| [Colombo et al., authenticated PIR, USENIX Security 2023](https://www.usenix.org/system/files/usenixsecurity23-colombo.pdf) | Authenticity with selective-failure privacy, including a single-server model | Record signatures/AEAD inside an ordinary PIR result do not by themselves protect an observed accept/reject bit |
| [Distributional PIR, 2025 preprint](https://eprint.iacr.org/2025/132.pdf) | Distribution-dependent retrieval correctness and RLWE-to-LWE improvements for SimplePIR | Conversion is close E17 prior work; relaxed retrieval success cannot silently replace exact search |

## 2. Freeze the contract before comparing systems

Use `M` for candidate count, `d` for binary dimension, `N` for polynomial degree,
`t` for plaintext modulus, `Q` for evaluation modulus and `P` for terminal modulus.
Our principal task is stable exact top-k, ordered by `(distance, original ID)`.
The data owner holds the HE secret key and may learn all distances. Both index
and query are encrypted from the evaluator's perspective. Third-party queries
that may learn only k results require a different output-privacy protocol.

Keep four result categories separate:

| Path | Current evidence | What it establishes |
|---|---|---|
| Raw public GPU BGV | 8,192-vector joint-precision local request: 48.47 ms and 229,583 query+response bytes | Compute/codec baseline; expected-response fixture excludes duplicate validation cost; not remote authentication |
| CPU BGV plus protected client/receipt | Same workload family with joint precision: server 2,428.56 ms, client finish 6.08 ms, 229,915 request+response+receipt bytes | Local protocol benchmark with synthetic enrollment; no real Nitro deployment measured |
| Verified GPU BGV | Not implemented | E13/E14 must close this gap; do not attach the CPU receipt overhead to the raw GPU timing |
| TEE holding plaintext/HE keys | Different proposed baseline | Changes confidentiality trust; do not merge it into the encrypted-only table |

These rows come from [compute/precision results](bgv-compute-followup.md) and
[authentication results](bgv-authentication.md), not a fresh paired comparison.
Their timings cover different phases; do not divide the displayed times to
claim a speedup. The current authenticated enclave has no HE secret key and
computes the public ciphertext circuit itself. Receipt signatures are cheap;
moving that trusted execution onto or around the fast GPU path is unresolved.

The fixed-work terminal decoder is implemented, but private query encryption,
key generation/import and plaintext handling still need assurance. Parameter
security, complete side-channel coverage and actual AWS attestation remain open.

Measure each proposal using:

```
T_request = T_client_prepare + T_evaluate + T_prove/check + T_client_finish
            + 8*U / upload_bps + 8*D / download_bps + rounds*RTT
T_amortized = T_request + (T_setup + T_index + T_preprocess) / queries_per_epoch
```

This additive expression is a planning model. Measure actual critical paths
when stages overlap. `U,D` include proofs, authorization and framing. Report
client↔service, GPU↔verifier and committee traffic separately; moving bytes off
the client link does not remove their cost. Include updates, proof memory,
preprocessing refill, durable state, cold starts and content retrieval.
One-use verification material has a per-request refill cost even when prepared
offline; include all such work in the epoch total, not only the first pool fill.

## 3. E13 — Verify an untrusted GPU with a small trusted arithmetic core

**Hypothesis:** the expensive public RNS transforms and fixed-index products
can be checked more cheaply than recomputed, leaving only bounded nonlinear
steps inside the measured CPU evaluator. This keeps the HE secret at the owner.
The closest precedent is Slalom; the proposed HE-specific partition is unproven.

The basic check is elementary. Over a prime field, for a fixed public matrix A
and proposed `y=A*x`, choose a fresh secret uniform vector r and precompute
`u=A^T*r`. Check:

```
r^T*y == u^T*x
```

For a fixed nonzero error, one check misses with probability `1/p`. With h
independent checks and J checks over the supported lifetime, a union bound is
`J / p_min^h`, before commitment/PRG/security losses. Work separately over every
RNS prime: an error may exist in only one limb, so two different limbs do not
automatically square soundness. A polynomially structured challenge also needs
its own degree-dependent bound; it is not a uniform full vector.

**First prototype:** inventory the actual evaluator DAG: canonical decoding,
NTTs, products with immutable index components, automorphisms, gadget digits,
key switching, CRT, terminal rounding and serialization. Verify one NTT and
one fixed-index multiplication with an independent tiny field reference. Then
place digit extraction and integer rounding in the trusted core as an honest
cost baseline. Account for every intermediate crossing that boundary.

The important obstacles are part of the experiment:

- Fixed-index tensor multiplication is linear in the query ciphertext, but the
  complete evaluator is not globally linear: gadget decomposition and rounding
  prevent applying one matrix fingerprint to the whole current pipeline.
- The verifier must compute a checksum of the committed output itself, or use
  a reviewed opening/proof protocol. A GPU-supplied checksum is not evidence.
  Reading a large trace can cost more than verifying the arithmetic.
- Keep challenges hidden until the relevant output is fixed; consume each
  preprocessing entry once, including on failure/retry. Bind entries to index
  epoch, circuit, parameters and stage. Any proposed reuse needs a separate
  adaptive-soundness proof, not a benchmark shortcut.
- Precompute honestly inside the trusted boundary, or verify preprocessing.
  Charge both precomputation and storage/refill; static index reuse is useful
  only if its cost amortizes at realistic query counts.
- The receipt must cover the complete checked output and context before owner
  parsing/decryption. Tests must mutate each stage, omit/reorder tiles, change
  a single limb, and substitute a valid intermediate from another query.

**Continue if:** a complete checked request beats the existing CPU protected
path after transfer and amortization costs. A stretch target is within 2× the
matched raw GPU path; that is a goal, not a prediction. **Stop or repartition
if:** trusted digit work or trace transfer dominates. A measured boundary where
verification loses is still useful evidence.

**Measured follow-up:** the [boundary study](bgv-digit-boundary-results.md)
implements the exact public CRT/digit step, four transfer layouts and one/eight
CPU workers. Aligned 16-byte integers beat tightly packed 15-byte integers even
with 6.7% more traffic. Eight-worker aligned boundaries cost 43.95/121.41 ms at
8,192/32,768 vectors, excluding all protocol work and Nitro/vsock copies. E16
radix schedules reduce that cost, but no measured authenticated GPU service
results from summing these component timings.

The [complete stage follow-up](bgv-checked-switch.md) now checks canonical
batched relinearization with fresh full-field weights after immutable output
commitment. Trusted digit extraction precedes linear batch folding; all output
coefficients are read and both components/limbs are checked. Three repetitions
per limb give a conditional miss bound below 2^-177 per fixed incorrect output
under the specified assumptions. This is statistical checking soundness, not
an HE security estimate. No secret preprocessing pool or refill is used.
Homemade C++/RNS arithmetic reduces paired reference checker costs by
37.9–99.3× for batches 1/8/32; native costs including input binding are
9.29/23.15/90.73 ms. It does not establish its input tensors or remaining search
stages, and it is not a receipt. Its proposed follow-up was to bind the preceding
fixed-index tensor product and compare against matched native recomputation.

The [composed follow-up](bgv-checked-product.md) now implements that product
binding. It eliminates c0/c1 witnesses and offers local c2 computation, with
40%/60% fewer coefficient bytes than a full tensor/output boundary. A first
GPU run loses heavily to export/conversion. Retaining that result, a direct
RNS/batched GPU subcircuit with local-c2 checking costs 61.27/155.85 ms for
32/64 ciphertext tiles versus 91.58/197.97 ms for optimized native recomputation.
Small batches lose or reach only near parity. These measurements include
allocation, export, framing and checking, but no enclave channel or remaining
search stages. Completing this path would require butterfly and terminal
relations, complete coverage and deployment traffic, and matched CPU thread
budgets. That integration is retained as a backlog under the new research
priority. This is conditional systems evidence, not a novelty or full-service
security claim.

Separately evaluate an attested-GPU deployment when suitable hardware is
available. It has a larger hardware/firmware trust boundary and needs its own
fresh evidence, channel binding and measured execution policy. The current
Nitro receipt does not establish correct execution by an external GPU.

## 4. E14 — Optimize the HE circuit and its proof together

**Hypothesis:** for this shallow, fixed search circuit, a proof of fused
ciphertext relations can be materially cheaper than a literal proof of every
CUDA/CPU instruction. Compare E13's hardware trust with a cryptographic route.
HELIOPOLIS, Phalanx and Fherret are separate baseline families, not interchangeable
security wrappers. Detailed review of their applicable definitions is required.

Start with a canonical public statement:

```
(protocol, owner, epoch, session, request_ticket, ordered_index_commitment,
 key/parameter_hash, circuit_version,
 query_bytes_hash, output_bytes_hash, layout, compression, vector_count)
```

The server already knows the encrypted inputs and intermediate ciphertexts.
Proving their prescribed evaluation does not inherently require a witness
containing plaintext data or HE secrets. Zero knowledge may be unnecessary for
this owner-authorized public-circuit setting; revisit that decision for private
server circuits, hidden metadata or third-party database privacy.

Build two specifications: a literal stage trace, and fused algebraic relations
for multiplication/accumulation/packing. The proof must establish the connection
between the committed ordered index, every covered tile and the exact response.
A Merkle membership proof alone does not prove arithmetic or full coverage.

**Rounding is a first-class proof obligation.** For our terminal map, let
`r=c mod t`, `A=2*P*c-2*Q*r+Q*t`, and `B=2*Q*t`. Its quotient satisfies:

```
k = floor(A/B)  iff  B*k <= A < B*(k+1)
output = (k*t+r) mod P
```

These are integer relations, including negative k. A field equality alone
admits incorrect quotients through modular wraparound. Constrain canonical
representatives, quotient/remainder ranges and sufficient integer widths, and
bind both query decompression and final response compression. Similarly, gadget
digits need range and recomposition constraints, not just an unchecked sum.

**First deliverables:** a scheme-independent relation interpreter and tiny
mutation corpus; operation/range/commitment counts for baseline versus fusion;
one end-to-end proof using an established proof backend as a reference.
Develop the HE circuit and arithmetic in our own code. Integrating a reviewed
proof backend does not replace our homemade encryption implementation.

Sweep proof block size and batching across **distinct** requests. A single proof
per epoch cannot certify future query-dependent arithmetic. Per-query nonces,
ordered input commitments and individual outputs must survive aggregation.
Measure proof bytes, proof memory, prover work, verification, queue delay and p95.

**Continue if:** fusion yields a better complete latency/byte frontier at a
matched soundness target. **Stop early** on an approach whose proof floor is
already outside every intended network/service budget. First prototype targets
are proof overhead below 5× raw evaluation and proof traffic no larger than the
encrypted response; missing them should trigger redesign, not hidden accounting.

## 5. E15 — Use the actual noise structure to choose precision

**Hypothesis:** tracking cancellation and coefficient support through our joint
trace/packing schedule permits tighter justified query/response precision than
the current uniform worst-case bound, without changing N or Q.
This extends E11 and the implemented joint precision planner. The starting
literature is [Xia's trace analysis](https://eprint.iacr.org/2026/1604); simply
reusing its variance result is not a proof for our schedule.

Represent each linear stage as a sparse signed operator `L`. For an error
vector e, track exact support, dependencies and (where justified) covariance:

```
e_next = L*e + e_switch + e_round
Cov(L*e) = L*Cov(e)*L^T
```

Multiplication needs explicit bilinear error terms before this linear analysis.
Shared query, index and evaluation-key errors are correlated across outputs
and requests. Do not replace their covariance by independent samples. Quantizer
error is data-dependent; preserve its deterministic bound unless a theorem
justifies a probabilistic treatment. Constant coefficients can be exceptional.

Run two tracks. First seek a **deterministic** improvement by combining signed
operators before applying absolute bounds. Separately investigate a stated
probabilistic correctness contract, with a tail proof and a lifetime bound such
as `epsilon_setup + L_queries*epsilon_query`; include all released coefficients
and distinguish one-time key/index events from per-query events. A tiny observed
failure rate or empirical variance cannot certify cryptographic failure tails.

**First experiment:** symbolic tiny-ring propagation versus exact integer
oracles, exhaustive rounding boundaries, then fresh-key/index/query campaigns
for diagnostic agreement. Add each proven bound as a separate public planner
policy; choose it without reading actual secret noise. If a probabilistic bound
is used, its failure contract must appear in the benchmark table.

**Continue if:** justified precision reduces complete payload or one meaningful
arithmetic stage. **Stop if:** gains rely only on Gaussian fits or fail under
shared-key reuse. New N/Q/t/secret/error distributions require a fresh security
assessment; correctness headroom is not evidence of lattice security.

## 6. E16 — Combine coefficient packing with radix packing

**Hypothesis:** compress several signed candidate vectors into each E06 block,
then collect several correlations per selected coefficient. Fewer tile products
may outweigh the larger plaintext and noise bounds. Radix packing itself is
established; the candidate contribution is its interaction with our coefficient
collection, verification and network/parameter planner.

Let `a[l,j]=1-2*x[l,j]`, `b[j]=1-2*q[j]`, and `B=2*d+1`. For a group of g
candidates, replace an index coordinate by:

```
A[j] = sum(l=0..g-1, a[l,j]*B^l)
selected_product_coefficient = sum(l=0..g-1, (d-2*H(x[l],q))*B^l)
```

Using E06's reversed query and block spacing preserves its non-overlap identity.
Each signed correlation lies in `[-d,d]`, so balanced base-B decoding is unique
when the aggregate is recovered as an integer. The aggregate magnitude is at
most `(B^g-1)/2`; an odd plaintext modulus `t > B^g` is a sufficient no-wrap
condition. At d=512, B=1025 and g=2 requires t greater than 1,050,625, versus
today's t=1031. Consequently a twofold reduction in tile count is **not** a
prediction of a twofold speedup or smaller total ciphertexts.

**First experiment:** enumerate small binary inputs and signed digit carries;
compare g=1,2,3 in a plaintext/reference BGV model, with tail groups and all
negacyclic boundaries. Re-derive noise after encryption, multiplication,
packing and rounding. Compare ordinary coefficient packing and a vertical
radix layout, including index bytes, output decoding and E14 proof complexity.

Sweep t/Q/N only with separately assessed security profiles. Additional radix
digits may consume exactly the noise/precision savings from E15. **Continue
if:** a complete request improves at matched correctness/security. **Stop if:**
extra limbs, wider responses or client digit extraction remove the tile saving.

**Implemented follow-up:** [E16 results](bgv-radix-results.md) retain the
balanced construction and add direct-distance digits with `B=d+1`:
`(B^g-1-S)*2^-1 mod t = sum_l H_l*B^l`. This needs odd `t>=B^g`, even when the
signed correlation S wraps; partial groups use their actual active length.
At d=512 it permits t=263,171 for g=2 and t=135,005,723 for g=3 under the
existing policy. Independent integer/native/CUDA tests cover carries, tails,
precision and exact distances. Larger t remains a separate parameter review.

The first scalar-client implementation lost much of its server saving to
decoding. Packed ciphertext handling plus independently checked NumPy plaintext
decoding reduces complete owner-index local latency at 32,768 vectors by
29.1%/37.0% for g=2/g=3. Only g=2 also saves total bytes there (12,290 B). Both
increase traffic at 8,192, and g=3 loses on the measured paced links at either
size. This is not an unconditional replacement for the existing layout.

The [joint planning follow-up](bgv-layout-planning.md) measures all 12 available
layout/precision plans at each size. A model using local timings selects five
of six separate paced-link winners; its one miss costs 1.64 ms. Charging fresh
keys/index preparation and coefficient upload changes the recommendation:
at 32,768 vectors, a resident ordinary index needs a modeled 6,680-query epoch
to amortize g=2 at symmetric 10 Mbps. Actual registration overhead is absent,
so this is a lower bound under the current representation. Next measure real
epoch turnover and registration, include resident memory, and validate other
dimensions/tails and independent runs before proposing an online policy.

## 7. E17 — Make query upload proportional to useful input

An 8,192-vector public-index query currently occupies 149,612 bytes after our
rounding, although its binary input is only 64 bytes. The gap motivates two
separate representation experiments; neither is ordinary lossless compression
of the current pseudorandom ciphertext.

1. **Small LWE/MLWE input, then ring packing.** Encrypt the short query in an
   independently assessed representation and convert it into the evaluation
   ring. HERMES supplies relevant conversion ideas. Count ciphertext dimension,
   seeds, conversion keys, new noise and private client work. A smaller ring
   at the same Q may weaken security; copying 512 coefficients out of a large
   ciphertext is not a valid conversion.
2. **Transciphering.** Upload a symmetric ciphertext and nonce; homomorphically
   decrypt it using an HE-encrypted symmetric key, then execute the search.
   Begin with the specified PASTA construction and known-answer tests. Do not
   design a new low-depth cipher or pass its plaintext key to the evaluator.
   Account for key setup, fresh nonces, request authorization, conversion depth,
   repacking and proof/attestation of the conversion itself. Recent subgroup
   PASTA packing is a baseline, not an unclaimed idea.

Use a cost model before implementing a large new backend. Even eliminating the
entire existing query saves at most about **12 ms at 100 Mbps, 120 ms at 10 Mbps,
or 1.20 s at 1 Mbps**, ignoring framing. Conversion must fit the relevant budget,
or benefit many batched queries without intolerable queue delay. Test batch
sizes 1/8/32, independent queries and explicit key/session lifetimes.

PASTA's modulus/depth requirements may force a different t/Q than our shallow
BGV profile. Preserve an exactness gate for approximate alternatives:
[Rubato explicitly targets noisy approximate data](https://iacr.org/archive/eurocrypt2022/132760256/132760256.pdf)
and cannot silently replace exact binary input encryption.

**Continue if:** upload plus client/conversion/verification time beats the
current bounded codec at a realistic link and amortization point. **Stop if:**
the conversion dominates even at 1 Mbps, or setup only pays off for a workload
we cannot justify. Keep isolated-query latency beside throughput.

## 8. E18 — Separate finding winners from encoding them

E09 already proposes encrypted selection. Refine it into two independently
measured subproblems: exact stable selection and compact output. Compare a
small-k tournament with arithmetic-to-Boolean/TFHE conversion and range-based
selection. Our existing shallow BGV parameters cannot be assumed to support
comparisons or bootstrapping. SANNS is useful approximate-selection prior art,
not evidence that a proposed exact selector is cheap.

For a concrete sparse encoding reference, suppose valid encrypted bits m_i
select exactly k distinct IDs `i in {1,...,M}`. In a prime field with
`p > max(M,d,k)`, form:

```
s_j = sum_i m_i * i^j             for j=1..k
v_j = sum_i m_i * H_i * i^j       for j=0..k-1
```

After authorized decryption, Newton identities recover the polynomial with
the selected IDs as roots from the s_j. Distinct roots make the Vandermonde
system for v_j invertible, recovering their distances. This is an elementary
sparse-recovery baseline in the territory of compressed oblivious encoding,
not a new cryptographic primitive. ID moments use additions and public scalar
multiplications **after selection**; distance moments add encrypted products.

The hard parts must stay visible. Produce the correct k selection bits with
stable ties; prove their connection to all candidate scores. Three moments in
a full RLWE ciphertext do not yield a small packet. Include extraction into a
separately assessed LWE/MLWE/small-output format, its key material and security
analysis. Our current t=1031 is too small for distinct 8,192 IDs; use an explicit
field-conversion design, not IDs silently reduced modulo 1031. An ordered-score
encoding `(M+1)*H_i+i` also needs enough range for its comparisons.

**First experiment:** exhaustively recover small winner sets, duplicates in
data but distinct IDs, and ties; then benchmark selection, conversion and sparse
encoding separately. Compare returning all authenticated packed distances.
The present 79,971-byte rounded response gives an absolute download saving
ceiling of **6.4 ms at 100 Mbps or 64.0 ms at 10 Mbps**. **Stop** if complete
selection/compaction costs more than it saves throughout the target regimes.

## 9. E19 — Exact private indexing with a coverage certificate

This develops E10 beyond a scan-time filter. Start with **multi-index hashing**:
split a binary vector into b substrings. If `H(x,q) <= tau`, at least one
substring has distance at most `floor(tau/b)`; otherwise the sum exceeds tau.
Enumerating all such substring buckets therefore covers every possible result
within radius tau. This is the existing plaintext exactness argument.

**Proposed composition:** the owner commits to an ordered epoch and its complete
bucket directory, including lengths and empty buckets. Retrieve the prescribed
bucket union through a declared protocol, evaluate exact encrypted distances
for the candidates, and return evidence of bucket coverage and scoring. If the
k-th distance is at most tau, every omitted vector is farther than tau. Resolve
ties by ID and include the whole radius boundary. Otherwise expand the radius
or fall back to a full scan, charging every round and duplicate candidate.

Compare three explicit contracts: visible bucket accesses, private bucket
retrieval with padding/ORAM/PIR, and trusted routing. PIR alone does not establish
complete/correct bucket contents; authenticated omission/empty-bucket evidence
and owner-authorized index construction are needed. Bind directory, vector
positions, query, radius and epoch together. Authenticate intermediate replies
before the owner makes a decryption-dependent next request. A valid proof of a
score on an incomplete candidate set is insufficient.

**Cheap first test:** measure bucket probes and union size on the existing
random/clustered/duplicate fixtures plus a licensed real binary dataset. With
substring lengths l_j, probe count is
`sum_j sum(h=0..min(l_j,floor(tau/b)), binomial(l_j,h))`. Measure this before any
encrypted implementation: enumeration, padding and RTT may defeat selectivity.

A second, more speculative filter uses a binary parity-check matrix H on each
coordinate block. Define `delta(s)=min weight(e) subject to H*e=s`. Then
`delta(H*x XOR H*q) <= Hamming(x,q)`, because `x XOR q` is one feasible e.
Sum these bounds across disjoint blocks. A small syndrome table can model
selectivity cheaply; encrypted lookup/selection still has a cost. Compare with
E10's simpler popcount and prefix bounds. Expect weak bounds on uniform random
high-dimensional data; verify rather than assume a win.

The [implemented follow-up](creative-algebra-results.md#e19-a-stronger-bound-and-its-encrypted-representation-cost)
adds the constraint `weight(y)=weight(x)` to the syndrome class and minimizes
`Hamming(q,y)` over that class. It can beat the parity-corrected maximum of the
separate bounds. Exact public rank factorization also reduces the lookup's
bilinear feature count. Favorable selectivity and small encrypted regressions
are established, but both encrypted lookup layouts still cost more modeled
products than the original full scan. Routing privacy, threshold discovery,
complete coverage and the scheme/proof costs remain open.

**Continue if:** an exact, fully costed private/authenticated protocol beats the
fixed scan on a declared workload. **Stop or relabel** if the gain depends on
revealing routing geometry, dropping candidates, or measuring only a small
reranking stage. A revealed-access variant belongs in a separate leakage row.

## 10. Execution order and criteria for a paper

Keep the main worktree and baseline intact. Proposed descendant branches are
`experiment/bgv-checked-gpu` (E13), `experiment/bgv-evaluation-proof` (E14),
`experiment/bgv-trace-bounds` (E15), and `experiment/bgv-radix-correlation`
(E16). E17–E19 start with models/oracles before native backends. The initial
literature-only update created no branches or scheme implementations. The
2026-09-27 work uses `experiment/bgv-verification-packing` for E13/E14 oracles,
E15 bounds, E16 layout/setup experiments and E13 transfer/stage checks, leaving
the baseline PR branch unchanged. The implemented checkpoint `7dd927f` and
`checkpoint/bgv-product-checks-2026-09-27` preserve that work. E20–E27 then ran
on `experiment/creative-search-algebra`, with E27 preserved at `10a9125` in
`checkpoint/dyadic-rank-capacity-2026-09-27`. The order below follows the
project's 2026-09-28 research priority. The
[experiment cards](creative-experiment-priorities.md) retain the earlier
hypotheses, failures and follow-up options.

| Order | Concrete output | Decision gate |
|---|---|---|
| 1 | Use the preserved implementation as a control; state each competing hypothesis and its difference from the closest prior work | No novelty assumption; no need to finish the current verifier before exploring |
| 2 | Use the completed E28 orientation/gadget and E17 full/constant-mask references to model the actual CRT query space | Charge offline upload, converted index, token pool, output packing and private maps; do not substitute online savings for total savings |
| 3 | Test E17 query space and E14 complete verification together, retaining E25/E26 encrypted exceptions as a competing direction | Trusted offline state is an obligation, not a solved premise. Include token lifecycle, updates, private arithmetic, parameter changes and outside-subspace leakage |
| 4 | Independent homemade encrypted references for the most informative survivors | A toy speed loss is acceptable; correctness, assumptions and the reason to continue must be explicit |
| 5 | Focused implementation and ablations for promising candidates | Establish whether the proposed mechanism, rather than unequal baselines, explains a benefit |
| 6 | Choose a paper direction; deepen proofs, parameter assurance, complete protocol and representative measurements | Claim only what the prior-art review, mathematics and equal-contract results support |

Routine fusion, codec tuning, broad benchmark sweeps and full E13 deployment are
deferred unless they are needed to test a research hypothesis or repair a
correctness issue. Negative results and failed constructions remain evidence.

For external reproduction, first pin BioZKFHE's artifact version and labels,
HERS/coefficient-packing and vertical/lookup search baselines, and a compatible
GPU HE backend. Reproduce their native settings before adapting the workload;
mark adaptations as ours. Inspect licenses before reuse. Papers or artifacts
unavailable for full reproduction stay literature comparisons, not measured
table rows. Our scheme implementations remain homemade; external libraries
are clearly identified correctness/performance/proof-backend references.

Before a security claim, pin lattice-estimator version and all distributions,
include evaluation/related-key assumptions, separate correctness failure from
attack cost, and define a lifetime soundness budget. Extend private assurance
to encryption/key generation and evaluate on real attested hardware. These are
necessary foundations, not novelty by themselves. Classical receipt signatures
and hardware trust do not become post-quantum merely because HE uses lattices.

For performance, retain the main plan's data/size matrix and all Paillier/BFV/BGV
variants. Use fresh paired queries, ≥100 samples for meaningful p95, separate
key/index lifetimes, and actual distinct data at large sizes. Measure a second
GPU before generalizing hardware claims. Report every security, approximation,
leakage and client-output difference beside the result it affects.

Keep several paper candidates in contention: a new search-specific algebraic
schedule, direct answer aggregation, private certified pruning, query conversion
fused with matching, and arithmetic designed for cheaper complete verification.
E13–E16 provide controls and may support a contribution if deeper analysis
establishes a new bound or useful tradeoff. Select the direction after the cheap
experiments, not from the amount of code already invested in one path. The
contribution claim should follow the proof and experiments; this review does
not establish that a combination is unpublished or secure.
