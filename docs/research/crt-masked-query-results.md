# CRT response columns, masked queries and complete linear checking

Research cycle seven, 2026-09-28, on `experiment/creative-search-algebra`.
Implementation commits: `26e8ffb`, then `b6e41c8` for the scalar-space control.
The preceding company and E27/E28 checkpoints remain unchanged.

**Result:** a new homemade representation removes online ciphertext products,
key switching and terminal rounding. It works on the actual E26/E27 private
affine maps and unequal CRT components. It also works without those maps, using
ordinary bit columns. Both alternatives return every exact distance and stable
top-three result on two 7,996-row public Mushroom index splits.

The price is owner preprocessing for every query, a different encrypted index,
stored one-use answers and private verification material. This is an experiment
with a different state/trust contract, not a replacement for the production
authentication path. No SEAL/TenSEAL code is used. Correctness bounds do not
constitute security parameter approval or private side-channel assurance.

## 1. Closest work and the question tested

The previous [matrix/query-mask cycle](matrix-arithmetic-results.md) tested
restricted masks and conditional linear checks on tiny matrix-BGV fixtures.
Here the question is whether the actual full-degree CRT search layout can
preserve that simple online relation without storing one complete ciphertext
response for every coordinate of every private map.

[Slalom, Tramèr and Boneh](https://arxiv.org/html/1806.03287v2), Sections 3.2–3.3
and Appendix B, is a close precedent for secret Freivalds preprocessing,
reusing hidden checking randomness and one-use input masks. We use those known
ideas; their DNN outsourcing construction is not a security proof for this
encrypted-index protocol. We read these sections and the model-privacy scope.
[HintlessPIR](https://eprint.iacr.org/2023/1733), inspected at abstract/metadata
level here, provides another relevant direction for outsourcing preprocessing.
Its database and retrieval contract must be compared before adapting it.

CRT, subring decomposition, seeded symmetric RLWE encryption, transposition
and adjoint convolution are established ingredients. The candidate research
question is their **joint index/query-space/verification/lifetime tradeoff**
for exact encrypted search. This cycle does not establish that the combination
is unpublished. No external paper's implementation or performance is reproduced.

## 2. Transpose enrollment into the reply layout

In the affine case, the owner already has each block's exact representation
`x = a + u B (mod t)`. Its query weights are `w = B(1-2q)` and the owner adds
`H(q,a)` after decoding. Private maps remain private. Component geometry,
feature counts, map-replica identifiers and occupancy remain public metadata.

Let `F` be the maximum feature count across maps, `h` their summed feature
counts after deduplication, and `D` the old common padded feature count. For
each feature `j`, enroll a polynomial `A_j` whose component coefficients already
occupy the final reply locations, containing `D*u_ij` there. Encrypt each
column freshly under the same full-degree BGV key. Multiple replies, unused
coefficients and empty component tails are included.

For an online masked weight difference `delta`, define `alpha_j` by plaintext
CRT: inside leaf `l`, it is the constant `delta[map(l),j]`, or zero when that
map has no such feature. Then

```text
plaintext correction = sum_j A_j * alpha_j  in R_t
```

It contributes the required weighted scores independently in every leaf.
One column serves all leaves, so the index has `F * replies` ciphertexts rather
than `h * replies`. On split 3001 this is 32 rather than 523 columns; on split
3002, 32 rather than 596. The test suite compares the **entire plaintext
polynomial** against the previous butterfly projection, not just selected scores.

Let `m` be the smallest leaf degree and `S=N/m`. These constants interpolate
inside `F_t[Y]/(Y^S+1)`, with `Y=X^m`. The owner/server can construct their `S`
coefficients directly. The encryption ring, RLWE secret and ciphertexts still
have degree **N=16,384**. No smaller encryption ring is substituted.

This changes the layout objective. The old 64-slot allocations require 18/20
encrypted tile products on the two splits. Choosing 32 slots would require
27/26 in that circuit. E29 pays none of those products: both choices give one
reply and 32 columns. The smaller subring halves the checking hints and reduces
the transform work. Layout choices should be priced against the actual circuit.

## 3. One-use masks, and a rejected preprocessing shortcut

Before choosing the future query, the owner generates private uniform-field
mask coordinates `r` (implemented with a private SHAKE seed and rejection
sampling). It computes the corresponding plaintext scores from its index and
**freshly encrypts** their complete reply layout as `T_r`. Public encryption
seeds and errors are fresh and independent of the enrolled columns.

Online, the owner sends `delta = w-r mod t`. The server returns

```text
Z = T_r + sum_j C_j * centered_lift(alpha_j(delta))  in R_Q.
```

The plaintext is the requested score vector modulo `t`. The query difference
has an input-independent marginal distribution when the mask is uniform over
the declared public coordinate space. Short seeds make this a computational
claim. Full transcript privacy still needs a formal protocol/security analysis.
Masking in an undisclosed, smaller data-dependent subspace would require a
separate leakage analysis; we do not publish the owner's basis to shrink `h`.

**Rejected shortcut:** publishing `T_r = sum C_j*alpha_j(r)` using the *same*
public ciphertext columns can disclose the mask. Flattening ciphertext
coefficients exposes a public linear system over `Q` for the short polynomial
coefficients. A regression solves that system without the HE secret. A fresh
owner-encrypted answer is inconsistent with that exact public linear relation.
That regression rules out this attack on the shortcut; it is not a general
security proof for fresh preprocessing.

Preparing `T_r` requires access to the plaintext coordinates: during enrollment,
from a retained owner cache, or through a separately designed trusted service.
The current experiment does not obtain trustworthy preprocessing from an
untrusted server. Index updates invalidate all remaining epoch-bound tokens.
The local locks reject double consumption and stale epochs, but reconstructing
or rolling back private ticket state defeats them; a retained regression shows
the resulting query-difference leakage.

## 4. Smaller modulus without terminal rounding

Seeded symmetric encryption in the existing homemade owner code has centered
phase bound `B0 = floor(t/2) + t*eta`. A correction polynomial has at most `S`
nonzero coefficients, each with absolute value at most `floor(t/2)`. Thus a
bound for the complete returned phase is

```text
B <= B0 * (1 + F*S*floor(t/2)) < Q/2.
```

The implementation also computes the tighter bound from the actual coefficient
one-norms. Tests independently compute noisy phases and check the bound. The
fixed profiles use `t=1153`, `eta=21`, the same full ring degree, and a prime
`Q = 1 mod 2N`. They need new keys and a newly encrypted index.

| Representation | F | S | Worst-case phase bound | Q bits |
|---|---:|---:|---:|---:|
| Affine CRT columns, either split | 32 | 32 | 14,621,171,925 | 40 |
| Original bit columns, public identity map | 126 | 1 | 1,799,111,253 | 32 |

The bit-column control uses `x dot (1-2q) + popcount(q)` directly. It has more
encrypted columns but needs no private affine maps; its correction is scalar.
It can send full 32-bit-modulus ciphertext coefficients without any terminal
rounding. The secret and error distributions remain explicit; a reviewed
lattice estimate, message-count analysis and complete protocol remain open.

## 5. Check every returned coefficient using a public linear relation

The checker receives the trusted encrypted index at setup and trusted fresh
offline answers before each query. It never receives the HE secret. For each
hidden field challenge `rho`, it stores

```text
h_jk = <rho, X^(k*m) C_j> mod Q,
h_r  = <rho, T_r> mod Q.
```

It checks `<rho,Z> = h_r + sum_jk alpha_jk(delta)*h_jk`. Challenges cover both
ciphertext components and every reply, including unused coefficients. Context,
canonical residues, output count and independently derived phase bounds are
checked too. The owner supplies its pinned request, not a server substitution.

The centered lifts of CRT coefficients are not linear over `Q`; the verifier
computes the actual lifts from `delta`. Tests retain a field-wrap counterexample.
Likewise, rounded/compacted coefficients do not satisfy this relation. The
experiment accepts only the complete full-Q output and rejects such mutations.

For `S>1`, adjoint negacyclic convolution computes all `h_jk` using one ring
product per column/component/challenge; it does not materialize the much larger
matrix of shifted ciphertexts. For `S=1`, ordinary coefficient dot products
suffice. Private SHAKE seeds regenerate challenge vectors, so those full vectors
need not remain in owner state. No tags or challenge seeds are published.

With ideal independent uniform challenges, prime `Q`, hidden verifier state,
trusted premises and a bounded verification-only transcript, the probability
of the first incorrect acceptance in `B` attempts is at most `B/Q^rounds`.
The implementation uses four rounds for the 40-bit benchmark and five for the
32-bit control. PRG security and leakage assumptions must be added; Python/GMP
private arithmetic has no timing assurance. This is **conditional checking of
the online relation**, not a public proof, a preprocessing proof or a deployed
authentication protocol. A poisoned answer accepted as a trusted premise still
passes; the negative test is retained. Budget and ticket state are not durable.

## 6. Implemented C++ arithmetic and measurements

Write each full polynomial as `sum_(r<m) X^r * C_r(Y)`. Multiplication by
`alpha(Y)` acts independently on these `m` coefficient fibers. The separate
C++ extension prepares their degree-S negacyclic NTTs, accumulates all columns
pointwise, and performs just the output inverse transforms. `S=1` specializes
to scalar multiplication. It uses 64-bit words and unsigned 128-bit products,
one prime modulus, one CPU thread, and no CGBN, CUDA or external HE library.

Every measured query compares the entire C++ ciphertext against the independent
GMP evaluator before verifying and decrypting it. The full-size study has four
cases, each with one warmup and three measured heldout queries: **16 encrypted
searches**, all distances and stable top-three exact. Queries do not choose maps,
allocations or preprocessing tokens. These are small diagnostic timing samples,
not latency percentiles or a general CPU/GPU speedup claim.

<!-- E29_TIMINGS -->
Median measured stage times (component medians need not sum to the total):

| Case | GMP evaluate | C++ evaluate | Verify | Decrypt + decode | Complete C++ online |
|---|---:|---:|---:|---:|---:|
| affine / 3001 | 858.8 ms | 12.4 ms | 34.9 ms | 23.8 ms | 76.3 ms |
| affine / 3002 | 915.4 ms | 12.4 ms | 35.2 ms | 23.8 ms | 76.3 ms |
| raw / 3001 | 1457.4 ms | 16.8 ms | 39.9 ms | 22.7 ms | 83.3 ms |
| raw / 3002 | 1455.2 ms | 16.8 ms | 40.0 ms | 22.8 ms | 83.7 ms |

Offline work remains charged:

| Case | Enroll encrypted columns | Prepare C++ index | Prepare epoch checker | Per-token answer | Per-token checking hint |
|---|---:|---:|---:|---:|---:|
| affine / 3001 | 0.94 s | 0.17 s | 3.65 s | 45.0 ms | 33.5 ms |
| affine / 3002 | 0.93 s | 0.17 s | 3.65 s | 44.6 ms | 33.7 ms |
| raw / 3001 | 3.40 s | 0.59 s | 1.81 s | 89.3 ms | 40.4 ms |
| raw / 3002 | 3.43 s | 0.59 s | 1.79 s | 88.4 ms | 40.6 ms |
<!-- /E29_TIMINGS -->

Online totals include request formation, evaluation, response-body packing,
conditional verification, reference decryption, decoding and selection. They
exclude network latency and trusted token preparation, which are reported
separately. The earlier E27 study measured roughly 206–214 ms CPU local and
51 ms CUDA local, without this conditional checker, with different parameters,
state and request contracts. Those historical figures are **not paired speedup
baselines** for E29. The new complete path does not establish a win over that
CUDA path. Local plaintext caching remains much faster on this small dataset.

## 7. Communication, state and lifetime costs

| Category | Earlier E27 BGV | Affine CRT E29 | Bit-column E29 |
|---|---:|---:|---:|
| Online query | 245,866 B | 1,046 / 1,192 B | 252 B |
| Response | 131,162 B | 163,840 B | 131,072 B |
| Online query + response | 377,028 B | 164,886 / 165,032 B | 131,324 B |
| Offline answer upload per token | None | 82,026 B | 65,642 B |
| Offline + online, all tokens used | 377,028 B | 246,912 / 247,058 B | 196,966 B |
| Encrypted index coefficient body | 8,847,360 / 9,830,400 B | 5,242,880 B | 16,515,072 B |
| New private epoch checking material | None in that benchmark | 20,608 B | 2,680 B |
| Private affine map body | 9,542 / 11,386 B | 9,542 / 11,386 B | 0 B |

Slashes denote splits 3001/3002. Prior query/reply numbers include their fixture
headers; new online numbers are coefficient bodies only. New offline uploads
are actual seeded fixture packets. New totals omit transport/authentication
envelopes, public layout framing, one-time enrollment/key uploads and persistent
state records. These are byte-accounting comparisons, not interchangeable
production protocols. Nominal online reductions are about **2.28×** and
**2.87×**; including fully utilized tokens gives about **1.53×** and **1.91×**.
The affine response itself is larger: its saving comes from query upload.

Public key/secret storage, common stable IDs and Python object overhead are
additional categories. Checking material counts challenge seeds and field
fingerprints, not the full transient challenge arrays. Each unused token also
has a private 32-byte mask seed, answer fingerprints, bounds and lifecycle
metadata. The server stores one expanded encrypted answer per token. Prepared
native index arrays use 8-byte words: 8,388,608 B affine and 33,030,144 B raw,
in addition to any retained serialized/reference copies and working buffers.

At 50% token utilization, split-3001 total communication per completed query
becomes 328,938 B affine or 262,608 B raw. At 10%, it becomes 985,146 B or
787,744 B: both exceed the old 377,028 B exchange. Expiry and updates can erase
the traffic saving. There is no token-refresh or incremental-update protocol.

The complete owner-cache control is essential. The public raw rows occupy
127,936 B before compression; existing E27 work also measures compact exact
affine caches. E29's temporary offline access to these coordinates is not free
outsourcing, and compressible owner maps/rows must be compared fairly with
essentially random fingerprint residues. This cycle identifies competing costs;
it does not establish that keeping a cache is the wrong choice at 8K rows.

## 8. Evidence, reproduction and next experiments

Code lives entirely in `experiments/bfv_search_lab`: `crt_query_space.py`,
`crt_masked_bgv.py`, `crt_linear_check.py`, `crt_native_bgv.py`, and
`_subring/bindings.cpp`. The existing Paillier/BFV/BGV fallback code is unchanged.

```bash
make -C experiments/bfv_search_lab/_subring PYTHON=../../../.venv/bin/python
.venv/bin/python -m pytest -q experiments/bfv_search_lab/test_crt_*.py
.venv/bin/python benchmarks/crt_masked_bgv_lab.py \
  --cache-dir /home/pete/yavor-projects/xtrace-work/research-data/uci-20260927 \
  --layout affine --q-bits 40 --seed 3001 --repeats 3 --json-out /tmp/crt-affine.json
# Repeat with --layout raw --q-bits 32, and with --seed 3002.
```

Retained artifacts: [affine 3001](../../benchmarks/results/crt_masked_bgv_affine_3001_20260928.json),
[affine 3002](../../benchmarks/results/crt_masked_bgv_affine_3002_20260928.json),
[raw 3001](../../benchmarks/results/crt_masked_bgv_raw_3001_20260928.json),
[raw 3002](../../benchmarks/results/crt_masked_bgv_raw_3002_20260928.json).
They pin source and native-binary hashes, fixture digest, exact query IDs, key
parameters, setup costs, every timing sample and token utilization models.
[Validation](../../benchmarks/results/crt_research_validation.md) records 336
passing regressions, native undefined-behavior sanitizer tests and static checks.

The next discriminating experiments are:

1. **Choose the query space and verification representation jointly.** Compare
   raw, affine and mixed public feature groups on several data distributions,
   at equal complete client state and index lifetimes. Optimize useful output
   capacity and checking hints, not the superseded ciphertext-product count.
2. **Reduce trusted per-token work without reopening the mask-recovery attack.**
   Model encrypted-query preprocessing, authenticated correlations and trusted
   offline services. Count all communication and distinguish relocation from
   elimination. Any proposed compressed token needs an independent leakage test.
3. **Test updateable correlations and lifetime budgets.** Include insertion,
   removal, changed maps, retries and unused pools. Derive the binding/noise
   invariants before implementing refresh; epoch-bound masks cannot simply be
   relabeled after an update.
4. **Keep exact verification compatible with small replies.** E29 already avoids
   terminal rounding through its linear-circuit modulus. Test whether better
   representations reduce response degree/components without increasing owner
   state or requiring unchecked nonlinear output conversion.
5. **Only then test a matching GPU kernel and deployment protocol.** A GPU study
   should compare the new scalar/subring contraction against both complete
   CPU/CUDA baselines under the same verification/preprocessing contract. The
   private checker, sampler/key routines, durable state and parameters need
   review before extending the production response authority.
