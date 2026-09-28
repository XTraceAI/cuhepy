# Matrix arithmetic, query masks and a conditional linear check

2026-09-28, `experiment/creative-search-algebra`. Source checkpoints `87e4b21`
and `aa1dc75` (offline placement of check preparation in the benchmark).
This sixth creative cycle implements E28 and probes E17/E14 using homemade
small-ring arithmetic. It preserves the preceding Paillier/BFV/BGV and CUDA
baselines, including `checkpoint/dyadic-rank-capacity-2026-09-27` (`10a9125`).

**Result:** changing the orientation of encrypted matrix inputs can reduce
the secret expressions that this reference must switch. Moving query work
offline gives a different tradeoff: a larger resident index and a one-use
stored answer allow online computation with public scalar coefficients. A
mask restricted to the query's public subspace preserves that scalar structure.
The online relation then admits a small conditional randomized checker.

These are exact algebra and noisy encrypted **toy** results, with explicit
count models. They are not native CPU/CUDA speedups, approved cryptographic
parameters, a complete authenticated service or established novel techniques.
The interesting remaining question is a useful *joint* query-space, state,
update and verification tradeoff under a matched deployment contract.

## Prior work and what we actually investigated

| Primary source | Reading scope and role |
|---|---|
| [Mali, generalized matrix BGV/BFV/CKKS](https://eprint.iacr.org/2025/972) | Read the construction, secret-expression expansion, relinearization and noise discussion in §§2–3, extending the earlier abstract-only review. It motivates the matrix baseline. |
| [Park, ciphertext-ciphertext matrix multiplication](https://eprint.iacr.org/2025/448) | Abstract and matrix-transposition lead; the technical comparison below uses the expanded treatment in Bae et al. This implementation does not reproduce Park's optimized backend. |
| [Bae et al., Fast Homomorphic Linear Algebra with BLAS, v1](https://arxiv.org/html/2503.16080v1) | Targeted reading of formats, §3.4 and §§5.3–5.4. Opposite input orientations and matrix external products are established comparison targets. |
| [Yang et al., preprocessing and key-switch tradeoffs, v1](https://arxiv.org/html/2606.25349v1) | Abstract, scope and preprocessing overview. A related offline/online tradeoff, not a reproduced implementation or a security proof for our protocol. |

Transposition, gadget decomposition, external products, additive query masks
and random linear fingerprints are known ingredients. No claim of inventing
them follows from implementing them here. The proposed search specialization
must eventually be compared with these techniques and ordinary scalar-ring
search under equal security, privacy, storage and query-lifetime assumptions.

No external HE library is used by the new code. Python integers implement the
ring and matrix operations; SHAKE from `hashlib` expands private fixture masks;
GMP's primality predicate checks the field precondition of the linear checker.
The experiments deliberately use small parameters and reproducible fixture
randomness. They cannot protect confidential data.

## 1. Keep the matrix secret in the correct order

In the entrywise ring `R_q = Z_q[X]/(X^n+1)`, let the module rank be `k`.
The owner creates matrix ciphertexts with phases

```text
C0 + C1*S = M + t*E.
```

Two right-oriented inputs have product phase

```text
C0*D0 + C0*D1*S + C1*S*D0 + C1*S*D1*S.
```

Our public evaluator expands this entry by entry. Treating `S` as a commuting
scalar is wrong; a retained 2×2 example demonstrates the failure. For one
output column, the literal reference uses `k²` linear sources and `k³`
ordered quadratic sources. Projecting away unused outputs helps, but zero
plaintext padding does not make the random ciphertext masks sparse.

An independent variant combines equal products of *scalar ring entries*.
It never commutes whole matrices. Across `b` selected output columns, with
`s=k*b` selected secret entries, the quadratic source count becomes
`k²*s - s*(s-1)/2`. Tests enumerate the actual source sets independently of
this formula, including all columns and rank one.

Now encrypt the query in the opposite orientation:

```text
D0 + T*D1 = W + t*F.

(C0+C1*S)*(D0+T*D1)
  = C0*D0 + C1*S*D0 + C0*T*D1 + C1*(S*T)*D1.
```

The middle secrets are adjacent. The evaluator can use masks of the entries
of `S`, `T` and `S*T`: `3k²` sources, independent of the number of output
columns. An additional probe chooses `T=S^T`; the Gram matrix `S*S^T` is
symmetric, reducing the count to `k² + k*(k+1)/2`. That probe changes the joint
key exposure and needs its own security analysis. The independent-key variant
is retained so that this extra assumption is visible.

Every source is switched to the **same independent module-vector output
format**, with `k+1` ring components. The reference pays for both linear and
quadratic sources. It is not the paper's full matrix-output relinearization,
nor an optimized implementation of its column-conversion suggestion.

### Count example, not a secure-speed comparison

For `k=8`, `n=2048`, `k*n=16384`, 120-bit coefficients and four 30-bit gadget
digits, one polynomial-valued output has:

| Our reference variant | Sources per output | Switching ring products | Offline gadget body | Query body if uniform masks are seeded |
|---|---:|---:|---:|---:|
| Right-oriented, ordered sources | 576 | 20,736 | 637,009,920 B | 245,792 B |
| Same, equal scalar products combined | 548 | 19,728 | 606,044,160 B | 245,792 B |
| Opposite orientation, independent secrets | 192 | 6,912 | 212,336,640 B | 245,792 B |
| Opposite orientation, transposed secret | 100 | 3,600 | 110,592,000 B | 245,792 B |
| Owner-prepared gadget query | 16 | 576 | 0 B | 1,966,112 B |

The final row moves its gadget material into **every query**. It is not free
setup. Seeded sizes are explicit standard-PRG count controls, not a new codec
or a measured wire protocol. The artifacts also retain unseeded query sizes
and seeded offline-key sizes. For example, the unseeded gadget query is
17,694,720 B; counting it against a seeded ordinary query would be misleading.

These products have degree 2048, not the old native degree 16384. Holding
`k*n` fixed is an accounting control, not a security estimate. The model uses
`t=65537` to support full plaintext SIMD in the modeled rings, unlike the prior
native `t=1153` profile. Coefficient formation, transforms, additions, client
work and setup are additional costs. All rows here return a 276,480 B
uncompressed module ciphertext; no cross-row packing or terminal reduction is
implemented. This table is not an 8,192-distinct-vector search benchmark.

The literal full-matrix relinearization body from the reading is retained as
a separate count reference. Its output format differs, so it is not used as
an apples-to-apples performance baseline.

## 2. Let the owner prepare the query in the needed form

For a known owner query-weight vector `w`, prepare gadget masks of `w_j` and
`(S*w)_j` under the independent output key. The server evaluates

```text
sum_j C0_j * w_j + sum_j C1_j * (S*w)_j = (M+tE)*w.
```

Each public ciphertext coefficient is decomposed into small gadget digits
before multiplying its mask. The reference needs `2k` sources per output.
Using just two unscaled encrypted vectors is an invalid shortcut: a retained
counterexample shows full-size ciphertext coefficients amplifying the masking
noise until reduction modulo `q` corrupts decoding.

A private rank-two map for four-bit rows is also exercised. The owner computes
its two exact query weights directly, then creates the gadget query. Every
four-bit query is checked against XOR/popcount. This is an owner-prepared
external-product reference, **not** a conversion of an arbitrary reader's
existing LWE ciphertext or a new transciphering scheme. It requires the owner
to know the index secret and private map; owner work and upload are charged.

## 3. A one-use mask can preserve the useful query structure

The owner prepares a random query `r` before the actual query arrives. The
server stores its encrypted answer `Y_r`. A separate epoch conversion gives
encrypted index entries under the output key. For the real query, the owner
sends `delta = w-r mod t`, and the server returns

```text
Y_r + Enc(M)*delta = Enc(M*w)                 modulo t.
```

All conversion and random-query work is charged offline. The full-ring mask
control samples every coefficient of `r`. It works, but turns the online
correction into dense polynomial products even when `w` was simple.

In this prototype's SIMD search, each feature weight is the same for every
lane, so each `w_j` is a constant polynomial. Sample `r` in that same public
constant subspace. Now `delta` consists of `k` field elements, and applying it
requires only coefficient-wise scalar multiplication and addition. There are
**no online key switches or polynomial convolutions** in this variant.

For a finite additive subspace `U`, the distribution of `w-r`, with `r`
uniform in `U`, is uniform on the coset `w+U`. Thus two allowed queries have
identical difference distributions exactly when their difference lies in `U`.
This elementary fact explains both the optimization and its failure case.
Using too small a mask space reveals the query's coset. The implementation
rejects nonconstant weights in constant mode, and tests retain an explicit
outside-subspace counterexample. This marginal-distribution argument alone
does not prove privacy of the whole preprocessing transcript.

At the preceding modeled `k=8,n=2048` setting:

| Charged item, one output row | Full-ring mask | Constant-subspace mask |
|---|---:|---:|
| Online difference body, byte-aligned field elements | 49,152 B | 24 B |
| Offline query body per token, seeded-mask model | 1,966,112 B | 1,966,112 B |
| Server stored encrypted answer per unused token | 276,480 B | 276,480 B |
| Original plus converted resident index bodies | 2,703,360 B | 2,703,360 B |
| Online degree-2048 polynomial products | 72 | 0 |
| Online scalar coefficient multiplications | — | 147,456 |

The 24 B is only the difference body. Epoch/token identifiers add 48 B in the
local model; protocol framing and authentication are additional. It is **not
24 B total communication**: the offline upload and the response still exist.
Even with seeded masks, total per-query upload is larger than the ordinary
matrix query. The result concerns online work and timing placement, not a
free reduction in total work, traffic or memory.

The converted index alone is `(k+1)/2` times the original coefficient body;
this implementation retains the original for offline token evaluation as well.
The client retains a 32-byte private mask seed plus identifiers. SHAKE with
rejection sampling expands it; short seeds replace ideal uniform masks with
a computational assumption. Expanded Python polynomials and long-term matrix
secrets cost additional memory. The canonical field-body counts in the model
are not measurements of Python working memory.

Tokens are consumed before releasing a request, including concurrent calls.
They bind a local epoch and identifier. Recreating the same private token after
rollback defeats this in-memory protection: two differences expose `w1-w2`.
That failure is deliberately tested. Durable one-use state and authenticated
epochs remain protocol obligations. Updating the index invalidates its stored
answers; this cycle does not implement token migration across updates.

## 4. The scalar online relation is easier to check, conditionally

Flatten the converted ciphertext coefficients into a public matrix `A`, the
stored encrypted answer into `y`, and the response into `z`. Constant-mode
online evaluation is exactly `z = y + A*delta mod q`, with canonical output
coefficients. There is no online rounding or digit decomposition in this
statement.

From **already trusted** `A,y`, a verifier samples a fresh private vector
`rho` and precomputes `rho*A` and `rho*y`. It checks the response using
`rho*z = rho*y + (rho*A)*delta`. Over prime `q`, one independent uniform
challenge misses a fixed nonzero error with probability `1/q`; repetitions
multiply that bound. The toy checker uses three rounds, consumes its ticket
before checking even malformed responses, and verifies all coefficients,
shapes, local epoch/token fields and the independently derived phase bound.

This is a classic fingerprint, not a new proof system. Exhaustion over `F_5`
checks the elementary probability statement. A composite-modulus example
shows why the same bound cannot simply be assigned to an RNS modulus. Private
fixture challenges are reproducible in the tests; this is not a security
assessment of the deployed sampler or private arithmetic.

The trusted preprocessing still costs `O(k*L)` field work per challenge for
`L` output coefficients. Online checking costs `O(L+k)` per challenge, while
the server does `O(k*L)` scalar arithmetic. Most importantly, the check does
not establish that the converted index or stored answer was computed honestly.
A poisoned offline answer passes when incorrectly treated as trusted. That
retained regression prevents presenting this as a solution to full malicious-
server verification. The existing authenticated BFV/BGV paths are unchanged.

## 5. Evidence and rejected shortcuts

- **308 focused tests pass**, including **73 new tests**. Independent integer
  schoolbook products, direct noisy phase evaluation, field interpolation,
  all-distance XOR/popcount and stable-ID tie oracles are used.
- [Matrix/gadget artifact](../../benchmarks/results/matrix_arithmetic_lab_20260928.json):
  **190 encrypted searches**, four fixtures, five variants, and 100 cost-model
  configurations. Small matrix rank is 1, 2 or 4; ring degree is 2, 4 or 8.
  The private-map fixture tests all 16 four-bit queries.
- [Masked-query artifact](../../benchmarks/results/matrix_masked_query_lab_20260928.json):
  **44 encrypted searches**, paired full/constant mask spaces, and 48 state/
  communication models. All 22 constant-mask searches check the online result
  before decryption. Offline pools are built before query selection.
- Every distance and stable top-3 matches. Duplicate rows, non-monotone IDs,
  partial tiles and query extremes are retained. Logged Python timings diagnose
  these tiny references; they are not secure CPU/GPU performance measurements.
- E25's support-class control retains a separate obstruction: sixteen groups
  of eight private addresses still span 128 singleton query features when the
  selected group must remain hidden. A per-class eight-feature count cannot
  replace the priced hidden selector. This concerns separated scalar bilinear
  encodings only, not all HE lookup circuits.

The full validation and reproduction commands are in
[matrix research validation](../../benchmarks/results/matrix_research_validation.md).
The JSON files pin code hashes and commits `87e4b21` / `aa1dc75`, respectively.
They contain deterministic
public toy-fixture identifiers/counts, timings and hashes, not customer data.

## 6. The next discriminating experiments

**Follow-up implemented:** [E29 CRT response columns](crt-masked-query-results.md)
now tests items 1–3 below on the actual search layout, including a failed
deterministic-cache construction, independently encrypted tokens, complete
conditional checks and full-size homemade GMP/C++ controls. The remaining
questions move to cheaper trustworthy correlations, mixed spaces and lifetime
costs; these original E28 results are unchanged.

1. **Extend masks to the actual CRT query space.** Derive a public embedding
   for the E26/E27 component queries while leaving the owner map private.
   Compare masks in that space with full-ring masks. Charge the resulting
   converted index, each token, output packing and verification; reject any
   apparent gain that needs a public private map or a near-complete owner cache.
2. **Test query-space choice and verification together.** Find whether a useful
   search workload keeps an inexpensive public linear online relation after
   compact output and updates. The current no-rounding relation is a starting
   point, not permission to omit terminal-output constraints.
3. **Price complete trusted preprocessing.** Compare owner preparation, a
   trusted service, and a verified untrusted preprocessor. Include token expiry,
   durable one-use state, update invalidation and adversarial retries. Do not
   report offline work as saved work.
4. **Keep the arithmetic alternative alive selectively.** Compare the
   independent-secret orientation with a equally specialized scalar-ring
   implementation, after parameter review. Large source/key growth currently
   argues against implementing the literal general matrix scheme in CUDA.
   The transposed-secret probe needs separate joint-key scrutiny.

The possible paper direction is the joint design of query space, bounded
preprocessing state and complete verification for exact search. Establishing
that contribution requires closer prior-art comparisons and a surviving
equal-contract experiment; this cycle establishes neither novelty nor a
production-ready protocol.
