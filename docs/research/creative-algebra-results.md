# Creative algebra experiments: limits, exact summaries and stronger filters

2026-09-27. Branch: `experiment/creative-search-algebra`, descended from the
planning checkpoint `537a559`. Implementation commits: `b972353` and `a23d813`.
The earlier company/research checkpoints and baseline PR are preserved.

This cycle follows the [creative research priorities](creative-experiment-priorities.md).
It implements independent mathematical oracles, homemade encrypted prototypes
and negative cases before attempting native/CUDA optimization. **No improvement
over the production-size encrypted search has been demonstrated.** The useful
outcome is a clearer set of mechanisms, costs and obstructions to investigate.

| Experiment | Result | Decision |
|---|---|---|
| E20: delay switching through the packing butterfly | Same modeled switch count for full groups; worse for tails; many more keys. Switching-noise amplification falls, but the modeled total phase-bound bit length does not | Retain the reference; park straightforward full deferral |
| E21: construct distance-generating polynomials | Exact histogram and stable IDs work in homemade BGV. The literal pilot is much more expensive than packed distance search | Retain tie/rank counterexamples; park this literal circuit |
| E19: combine syndrome and weight constraints | Stronger deterministic bound; 26–74 of 8,192 candidates remain on favorable synthetic fixtures, versus almost no pruning on uniform data | Investigate representation/protocol costs and more representative data |
| E19 follow-up: factor the lookup table | Exact public factorization reduces 6,117 features to 3,549 and halves modeled ciphertext products | Still 8× the original scan's products before reranking; do not promote it as a speedup |

## Evidence and closest prior work

The new scheme arithmetic imports our own Python/GMP BGV implementation, not
Microsoft SEAL. Tiny rings test algebra and integration, **not cryptographic
security**. No protected client, production default, native library or CUDA
kernel changed. Prefix recovery is a local fixture with explicit routing
leakage, not an authenticated private-search protocol.

| Primary source checked | Consequence |
|---|---|
| [HEIR relinearization design](https://heir.dev/docs/design/relinearization_ilp/) | Lazy relinearization and key-basis scheduling are established. Our question concerns the actual butterfly and its growing automorphism basis |
| [Chen–Dai–Kim–Song, conversion/packing](https://eprint.iacr.org/2020/015) | The existing packing butterfly remains a prior ingredient; this cycle does not claim a new packing primitive |
| [Azogagh–Killijian–Larose-Gervais, blind counting sort/top-k](https://eprint.iacr.org/2024/1894.pdf), §§4–5 | Encrypted counting and top-k already exist. Their TFHE/private-classification setting includes a plaintext server corpus and an honest-but-curious server; it is not our complete malicious-server contract |
| [Alman–Williams, probabilistic polynomials for Hamming neighbors](https://arxiv.org/abs/1507.05106) | Polynomial approaches to Hamming search are established. Their randomized construction is a separate lead, not an implementation or exactness guarantee supplied by our histogram experiment |
| [Norouzi–Punjani–Fleet, multi-index hashing](https://arxiv.org/abs/1307.2982) | Exact Hamming filtering/indexing is prior territory. Our filter needs a separate private lookup and complete-coverage protocol |

This is a targeted review, not a novelty determination or reproduction of those
systems. Coset leaders, generating functions, rank factorization and prefix
selection are known mathematical tools. The particular filter/circuit
composition needs a closer related-work comparison before any contribution
claim. The rank arguments below are elementary explanations, not claims of new
general lower bounds for encrypted search.

## E20: where delaying transformations fails to save work

[`reduction_oracles.py`](../../experiments/bfv_search_lab/reduction_oracles.py)
tracks formal terms `sigma_g(s)^j`, with `j` equal to 1 or 2, through the entire
packing butterfly. It checks the resulting integer polynomial against direct
coefficient projection, independently of the HE helpers. The
[`encrypted reference`](../../experiments/bfv_search_lab/deferred_bgv.py)
retains these terms for a configurable number of levels, then switches each
source back to `(1,s)` using newly generated public evaluation keys.

Let a full response group contain `D` tensor products, and delay collapse for
`r` levels. Each surviving expression has `2*2^r` nonconstant formal terms.
One is already `s`, so the collapse uses `2*2^r-1` source switches per expression.
There are `D/2^r` expressions and `D/2^r-1` subsequent ordinary rotations:

```text
switches = (D/2^r)*(2*2^r - 1) + (D/2^r - 1) = 2D - 1
distinct evaluation keys = 2*2^r - 1 + log2(D) - r
```

This counts **this per-source gadget construction**, not all possible
representations or switching algorithms. Ordinary addition under one secret
can still benefit from lazy relinearization; a regression preserves that
positive control. Other regressions show why coefficient projection does not
commute with arbitrary multiplication, and why canonical gadget digits cannot
be distributed over addition without accounting for carries.

Model at `N=16384`, dimension/padding 512, `Q_bits=120`, digit width 30:

| Vectors | Current schedule switches | Fully delayed switches | Current key coefficient bytes | Fully delayed key coefficient bytes |
|---|---:|---:|---:|---:|
| 32 | 10 | 1,023 | 19,660,800 | 2,011,299,840 |
| 8,192 | 767 | 1,023 | 19,660,800 | 2,011,299,840 |
| 16,384 | 1,023 | 1,023 | 19,660,800 | 2,011,299,840 |
| 32,768 | 2,046 | 2,046 | 19,660,800 | 2,011,299,840 |

Keys are reused across groups. These are canonical coefficient counts, not a
new serialized format or measured setup transfer. Temporary allocation is not
included in the checkpoint-storage model.

For a full group, the coefficient multiplying a single-switch worst-case
error bound falls from `(4D^2-1)/3` to `2D-1`: at `D=512`, from 349,525 to 1,023.
However, the product-phase term dominates the original conservative bound at
the modeled parameters. Total bound bit lengths remain 90 at 8,192 vectors and
91 at 16,384/32,768. This is not a precision saving or a measured noise estimate;
it does not replace the tighter E15 support analysis.

The encrypted pilot uses `N=64`, dimension 16, 128 vectors, `t=1031`, 180-bit Q,
eta 2 and 12-bit digits. Seven paired rounds follow one excluded warmup, with
fresh queries and shuffled variant order, on the Ryzen 7 5800X:

| Python/GMP evaluator | Median server time | Phase-bound bits |
|---|---:|---:|
| Existing butterfly reference | 98.23 ms | 51 |
| New reference, delay 0 | 100.30 ms | 51 |
| Delay 1 | 102.42 ms | 51 |
| Delay 2 | 104.54 ms | 51 |
| Delay 3 | 108.46 ms | 51 |
| Delay 4 | 110.78 ms | 51 |

All distances match the plaintext reference. The independent per-tile trace
tests also compare complete decrypted polynomials. These small pilot medians
do not establish a hardware trend or latency distribution.

## E21: compact answer algebra still has to compute and identify the winners

[`answer_oracles.py`](../../experiments/bfv_search_lab/answer_oracles.py) implements
three exact constructions: balanced polynomial products, evaluation/interpolation,
and a full Walsh-feature expansion. For mismatch bits `b_ij`:

```text
G(z) = sum_i product_j (1 + (z-1)*b_ij) = sum_i z^Hamming(x_i,q)
```

The coefficient of `z^h` counts distance h. Counts and interpolation points use
a prime greater than both database size and dimension. IDs are recovered by
exact counts in successive ID intervals, ordered first by distance, then ID.
This handles arbitrarily large ties; three ID moments alone do not. A regression
uses two distinct eight-element subsets of IDs 0..15 with identical moments
through degree three and different first three IDs.

[`aggregate_bgv.py`](../../experiments/bfv_search_lab/aggregate_bgv.py) executes the
literal balanced circuit with our own encryption, multiplication and
relinearization. It retains each row's encrypted polynomial for prefix counts.
The public integer request `(distance, ID interval)` leaks routing information.
There is no claim that these requests constitute our eventual private protocol.

Paired encrypted pilot: 32 vectors, dimension 4, stable top-3, `N=16`, `t=257`,
180-bit Q, eta 1, 12-bit digits; seven rounds after a warmup:

| Measure | Existing packed distances | Literal histogram plus prefix recovery |
|---|---:|---:|
| Median local query/evaluation/finish time | 5.87 ms | 286.21 ms |
| Initial server time | 5.68 ms | 284.39 ms |
| Ciphertext products | 8 | 672 |
| Multiplicative depth | 1 | 3 |
| Response ciphertexts | 2 | Median 18: 5 histogram + 13 prefix counts |
| Additional retained row ciphertexts | — | 160 |
| Public phase-bound bits | 35 | 146 |

Setup is recorded separately. Local recovery includes its extra server sums
and owner decryptions; there is no network, serialization or authentication.
Ciphertext counts are not byte measurements. The literal histogram is unbatched;
the comparison motivates a different circuit, not a claim that every histogram
or TFHE approach must lose.

At dimension 512 the balanced factor construction has depth 10. At 8,192 vectors
its scalar model uses 1,117,773,824 products and caches 4,202,496 field elements.
These are scalar counts, not batched RLWE operations. The small plaintext output
of 513 histogram elements does not by itself imply a smaller RLWE packet.

There is also an obstruction to a generic short separated-feature expansion.
For fixed z over an odd field:

```text
K_z[x,q] = z^Hamming(x,q) = [[1,z],[z,1]] tensor-powered d times
```

For `z != +/-1`, the base determinant `1-z^2` is nonzero, so the matrix has rank
`2^d`. Thus an exact representation `sum_l f_l(x)*g_l(q)` valid for every binary
x and q needs at least `2^d` terms. Exhaustive small-field rank checks cover
dimensions 1..6. This rules out that particular generic bilinear shortcut;
it says nothing comparable about arbitrary nonlinear, interactive,
distribution-specific or approximate algorithms.

## E19: a stronger bound and its encrypted representation cost

[`syndrome_oracle.py`](../../experiments/bfv_search_lab/syndrome_oracle.py) compares
weight differences, coset-leader syndrome bounds, their maximum rounded to the
correct Hamming parity, and a coupled bound on each disjoint coordinate block:

```text
L(q,x) = min Hamming(q,y) subject to H*y = H*x and weight(y) = weight(x)
```

The real x is feasible, so `L(q,x) <= Hamming(q,x)`. The coupled constraints also
imply both individual bounds and the parity restriction. Summing over disjoint
blocks remains safe. The tests exhaust every query/block pair through width six,
include tails and duplicates, and catch unsafe addition of overlapping bounds
and unsafe removal of equal-radius candidates.

Use 64 eight-bit blocks with fixed public rank-four maps. At the **oracle kth
radius**, the counts of retained candidates for three independent data seeds are:

| Synthetic fixture (8,192 vectors, dimension 512) | Weight only | Parity-corrected max | Coupled bound |
|---|---:|---:|---:|
| Uniform | 8,192 / 8,192 / 8,192 | 8,192 / 8,192 / 8,192 | 8,192 / 8,192 / 8,190 |
| Three planted close neighbors | 3 / 3 / 3 | 3 / 3 / 3 | 3 / 3 / 3 |
| All identical | 8,192 / 8,192 / 8,192 | 8,192 / 8,192 / 8,192 | 8,192 / 8,192 / 8,192 |
| Every block has weight four; planted neighbors at distances 120/122/124 | 8,192 / 8,192 / 8,192 | 7,643 / 7,667 / 7,676 | 26 / 74 / 54 |

The last fixture is deliberately favorable, not a production-distribution claim.
Exact stable top-3 is retained in every case. Radius discovery is not free:
the artifact separately records fixed radii and whether they cover k results.
All 524,288 block features are scanned. Candidate reduction is not a measured
server speedup, private access scheme or proof that an untrusted server omitted
nothing. The syndrome-plus-weight features use 512 bits per vector here, so
they do not even shrink the unencrypted fixed-width feature record.

We then tested an actual depth-one encrypted representation: a query table
dot-product with one-hot index buckets. Only reachable `(syndrome, weight)`
buckets are kept. A public finite-field rank factorization `A=C*R` reduces this
further: the query owner encrypts row `C[q]`, and index preprocessing encrypts
the appropriate column of R. All possible block queries are used to derive the
basis; preprocessing does not depend on a private observed query.

Both layouts pass an independent integer-ring oracle and our homemade encrypted
butterfly at `N=128`, including an empty database, tails and multiple responses.
Factorized index coefficients are full-field values, so binary/sparse noise
bounds must not be reused. The encrypted test uses the original conservative
bound and a plaintext prime greater than the total dimension.

Model for 8,192 vectors with `N=16384` and plaintext prime 1031:

| Layout | Input features | Padded features | Ciphertext products | Gadget switches |
|---|---:|---:|---:|---:|
| Original signed distance scan | 512 | 512 | 256 | 767 |
| One-hot filter | 6,117 | 8,192 | 4,096 | 12,287 |
| Factorized filter | 3,549 | 4,096 | 2,048 | 6,143 |

This factorization halves the filter's products and index-tile count, but leaves
an 8× product penalty versus computing every distance directly, before exact
reranking or private selection. These are operation counts, not timings or wire
bytes. The block table ranks range from 39 to 57. A separate code-rank sweep
shows why more aggressive feature engineering needs controls: singleton buckets
recover ordinary Hamming distance, whose bilinear rank is only width+1, and the
existing signed layout already removes its known constant. A complicated lower
bound can be harder to evaluate under HE than the exact score.

## What to pursue next

**Follow-up implemented:** [the second creative cycle](certified-folding-results.md)
tests one-sided lookup compression and E22 coordinate folding, then connects
bounds to actual threshold discovery and whole-tile refinement. It retains the
lookup's negative result and measures a structured-data CPU/CUDA folding gain.
Its experiment cards supersede the execution order below, which records the
questions at the end of this first cycle.

1. Investigate a different cost model for the coupled filter: compact nonlinear
   lookup, shared computation across records, or a declared mixed protocol. For
   pure per-block bilinear lookup, the measured rank is already a constraint;
   another ordinary matrix factorization cannot remove the remaining penalty.
   Include shared constants, padding and full-field coefficient noise when
   comparing representations.
2. Connect E17's query-conversion question to these query tables: can conversion
   produce only the useful statistics, without recreating an expensive expanded
   query? Keep index/setup growth and batch-one latency in the cost model.
3. Compare exact selection circuits from the closest TFHE/counting literature
   under a compatible corpus/privacy contract. Keep E21's stable-ID and field
   counterexamples as tests for any compressed-output design.
4. For a surviving pruning protocol, establish a threshold and complete coverage
   without exposing queries, survivor IDs or decryption reactions. This is a
   mathematical/protocol question before another round of kernel tuning.

Do not optimize the present losing constructions into CUDA simply because their
oracles now exist. Preserve them as controls and pursue a mechanism that changes
the cost or explicitly stated contract.

## Artifacts and reproduction

- [E20/E21 raw models and seven-round pilots](../../benchmarks/results/creative_search_algebra_20260927.json), source commit `b972353`.
- [E19 three-seed selectivity, rank sweep and lookup models](../../benchmarks/results/syndrome_search_model_20260927.json), source commit `a23d813`.
- [Validation details](../../benchmarks/results/creative_search_validation.md) and [101-test output](../../benchmarks/results/creative_search_validation_pytest.txt).

Both artifacts include source hashes and complete model/pilot scope. Their
encrypted fixtures use variable-time private arithmetic and insecure tiny rings.
No secret key or ciphertext contents are stored in the artifacts.

```bash
.venv/bin/python benchmarks/creative_search_algebra.py --repeats 7 \
  --json-out benchmarks/results/creative_search_algebra_20260927.json
.venv/bin/python benchmarks/syndrome_search_model.py \
  --json-out benchmarks/results/syndrome_search_model_20260927.json
```
