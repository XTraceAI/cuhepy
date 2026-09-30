# E32 — Fixed-batch correctness bounds and smaller BGV moduli

2026-09-29. Homemade research implementation on
`experiment/creative-search-algebra`; benchmark source
`a55bfac93d9bf17547451a3c46173f01211f962d`. The company Paillier/BFV/BGV,
CUDA, protected service and earlier research implementations are preserved.

The previous [E31 projection](hierarchical-query-basis-results.md#more-promising-next-experiment-the-phase-bound-itself)
now has an implementation, exact distribution controls and full encrypted
measurements. For **queries fixed before enrollment**, a scoped CBD tail bound
permits a 32-bit ciphertext modulus at the same full encryption degree, index
column count and score capacity as the 40-bit deterministic control.
Coefficient response and index bodies decrease by **20%**. Checked native local
time increases: smaller Q requires another fingerprint round at the chosen
verification target. This is a communication/correctness tradeoff, not a
general speedup or an approved production parameter profile.

## What changed

- [crt_noise_budget.py](../../experiments/bfv_search_lab/crt_noise_budget.py)
  specifies the finite-batch CBD calculation, exact integer rounding and a
  profile binding. It also supplies a small exact distribution oracle.
- [fixed_batch_bgv.py](../../experiments/bfv_search_lab/fixed_batch_bgv.py)
  fixes immutable queries, masks and CRT corrections **before** index
  encryption. It uses fresh independent symmetric encryption for each index
  column/reply and each offline answer. Its separate `StatisticalCiphertext`
  has a `Certificate`; it has no deterministic `phase_bound` field.
- The separate GMP and existing homemade C++ subring evaluators produce the
  same complete ciphertext. The native source and binary are unchanged.
  All secrets remain full degree N. No SEAL or GPU computation is used here.
- The owner verifier pins the fixed requests, authenticates every ciphertext
  coefficient with hidden fingerprints, then issues a process-local one-use
  receipt. Only that receipt reaches the prototype's private decryption API.
  Index and answer preparation are trusted premises; this is not a proof that
  an untrusted party prepared them correctly.
- [fixed_batch_noise_lab.py](../../benchmarks/fixed_batch_noise_lab.py)
  measures both profiles and separately reconstructs unreduced integer
  phases. The [summarizer](../../benchmarks/fixed_batch_noise_summary.py)
  audits source hashes and exports charged fixed-pool models.

The old deterministic key gate, ciphertext type and decryption interfaces are
unchanged. A regression confirms that old `masked.key_gen(..., q_bits=32)`
still rejects the full Mushroom local circuit. The new type does not pretend
that a probable bound is an absolute one.

## A narrow analytic correctness claim

Let `R = Z[X]/(X^N+1)`. The seeded symmetric inputs have phase

```text
C_j: m_j + t e_j       T_r: m_0 + t e_0
Z = T_r + sum_j C_j alpha_j(delta)
phase(Z) = m_0 + sum_j m_j alpha_j + t(e_0 + sum_j e_j alpha_j)
```

Every message coefficient uses a centered representative with absolute value
at most `b = floor(t/2)`. Every error coefficient is a fresh independent
`CBD(eta)` sample. The centered correction polynomials `alpha_j` are fixed
before those index errors are sampled. Symmetric phase cancellation removes
the uniform mask/secret product exactly; public-key encryption's additional
error terms are not part of this claim.

For one output coefficient, negacyclic multiplication introduces signs but
selects distinct error coefficients within each fresh polynomial. Across
different columns the errors are also independent. Consequently the random
term is a weighted sum of independent CBD variables, with squared weight sum

```text
S2 = 1 + sum_j ||alpha_j||_2^2.
```

For one CBD error, the **exact** moment generating function is
`E exp(lambda e) = cosh(lambda/2)^(2 eta)`.
The analytic inequality `log cosh(x) <= x^2/2` follows by integrating
`tanh(x) <= x` for `x >= 0` and symmetry. Thus

```text
E exp(lambda * random_term) <= exp(lambda^2 t^2 eta S2 / 4)
Pr[abs(random_term) >= u] <= 2 exp(-u^2 / (t^2 eta S2)).
```

The deterministic message/carry contribution is bounded separately by

```text
M = b * (1 + sum_j ||alpha_j||_1).
```

For at most B fixed requests and R replies per request, a union bound charges
**all N R B coefficients**. It does not assume independence between different
output coefficients or between requests that reuse index errors. It does
require each request's correction to be independent of the reused errors.

```text
epsilon = 2^(-correctness_bits)
u >= t sqrt(eta S2 ln(2 N R B / epsilon))
abs(integer_phase) <= M + u except with probability at most epsilon.
```

The implemented integer calculation deliberately rounds upward. With
`K = bit_length(2 N R B) + correctness_bits`, the logarithm is less than
`0.7 K`, since `ln(2) < 0.7`. The helper finds the least integer u satisfying
`10 u^2 >= 7 t^2 eta S2 K`, using integer arithmetic only. Requiring
`2(M+u) < Q` then suffices for centered phase recovery under these assumptions.

The universal certificate uses `W = sum_j degree(alpha_j)`,
`sum ||alpha||_1 <= W b` and `sum ||alpha||_2^2 <= W b^2`. It is conservative
over every centered correction in the fixed batch. Per-request certificates
also record the actual centered correction norms.

At N=16,384, t=1,153, eta=21, R=1, B=1,024 and 128 correctness bits:

| Local circuit | W | Old absolute phase maximum | Message/carry bound | CBD tail bound | New universal total |
|---|---:|---:|---:|---:|---:|
| Mushroom | 1,024 | 14,621,171,925 | 339,739,200 | 1,011,162,134 | 1,350,901,334 |
| Semeion | 1,472 | 21,017,923,797 | 488,374,848 | 1,212,340,808 | 1,700,715,656 |

The q32 prime is **4,294,475,777**; q40 is **1,099,510,054,913**, each congruent
to 1 modulo 2N. Both new universal totals fit below q32/2; both old maxima do
not. The prototype fixes nine actual requests but retains the conservative
budget B=1,024. It cannot append the remaining requests later.

This argument is a reviewable mathematical derivation for this circuit, not
an independently reviewed security theorem. It does not apply to adaptive
error-dependent corrections, correlated errors, public-key encryption,
ciphertext products, key switching or modulus rounding. Correctness bits are
not lattice security bits.

## Counterexamples and independent oracles

The 20 new tests include exact enumeration of all sampler entropy words for
eta=1,2,3,4; exhaustive weighted independent error assignments; independent
negacyclic schoolbook multiplication; exact variances; high-precision sanity
checks of the MGF; and integer square-root rounding on large inputs. Analytic
inequalities, rather than numerical checks, support the negligible-tail claim.

Two negative controls are retained:

1. With 256 independent CBD(1) errors, choosing each weight as `sign(e_i)`
   makes the sum `sum |e_i|`. Its exact binomial tail exceeds the purported
   fixed-weight budget with probability greater than 99%.
2. Repeating one CBD(1) error 256 times instead of sampling independent errors
   exceeds that budget with probability 1/2.

These are counterexamples to invalid assumptions, not attacks on the immutable
batch API. Passing a marginal error-distribution test alone is insufficient.
The lifecycle refuses resampling enrollment or answer pools in a used batch;
all weights and corrections precede the only enrollment attempt.

A small full encrypted fixture enumerates all 32 binary queries, including
three replies and mixed correction degrees 1,2,4. GMP/native ciphertexts,
schoolbook integer phases, distances and stable top-three selection agree.
Complete-body mutation, certificate/context changes, truncated responses,
request substitution, replay and concurrent request consumption are tested.
Malformed responses are rejected before the private product routine is called.

The full retained suite reports **387 tests passed**. These finite tests do
not empirically establish a failure probability of 2^-128.

## Paired full-size experiment

Both cases use the same index-only private maps and predeclared held-out binary
queries, full N, t, eta, encrypted column count and reply layout:

- Mushroom: 7,996 indexed rows, 126 bits, 32 columns, 32 CRT slots, one reply.
  Private query dimension h=523/596 for split seeds 3001/3002.
- Semeion: 1,465 indexed rows, 256 bits, 23 columns, 64 CRT slots, one reply.
  Private query dimension h=1,401 for both splits.

Each of four dataset/split runs contains two independently encrypted profiles,
one warmup and eight measured queries per profile. Profile order reverses
between split seeds; GMP/native evaluation order alternates between queries.
The same query IDs are paired, but keys, ciphertexts and masks depend on the
fresh context. There is no GPU, SEAL, network, enclave or multi-query throughput
measurement. Reproducible public mask seeds are benchmark fixtures; HE errors
and private checking seeds use OS randomness.

The q40 control uses the existing deterministic evaluator, checker and
decryption. Its key distribution is the same homemade ternary/symmetric
distribution, generated by the fixed-batch harness with a separate context
tag. It also pays to fix the batch, so this isolates Q/correctness/checking
rather than comparing different query scheduling contracts.

### Payloads and storage

| Dataset / split | Query body, both | q40 response | q32 response | q40 expanded index | q32 expanded index |
|---|---:|---:|---:|---:|---:|
| Mushroom 3001 | 1,046 B | 163,840 B | 131,072 B | 5,242,880 B | 4,194,304 B |
| Mushroom 3002 | 1,192 B | 163,840 B | 131,072 B | 5,242,880 B | 4,194,304 B |
| Semeion 3001/3002 | 2,802 B | 163,840 B | 131,072 B | 3,768,320 B | 3,014,656 B |

Query and response bodies are actually packed. Expanded index bodies are
canonical size models, not Python heap measurements. All Q coefficients use
five versus four bytes, while the full-degree secret and number of components
stay unchanged. Seeded index packets measure 2,624,832→2,100,544 B for Mushroom
and 1,886,598→1,509,766 B for Semeion. Each one-use seeded answer packet is
82,026→65,642 B, including its existing serialized metadata.

A modeled 56-byte probabilistic certificate (binding and three u64 fields)
still leaves **32,712 B saved per query/response**, about 19.6–19.8%. There is
no new transport parser or measured certificate wire format. Common context,
token, authentication and network framing are excluded on both sides.

The C++ prepared index remains eight-byte words: q32 does **not** reduce that
working allocation. It reduces canonical encrypted storage/traffic, rather
than every in-memory representation.

### Computation and phase evidence

Full stage medians, observed phase maxima and source audits are exported in
[the stage CSV](../../benchmarks/results/fixed_batch_noise_stages_20260929.csv).
Entries below are milliseconds, split 3001 / 3002. The total uses the native
server; the GMP server is an independent slower reference.

| Dataset / profile | GMP server | C++ server | Verify | Decrypt | Checked native local total |
|---|---:|---:|---:|---:|---:|
| Mushroom q40 | 863.12 / 872.22 | 12.26 / 12.78 | 35.19 / 36.57 | 17.28 / 17.53 | 74.90 / 77.97 |
| Mushroom q32 | 851.27 / 844.17 | 12.91 / 12.90 | 44.70 / 44.74 | 14.51 / 14.18 | 82.80 / 82.37 |
| Semeion q40 | 688.46 / 646.39 | 13.45 / 13.41 | 39.65 / 37.62 | 18.47 / 17.12 | 77.63 / 74.24 |
| Semeion q32 | 636.23 / 612.96 | 14.28 / 13.93 | 48.63 / 46.00 | 14.81 / 13.96 | 84.45 / 79.96 |

The public C++ evaluator retains u64 words, u128 products and the same NTT
operation count at either Q. A smaller serialized word does not automatically
accelerate that implementation. GMP and private decryption benefit from
smaller integers in these runs, while the extra checking round raises native
local totals by 4.40–7.90 ms. This is the measured bottleneck, not a claim of
statistical significance or a reason to skip authentication.

All **72 full encrypted searches**, including warmups, match every distance,
stable top-three result and GMP/native ciphertext coefficient. They use
**36 distinct dataset/query IDs**. The audit checks **1,179,648 unreduced phase
coefficients**. Observed q32 maxima are 189,737,063–230,323,280 across cases,
8.8–10.7% of Q/2. These samples verify concrete executions and the audit code;
they cannot establish the analytic failure probability or justify a smaller Q
from empirical headroom alone.

The independent phase audit first decrypts each **fresh** input phase on the
owner. It then reconstructs the unrounded response phase at an auxiliary
integer modulus greater than twice the old absolute phase maximum. The GMP
oracle therefore cannot wrap within that modulus. Every reconstructed
coefficient is checked against the actual ciphertext phase modulo Q, its
certificate and Q/2. Secret diagnostic vectors never reach the evaluator.
Only maxima and diagnostic hashes are retained. Audit preparation/work is
separately timed and excluded from online performance.

Online local time includes fixed-request release, public evaluation, complete
verification, private decryption, decoding/stable selection and response
packing. It excludes transport and all offline stages. Stage medians need not
sum to the median of a per-query total. Eight samples support these observed
medians, not latency-percentile or statistical-significance claims.

At the bounded verification budget, q40 uses four rounds and q32 five. In the
ideal uniform-challenge model, `B/Q^rounds` is approximately 2^-150 for either.
The implementation expands hidden SHAKE seeds, so that model additionally
requires a pseudorandomness argument and the existing verification-only
transcript/no-private-timing assumptions. This integrity budget is separate
from 128 correctness bits and from RLWE security.

### Charge scheduling and unused work

The prototype has a different contract from interactive E29: all requests must
be fixed before enrollment. Constructor validation/deep copying, query
transforms and mask fixing are now explicitly timed. The additional fixed
schedule body model stores query weights, corrections and mask seeds: 19,116
or 21,744 B for the two Mushroom batches; 50,724 B for Semeion. It excludes
Python object overhead and is not the complete owner-state total.

The [utilization CSV](../../benchmarks/results/fixed_batch_noise_utilization_20260929.csv)
charges the complete measured index/check setup and all nine offline answers
even if only 1, 4 or 9 requests are used. These are sums of recorded stages and
packet/body counts, not measured elapsed workloads. They do not project an
adaptive extension or silently amortize a batch over 1,024 new queries.
Uncaptured orchestration, provisioning, durable state and transport remain
outside those sums. New queries require a new fixed enrollment in this API.

Recorded setup stage sums increase from 7.22–8.25 s for q40 to 8.03–8.78 s
for q32. The complete nine-answer preparation/check pool costs 0.64–0.76 s
versus 0.72–0.83 s. That work is not free. Both profiles have the same fixed
scheduling contract in this paired comparison; neither is an immediate
replacement for an interactive service.

The [comparison CSV](../../benchmarks/results/fixed_batch_noise_comparisons_20260929.csv)
also gives a deliberately simple link model. Dividing 32,712 saved bytes by
the extra checked local time gives break-even payload rates of **33–60 Mb/s**.
Below those rates a serial transfer-only model favors q32. This excludes RTT,
concurrency, compression and amortized setup; no network measurement was made.

## Prior work and contribution ledger

[Gao and Zheng, WAHC 2025](https://people.iiis.tsinghua.edu.cn/~gaomy/pubs/he_noise.wahc25.pdf),
abstract and Sections 1–3.2, explain why Gaussian approximations and overlooked
dependencies can underestimate RLWE noise, and why full-polynomial tails must
charge every coefficient. Our scoped linear CBD calculation uses an exact MGF
and avoids their ciphertext-product setting. Their paper does not validate our
profile. Standard concentration inequalities are established ingredients.

[The HE standardization security-guidelines page](https://homomorphicencryption.org/security-guidelines/)
links current parameter guidance and estimators. No estimator result or
independent parameter approval is supplied by this correctness experiment.

| Question | Evidence here | Still missing |
|---|---|---|
| Does concentration change the IO frontier of the transposed linear circuit? | Same-capacity q32 execution and a 20% coefficient-body saving | Independent proof/parameter review and a useful deployment/state comparison |
| Does a smaller modulus automatically accelerate the server? | Existing u64/u128 C++ work counts and working allocation stay the same | A separate backend experiment if it tests a surviving research hypothesis |
| Can a probabilistic bound retain the old ciphertext semantics? | Separate type and unchanged rejecting deterministic gate | No intent to relabel the bound; production integration would need its own contract |
| Can arbitrary adaptive corrections use the same proof? | Exact error-dependent counterexample; fixed schedule enforces independence | A formal adaptive transcript/query policy or a stronger uniform bound |

No new primitive or original theorem is claimed. A possible paper direction is
the joint search representation, correctness, authentication and lifetime
frontier; this experiment supplies one measured point and an obstruction.

## Next discriminating experiments

1. **E34: adaptive scheduling with fresh correlations.** In an ideal model,
   a fresh uniform r chosen independently after fixing w makes
   `delta = w-r mod t` uniform even when w depends on earlier history. Test
   that identity exhaustively, then specify precisely when masks/offline
   ciphertexts become visible. Existing encrypted preprocessing and SHAKE
   seeds do not automatically inherit the ideal statement. Keep reuse,
   collusion and error-dependent controls; do not relax this fixed-batch API
   until the complete transcript argument is reviewed.
2. **E35: joint plaintext/ciphertext/verification field selection.** The
   current t=1,153 came from an earlier profile. Search admissible primes
   satisfying CRT root and exact score-range conditions, rebuild private
   finite-field maps and charge changed ranks, padding, Q, checker rounds and
   owner state together. Retain q40 and the deterministic correctness control.
   A smaller field is a hypothesis, not permission to wrap scores or reuse
   maps fitted over another field.
3. **E33: authenticated two-field correlations.** Use the
   [existing contract](authenticated-correlation-contract.md) to include
   centered-lift carries, malicious preprocessing, fresh encryption, unused
   tokens and crash/rollback semantics. Check a complete tiny relation before
   accelerating it. Moving verification to a larger field without accounting
   for Q-reduction carries is not an exact linear check.

Before any production promotion, trusted setup, complete-response integrity,
private arithmetic/side channels, parameter assurance and durable consumption
still require their separate reviews. This local receipt is neither Nitro
attestation nor a remotely verifiable proof, and this experiment changes no
production authorization path.

Reproduction commands, all raw observations, the validation transcript and
the 100 source/binary comparisons are listed in
[the validation record](../../benchmarks/results/fixed_cbd_validation.md).
