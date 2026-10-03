# Q41/E115 partial component: one fixed mask-stream budget

Status: **standard exact probability control only**. For the frozen E113
N16384/Q60/radix15 profile, M=N+6 candidate words give a uniform-stream exhaustion
bound below 2^-186 over 2^32 queries. The comparisons below are exact integer
comparisons. They assign neither SHAKE distinguishing advantage nor unit-secret
probability, and do not approve a parameter or security level.

The existing runtime sampler is still uncapped and unchanged. No sampler, key
generation, native artifact, test or timing workload was executed. One literal
probability card was frozen before calculation; no M or profile search was done.

## 1. Frozen public inputs and budget

The profile is the actual E113 N16384, d512, radix15 context with
Q=1152921504606748673, bit_length(Q)=60. The E113 supported canonical query drop22
and radix are context labels; they do not enter this stream-exhaustion calculation.
The fixed choice was M=N+6=16390 before computing the bound.

Each candidate consumes ceil(60/8)=8 bytes. Thus the bounded-output PRG component
would need exactly

```
8*M = 131120 bytes,
8*ceil(60/8)*M = 1048960 bits.
```

This is a mathematical output budget, not a change to the public packet or source
loop. The SHAKE assumption in the marginal card must cover this actual output
length and relevant total distinguishing work.

## 2. Exact uniform-stream bound

For independent uniform stream bytes, each 8-byte candidate is masked to 60 bits
and accepted exactly when it is below Q. Its rejection probability is

```
rho = (2**60-Q)/2**60
    = 98303/1152921504606846976.
```

Fewer than N acceptances among M=N+6 candidates is equivalent to at least seven
rejections. If that happens, some seven-element subset of the M positions all
rejects. The union bound over those subsets gives

```
alpha = Pr[Binomial(M,rho) >= 7]
      <= C(16390,7) * (98303/1152921504606846976)**7
      < 2**-218.

2**32 * alpha
      <= 2**32 * C(16390,7) * (98303/1152921504606846976)**7
      < 2**-186 < 2**-160 < 2**-128.
```

No independence between queries is needed for the lifetime union bound, provided
each next query has the applicable fresh uniform-stream law and this fixed
geometry. Approximate display-only logarithms of the two upper bounds are
-218.20272433185937 and -186.20272433185937. The stored rational numerator and
denominator, and integer comparisons with 2^-128 and 2^-160, are the evidence;
floating-point displays are not used to establish the inequalities.

## 3. Why the existing bulk loop has the same candidate sequence

`experiments/bfv_search_lab/owner_bgv.py:34` initializes
SHAKE256(TAG || key_id || seed). On each iteration it reads `remaining*8` bytes,
unpacks consecutive little-endian 8-byte words, restores any trailing zero words,
masks to 60 bits, and retains values below Q. This produces the same successive
candidate words as the scalar loop in `seeded_bgv.py:25`; chunk boundaries do not
resample or skip candidates.

If r coefficients remain, that iteration has exactly r candidate words. If any
rejects, fewer than r are accepted and the loop continues. A terminating iteration
therefore accepts all its r words: the final word is the Nth accepted word, and
the loop then stops. It reads no extra candidate after that final accepted word.
The byte-budget event is consequently the same event that the Nth accepted word
occurs after position M. Bulk unpacking's zero padding restores actual zero-valued
words; it does not add extra random candidates.

This is a static Python-source argument, not executed native equivalence testing.
Current uncapped execution may consume more than M words. The marginal proof
conservatively charges all such paths to its exhaustion event instead of changing
runtime behavior or assuming those paths cannot happen.

## 4. Scope and remaining obligations

In the [marginal correctness card](query-mask-marginal-correctness-card-20261003.md),
the real-source lifetime bound still has the form

```
epsilon_setup + sum_i(delta_i + alpha_i + Adv_i).
```

This card supplies only an upper bound on the uniform-stream alpha term for one
fixed geometry and lifetime. It does not set Adv_i, epsilon_setup or delta_i.
The bounded-output SHAKE assumption, actual unit/nonunit secret law, complete
raw/terminal margin event, pointwise coverage of accepted responses, adaptive
epochs and separate protocol/privacy analysis remain open. In particular,
alpha<2^-186 is not a claim that the whole system has 186-bit security or that
its actual SHAKE-based abort probability has that statistical bound.

External immutable evidence is under
`WORK/research-data/query-mask-marginal-correctness-20261003/`:

- `stream-budget-freeze.json`: fixed geometry, M and formula before calculation.
- `stream_budget_calc.py`: standalone exact Fraction/comb calculator, no repository
  imports or sampler execution.
- `stream-budget-raw.json`: exact reduced fractions and threshold comparisons.
- `stream-budget-review-receipt.json`: commands, source hashes and scope accounting.

This ordinary control completes one small mathematical component of Q41/E115.
It establishes no original contribution and leaves the proposed parameter-frontier
and full correctness theorem gates unresolved.
