# Q51 reviewed static falsifier: the known quartet error envelope

Status: **conditional proof passed independent static review**. This
is a separate symbolic usefulness check after the first
[eligibility card](source-certificate-eligibility-screen-20261003.md). It
executes no program, root enumeration, exact source exponent/probability,
HE operation, test, parameter selection or benchmark. The proof concerns an
upper-bound formula, not the true bad-key probability.

The fixed E120 source has degree16384 and two recorded60-bit primes. Consider
the more generous general envelope `8 <= N <= 2^14`, `p >= 2^59`,
`0 < eta <= 1`, `C >= 1`. These are declared comparison assumptions, not
guessed certified HPX constants. Grant all other HPX degree/order/root
premises optimistically. The source law uses eta_HPX=2/3; CBD parameter21
is unrelated to this symbol.

The retained [primary comparison](joint-root-census-prior-comparison-20261003.md)
identifies HPXv2 Proposition6.2(2)'s prescribed-quartet envelope

```
U = p^-4 + exp(-theta),
theta = eta*(N-1)/(C*4*ln(p)*ln^5(4*ln(p))).
```

## Conditional proof

The elementary series bound `e < 3` follows from
`j! >= 2^(j-1)` for j>=2, with strict inequality for j>=3. Therefore
`exp(1/2) < sqrt(3) < 2`, so `ln(2) > 1/2`. Consequently

```
ln(p) >= 59*ln(2) > 59/2,
4*ln(p) > 118 > 64,
ln(4*ln(p)) > ln(64) = 6*ln(2) > 3.
```

Since eta<=1 and C>=1,

```
0 < theta < 2^14/(2*59*3^5) < 1.
```

The final integer inequality can be checked without floating arithmetic:
`59>48`, `3^5>192`, and
`2*48*192 = 18*1024 > 16*1024 = 2^14`.
It follows that the additive error in this formula satisfies

```
exp(-theta) > exp(-1) > 1/3.
```

This is a lower bound on the size of the **reported error allowance**. It
is not a lower bound on any actual quartet event.

Let z=3^-N be the raw zero-secret atom. For N>=8, z<1/12, while
choose(N,4)>=5. Thus the ordinary zero-once all-quartet union adapter, even
for just one source limb, gives

```
z + choose(N,4)*(U-z) > z + 5*(1/3-1/12) > 1.
```

Its probability upper bound therefore clips to1. More limbs or enrollment
events cannot improve this particular certificate. The result needs no
chosen epoch count or complete-system failure allocation: it cannot certify
any nontrivial probability through this adapter in the declared envelope.

## Scoped decision and next proof obligation

Stop chasing large unknown constants
for this particular HPX additive-error/ordinary-union application in C>=1. Even the
generous C>=1 comparison is vacuous at the fixed source bit/degree range.
This neither audits the paper's full proof nor establishes its smallest
valid constant. A substantiated C<1, a different theorem, finer dependency
argument or stronger source-specific certificate is outside this result.
The known theorem remains a direct originality comparator.

The [first eligibility card](source-certificate-eligibility-screen-20261003.md)
still governs the source/enrollment/failure/frontier requirements. The stronger
target would need a coherent explicit all-quartet or direct defect-event
bound that survives those budgets and changes a fully paid system frontier.
That target is unproved. Generic near-uniformity, this elementary envelope
comparison, and ordinary union bounds are known methods, not an accepted
original contribution. No raw-secret rejection, guard bypass, source-security
number or actual communication improvement follows.

The [independent review](../../../research-data/joint-root-census-20261003/source-certificate-eligibility/envelope-proposal-review.md), proposal and final receipt are retained in the new external
`research-data/joint-root-census-20261003/source-certificate-eligibility/`
folder. All E123 scientific code/raws, prior corpus and earlier cards remain
unchanged.
