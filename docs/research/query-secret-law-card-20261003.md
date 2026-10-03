# Q41/E115: actual ternary support and ideal nonunit-mask law

2026-10-03. **One bounded mathematical difference card; the ideal correctness
control can cover every nonzero ternary secret without assuming it is a unit.**
This does not establish the actual SHAKE/ROM transfer, cryptographic security,
new algorithm originality or an admitted production parameter set. No sampler
was changed, no secret was sampled/rejected, and no implementation, repository
test, native/GPU/timing or additional parameter experiment was run.

The source-law profile is the frozen E113/E114 N16384, d512, count8192, t1031,
CBD_eta21, radix15, Q1152921504606748673 and P4294953991. It is a **hypothetical
owner-only profile using the actual raw sampler law**: the current general
`shallow_bgv.key_gen` correctness guard refuses these parameters before drawing
a secret. This card neither changes that guard nor supplies a new setup API.
Only the existing E114 drop23 card is evaluated.

## 1. Exact return

| Quantity | Exact result |
| --- | ---: |
| Maximum split-ring nullity for any nonzero ternary secret |1911|
| Fixed jointly uniform prefix coordinates m=N-1911 |14473|
| Omitted codec+CBD contribution, charged pointwise before trace |174435342101748|
| Retained random threshold after that charge |854139466878445|
| Floor of conservative rational log exponent |2185|
| Complete lifetime tail for each nonzero secret, ideal masks |at most2^-2138|
| All-zero mass under one unconditioned raw IID ternary draw |3^-16384, at most2^-25968|
| Single fresh setup plus2^32-query lifetime, ideal masks |at most2^-2137|

The complete lifetime multiplier remains2^46:2^32 queries times all16384 output
coefficients, including unused positions. The nonzero-secret tail is uniform
over supported fixed setup/index errors and all common bounded gadget witnesses;
it does not average or assert independent reused digit/key errors. The setup
mass is charged once per this **single fresh unconditioned setup epoch**. It is
not charged per query, reused as a posterior probability after seeing a key, or
silently applied to a sampler conditioned on a test or selected key history.

For comparison, E114's unit-secret ideal drop23 tail was2^-2595. The weaker
2^-2138 bound trades a fixed worst-case suffix allowance for removing the unit
premise. The exact setup-plus-tail expression and its conservative dyadic bound
are archived. Both clear2^-128 **only as ideal statistical correctness controls**;
no computational-advantage, actual-sampler transfer or security budget is proved
here. The declared drop23 query/response body choice is unchanged from E114.

The generic baseline, **given this same derived lemma**, receives its determinant
bound, fixed projection, suffix allowance and concentration control: ratio1.
The ingredients are standard algebra and concentration; the resulting precise
nonunit correctness consequence has not been compared against the closest
published theorems. Giving both controls the lemma does not show that this
complete consequence was already published. Originality remains unconfirmed.
The next questions are a closest-theorem comparison and a reviewed computational
transfer for the actual public-seeded implementation, with complete lifecycle
assumptions; another scalar grid is not needed.

## 2. Actual sampler and split-ring criterion

[`_ternary_poly`](../../src/cuhepy/bfv/scheme.py) independently returns
`secrets.randbelow(3)-1` modulo Q for each coefficient. Its formal raw law is
IID uniform on{-1,0,1}^N; it does not reject the zero polynomial or test units.
[`shallow_bgv.key_gen`](../../experiments/bfv_search_lab/shallow_bgv.py) calls
this sampler only after its unchanged general one-product guard passes.
This distribution statement assumes the intended independent uniform random
coins; it is not an audit of OS entropy or an RLWE security estimate.

Since Q is the selected prime with Q=1 mod2N, `X^N+1` splits into N distinct
nonzero roots alpha_j in F_Q. The existing source/root checks are pinned by
E113; this card does not search new primes/roots. Evaluation gives the CRT map

```
R_Q = F_Q[X]/(X^N+1)  ~=  product_j F_Q,
s is a unit iff s(alpha_j) != 0 for every j.
```

Multiplication by s has rank N-k, where k is the number of zero evaluations.
The exact nonunit probability is symbolically

```
3^-N * #{s in{-1,0,1}^N : some s(alpha_j)=0}.
```

**This cardinality and the actual unit probability were not evaluated.**
The N root-zero events share the same secret coefficients; no independent-root
probability, uniform-secret replacement or approximate N/Q forecast is assumed.
Conditioning the secret sampler on being a unit would change its distribution
and requires its own cryptographic analysis. No such conditioning is introduced.

## 3. Deterministic nullity bound for all nonzero ternary secrets

Let M_s be the N by N integer matrix for negacyclic multiplication by s and
Delta=det(M_s). Three elementary facts suffice.

1. **Delta is a nonzero integer.** For power-of-two N, `X^N+1` is irreducible
   over the rationals. After `X -> X+1`, every nonleading coefficient is even
   and the constant is2, not divisible by4, so Eisenstein at2 applies. A
   nonzero s of degree<N is coprime to this polynomial. Its multiplication
   determinant, equivalently its resultant, cannot vanish.
2. **Q^k divides Delta.** Modulo prime Q, M_s has rank N-k. Lift a rank-N-k
   factorization to integer matrices U,V and write M_s=UV+QW. In the
   column-multilinear determinant expansion, any term with fewer than k
   columns from QW has more than N-k columns from the rank-N-k matrix UV
   and is zero. Every remaining term contains Q^k. This proves the divisibility
   without assuming independent CRT coordinates of the secret.
3. **|Delta|<=N^(N/2).** At the complex roots omega_j of `X^N+1`,
   Delta is the product of s(omega_j). Parseval gives
   `(1/N)*sum_j |s(omega_j)|^2 = sum_i s_i^2`.
   Applying AM-GM to these nonnegative squared magnitudes yields
   `|Delta| <= (sum_i s_i^2)^(N/2) <= N^(N/2)`.

Consequently every nonzero ternary secret satisfies

```
Q^k <= |Delta| <= N^(N/2).
```

The sole registered exact integer comparison gives

```
Q^1911 <= N^(N/2) = 2^114688 < Q^1912.
```

Thus k<=1911 deterministically. The compared Q powers have114660 and114720
bits, respectively. No floating logarithm, sampled secret, average-case rank
or unit probability enters this result. The bound is sufficient, not asserted
tight or typical.

## 4. Uniform projection despite nonunit multiplication

For an arbitrary fixed s, let Z be its set of k zero roots. A vector v belongs
to Im(M_s) exactly when

```
sum_i v_i*alpha^i = 0  for every alpha in Z.
```

These are k independent Vandermonde parity checks. Let K1911. Their LAST K
coefficient columns include k consecutive columns, whose minor is a nonzero
root-power diagonal times an ordinary Vandermonde matrix. It is invertible.
Therefore arbitrary values on the FIRST m=N-K=14473 coordinates extend to a
vector in Im(M_s). The prefix projection is surjective for every nonzero
ternary s, regardless which roots vanish. This is a fixed public prefix; it
does not choose coordinates after inspecting a private secret or its roots.

With a genuinely uniform full-ring mask a, a*s is uniform over Im(M_s), since
every image element has the same number of preimages. For any fixed fresh E
and any query chosen before its own mask,

```
c0 = message + t*E - a*s
```

is uniform over a translated image code. Its prefix is jointly uniform over
F_Q^m and independent of **all** fresh E. Thus the prefix's deterministic codec
errors are IID with the exact E114 scalar law and independent of the CBD vector.
The full N-coordinate vector is generally a correlated affine-code law; it
is not assigned IID by this argument. The remaining K coefficients may depend
arbitrarily on the prefix, the query, the secret and the fresh errors.

Individual c0 coefficients are already uniform for any nonzero secret, because
each multiplication row is nonzero. Individual marginals alone would not
justify an N-fold MGF. The fixed jointly uniform projection is the additional
ingredient that makes this bound valid.

## 5. Same exact MGF, with a paid correlated suffix

For drop23, E114's exact codec support is delta/t in[-4068,4068]. Fresh CBD
errors satisfy |E_i|<=21. With W=1+t*eta=21652, bound each omitted weighted
term by t*W*(21+4068), without independence. Its total is

```
K*t*W*4089 = 174435342101748.
```

E114's complete graph/terminal threshold h1028574808980193 becomes
h'854139466878445. The existing complete maintenance cap47563105782398976,
safe final phase radius574193413656199173, terminal rounding cap8446468 and
E15 trace factor512 are unchanged. E15 gives D times one shifted input-product
coefficient in each final coordinate, so the same prefix/suffix split of fresh
query atoms covers every output without a separate tile union.

Only the m14473 prefix atoms use the independent exact law. The same fixed
z16385/16384 and same upward endpoint MGF1084829195/1073741824 give

```
J' = floor(h'/(t*W)) = 38262391,
A' = J'*(z-1)/z - m*(Mplus-1)
   = 38454669179827229/17593259786240,
floor(A') = 2185.
```

The archived calculator records the exact rational A'; the fraction above is
read from that archive, not a fitted log. The two-sided per-output dyadic upper
is2^-2184. Multiplying by2^46 yields2^-2138. The suffix is paid pointwise and
can be fully dependent; reused maintenance errors also stay pointwise. Neither
a posterior-IID assignment nor an independent digit/error law is introduced.

Under the unconditioned raw ternary draw, zero-secret mass is exactly
p0=3^-16384<=2^-25968 by integer comparison. For one setup and the stated
ideal lifetime, the total correctness-failure upper is

```
p0 + (1-p0)*2^-2138
  <= 2^-25968 + 2^-2138
  <= 2^-2137.
```

For multiple fresh setups, the setup union must count every distinct draw/epoch.
No per-query reuse of the single-epoch setup budget or posterior probability
is licensed by this card.

## 6. Provenance and remaining boundary

The external frozen specification is
`research-data/seeded-correctness-20261003/secret-law/preregistration.md`, SHA256
`dac2640ac9ceb49470d067e84fcfce744400c19a6e6a77f6a9d8655e829ef923`.
It pins the actual sampler/codec/bound sources and both E113/E114 raw receipts.
The literal calculator source was separately frozen before its only run.
`calculate_secret_law.py` uses integers/Fraction and reads only the selected
drop23 E114 card; no full secret domain, new query drop or setup was evaluated.
The command exited0. There were no new repository tests or source changes.

The exact result is
`research-data/seeded-correctness-20261003/secret-law/one-drop23-exact-card.json`,
SHA256`b1ab39ea3c2df5139f848d29ab342ce267589d03f9aaa9ba0daccd0cb45bfb37`.
The source/hash/run receipts and calculator are in the same external folder.
Independent read-only review supports the determinant/divisibility, fixed
Vandermonde projection, correlated-suffix charge and one-epoch setup accounting.
This is a correctness-law review, not an external cryptographic audit.

The mask still must be genuinely uniform over the complete ring. Actual
public256-bit SHAKE seeds do not information-theoretically sample a uniform
prefix of14473 field coefficients. Any computational marginal-event transfer,
rejection-sampler truncation and ROM/revealed-seed composition require their
own explicit argument. Accepted original queries, complete checked/attested
server execution, owner enrollment and adaptive release/epoch lifecycle remain
external prerequisites. No RLWE parameter estimate, secret-distribution security
reduction, private side-channel assurance or complete proof-cost claim follows.

Stop the registered scalar card here. Retain the unit-free **ideal conditional
correctness** fact and the actual raw all-zero budget for the next reviewed
composition task, with current API refusal and generic containment recorded.
