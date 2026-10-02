# Q17/E91: deterministic rounding bounds for a derived squared secret

2026-10-02. **Bounded execution complete; no original complete construction
selected.** This executes the [preregistered question](quadratic-drift-plan-20261002.md).
The [initial raw receipt](../../benchmarks/results/publication-quadratic-drift-screen-20261002.json)
retains exact counts, source hashes, synthetic cards and its scope. This is
homemade GMP arithmetic and full public recomputation, with no SEAL import.
The [closest controls](quadratic-drift-closest-work-20261002.md) remain mandatory.

## Restricted statement and proof

Work over Z[X]/(X^N+1), with N a power of two. S is ternary and has support
within an owner-approved public prefix of length D. S-squared means its actual
ring square; it is neither an independent secret nor a ternary polynomial.
For public integer rounding numerators d0,d1,d2, the target is a bound on every
coefficient of `d0 + d1*S + d2*S-squared`.

Let C be multiplication by d2 in the signed negacyclic coefficient basis.
The coefficient-k quadratic matrix H_k has entry equal to the signed
coefficient of d2 contributing to X^(i+j). It is symmetric. The signed
reflection J_k is orthogonal, H_k=C J_k, J_k C J_k=C-transpose, and C is normal.
Consequently **H_k squared = C C-transpose for every k**. This is a restricted
integer-matrix identity, not a new hardness assumption.

Thus `abs(S-transpose H_k S) <= D * spectral_norm(C)`. With
`d2-star=(d2[0],-d2[N-1],...,-d2[1])`, normality and the nonnegative eigenvalues
of C C-transpose give, for p=1,2,4,8,

```
spectral_norm(C)^(2p) <= trace((C C-transpose)^p)
trace((C C-transpose)^p) = N * coefficient_0((d2*d2-star)^p).
```

Every convolution here is over Z. Upward GMP integer roots give conservative
integer bounds. The implementation takes the minimum of these valid moment
bounds and a strong coefficient-box bound that counts all ordered prefix
pairs. The linear term uses the exact largest cyclic prefix-window L1 sum;
the body term uses its largest absolute coefficient. This is deterministic
over the whole approved secret class, including arbitrary dependence between
public components and S. It assumes no Gaussian law or posterior independence.

The exact canonical embedding gives the spectral norm itself and is therefore
at least as tight as the moment bound. General canonical/Schatten norm methods
are known. The identity and its GMP certificate alone do not pass the project's
original-mechanism gate.

## Implemented interface and verification

[quadratic_drift.py](../../experiments/bfv_search_lab/quadratic_drift.py) implements
signed Kronecker convolution, the involution, moment powers, integer roots,
box controls, canonical rounding and a complete public subrelation verifier.
The packing base exceeds twice the full integer coefficient bound; carries
and signs are recovered before negacyclic folding. No modular reduction or
floating FFT participates in an accepted bound.

Owner-approved originals pin q, target modulus, C0/C1/C2, public support,
context/key/epoch and a drift budget. The receiver checks types and framing,
recomputes all roundings, products and roots, and compares the complete
certificate before an opaque callback. The context hash identifies this
approved public input; it does not authenticate where an encrypted score came
from. The callback is **not decryption authorization**. Original-score/query
binding, actual key basis and support, source phase noise, PBS, output IDs and
malicious-server release security still need their complete matching protocol.

## Independent finite checks

| Check | Retained cases |
|---|---:|
| Entire small signed polynomial pairs against schoolbook convolution | 6,642 |
| Entire small all-k H_k/Gram equalities | 342 |
| Dense-matrix traces against integer polynomial traces | 360 |
| All-prefix/all-ternary-secret/all-coefficient bound inequalities | 39,096 |
| Whole tiny rounding phase and total-bound coefficient cases | 17,496 |
| Single-cell/framing corruptions rejected before callback | 56 |

Thirty-one scoped tests pass. A fresh local homemade BGV product (N8, t17,
q4294967291, eta1) is unit-converted, rounded to 2^64, and checked at all eight
coefficients against the GMP decryption path and literal integer drift. The
public phase and all-secret rounding bounds suffice for that **toy trusted
fixture**. No production/PBS/security conclusion follows.

Negative controls preserve three important failures. Cropping H_0 to the
prefix loses the full orbit identity: d2=X, D=1 gives cropped H_0=0 and
cropped H_1=1, so a zero bound cannot cover every output. A wrong involution
or modularly reduced trace invalidates the certificate. For N2 and d2=(1,1),
the fourth-moment trace is 8; a floor fourth root of 1 is not an upper bound.

## Synthetic geometry cards and paid limitations

The runner produces 96 cards: eight retained E72 profiles, PBS degrees
2048/8192, public prefixes 512/full N and three seeded public input shapes.
These are **not encrypted search workloads**. Combining their drift with an
E72 input phase bound is a conditional model premise, not an established
noise bound for these synthetic component arrays.

| Public input shape | Secret support | Cards | Moment improves strong box | Box-total / chosen-total bound |
|---|---|---:|---:|---:|
| Uniform seeded | Prefix512 | 16 | 14 | 1.00–3.58× |
| Uniform seeded | Full N | 16 | 16 | 12.24–32.98× |
| Coherent | Prefix512 | 16 | 0 | 1.00× |
| Coherent | Full N | 16 | 16 | 1.50× |
| Monomial | Prefix512 | 16 | 0 | 1.00× |
| Monomial | Full N | 16 | 0 | 1.00× |

These ratios measure **bound tightening**, not time, traffic, secure parameter
reduction or a complete-system gain. The moment beats the strong box in 46/96
cards. A floating canonical-norm diagnostic is tighter; the uniform-input
moment/canonical gap is 1.071–1.213×. Floating results are diagnostic only;
a certified Fourier/prefix control and its actual cost are not implemented.

None of the 96 conditional original-q cards passes the specified sufficient
odd-domain lookup margin. This is a failed sufficient model, not an observed
decoding failure or a proof that high-precision/other methods cannot work.
Each moment calculation pays four exact wide-integer polynomial products,
plus two products for the pair-box control; the full verifier repeats them.
The modeled moment body uses variable-width integers, with no implemented
codec or measured RSS. Key switching/relinearization, derived-S-squared PBS
keys, compact authentication, client enrollment/caches and whole elapsed are
unimplemented costs, not zeroes.

## R6 return

Keep the sound derived-secret bound and homemade certificate as company and
research controls. Stop claiming a generic norm bound as a new mechanism.
The next discriminator is [Q18/E92](partial-packed-switch-plan-20261002.md):
can certified precision allow low C2 gadget levels to remain under the
original S-squared, round to a zero mask, and save **paid** switching work?
Its mixed source/target key basis, exact carries and strongest ordinary
truncated-switch/canonical-norm controls must be explicit. Return to the plan
after the first oracle and cost decision. Q6–Q10 and broad assurance remain
conditional; no production source changed.
