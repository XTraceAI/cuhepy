# Q17/E91: orbit-aware deterministic quadratic drift certificate

2026-10-02. **Proposed before implementation/retained results.** E90 exact
carry/grid controls survive; generic hoisting supplies the same reuse.
This is a finite creative bound/certificate screen, not an approved protocol.

## Candidate consequence and proof to falsify

Direct one-product BGV has components under (1,S,S-squared). Rounding-error
numerator polynomials are public d0,d1,d2 with a common positive denominator.
For a ternary S in an owner-approved public prefix of length D, test a
deterministic bound on **all** coefficients of

`d0 + d1*S + d2*S-squared`.

The coefficient-k quadratic matrix H_k(d2) is signed negahankel. Proposed:
H_k is symmetric and H_k squared equals C(d2) C(d2) transpose, independently
of k, where C is the negacyclic multiplication matrix. Therefore

```
abs(coefficient_k(d2*S-squared)) <= D * ||C(d2)||_2
||C(d2)||_2^(2p) <= tr((C C^T)^p)
tr((C C^T)^p) = N * coefficient_0((d2*d2-star)^p).
```

Use p=1,2,4,8, exact integer convolution and upward integer roots. All ring
products remain over Z; no modular reduction or unchecked floating root.
One trace-power certificate can cover all output coefficients without an
independence/Gaussian/key-posterior assumption. Prefix-cropped H_k matrices
may break invariance; do not reuse a crop-zero certificate for every k.

Combine with exact maximum prefix-window L1 for d1 and a strong coefficient
box control counting every prefix pair for d2. Use the minimum of valid
bounds; the moment method need not win for small D or structured adversarial
masks. Price full original rounding binding and exact polynomial traces.

## Strongest controls and originality criterion

Bernard/Joye/Smart/Walter public exact drift/rerandomization is prior work.
Known canonical embedding gives the exact convolution spectral norm; the
moment bound cannot beat that mathematical norm. Compare it explicitly,
with floating FFT as a **diagnostic only**, and leave certified interval-FFT
implementation/cost open. General PSD/Schatten/norm methods are known.
The possible contribution is a complete cheaply authenticated dependent-secret
bound with a useful cost/parameter consequence; a known norm application
or boxed-versus-spectral improvement alone does not select Q6.

Targeted dependency-noise review must precede any probabilistic claim.
Known private-M/EMVP/proof/caches, packed partial-key/relin controls and the
actual S-squared auxiliary-key cost remain mandatory. Noise certification
does not prove correct encrypted scores or authorize arbitrary decryption.

## Finite execution and returns

1. Independently exhaust small polynomial/ternary-secret spaces, all k and
   prefixes. Compare literal squared-secret products, dense matrices and
   integer trace powers. Preserve wrong-star/sign/normalization, modular-
   overflow, cropped-orbit and floor-root counterexamples.
2. Instantiate a full public rounding-and-moment verifier against owner-
   approved originals. No secret witness; false products, inputs, roots,
   epochs or thresholds reject before callback. State what upstream binding
   and input/key-noise bound are still assumed.
3. Exact/count cards at N2048/N16384, D512/full, actual original modeled Q,
   scaled endpoints and contrasting random/structured public inputs. Do not
   infer ciphertext uniformity, whole speed or secure parameters from them.
4. Return to R6 after every component. Keep any sound useful bound and stop
   generic norm novelty claims. Advance only a new complete authenticated
   step and useful effect; otherwise specify the next finite discriminator.
