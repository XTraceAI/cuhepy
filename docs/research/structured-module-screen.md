# E80: module closure survives; the retained-H fallback is not a system winner

2026-10-01. [Preregistration](structured-module-preregistration-20261001.md),
[raw run](../../benchmarks/results/publication-structured-module-screen-20261001.json).
Source checkpoint `71d276e`; homemade
[implementation](../../experiments/bfv_search_lab/structured_module_oracle.py),
[test](../../experiments/bfv_search_lab/test_structured_module_oracle.py) and
[runner](../../benchmarks/structured_module_lab.py). Production code is unchanged.

**Return decision:** retain the exact module/composition control and its state
tradeoff; stop this literal retained-H fallback as a universal paper candidate.
Return to H2/E78. A different complete release representation may still be
interesting, but no new primitive, parameter approval or speedup is shown.
Subsequent E78/E81/E79 returns are now complete; the
[current selection](construction-selection-20261001.md) proposes E82.

## Exact implementation and evidence

For `m | n_j`, polyphase conversion maps the actual signed inner-Q operator to
`D_m in S_q^(L/m x W/m)`, with `S_q=Z_q[Y]/(Y^m+1)`. Gather maps preserve every
coefficient without padding. Negacyclic signs and the coefficient-dot adjoint
involution `Y -> Y^-1` are retained.

The run checks **54 configurations / 768 independent signed-matrix basis
columns** at N=8/16/32, mixed/uniform degrees, m=1/2/4/8 and one/two replies.
Forward, adjoint, all CRS shifts of H and Z identities agree. Partial coset
projection, incompatible m, D+Q lift aliases and illegal digit factoring are
negative controls. Tiny binary challenges confirm only the fixed-error bound;
m coefficients are not m independent soundness repetitions. Scoped tests:
**91 passed** (74 E80, 17 existing E68). Three explicit Ruff paths pass.

The paid owner-generated retained-H transcript is instantiated as a fixture:

```
u = A_m*s + e + floor(q/Q)*x (mod q)
y = D_m*u
check Z_m*u = C*y
then remove H_m*s, recover D*x mod Q, then decrypt the inner BGV ciphertext
```

**112 encrypted searches** cover all seven existing decoder cases, mixed CRT
layouts, multiple replies, duplicate vectors, stable-ID ties and an empty group.
Nonzero bounded outer errors are explicit fixture inputs. Both recovered
ciphertext components match the independent inner operator before decryption;
every score/ID/top-3 matches plaintext. Malformed, tampered and wrong-context
responses retire the registration before outer secret arithmetic. The receiver
has A/H/C/Z, not D/index/inner key; the server receives no private registration.

## Recovery and security boundary

For `p=Q`, `Delta=floor(q/p)`, and integer `D*x=p*k+r` with centered r, the
centered phase after mask removal is

```
Delta*r + D*e - (q mod p)*k.
```

The conservative residual must be strictly below `Delta/2`; recovery centers
modulo q and rounds by Delta. It does not use `round(p*phase/q)` with a bound
for a different rule. A negative test finds prime q passing the noise-only
inequality but failing the complete remainder bound. Signed boundary inputs pass.

Enrollment is owner-built and privately provisions C/Z in the model. The local
constructor/hash is **not** remote authentication. Public context never hashes
plaintext IDs or private checker material. Reject retires C/Z and pending queries;
refresh is charged. Successful adaptive reuse, durable rollback/concurrency,
module-LWE privacy, samplers, inner/outer parameters and private timing remain
unproved. Honest recovery does not establish them. Server-built registration
adds extraction/SIS obligations not established here.

## Complete count screen

All eight E68 geometries plus two strong E76 scalar geometries are counted.
Outer dimension2048/kappa128 are **count assumptions, not equal approved
security**. Candidate primes guarantee the stated correctness bound at eta1;
a justified noise distribution may cost more. Bodies use exact bit widths.
No timing is inferred.

| Profile | m | Outer bits | Scalar outer registration MiB | Module registration MiB | Upload B | Outer reply B | Inner reply B |
|---|---:|---:|---:|---:|---:|---:|---:|
| Mushroom selected legacy |32|81|669.61|21.68|10,368|331,776|131,072|
| Semeion selected legacy |64|82|687.15|11.77|15,088|335,872|131,072|
| Connect4 global affine |1|77|1,234.62|1,234.62|790|630,784|262,144|
| Mushroom strong E76 global affine |1|78|313.94|313.94|829|159,744|65,536|
| Semeion strong E76 global raw |1|80|85.25|85.25|2,560|40,960|16,384|

Registration includes material A/H, binary C, bounded signed Z, inner public
key and ternary secret bodies. Raw fields also list implicit generators,
material module D, ephemeral secret, setup H/Z work, encode/evaluate/check/
release products, recovered ciphertext and rejection refresh. Private maps/IDs,
authentication/framing and metadata remain explicitly **unmeasured**, not zero.
H-prime for a compressed release is **unspecified**; this fallback pays H and
online H*s. No measured system frontier follows.

At equal algebra dimension H's coefficient count falls m-fold and honest Z's
bound falls from `L*B_D` to `(L/m)*B_D`. This shrinks the legacy fallback's
registration about31x/58x, but still retains21.68/11.77 MiB on these datasets.
Every outer response grows **2.41–2.57x** across all ten profiles. Best scalar
layouts have m=1 and no saving. Constant-binary module checks use kappa output
polynomials; their schoolbook input product count grows m-fold over scalar
outer checks. Polynomial acceleration could change compute, not these bytes.

## Originality and next step

Polyphase modules, structured LWE and fingerprints are known. This is an
owner-generated **known-composition control**, not a malicious-digest scalar
theorem transferred into an established module theorem. Compare vReinsPIRe,
small-state vLHE and VeriSimplePIR at the matching trust boundary in the
[closest-work review](contribution-reassessment-20261001.md).

The remaining positive question needs a new complete release/digest step that
avoids this modulus/response/H*s cost on a justified non-scalar workload. That
step is absent. Do not accelerate this fixture yet. Execute E78's composed
relation card, then complete E79 before deployment-frontier claims.
