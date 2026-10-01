# E81: bounded global aliases preserve exact BGV; bounds and RNS links matter

2026-10-01. [Preregistration](admissible-trace-preregistration-20261001.md),
[raw](../../benchmarks/results/publication-admissible-trace-screen-20261001.json),
homemade [oracle](../../experiments/bfv_search_lab/admissible_trace_oracle.py),
[test](../../experiments/bfv_search_lab/test_admissible_trace_oracle.py) and
[runner](../../benchmarks/admissible_trace_lab.py). Source `e1883a2`.
Production acceptance/decoder code remains unchanged.

**Return decision:** retain the exact bounded-trace lemma and adversarial
controls as a potential proof-frontend building block. This is a known-method
adapter, not an original complete protocol or measured proof speedup. Return
to [the current R6 decision](construction-selection-20261001.md) after the
completed E79 first-release observations; no paper winner is selected.

## Conditional exactness argument

Assume owner-generated index/query ciphertexts satisfy their pinned public
phase bounds, and approved switching keys satisfy

```
b_j + a_j*s = B^j*s_target + t*e_j (mod Q),  ||e_j||inf <= eta.
```

Admit globally shared integer digit polynomials with `0 <= d_j < B` and
`sum B^j*d_j = c (mod Q)`. They may recompose to c+Q, c+2Q, etc as integers;
uniqueness/canonical integer representation is not required for this lemma.
After switching, cancellation of the key-A terms gives the intended phase plus
`t*sum d_j*e_j (mod Q)`. Negacyclic convolution obeys

```
||t*sum d_j*e_j||inf <= t*N*ell*(B-1)*eta.
```

This is the **same worst-case bound as canonical unsigned digits at the same
base/key parameters**. An automorphism or monomial is a signed permutation;
a plus/minus expansion branch doubles its input bound and adds switch error.
Thus a factor-H expansion has bound `H*B_fresh+(H-1)*B_switch`. Multiplication
by each approved index ciphertext contributes at most
`N*B_index*B_expanded`; sum every column and check every full output. If the
complete bound is strictly below Q/2, centering modulo Q recovers that bounded
integer phase, so reducing modulo t yields the intended plaintext. With t>d
and the approved score/ID decoder this is the exact Hamming result.

This argument quantifies over **every** boxed globally recomposing witness;
it does not use an observed secret-noise diagnostic to decide acceptance.
Key-generation laws, valid original input, every circuit branch/component,
projection and public no-wrap inequality are premises. It covers this shallow
switch/expansion/product circuit, not rescaling, arbitrary leveled computation,
malicious owner keys or unlinked RNS witnesses. It is an explicit conditional
argument awaiting independent proof review, not parameter/security certification.

## Executed controls

- **62,208 scalar algebra cases:** three ternary secrets, all81 bounded
  switching-error tuples, all256 boxed gadgets at Q97/t3/base4. Fixed public
  A terms cancel symbolically. **38,637** are noncanonical integer aliases.
  Every integer phase and exact decode agrees. N1 is an algebra fixture, not
  an RLWE security parameter.
- **112 canonical +336 alternative encrypted searches** on all seven existing
  layouts. At digit_bits5 the gadget capacity exceeds Q enough to exercise
  aliases. Maximum representative, alternating and maximum digit-sum policies
  choose witnesses without private key/error information. All336 full outputs
  differ from the canonical outputs; all scores/IDs/top-3 remain exact.
  There are1,008 noncanonical switch witnesses. Both canonical and admitted
  cases use the same keys/Q/public output bound1,133,580,800. Private phase
  diagnostics occur only after the public relation; observed maxima are below
  2.92million but do not replace the universal bound.
- Canonical E78 checking rejects these traces, while the bounded E81 relation
  admits them. This clarifies E78's x+Q negative: modular equality is inadequate
  for a **canonical** relation, but a different bounded relation can be correct.
- Unbounded carry `(34,-5,1,0)` still recomposes exactly to30 at base4, but
  switching at Q97/t3 changes message1 to0. Omitting bounds loses exactness.
- Separately valid limb digits `(1,3,0,0)` at q13 and `(1,0,1,0)` at q17 both
  recompose to0 in their own fields. Their switched error CRT phase is-79,
  decoding to2 instead of0. They are not one global gadget over Q221.
  Per-limb range/recomposition checks alone do not supply the global bound.

Fourteen scoped tests and three explicit Ruff paths pass. Wrong bounds,
recomposition, partial output and context fail before private diagnostics.
The checker still recomputes public work; there is **no** succinct proof/PCS,
approved reusable release service or private timing guarantee.

## Cost and closest-work decision

Eight equal-base retained-profile models are counted. The selected legacy
Mushroom/Semeion models use7,618,560 digit coefficients and38,092,800 simple
digit-range bits at base32; both need507,904 modular recomposition equations.
The relaxation can remove507,904 canonical less-than-Q comparisons. It retains
digit-box, modular arithmetic, all keys and full output/response work. No
Q/key/wire increase is required **relative to canonical base32**, not relative
to E78's different base16 profiles. No proof bytes/time/complete gain is measured.

The direct prior control is
[Cascudo et al., ring/range vHE](https://eprint.iacr.org/2025/286), §§3.4/4.1
and Appendix B, pinned in the [registry](publication-literature-sources.json).
It already permits relaxed maintenance decompositions and explicitly discusses
BFV/BGV extensions. The current archive revision notes a corrected Theorem4.8;
use the pinned revised source, not an older theorem silently. Specialized
controls may already omit/share the comparator. An ordinary exact-BGV port
does not establish novelty.

The interesting next question is whether a **specific new semantic proof
representation** uses this admissible family to remove enough complete work
beyond those specialized controls. It must prove the actual bounded relation,
not only return a correct-looking score, and pay commitments/ranges/setup/
release/feedback. Accepted traces must decode to the authorized ideal result
before privacy hybrids are argued. Variable-time decryption, durability,
parameters and related-key/seed assumptions remain separate obligations.
