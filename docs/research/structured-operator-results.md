# E68: exact structured operator and bounded-digit screen

2026-09-30. Executed R3 subcomponent of the
[research plan](publication-research-plan.md), not an outer vLHE protocol.
Homemade [oracle](../../experiments/bfv_search_lab/structured_operator_oracle.py),
[tests](../../experiments/bfv_search_lab/test_structured_operator_oracle.py),
[runner](../../benchmarks/structured_operator_lab.py) and
[raw](../../benchmarks/results/publication-structured-operator-screen-20260930.json).
The raw pins source/input hashes and source HEAD `35e76fc`.

## Hypothesis and exact relation

The public encrypted columns generate a matrix D of signed negacyclic shifts.
Its W columns are the actual coefficients of the query forms; its L=2RN rows
are the two complete ciphertext components of R replies. D operates in the
inner ciphertext field F_Q, **not** the score field F_t. Retaining F encrypted
column generators uses 2RNF coefficients rather than 2RNW literal entries.
This is ordinary convolution structure, already anticipated by E47 and the
closest-work compilation results; it is not a new cryptographic technique.

The independent references compare literal matrix multiplication, schoolbook
ring multiplication, implicit forward products, convolution adjoints, balanced
integer digit products and reconstruction modulo Q. Projection keeps all C1
and exactly the certified C0 coordinates. Its check uses the zero-extended
adjoint P^T beta; selected-phase decryption is exercised only after an **ideal
exact equality gate**, explicitly standing in for the unimplemented outer
verification protocol. This test does not solve registration or safe release.

## Executed discriminators

- N=8/16/32, mixed and collapsed correction degrees: 40 binary queries match
  every full ciphertext coefficient and every decoded field score.
- Adjoint dot products and supported projection match independent literal
  references; signed wrapped shifts and nonzero other CRT components are
  retained. Every tested digit reconstruction matches the full-Q result.
- Exhaustive signed digit endpoints/ties avoid an artificial leading carry.
  A Q=97, base-4 example shows that small digit entries alone do not justify
  outer reduction: p=17 wraps evaluated products and changes the answer.
- A deterministic full-rank example and all 40 toy queries recover private
  forms when their full result is made public. A public mask image plus a
  public difference likewise recovers the query. These are controls against
  that proposed transcript, not attacks on a private vLHE construction.
  Rank deficiency alone is not a privacy argument.

The combined scoped validation includes nine operator tests and four existing
backend/carry tests. The separate validation receipt records the complete
51-test selection used in this execution tranche.

## Digit response bound on retained geometries

For base B, let J be the digit count. The optimistic body contains J*L integer
outputs, each using enough bits for signed reconstruction of a product bounded
by W*(B/2)*a_max. This counts **no outer ciphertext, proof, setup or private
state**. It is not a cryptographic parameter selection. The best of bases
4,16,256,4096,65536 in the retained eight profiles is:

| Profile | Inner Q bits | Best base | Digits J | Minimum integer output bits | Digit / full inner body |
|---|---:|---:|---:|---:|---:|
| Mushroom baseline t=1153 | 40 | 65536 | 3 | 36 | 2.700× |
| Mushroom same-field reduction | 35 | 4096 | 3 | 32 | 2.743× |
| Mushroom selected t=193 | 32 | 65536 | 2 | 33 | 2.063× |
| Semeion baseline t=1153 | 40 | 65536 | 3 | 36 | 2.700× |
| Semeion same-field reduction | 36 | 4096 | 3 | 32 | 2.667× |
| Semeion selected t=257 | 32 | 65536 | 2 | 34 | 2.125× |
| Connect-4 global raw | 32 | 65536 | 2 | 30 | 1.875× |
| Connect-4 global affine | 32 | 65536 | 2 | 29 | 1.813× |

These are count screens using old pinned geometry inputs, not new full-size
encrypted runs or measured latency. Literal expansion is still 32–64× on the
Mushroom/Semeion profiles. No full-size dense matrix was allocated.

## Return to the plan

**Stop this elementary integer-digit wire encoding.** Even its optimistic body
is 1.81–2.74× the original. This does not rule out terminal LHE compression or
another digit protocol; those must pay their own reconstruction and security
costs. Do not equate digit norms with the larger admissible/extracted database
norm in a malicious vLHE proof.

**The next subcomponent was executed:** [distinct-field H/Z registration](structured-registration-results.md)
preserves these linear identities but rejects universal per-limb packing
factorization. Its count ledger includes the known bounded-norm packing
control. Continue with a genuine carry-aware construction or E70's bounded
public-arithmetic proof screen; fast multiplication does not make the whole
outer protocol implicit. No acceleration or new protocol promotion is justified
yet. The [construction cards](protocol-baseline-cards.md) assign those premises.

Reproduce the executed screen:

```bash
.venv/bin/python benchmarks/structured_operator_lab.py \
  --json-out /tmp/e68-structured-new-run.json
```

Use a new output path. The scope remains research arithmetic, with no outer
encryption, reviewed parameters, private timing assurance or production claim.
