# E53: a conditional obstruction to public-seed correlation compression

2026-09-30. [Tiny defensive oracle](../../experiments/bfv_search_lab/seed_composition_oracle.py)
and [regressions](../../experiments/bfv_search_lab/test_seed_composition_oracle.py).
This strengthens the E49 one-column negative control. It does **not** break the
implemented factory, which keeps its zero seed private, or the underlying HE.
It is an algebraic constraint on a hypothetical optimization, not a novelty
claim or a complete protocol proof.

## Statement and argument

Let Q be prime and let `A1` be the public matrix mapping actual centered CRT
coefficients `alpha(r)` to all C1 output coefficients of the authorized index.
Suppose a correlation factory publishes

```text
Y1 = A1 * alpha(r) + a0             (mod Q)
delta = w - r                      (mod t),
```

and also publishes a seed from which a0 can be computed. If A1 has full column
rank, the public transcript determines alpha(r), r and w.

Subtract a0 and solve the overdetermined system over F_Q. Full column rank
gives a unique alpha residue vector. Its honest coefficients lie in
`[-floor(t/2), floor(t/2)]` with t<Q, so centering lifts them unambiguously.
Reduce them modulo t, expand each column in its **actual** `X^(N/degree_j)`
subring, and decode the public CRT components. Those polynomials are constants;
their constant coefficients are the per-map masked coordinates. Replicated or
shared form identifiers give the same r in each occurrence. Then `delta+r`
recovers w modulo t. Raw binary sign weights recover the query bits exactly.

No secret HE key, private map, guessed error or cryptanalytic assumption is
used in this argument. Its full-rank condition is explicit. Rank deficiency
does not establish privacy: projections may still leak, and the structured
bounded CRT input can impose further constraints. This oracle does not assess
all such cases or prove a full-rank probability for real parameter profiles.

## Executed controls and oracle correction

Two own N=32/t=17 toy contexts exercise all sixteen four-bit queries, with two
encrypted columns and two distinct two-coordinate map pads. One context has
four CRT leaves whose equal-form pairs collapse each column to degree two.
The recovery routine receives only index, public key/context, answer, delta
and deliberately exposed zero seeds. A test-only spy captures those seeds to
simulate the proposed unsafe serialization; the genuine Factory API releases
full coefficients and no zero seed. All four query coordinates are recovered.
Duplicate columns are rejected for insufficient rank; an inconsistent
overdetermined field system is rejected instead of inventing a mask.

While checking this composition, the E47 literal matrix oracle was found to
use the final cover's minimum leaf degree for every shift. Shared columns
may lie in a smaller subring. The correct spacing is `N/column_degree`, matching
`crt_query_space.expand` and the native evaluator. The research oracle is
corrected, with an exhaustive 17²-input regression against independent
schoolbook ring products. Earlier E47 tests covered full-degree/scalar cases
but missed this intermediate collapsed degree. Production encrypted arithmetic
and the existing response gate were unaffected.

## Consequence for the research plan

E48's public recipe can reconstruct the C1 of a **fresh plaintext-encrypted**
correlation. E49's rerandomized encrypted-index correlation has a different
dependence on r. Publishing its rerandomizer seed to reuse the same recipe is
therefore invalid under the condition above. Ciphertext representations that
look identical in byte counts can have incompatible privacy semantics.

A client-only private reconstruction recipe is a separate proposal: it would
need confidential/authentic provisioning, one-use state, charged client work
and a reviewed simulation. Keeping the zero seed private is necessary for this
attack boundary; it is not sufficient production assurance by itself.
Preserve this negative oracle in P07/P10/P12, retain the complete pre-decryption
checker, and audit closest work before naming it a new contribution.
