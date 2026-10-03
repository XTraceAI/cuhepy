# Q65: one propagation is noise-safe; savings are geometry-specific

**Current refinement:** the v1 per-sibling product count below is superseded by
the separately registered stronger control at
`../research-data/gadget-cut-research-20261003/Q65-refined/`. Combine sibling
terms before applying the two public key families. This adds1,024 key ring
products rather than3,072 at8k. Its cached-NTT implementation also charges
sibling monomial multiplications; see the native prototype report. The repeated
24 public trials verify the refinement but are not additional independent
samples. The original raw ledger and exact executed-source archive remain
preserved; the guard and source-body conclusions are unchanged.

The registered public oracle completed 24 trials over N8/N16: 96 switching
relations (1,152 coefficients) and 576 fused-correction coefficients agree with
the independent schoolbook modular oracle. One, two and three total switch
stages recompose correctly algebraically. This does not imply their noise is
acceptable. Raw output and pre-run source/registration hashes are at
`../research-data/gadget-cut-research-20261003/Q65/`.

At N16384, Q=`0xffffffffffc00020000003bffc0001`, t1031, eta21,
D512, radix2^30/four digits, the following are **public worst-case models**,
not latency measurements or parameter approval. The query bound uses the
existing owner-query phase assumption; the index uses the existing fresh public
encryption bound. The Q66 small-key diagnostic cohort uses ordinary public
encryption and does not measure this large profile.

| Vectors / rule | Full phase-bound bits | Q120 / P25 guards | Removed cuts | Full source + terminal-Q body | Body saving |
| --- | ---: | --- | ---: | ---: | ---: |
| 8,192 canonical | 71 | pass / pass | 0 | 180.234375 MiB | 0 |
| 8,192 one propagation after unary anchor | 115 | pass / pass | 128 | 150.234375 MiB | 30 MiB (16.64%) |
| 8,192 two propagated stages | 161 | fail / fail | 192 | inadmissible | no accepted saving |
| 32,768 canonical or free-anchor policy | 71 | pass / pass | 0 | 480.46875 MiB | 0 |

Fixed P=33,548,413 remains admissible with one propagated stage: its terminal
phase bound is 9,139,176, below P/2. The canonical terminal bound is 8,446,469.
The packed terminal response body remains 102,400 bytes per group. The table's
large bodies describe a **complete source-cut trace** with one canonical Q
polynomial per product/rotation source and two terminal Q polynomials per group.
They are not the old product-only128MiB path, which retains trusted rotation
execution; that path does not gain the modeled 30MiB saving from this rewrite.
Framing, query, enrollment and transport are additional costs.

## Conditional public correctness argument

With common integer source digits of norm L, switching introduces phase error
at most `t*eta*N*ell*L`. This follows from the existing key equation and the
negacyclic product bound; signed digits require the same absolute-norm bound.
A unary canonical anchor has digit bound `L0=B-1`. Decomposing public key-A
columns gives the deterministic state bound `L0*F`, where
`F=1+ell*N*(B-1)`. A following binary source has bound `2*L0*F` (unary: `L0*F`).
These assumptions hold for every admitted small source, without observed
private noise or independence of errors.

The existing joint trace support lemma applies to each error polynomial:
`B_final <= D*B_product + sum_j (D/2^(j+1))*max_node(S_j)`.
Inputs include canonical relinearization error. The trace supports of sibling
nodes are disjoint, and the remaining suffix projects onto its trace support;
thus the max, rather than a sum over nodes, is valid at each level. The complete
physical output, including unused coordinates, is bounded. Require
`2*B_final<Q` and
`2*(ceil(P*B_final/Q)+ceil((N+1)*t/2))<P` before terminal reduction.
This is a conditional honest-execution correctness argument, not an RLWE
estimate, reduction for the protected protocol or production approval.

## Complete cost and falsifiers

The initial v1 fused known-method control counted 3,072 **additional** online ring products
in the 8k shape, compared with 6,136 canonical switching products (50.07%
increase in that category). Tensor multiplication and all unchanged work remain
additional. It shares32 setup ring products, eight H polynomials (1.875MiB
packed-Q body), and16 public A-digit polynomials (0.9375MiB packed digit body).
Actual native/RNS layouts and workspace cost more than these packed bodies.
The direct reference instead constructs4,096 extra integer ring products and
materializes large digits. Neither implementation gets free preprocessing.
Removing a cut is not evidence of lower total producer/checker time.

For a full first group, `(left,right)=(X^h*u,u)` and `(0,0)` have the same minus
source0 but different plus source `2*X^h*u`. A minus-only anchor cannot determine
the output C1. A repair needs256 additional plus/input cuts at the first stage,
while saving128 next-stage cuts: a net128 extra cuts per full group. No free
full-group saving is claimed. Componentwise multiplication of radix digits
fails; independent small RNS limbs and unbounded carries remain invalid, as in
E81. A third unnormalized switch stage fails the fixed-profile guard despite
algebraic recomposition. Raising Q or changing P is outside this registration.

**Return to plan:** Q65 is complete. A narrow feasible rule survives correctness
screening, so Q66 proceeds under its already registered four-context cap. Q67
remains conditional: a complete resource tradeoff and a testable systems claim
must justify a native prototype. No originality or performance acceptance yet.
