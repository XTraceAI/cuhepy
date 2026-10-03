# Q70: a stronger factorized control changes the state tradeoff

The large query matrix in [the initial tensor-seed model](gadget-cut-followups-20261003.md)
is sufficient, not necessary. A separately registered public control groups all
radix cross terms by their power sum and uses shared composite keys. The
[initial registration](gadget-cut-factorization-registration-20261003.json) and
[adaptive sibling-fusion refinement](gadget-cut-factorization-fused-registration-20261003.json)
retain both executions and their exact source archives. The refinement repeats
the same inputs; the counts below are not added across executions.

The final bounded control passes 32 public trials at N8/N16, including the fixed
Q120 modulus with 14/18-bit digits: 6,400 common integer seed coefficients agree
exactly with the direct reference, and 1,792 unary/binary correction coefficients
agree with the independent schoolbook modular oracle. Both source norms satisfy
the same public bounds. The off-diagonal negative control exposes the invalid
shortcut of retaining only equal digit indices. No fresh HE key was generated;
these arbitrary public coefficients test the algebra rather than encryption
security or another independent encrypted cohort.

Code: [factorization](../../experiments/bfv_search_lab/tensor_gadget_factorization.py),
[tests](../../experiments/bfv_search_lab/test_tensor_gadget_factorization.py),
[registered runner](../../benchmarks/tensor_gadget_factorization_lab.py).
Raw evidence: `../research-data/gadget-cut-research-20261003/Q70-factorization/`
and `Q70-factorization-fused/`. The first per-tile model remains a valid sufficient
control; sibling fusion gives a stronger cost/state model for full groups.

## Exact control and its origin

Let `gamma[r,j]` be the common canonical radix digits of `B^r mod Q`. Write the
query and each index ciphertext component in radix B. For the first rotation g,
combine the left/right index **digits** before multiplying shared query digits:

`q'_alpha,a = sigma_g(dq_alpha[a])`

`I'_alpha,b = sigma_g(M_product*(dI_left,alpha[b] - X^shift*dI_right,alpha[b]))`

`T_r = sum_(a+b=r),alpha q'_alpha,a * I'_(1-alpha),b`.

Absent right inputs are zero. All these are signed common integer polynomials;
canonicalizing the combined family would change the chosen lift. Define shared
public composite keys

`L_r,k = sum_j gamma[r,j]*K_rotation[j,k]`

`R_c,k = sum_j sigma_g(digits_B(K_relin_A[c])[j])*K_rotation[j,k]`.

With the same shifted/automorphed C2 digit family `D'_c`, the switching correction
is `S_k = sum_r T_r*L_r,k + sum_c D'_c*R_c,k` modulo Q. Distributivity proves this
equals switching with the original bounded tensor seed. It changes neither
that common lift nor its noise proof, fixed modulus, trace cuts or complete
terminal output. C0, plus inputs and later maintenance are still required.

This is ordinary convolution in the digit variable, followed by known public
external-product composition. [Belorgey et al.2023/771, §3 and §3.1](https://eprint.iacr.org/2023/771.pdf)
already develop bivariate representations and precomputed external products;
[Kim et al.2022/347](https://eprint.iacr.org/2022/347.pdf) provides the bounded
homomorphic-gadget control. Their settings/theorems are not transferred unchanged
to this exact Q120 relation. This implementation is our explicit adaptation,
not a reproduction of their artifacts. The tensor identity, power-sum grouping
and composite-key compression are **not new primitives**. E110 stays closed.

## Priced alternatives at tensor18

These are sufficient two-prime uint64 RNS models for the **first correction**,
not measured peak memory or complete server/checker costs. The small reference
uses Python integer polynomials; the large RNS implementation is unbuilt.

| Resource | 8,192 vectors | 32,768 vectors |
| --- | ---: | ---: |
| Full source + terminal-Q verification body, unchanged tensor18 model | 120.234375 MiB | 360.46875 MiB |
| Expanded public query matrix, RNS body | 1.75 GiB | 3.5 GiB |
| Cached combined first-node index digit families | 0.875 GiB | 1.75 GiB |
| Shared 34 L/R polynomials | 8.5 MiB | 8.5 MiB |
| Shared query digit family | 3.5 MiB | 3.5 MiB |
| Streamed two-index digit buffer, before scratch | 7 MiB | 7 MiB |
| Factorized correction word multiplications per query, both primes | 1,107,296,256 | 2,214,592,512 |
| Expanded matrix correction word multiplications per query, both primes | 301,989,888 | 603,979,776 |
| First-family setup forward prime NTTs | 7,168 | 14,336 |
| Original index polynomials requiring canonical decomposition | 512 | 2,048 |

The factorized correction does about 3.67 times the modeled word multiplication
work of the expanded online correction. It trades that work for state; this is
not a predicted latency ratio. Streaming additionally repeats index decomposition
and first-family preparation each query. Cached preparation pays those costs at
enrollment/update. Shared L setup uses 5,963,776 word multiply-accumulates; R setup
uses 56 ring-product equivalents. All controls pay this preparation. One fixed-
position tile replacement affects one first-node family; authenticated updates,
its partner access and actual replacement costs remain unimplemented.

Original ciphertexts/keys, C0/C2 tensor/relinearization and plus work, index CRT,
all transforms/permutations, later rotations, verification state, terminal
conversion, allocations/scratch, update authentication and lifecycle costs are
additional. A digit-variable FFT is another known bivariate control, not run
here. The earlier packed-Q matrix figures (1.64/3.28 GiB) and current RNS figures
(1.75/3.5 GiB) describe different representations; neither is a lower bound.
Client reply lengths do not change. This body model is not the historical
product-only traffic with a trusted suffix.

## Return to the plan

Q70's factorized known-control component is complete. It prevents a premature
rejection based on a huge matrix and prevents manufacturing originality from
that matrix's compression. It does **not** finish the full algorithm/prior-work
gate. The verification-aware semantic cut policy remains an unexcluded systems
hypothesis, with no accepted original main result or measured service gain.

The next bounded discriminator must specify an actual noise-budgeted cut planner:
its complete legal rewrite grammar, public common-lift induction, objective and
setup/state/update prices, compared with an equally specialized generic planner
and the published gadget/relaxed-maintenance adaptations. A finite exhaustive
small-graph oracle can check a claimed algorithmic guarantee. Search over known
rules alone is an engineering control; a paper needs a useful new verification
boundary, theorem, or system result beyond renaming it. Only a surviving declared
distinction activates Q71 complete native admission and Q72 matched lifecycle
measurements. The allowed plaintext cache remains a mandatory usefulness control.
