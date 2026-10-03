# Q69/Q70: tensor seeding removes the full-group information barrier

Latest Q70 component: [power-sum factorization and sibling fusion](gadget-cut-factorization-20261003.md)
give a stronger known control. The large matrix below remains a sufficient
representation; it is not required. Full originality/usefulness gates stay open.

The [registered public follow-up](gadget-cut-followup-registration-20261003.json)
completed24 tiny public trials:864 C1/source/plus coefficients and576 switch
coefficients agree with the independent schoolbook oracle. All scalar radix
cross terms are retained. The fixed screen preserves all24 model cards,
including four failed guards and six full-group canonical fallbacks. Twenty
cards pass, but only14 actually exercise a new policy. This is not20 measured
implementations or evidence that every passing card is useful.

The [separately registered encrypted component](gadget-cut-small-followup-registration-20261003.json)
completed two fresh homemade toy key contexts, four query/context pairs and12
base geometry/query cases. Mixed14 and tensor18 give24 variant comparisons:
488 variant/case distance checks and768 variant/case physical coordinates,
with nested-prefix overlap. Every whole public replay, full-Q plaintext,
terminal plaintext, distance, stable ID and top3 agrees with canonical and
independent truth. Twenty variants have different ciphertext bytes; the four
mixed full-group fallbacks do not. Frame lengths are unchanged. Diagnostic
fixtures retain unused full14/18-bit key sets, so they do not measure optimized
setup. No HE secret or private error coins are retained.

Evidence:
`../research-data/gadget-cut-research-20261003/Q69/` and `Q70-small/`, including
pre-run/pre-key input/registration/source receipts, executed-source archives,
all model/failed-guard cards, public contexts, complete responses and traces.

## Two precise mechanisms and models

Keep N16384/Q120/P25/t1031/eta21/D512 and the same owner-query/public-index
phase assumptions as Q65. Product relinearization and later rotations remain
30-bit. The table is a **complete source-cut/body and sufficient-state model**;
it is not measured traffic, a proof implementation or client response savings.

| Rule | Vectors | Removed source cuts | Source + terminal-Q body | Reduction | Extra selected key body | Sufficient compiled query-matrix body |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Canonical | 8,192 | 0 | 180.234375MiB | 0 | 0 | — |
| Mixed14, two stages after unary anchor | 8,192 | 192 | 135.234375MiB | 24.97% | 7.03125MiB | not modeled here |
| Tensor18 seed, first rotation | 8,192 | 256 | 120.234375MiB | 33.29% | 1.40625MiB | 1.640625GiB |
| Canonical / mixed free-anchor fallback | 32,768 | 0 | 480.46875MiB | 0 | mixed keys still charged | — |
| Tensor18 seed, first rotation | 32,768 | 512 | 360.46875MiB | 24.98% | 1.40625MiB | 3.28125GiB |

Mixed14's early rotation block uses nine digits rather than four. Its full
phase bound has116 bits and terminal bound10,418,701 at8k, so the existing
Q/P guards pass. It has more key columns and work; a native implementation and
complete producer/checker/preprocessing cost are not available. It is not a
latency winner selected from the screen.

Tensor18 uses seven digits only for the first rotation. Full phase bounds have
113/114 bits at8k/32k and terminal bounds8,581,544/8,716,620. The public matrix
bodies in the table become1.75/3.5GiB as two-prime uint64 RNS words, before
additional state and scratch. They are one sufficient representation, not a
required-state lower bound. Matrix-free/generic controls get the same factor-
ization opportunities. Setup and update work must be measured; compiling a
large public matrix is not free or automatically preferable to direct work.

## Common tensor seed equation and conditional correctness

Let query/index components have common radix digits
`q_alpha=sum_a B^a*dq_alpha[a]` and `I_beta=sum_b B^b*dI_beta[b]` modulo Q.
For each public scalar power, choose canonical small digits
`B^(a+b) mod Q=sum_j B^j*gamma[a,b,j]`. Then

`E_j = sum_alpha,a,b gamma[a,b,j]*(dq_alpha[a]*dI_(1-alpha)[b])
       + sum_c dC2_30[c]*digits_B(K_relin_A[c])[j]`.

All products are in the **integer** negacyclic ring. `G*E` recomposes to tensor
C1 plus the ordinary30-bit relinearization-A correction modulo Q. No secret
is used: query/index C0/C1 are public **ciphertext** components. Public input
digits bound the seed by

`L_seed = 2*N*(B-1)^2*max_j sum_a,b gamma[a,b,j]
          + N*ell30*(2^30-1)*(B-1)`.

Shift E with the product. Both plus and minus now have a common integer
representation before a binary merge, removing the minus-only information
barrier. Its first rotated source is bounded by `L_seed` for unary nodes or
`2*L_seed` for binary nodes. Apply the same conditional key-error/support/Q/P
induction as Q65. Reset later sources to canonical30-bit digits. This does not
justify unbounded carries, independent limb lifts or using private observed
noise to relax a guard.

For tensor18 at8k, direct seed construction costs25,088 query/index and7,168
relinearization-A integer convolutions. The compiled control instead uses
28 query-matrix and eight relin-matrix convolution equivalents per first output
node, plus its charged setup/state, monomial factors and unchanged work. Large
matrix traffic could erase the tape saving. Both implementations are known
gadget/public compilation controls; their speed has not been measured.

## Originality discriminator and precise next gate

[Kim et al.2022/347](https://eprint.iacr.org/2022/347.pdf) already use bounded
valid gadget replacements; the RNS componentwise product requires idempotent
gadgets. Radix cross-term expansion is ordinary algebra, not a new primitive.
[Fernàndez-València2023/365](https://eprint.iacr.org/2023/365.pdf), introduction
and§2.4, already combines homomorphic gadgets with verifiable multigroup HE.
That rules out any claim that gadget-aware verification itself is new. Its
RNS gadget/replication setting is not our implemented native first-source
relation; no security/performance theorem is transferred. The fourth new paper
is archived with PDF/text hashes and inspected page5. No artifact was run.

[Cascudo et al.2025/286](https://eprint.iacr.org/2025/286.pdf), revised§3.4,
already relaxes maintenance relations with controlled added noise. Its stated
key-switch range relaxation is limited to twice the relevant prime scale. Our
derived common lifts can exceed a single RNS prime; that demands the explicit
global derivation and norm proof, rather than borrowing its theorem unchanged.
Its ring/range proof backend and generic affine compilation remain strong
adaptation controls. These targeted passages do not establish paper novelty.

**Current return:** Q69 public algebra/model acceptance is met; Q70's bounded
encrypted-correctness component is met. The full Q70 algorithm/prior-work gate
is **open**. Before Q71, compare a noise-aware, mixed-key cut scheduler with
equally specialized homomorphic-gadget/relaxed-ring/generic matrix-free methods,
including E110 functional-orbit controls, under the same Q, input/output,
key-origin, full relation and setup/state/update prices. Require an actual
algorithm or systems distinction and a useful declared resource frontier. A
generic control must not be denied our public equations, nor should a new
schedule be dismissed merely by allowing an unpublished adapter without
identifying the established construction and its actual costs.

If that gate survives, implement one complete native admission relation with
per-stage key bases, immutable original query/snapshot/epoch, common digit
derivations, complete terminal bytes and fresh hidden checks. Then register a
matched full-service pilot, including canonical replay and allowed cache
controls. No production integration or large timing grid precedes those gates.
