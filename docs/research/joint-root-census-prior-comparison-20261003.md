# Direct prior for the multiple-root theorem direction

One additional exact primary PDF/text pair is retained in the [literature registry](publication-literature-sources.json).
Generic prescribed multiple-root near-uniformity is already present in prior work;
our next originality question concerns a useful concrete certificate or a
defensible complete-system consequence. No source-parameter applicability or
cryptographic approval follows from this reading.

Primary source: [He–Pham–Xu v2](https://arxiv.org/abs/2201.06156v2).

---

# Exact HPXv2 mathematical reading: known multi-root form, concrete gate open

Date: 2026-10-03. Retained primary: Jimmy He, Huy Tuan Pham, Max Wenqiang Xu,
*Universality for low degree factors of random polynomials over finite fields*,
[arXiv2201.06156v2](https://arxiv.org/pdf/2201.06156v2), version dated
23 February 2022. The exact downloaded PDF is 34 pages, 1,010,482 bytes, SHA256
`4d843340d54cdcbb3c8fd6104d5ebc7669b14afe94946aebf396d09148e7af6b`.
Its first-page arXiv stamp confirms v2. Read-only Poppler extraction and complete
rendered pages 1,11,12,14–18,20,22 were inspected, including the full targeted
Theorem4.1 proof pages and Proposition6.2 statement/proof. External cited lemmas
were not quantitatively re-proved. This is not a whole-paper proof/security audit.

## Direct primary claim and exact source defects

Proposition6.2(2), PDFp20, explicitly bounds the difference between prescribed
joint root/multiplicity probabilities and the uniform comparison by

`exp[-η n/(C d log p log^5(d log p))]`

for high-order roots; its displayed proof repeats the negative exponent.
Definition6.1 on that page gives an order threshold
`C H(K+1)e log p log(H(K+1)e log p)`. Theorem4.1, PDFp14, separately states a
degree-range condition and a Fourier-bound/low-order alternative.

**The sign issue is in the exact PDF, not just HTML conversion.** Theorem4.1
displays a positive exponent on p14. Proof equation(4.2) and its final grouped
bound on p17 also display positive exponents, while intervening characteristic
function bounds on p17 and Proposition6.2/proof on p20 explicitly decay.
The negative Proposition6.2 claim is retained exactly as written; these apparent
source sign errors are not silently repaired or converted into an approved
executable certificate. Its proof's uniform-comparison line also has a
multiplicity-index inconsistency, avoided here by the explicit simple-zero event.

The §3.1 definition on p11 omits “proper” when ranging over affine subspaces.
Lemma3.1 on p12 and §7.1 on p22 explicitly require **proper** affine prime-subfield
subspaces; p22 specializes η to `1-max_x μ(x)` in the prime field. The reading uses
that explicit proper-subspace definition, not the literal all-subspaces maximum.

## Source-graph match that a later certificate must establish

Use the source raw polynomial `f(X)=sum_{j=0}^{N-1}s_j X^j`, with all s_j
independent uniform in {-1,0,1}; do not condition on a unit, a nonzero constant,
or a fixed leading coefficient. The paper's IID degree-at-most-n model on
p1/p11 has n+1 sampled coefficients, so the match is **n=N−1**. Its uniform monic
comparison is distinct from the sampled model. For four distinct nonzero roots
and n>=4, the comparison's specified-divisor probability is p^-4.

Required formal premises are:

- Coefficients lie in the **prime field** for the stronger §4 bound. The raw
  ternary law escapes every proper affine subspace of F_p with η=2/3. This is an
  algebraic law match, not a measured source-parameter probability.
- Four prescribed roots have distinct minimal polynomials/nonconjugacy, each
  generates its stated field, and no derivative conditions are imposed. For
  distinct prime-field roots use H=4, e_i=1, derivative set {0}, K=0 and d=4.
  Repeated roots must not be treated as four independent constraints.
- The selected source prime splits X^N+1 and the selected root is genuinely
  primitive of order 2N. Its distinct odd powers then all have that order. No
  actual root or powers were selected/calculated in this reading.
- Theorem4.1's n/range condition and Definition6.1's **quantitative** order
  condition must hold with appropriate dominating absolute constants. Merely
  calling 2N “high order” proves neither. Do not approve an equality boundary by
  conflating the stated “at least” high-order threshold with the theorem's
  “at most” exceptional alternative.
- Fourier characters with zero coordinates need the reduced-root argument used
  in the Proposition6.2 proof, rather than an all-nonzero-character assertion
  applied indiscriminately. For simple prime-field roots this remains a known
  joint-evaluation method, not independence of the sampled root values.
- If the same raw secret is used across RNS primes, apply an appropriate union
  or separately proved joint bound. Nothing here makes the secret's reductions
  or its NTT evaluations independent. The composite RNS modulus is not itself
  a prime field for invoking this bound.

## Constants and usefulness remain unresolved

Theorem4.1 supplies existential C>0, Definition6.1 asks for a sufficiently large
C, and Proposition6.2 displays C without a numerical assignment. Proposition4.5,
p15, has an explicit local threshold coefficient **200**; it is **not** the final
Theorem4.1/Proposition6.2 constant. The proof pages16–18 additionally depend on an
external large-degree lemma, Dobrowolski/Mahler-measure estimates and a totient
lower bound, and choose constants “large enough.” This inspected proof does not
provide a certified value for the source-profile use. No C was guessed.

No source q60 inequality, Fourier exponent, zero/rank probability, lifetime
union, owner setup, or communication/security consequence was numerically
evaluated. General random-polynomial factor-count asymptotics are not a substitute
for a prescribed four-root event, and the easy corollary's broad prime range is
not the complete range of the stronger targeted proposition.

## Prior separation decision

The **generic near-uniform simultaneous-root theorem form is already known**:
Proposition6.2 explicitly addresses prescribed multiple roots with quantitative
degree/order/error hypotheses. Replacing four scalar bounds by a multivariate
Fourier/recurrence argument, or stating p^-4 plus a mixing error, cannot by itself
serve as the project's original contribution. The exact-source presentation
defects do not erase that clear prior claim.

A responsible later gate is to obtain a coherent, explicit quantitative bound
with source-matched law and constants before assessing concrete usefulness.
If that known theorem already pays the required all-subset/all-limb/enrollment
budget, the result is a supporting known-control application. If it does not,
an original candidate must prove a genuinely stronger concrete certificate or a
different useful verification-aware complete-system frontier, compared against
this same-informed control. A finite census pattern is not such a theorem.
Neither containment beyond the inspected claim nor a genuinely uncontained
improvement has been proved here; no exhaustive novelty search is claimed.

## Acquisition and preservation

The default sandbox acquisition failed DNS and its receipt was preserved. A
separately authorized network retry downloaded the exact public v2 URL; the
network result, PDF SHA/size, extraction and rendered pages are retained in this
fresh cache. The browser-only card and all old E122 99-pair registry/cache/source
cards remain unchanged. A registry-ready source entry is provided separately;
this task does not append or mutate that registry. Downloaded paper content was
never executed, and no tests, kernels, HE operations, or scientific programs ran.
