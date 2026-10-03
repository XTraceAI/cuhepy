# Fixed-prefix correctness: the closer mathematical controls

2026-10-03. Targeted primary-source follow-up to the
[secret-law card](query-secret-law-card-20261003.md) and
[three-paper comparison](seeded-correctness-prior-card-20261003.md).
Five PDF/text pairs are archived under
`WORK/research-data/seeded-correctness-20261003/primary/` with hashes in the
[literature registry](publication-literature-sources.json). Nine complete
mathematical pages were rendered and inspected. This is neither an exhaustive
novelty search nor a complete proof audit; no author implementation was run.

## Direct controls and the remaining question

| Primary source and inspected location | Known consequence / scope | Effect on our claim |
| --- | --- | --- |
| [Lyubashevsky–Seiler, EUROCRYPT2018](https://www.iacr.org/archive/eurocrypt2018/10822333/10822333.pdf), Lemma2.7 and full Lemma3.1 proof, printed pp12–13 | Ideal-lattice norm lower bound in terms of ideal index; noninvertibility gives membership in a vanishing-factor ideal. | The short-vector norm/nullity ingredient is a direct known control, not our theorem novelty. |
| [Attema–Lyubashevsky–Seiler, CRYPTO2020](https://eprint.iacr.org/2020/517.pdf), §3, Lemmas3.1–3.3, pp9–11 | Fourier bounds for NTT residues of IID ternary polynomials, including uniform ternary coefficients. | There is prior analysis of this exact coefficient law. We have not calculated its bound at our large Q or asserted a unit probability. |
| [Farzaliyev–Willemson–Kaasik](https://eprint.iacr.org/2021/1499.pdf), §2.4, p4 | Invertibility/challenge discussion leading to the preceding controls; the discussed challenge probabilities differ from our raw uniform ternary secret law. | Retained discovery lead, not an applicable secret-law estimate or full paper audit. |
| [Skorski, RANDOM2022](https://drops.dagstuhl.de/storage/00lipics/lipics-vol245-approx-random2022/LIPIcs.APPROX-RANDOM.2022.15/LIPIcs.APPROX-RANDOM.2022.15.pdf), Theorem1 and context, pp2–4 | Sharp moment/tail controls assuming every subset of up to k variables is independent. | One fixed jointly uniform prefix is weaker than all-coordinate k-wise independence. Applying that theorem to all N coordinates would require an additional premise we do not have. |
| [Bellare–Rogaway, CCS1993](https://cseweb.ucsd.edu/~mihir/papers/ro.pdf), §1/1.1 | Public random-oracle model, separated from concrete hash instantiation. | The [ideal-XOF transfer](query-mask-rom-correctness-card-20261003.md) is a classical known-model component, not concrete SHAKE assurance. |

For cyclotomic index `m=2N` with power-of-two N, `phi(m)=N` and the
source's `s1(m)=sqrt(N)` cancel in Lemma2.7. Its ideal norm bound
specializes to `||s||_2 >= index(I)^(1/N)`. If s vanishes at k distinct roots
modulo prime Q, the ideal imposing those k vanishing conditions has index Q^k.
The same standard machinery therefore gives

```
Q^k <= ||s||_2^N <= N^(N/2).
```

Our determinant proof is an elementary independent derivation of this known
ingredient. The Vandermonde completion of a fixed prefix and the Chernoff
calculation are also standard ingredients. Do not promote any of them alone
as a new cryptographic construction.

The narrower candidate is a **complete correctness consequence**: a public
fixed uniform prefix for every nonzero supported secret; a pointwise charge
for its dependent suffix; full reused-key maintenance costs; all bounded
common-witness choices after seed publication; and the complete terminal
decoder and lifetime. The inspected pages do not themselves state that
application-specific consequence. This targeted absence is not evidence of
originality. Compare the whole theorem against the retained BGV/correctness
papers and give the strongest generic control the same lemma before claiming
a useful parameter, communication or verification frontier.

The existing ideal drop23 card retains14473 of16384 coefficients and pays the
remaining1911 conservatively. Its lifetime bound is statistical correctness
under stated ideal and admission premises. It is not an RLWE security estimate,
concrete-sampler guarantee or production approval. The current general API
still refuses the hypothetical large owner-only profile.

## Proposed RNS extension: precise guardrails

For distinct split primes `Q=product_i q_i`, let k_i be each prime-limb
nullity. The valid determinant implication is
`product_i q_i^k_i | Delta`, not `Q^max(k_i) | Delta`.
Missing roots may concentrate in one limb. A fixed prefix of length
`N-max_i K_i`, with each K_i certified separately, is surjective in every limb;
CRT then makes that prefix jointly uniform modulo the whole Q for a full-ring
uniform mask. This says nothing about independence between limbwise rounding
errors or secret-derived gadget digits.

Any next packet must separately register the squarefree restriction, exact
limb controls and a concrete counterexample to the product-as-field shortcut.
Prime powers, limb codecs and actual multi-limb query drops require their own
analysis. No new RNS parameter, backend or timing run is enabled by this note.
