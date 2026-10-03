# Q41/E115 prior card: seeded correctness and a unit-free projection question

2026-10-03. **The completed seed-blind reduction and unit-secret codec identity
are standard controls. A useful unit-free, complete native correctness consequence
is a narrower open question; this bounded reading does not establish novelty.**
No experiment, sampler, key generation, benchmark, parameter approval or new proof
backend was executed. The 91-pair source registry and retained PDFs are unchanged.

## 1. Exact question and assumption boundary

[E114](query-quantizer-law-screen.md) gives an exact, biased finite codec law and
conservative complete-event Chernoff certificates at the frozen drop22/drop23
profile. It assumes a unit secret, an ideal uniform full-ring mask, fresh CBD coins
and a query fixed before its own mask. The equally informed generic control gets
the same law and certificate: ratio1. Its 2,048-byte model saving is not an
algorithmic or latency result, and the literal recipe has stopped.

The [marginal card](query-mask-marginal-correctness-card-20261003.md) transfers a
seed-blind, efficiently computable sufficient bad event under a specifically
stated bounded-output SHAKE-as-PRG assumption. It simulates a real prefix, compares
only the next expanded mask, and stops before needing the unknown seed. The event
must pointwise cover every admitted server/common-digit choice. This is an ordinary
reduction, not joint public-seed transcript indistinguishability or HE privacy.
Its lifetime budget remains setup failure plus ideal bad-event, truncation and
distinguishing terms. Actual SHAKE/entropy advantages and the release implication
are unassigned. The [single stream card](query-mask-stream-budget-card-20261003.md)
bounds only uniform-stream exhaustion, below2^-186 over2^32 queries; runtime is
still uncapped. These assumptions are not discharged by an observed good sample.

## 2. Direct theorem comparison, with full-page reading

| Primary control | Statement/proof actually inspected | Containment and precise remaining difference |
| --- | --- | --- |
| [BGV dependency analysis,2504.18597v3](https://arxiv.org/abs/2504.18597v3) | §4 starts with independently encrypted random messages. Proposition3 gives modulus-switch variance. Theorem2 bounds multiplication variance with secret/public-error correction factors. AppendixA's modulus/key-switch paragraph treats ciphertext components and rounding deltas as uniform/independent. §5 uses dominance and CLT/Gaussian reasoning; AppendixC justifies neglecting GHS switching under its noise-dominance regime. Full PDF pages12,14,15,17,36,40 inspected. | Accounting for shared-key dependencies and guiding parameters are existing research goals. Those statements do not directly supply an exact biased-codec PMF for every fixed nonzero ternary secret, with bounded adversarial maintenance and a compact-terminal lifetime margin. This is a scope difference, not a claim that their results fail within their premises. |
| [Average-case critique,2025/1036](https://eprint.iacr.org/2025/1036) | Theorems4.1/4.3 derive moments for products/powers of Gaussian polynomials; Theorem4.6 handles a noise expression's variance. Their proofs and discussion distinguish common-key and ciphertext dependencies and demonstrate why variance/CLT reasoning can miss heavy tails. Full PDF pages4,5,6 inspected. | The dependency warning and need for defensible tails are already prior work. E114's finite-law/pointwise envelope avoids the examined Gaussian shortcut, but its conditioning, convex endpoint MGF and union bound are standard. Neither the critique nor this audit certifies our actual native distribution. |
| [Corrected approximate-HE verification,2025/286](https://eprint.iacr.org/2025/286), October1 correction | §3.4 permits bounded alternative decompositions/rescalings and bounds extra maintenance noise. Remark4.12/Figure2 repair independent-CRT range checks with an auxiliary-field common-integer link. AppendixC explicitly models verification-oracle acceptance feedback in privacy and soundness. Full PDF pages12,26,45 inspected; surrounding text and Theorem4.11 read. | Semantic alternatives, their paid noise, common-integer linkage and feedback-aware composition are mandatory known controls. We cannot claim those ideas as new. Their CKKS relation and correction do not directly prove the particular seeded, deterministic BGV query-codec law or close our release implication. |
| [SEALv4.1.2 symmetric RLWE source](https://raw.githubusercontent.com/microsoft/SEAL/v4.1.2/native/src/seal/util/rlwe.cpp), `encrypt_zero_symmetric` | Full tagged source read, especially source lines249-365: it creates a public seed for a mask generator, samples error on the separate bootstrap path and can store the mask-generator seed in the ciphertext. | Public-seed mask compression and separate noise generation are established implementation controls. This source is not a theorem for our SHAKE family, quantizer, adaptive lifetime or nonunit key law. No SEAL artifact was run or imported by this audit. |

The corrected paper is the retained October1,2026 version, not its old range
protocol or old cost estimates. Author-reported performance in these sources is
unreproduced here. No paper was newly downloaded; the SEAL and coding-standard
pages were consulted as primary implementation/algebra controls, not added as
new PDF/text pairs. The exact file identities and reading pages are external.

## 3. Proposed unit-free component: what is standard and what must be checked

The new question from the independent finite-noise derivation is restricted to
a **prime, fully split** Q and N a power of two. Let T_s be the integer negacyclic
multiplication matrix of a nonzero signed ternary secret s. Its determinant is
the resultant Delta=Res(X^N+1,s). Irreducibility over the rationals and deg(s)<N
imply Delta is a nonzero integer. If T_s modQ has nullity k, its integer Smith
invariants imply Q^k divides Delta. Hadamard, equivalently Parseval plus AM-GM,
gives

```
1 <= |Delta| <= ||s||_2^N <= N^(N/2),
k <= K := max{j : Q^j <= N^(N/2)}.
```

These are classical resultant, determinantal-divisor and norm facts, not a new
cryptographic assumption. The derivation does not certify a random key's unit
probability. It bounds the defect for EVERY nonzero signed ternary key.

In the split ring, the image of multiplication by s consists exactly of coefficient
vectors vanishing at its k zero NTT roots. The last k coefficient columns of
these constraints are an invertible Vandermonde times nonzero row scalars. Thus
every first N-k coefficient prefix occurs equally often in that image. For ideal
uniform A, its first N-K product coordinates are therefore jointly uniform.
After adding any fixed message and conditioning on the ENTIRE fresh E vector,
the same c0 prefix remains uniform. Its codec errors have the E114 finite PMF,
are IID on that fixed prefix and are independent of E. The remaining K coordinates
must be charged pointwise, including both CBD and codec support.

The consecutive-column argument is the classical systematic/interpolation fact
illustrated in [RFC5510,§§8.2.1-8.3.1](https://www.rfc-editor.org/rfc/rfc5510.html#section-8.2.1).
It does **not** mean this arbitrary-root image code is MDS or that arbitrary
N-k coordinate subsets are uniform. Nonconsecutive columns can be singular;
roots r,-r with exponents0,2 are a simple counterexample. Any different coordinate
selection needs its own rank argument. Nor does a prime-field proof silently
extend to a composite RNS modulus or independent per-limb digit choices.

This projection restriction is substantively different from declaring the whole
c0 vector IID for a nonunit secret. It also avoids the unhelpful generic whole-coset
likelihood penalty Q^k by separating a fixed uniform prefix from a bounded suffix.
For an honest independent uniform-ternary sampler, the all-zero secret has exact
probability3^-N. That exception is a setup-analysis term; the proposed reasoning
does not change key generation, privately reject secrets or publicly expose their
unit/rank status. Re-enrollment and any nonuniform sampler need their own budget.

The useful prospective consequence is a fully explicit finite-lifetime raw AND
compact-terminal correctness certificate for the existing owner/index graph,
without a unit-key premise or an independence assumption for reused maintenance
errors, under the separate marginal seed-expansion assumption. The three inspected
papers do not state that complete consequence. This limited absence is not an
originality proof: the algebra, information-set argument, omitted-coordinate norm
bound and concentration machinery are standard. A generic control must receive
the very same projection and coefficient envelopes. If it matches, the result may
remain an assurance adapter rather than a new algorithm or conference contribution.

## 4. One next hypothesis and its falsifier

**Hypothesis:** a fixed public resultant-certified coefficient prefix retains
enough exact quantizer randomness to certify the registered E113 drop23 profile
for every nonzero supported ternary secret, while paying the dependent suffix
and all bounded common-digit/terminal costs, and without changing the sampler.
This is the next unit-free component, not a request for another drop grid or
hardware optimizer. Its numerical screen is being owned separately; this audit
does not claim its outcome.

First falsifiers are an invalid suffix-rank claim, an omitted message/CBD/codec
term, a terminal-margin failure, or no advantage in the *theorem's assumptions*
over an equally informed generic control. Freeze one original profile/drop23 card;
prove the fixed-coordinate law and the complete pointwise phase implication before
any real-sampler or implementation claim. All direct computational PRG, protocol
authenticity/feedback and RLWE parameter-assurance obligations remain separate.

If this only instantiates familiar bounds with the same algorithm/costs, retain
the company correctness fact and stop the originality claim. Do not rename ordinary
PRG hybrids, Reed-Solomon interpolation or resultant/Hadamard bounds as a new
mechanism. A stronger paper would need a demonstrably useful general consequence
or a further prior-separating mechanism, not merely the same2,048-byte body fact.

External source/read receipts, primary-web response captures and twelve complete
rendered math pages are under
`WORK/research-data/seeded-correctness-20261003/prior/`. No retained source bytes,
source registry, existing governance document or branch history were modified.
