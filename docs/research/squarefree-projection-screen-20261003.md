# Q45/E119: squarefree-CRT fixed-prefix discriminator

2026-10-03. **The bounded public oracle passes; retain the correct CRT
prerequisite. A large whole-Q correctness consequence, concrete seeded transfer,
security approval and originality remain open.** This packet is a homemade
public mathematical oracle. It neither implements encryption nor changes any
HE, sampler, private-release, native/CUDA or production path.

The [original preregistration](squarefree-projection-preregistration-20261003.md)
preceded all new source/tests/cohort work. A separately frozen
[codec clarification](squarefree-projection-codec-amendment-20261003.md)
preceded the cohort and records that the five-modulus substitution is a
**formal, unadmitted formula**, not a guarded codec. The
[selected raw](../../benchmarks/results/publication-squarefree-projection-20261003.json)
has exactly one N8 public ternary witness, two N2 full-mask panels with4225
masks each, and one65-coefficient scalar codec panel. No grid or large model
was added.

## 1. Correct relation and known controls

For power-of-two N, nonzero integer degree<N polynomial s and distinct fully
split prime limbs p_i, its integer multiplication determinant Delta is nonzero.
If k_i is its nullity in prime limb i, the valid exact implication is

```
product_i p_i^k_i divides Delta,
product_i p_i^k_i <= abs(Delta) <= norm2(s)^(N/2).
```

The product modulus Q is not a field. In particular, these statements do not
imply `Q^max_i(k_i) divides Delta`. Missing roots can occur at one prime only.
The new [module](../../experiments/bfv_search_lab/squarefree_projection.py)
admits exact prime limbs and keeps field rank separate from the composite
coefficient modulus. Its public norm certificate derives each cap K_i by exact
integer comparisons and uses common K=max_i(K_i), prefix length N-K. A cap
equal to N gives the empty, explicitly vacuous guaranteed prefix. Zero is
outside the nonzero determinant/projection premise.

The same first N-K consecutive coefficients are surjective in every limb.
The last K parity-check columns contain an invertible consecutive Vandermonde
minor for its k_i distinct nonzero missing roots. A full-ring uniform mask
has independent uniform CRT limb vectors; the common prefix is therefore
jointly uniform over `(Z/QZ)^(N-K)`. Every fixed translation independent of
that mask preserves the law, including translation after conditioning on
independent fresh errors. Its dependent suffix still pays full support.
Different limb information sets, arbitrary subsets, full-vector IID and
marginal uniformity alone are not substituted for that premise.

These are known controls. The directly inspected
[Lyubashevsky–Seiler EUROCRYPT2018 primary](https://www.iacr.org/archive/eurocrypt2018/10822333/10822333.pdf),
Lemma2.7 and Lemma3.1 proof, printed pp12-13, gives the short-vector norm bound
in terms of ideal index. The intersection of the vanishing-root ideals at
distinct primes has index `product_i p_i^k_i`, supplying this same weighted
norm/nullity inequality. The fixed information-set and CRT steps also use
standard algebra. An equally informed generic evaluator gets the identical
certificate and consequence: ratio1. This is not an original cryptographic
construction or an exhaustive prior-work assessment.

The [runner](../../benchmarks/squarefree_projection_lab.py) checks genuinely
separate finite controls: literal schoolbook monomial columns versus the
module's signed coefficient matrix; fraction-free Bareiss versus rational
elimination determinant; division-free field echelon versus normalized Gaussian
elimination; literal root-power zero membership versus Horner; and a full
coefficient CRT inventory versus the modular-inverse CRT formula. Root checks
compare zero membership, not every numeric nonzero evaluation. Logical counts
are not machine-operation or performance measurements.

## 2. One genuine ternary N8 counterexample

Use Q17*97=1649, primitive16th roots3 and8, and the fixed public polynomial
`s=X^3-X^2-1`. Its squared norm is3. The exact independent determinant is17.
The prime17 zero-root set is{3}; the prime97 set is empty. The actual limb
nullities are(1,0), and the weighted divisor17 divides Delta. Q1649 does not.

| Exact public-witness quantity | Result |
| --- | ---: |
|Integer determinant / norm determinant cap|17 /81|
|Prime-limb nullities|1 /0|
|Actual-public-norm limb caps K_17,K_97|1 /0|
|Common norm-guaranteed prefix / ranks|7 /7,7|
|Invalid product-as-prime nullity cap|0|
|Incorrectly predicted full-vector prefix|8|

Thus the product-as-field shortcut is concretely false for a genuine ternary
polynomial. The full vector satisfies a nontrivial prime17 parity relation and
cannot be uniform on all Q^8 vectors. No N8 masks were enumerated.

The broader public **all-ternary** norm envelope has squared-norm cap8 and
determinant cap4096. It gives limb caps(2,1), common K2 and prefix6. The
witness also has rank6 on that prefix. This packet checks one polynomial;
it does not enumerate another3^8 domain or attribute its prefix7 to the entire
ternary distribution. No actual key or secret draw occurred.

## 3. Exactly two N2 exhaustive CRT diagnostics

Use Q5*13=65 and primitive4th roots2 and5. The public polynomials are
**nonternary** diagnostics, not the supported secret distribution. Each panel
enumerates every65^2=4225 canonical mask:8450 masks and16900 unique output
coefficient positions in total. Whole-Q schoolbook output, literal prime-limb
products/CRT and module output agree completely.

| Public s | Integer Delta | Actual nullities(5,13) | Image vectors | Fibre per image | Actual-rank prefix bins / mass |
| --- | ---: | --- | ---: | ---: | --- |
|X-2|5|(1,0)|845|5|65 /65|
|X-5|26|(0,1)|325|13|65 /65|

The complete image fibres are uniform, but neither full image equals all4225
ring vectors. The first-coordinate histograms are uniform. The fixed
translation(1,2) gives the same prefix support/mass and the correct affine
root-parity coset. This was one fixed translated context per panel, not an
enumeration of all fresh-error translations or a sampled error law.

For X-2, squared norm5 gives norm-only caps(1,0) and prefix1. For X-5,
squared norm26 gives caps(2,1), common K2 and **norm-only prefix0**. Its
actual public limb ranks separately justify prefix1. The raw keeps both
certificates; the latter is not a tighter guarantee from the conservative
norm envelope and is not a proposed large private-secret inspection.

Complete finite histograms are outside Git:

- `research-data/squarefree-projection-20261003/X_minus_2-complete-public-histograms.json`,
  SHA256`6e74d4c3a88dc6a6e8efe02571bafa648942d1a549cc6b94a2a50f155c72342f`.
- `research-data/squarefree-projection-20261003/X_minus_5-complete-public-histograms.json`,
  SHA256`efedbfc59a6b19ecc709f10def37ef0dddebf3bb46ac22c1c49ae7357585ea82`.

## 4. One whole-Q scalar law and formal substitution negative

For Q65,t3,drop2, all65 canonical coefficients match the existing exact scalar
`QuantizerLaw` and independent literal word/reconstruction inventory. The
signed added-error units delta/t have mass49 at0 and16 at-1, mean-16/65.
Coefficient64 is the one-element final radix cycle; its word is48,
reconstruction64 and added error0. The partial cycle and signed bias are paid.

At coefficient8 the whole-Q formula reconstructs8. Formally applying that
formula separately to its five- and thirteen-modulus residues gives0 and8,
whose canonical CRT lift is60. This is a concrete algebraic rejection of blind
limb-codec substitution.

**The five-modulus formula is unadmitted.** `QuantizerLaw(5,3,2)` rejects its
added-error bound because radius3 has no unique centered lift modulo5. Both
the unit regression and main independently assert that refusal; no guard is
bypassed. Q65 admits the scalar mathematical law but is also below the actual
HE coefficient-encoding API's16-bit modulus floor. No actual RNS ciphertext,
query packet, codec invocation through an HE key, or parameter approval
follows from this toy formula.

The65-coefficient inventory is external:
`research-data/squarefree-projection-20261003/wholeQ65-t3-drop2-all65-coefficients.json`,
SHA256`cf80405d2e5dedd39d1d3293fb543bf7229dbd355578a1b6e0ae471cd6264c99`.

## 5. Validation, provenance and scoped return

78 distinct scoped tests pass. They cover independent determinant, matrix,
prime-rank and CRT controls; the genuine ternary shortcut negative; exact
norm caps and forgeries; norm-only versus public-rank/vacuous prefixes; zero;
strict prime/squarefree/split/root/number/canonical-residue grammar; common
projection/mask admission; the codec partial cycle/sign and unadmitted-limb
negative. The tests do not rerun the full mask panels. Explicit nonempty Ruff
over the three owned Python paths passes.

The initial passing test/lint execution used the final unchanged source.
Its XML/logs were copied to final receipt names without rerunning the tests.
The78 unique case IDs were derived from the passing JUnit and checked against
that inventory; initial logs/snapshot and the exact mapping are retained.
Independent read-only module/test/runner review found no material blocker
before the single main cohort, which exits0 with empty stderr. No recorded
test/lint/main failure or source correction occurred.

The original prereg SHA256 is
`3073a0c49f88886598a45bbda41bf10bc8ad56f3cd32968d706cc7662d80bcee`;
the separate codec clarification is
`1bbd04cf061a34483c9229cbb3a033efee01c3b357814c435bdba9705c5f7083`.
The absolute-source/exact-argv freeze pins13 files including both documents,
all new sources, unchanged relevant controls, the external proposal, and the
inspected primary PDF/text. Freeze SHA256:
`1fb8866975dd7968348f86567e76771eacea392f23ea15db9d9933158c81654d`.
Selected raw SHA256:
`214706d4077dd142dec24c2933910284389a8cfdcd6a59888d1873869320c4d3`.
Snapshots, logs, inventories and execution/hash receipts reside under
`WORK/research-data/squarefree-projection-20261003/`. Wall clocks are provenance
only. Root owns checkpoint/governance; this agent performed no git mutation.

**Return to R6:** this is a useful known CRT prerequisite and a guard against
an invalid field/law transfer. Prime powers/repeated factors, nonsplit rings
and different limb projections require separately registered arguments; they
are not inferred from this packet. A later whole-Q consequence must specify
actual RNS/source/sampler/query codec, unchanged original-query/index law,
common global digits and every bounded witness, complete product/rotation
maintenance, dependent suffix, terminal P rounding, all positions/lifetimes,
authentication and feedback/side-channel terms. None is discharged by this
finite CRT oracle. No large profile, native/HE/private/proof/timing grid,
service activation or new original main is approved by the pass.
