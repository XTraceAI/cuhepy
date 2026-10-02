# Q5/E84 finite exact-selection screen

2026-10-02, before new E84 oracle/results. Activation: Q4/R6 selected no main
survivor among the specified E82/E83 candidates. Full scores and stable local
top-3 remain the comparison contract; this is a separate exact-top-3 attempt.

Test a proposed bucket/coverage certificate sharing powers and a grand-product
relation across exact scores. All candidate work, integer counts, IDs, score
binding, ties and omitted rows must be accounted for. Primitive ingredients
are known controls (counting sort, lookup/grand products, polynomial evaluation).
This screen asks whether their proposed composition has a new complete benefit.

1. Exhaust all five-row distances in 0..3 with nonmonotone stable IDs. Check a
   complete integer certificate against independent sorted (distance,ID).
2. Reject histogram-only ID claims, omission, duplicated rows, bad threshold,
   count overflow and carry/field aliases. A histogram does not bind IDs.
3. Check a potential small-field multiplicity collision: equal-total
   histograms `(q,1)` and `(1,q)` at distances 0 and 1. Evaluate products at
   every base-field point. Test a quadratic extension repair in F25 separately;
   correct algebra does not supply original-score commitment or proof.
4. Verify exact prefix-polynomial interpolation on the entire admitted score
   domain; record degree, shared-evaluation work and count-range requirements.
5. Count challenge extension degree for an 8192-row, 128-bit fixed-polynomial
   target. Check actual plaintext ring factor degrees: coefficient-packed
   scores cannot silently become independent scalar SIMD slots.

Advance only with a new cheaper complete conversion/coverage step and compatible
score binding. Stop generic interpolation/grand products if known controls
explain the benefit, integer/field semantics fail, or required repacking/proof
costs remain unspecified. No TFHE/native/CUDA port follows the finite oracle.
Return to Q4/R6 with all controls and the next specific mathematical question.
