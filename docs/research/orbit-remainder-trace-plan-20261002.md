# Q16/E90: tie-aware shared orbit remainder and authenticated precision trace

2026-10-02. **Proposed, not implemented.** Q13–Q15 advance useful known
controls but select no original complete mechanism. Do this finite packet
before a full CM/CUDA/high-precision engine. Preserve production/fallbacks.

## Precise candidate and strongest controls

E88's block masks are signed permutations of a single packed mask polynomial.
Meta-PBS repeatedly uses public quotient/remainder decomposition and packing
to refine modulus-switching error. The candidate is sharing those **exact
public traces and their binding** across orbit blocks/iterations, rather than
materializing and independently proving scalar samples. Original components,
digits/carries, keys/epoch, positions and the public PBS/selector trace must be
bound before private work. The witness is public ciphertext arithmetic,
not source secrets, secret phases, noise or plaintext winners.

Compare against Meta-PBS Algorithm1/Theorem2 and optimized HomTruncRepeat
section5; 2023/645 full-domain/refined digits; large-precision sign/floor;
ordinary shared PBS keys; CM AppendixC.1; HasteBoots/general vFHE/hoisted
common-subexpression proof controls; E70–E72 and full scores/caches. Simply
hoisting public arithmetic or wrapping a known circuit is an engineering
control. Require a new complete relation/bound consequence and its useful
effect before selecting Q6.

## Exact sign/carry question to settle first

For even divisor L define the unique centered remainder
`R_L(x)=(x+L/2 mod L)-L/2` and unreduced integer quotient
`U_L(x)=(x-R_L(x))/L`. At a half tie `H_L(x)=1[x mod L=L/2]`, the proposed
identities are

```
R_L(-x) = -R_L(x) - L*H_L(x)
U_L(-x) = -U_L(x) + H_L(x).
```

Canonical torus negation introduces an additional *public* modulus quotient,
which must be retained where the Meta-PBS algorithm requires unreduced U.
Propagate this through successive remainders and every signed block rotation.
One original-coefficient half-tie bitmap per family/stage might suffice for
all signed orbits; do not assume a bitmap plus hash is a proof of its truth.
Compare with a strong standard hoisted decomposition with identical reuse.

Also test the proposed sufficient no-tie grid condition: for odd original Q,
`round(B*x/Q)` cannot meet a centered half remainder for quotient target T
when power-of-two B is large enough that `B >= T*Q`. State strict rounding,
canonical endpoints and later-stage accumulated target factors. This is
an exact arithmetic control, not a statement about typical tie probability
or a reason to make B128 free. B64/later stages may need actual corrections.

## Bounded sequence and return policy

1. Targeted-read the cached Meta-PBS definition, Algorithm1/Theorems1–3 and
   section5; current reading is targeted, not a complete proof audit. Record
   how binary secrets, Gaussian perturbations, divisibility and known output
   formats differ from our BGV/partial/orbit distributions. Do not copy its
   published timing or 128-bit parameters to this implementation.
2. Independently exhaust small even torus moduli/divisors, all residues,
   signs, carry endpoints, multi-stage remainders and block starts. Compare
   literal versus shared full quotients/remainders, and exact phase-plus-error
   laws. Include odd-source rounded grids, missing bitmaps/components/limbs,
   false tie bits, modular-only reconstruction aliases, wrong epochs and
   challenge-before-binding. Preserve every negative.
3. Specify and instantiate **one full verifier** for the public subrelation,
   or label it arithmetic only. Verify all bit predicates/range/centered
   carries and original score dependencies. Hidden points/public challenges
   require their actual binding/reuse protocol; no root-only or basis-only
   substitute. Full recomputation is a mandatory paid control.
4. Price shared versus strongest hoisted traces at N2048/N16384, sparse/dense,
   staged/tiled/repeated queries. Include actual compact-key generation,
   relinearization, conversion, HomTruncRepeat/PBS, signed-key compatibility,
   original-input proof, lookup/ID coverage, auxiliary-key privacy, owner/new
   client state, setup/RTTs and cache acquisition/update controls.
5. Return to R6 after each component. Advance only an actual new authenticated
   step and a complete measured/model-supported effect against strong
   controls. Otherwise retain controls and pivot; do not build a full
   backend hoping composition becomes a contribution.

This remains a creative candidate with explicit falsifiers. Q6–Q10, broad
P packages and production/parameter/private-side-channel approval are still
unmet. Conference selection does not change those gates.
