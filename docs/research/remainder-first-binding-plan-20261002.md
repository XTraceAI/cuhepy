# Q26/E100: original-score remainder-first binding discriminator

2026-10-02. **Proposed, unimplemented, no original main selected.** R6 return
after [E99](gadget-dependency-screen.md). Stop repeating generic gadget/noise
optimizations as novelty candidates. This packet asks whether a different
complete proof relation can remove paid conversion witnesses/commitments
while binding the original encrypted query and index.

## Concrete relation to compare

For odd prime source Q and dyadic B, write B*x=Q*v+r with canonical
0<=r<Q, public fresh owner coin0<=U<Q, i=1[U<r], and y=(v+i) modB.
Because Q is a unit moduloB,

`y = i - inverse(Q modulo B)*r (mod B)`.

Proposed construction: prove the original source arithmetic directly to
R=B*X in the source field, canonicalize only R's coefficients, reuse those
same remainder bits for the coin comparison and target low-bit relation, and
fold the constant B into source terms instead of committing a separate full
pre-rounded X/carry tape. For signed views, reuse the exact negation/remainder
and complement-coin relation already checked by E97. When Q=1 modB, the
target constant multiplier simplifies further. Unsupported nonunit Q/B,
composite source fields and changed signing/order models keep ordinary paths.

This algebra does not itself establish originality. E85 already contains
modular-unit conversion and E97 contains stochastic/signed rounding. A strong
generic proof compiler must get the same unit rewrite, canonical bit reuse,
constant folding, shared intermediates and commitments. In particular, the
target inverse multiply and its moduloB carry/range constraints are **paid**;
they do not become free by writing a congruence. A win against a deliberately
unoptimized quotient circuit is inadmissible.

## Bounded execution order, returning to R6 each time

1. **Closest primary methods and registration.** Cache/read relevant complete
   modular-arithmetic, range/cross-field proof and homomorphic execution
   verification passages, plus actual available compiler/artifact behavior.
   Compare with E73 packed-query, E85 unit, E97 sign/coin and known GKR/PIR
   original-binding controls. Record exact versions, assumptions and whether
   authors already supply this complete optimized relation. Specify a distinct
   possible mechanism or stop generic originality before implementation.
2. **Exact relation/corruption oracle.** Fresh preregistration fixes finite
   Q/B/x/U including r0, final y wrap, Q=1 modB, negative signs/complement coins
   and nonunit falsifiers. Compare independent integer quotient and
   remainder-first reconstruction. Mutate every original query/index/key/coin
   commitment, coefficient, bit/range, target relation and selected view.
   Prove identity and required ranges, not a decryption or RLWE reduction.
3. **Whole original computation trace.** Connect a freshly generated homemade
   BGV encrypted index/query evaluation and functional switching to the exact
   source-field R statement; do not start from unbound server-expanded inputs
   or a trusted claimed score. Include original enrollment and key generation
   premises, all source/S-squared dependencies, source field choice, terminal
   precision and complete verifier/PBS interface. No secret/plaintext phase
   witness is available to the server. Keep TEE/full-recompute company control.
4. **Fair complete proof/count comparison.** Implement a transparent relation
   trace first, not a pretend succinct proof. Count witness bits, commitments,
   constraints, prover/verifier/state/wire and original expansion/evaluation
   work against an equally optimized generic composed relation, including
   identical preprocessed index state and all permitted plaintext caches.
   On the actual six Q/N contexts and E99 paid grid, mark prime-field/range/
   Q-modB applicability and charge inverse-multiply carries and full families.
   A count reduction needs a justified complete protocol and measured proof
   follow-up; it is not automatically measured CPU/GPU speed or a main result.
5. **Select or stop.** Only a different complete construction satisfying
   mechanism gateB and useful-effect gateC advances to implementation, native/
   CUDA profiling, proof soundness/reduction, private lifecycle assurance,
   matched HE/Paillier/cache/network evaluation and paper/artifact. The initial
   project gate is20% complete cost or2x binding-state/preparation with<=10%
   latency/traffic regression. If the strongest compiler contains it or full
   cost fails, retain the useful control and update the plan. Another possible
   route is a rigorously scoped dependency/finite-tail assurance contribution,
   but E99's generic Gram/support adapter alone does not supply one.

This packet prioritizes a different mechanism and end-to-end evidence over
another CPU/GPU microbenchmark. There is no claim that the identity is novel,
that a proof system has been built or that sparse-target parameters are
approved. Record component scope, falsifiers, resources, raw hashes and next
gate in publication-progress.md; maintain all earlier results/checkpoints.
