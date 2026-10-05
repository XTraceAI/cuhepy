# Terminal arithmetic assurance return

This independent Q78 subcomponent follows the
[bounded registration](terminal-assurance-registration-20261005.json). It does
not change Q77's frozen implementation, choose R4 from partial data or satisfy
the required creative extension. The next scientific dependency remains actual
20 GiB workspace headroom and the unchanged complete-comparison preflight.

## What is now checked

[Terminal.lean](../../proofs/shared_query/Terminal.lean) adds four supporting
assertions alongside the unchanged twelve-lemma model. The pinned Lean4.34.1
core/Std toolchain checked the module successfully on its second invocation.
The first failure and its executed source remain retained: `List.Forall2` was
unavailable in core/Std, so the final source uses an explicit complete aligned
component relation. No Mathlib installation or scientific execution occurred.
The successful axioms report contains only Lean's ordinary `propext` and
`Quot.sound`; it contains no `sorryAx` or user-defined axiom. Closed numeric
counterexample evaluation uses kernel `decide`, not `native_decide`.

| Assertion | Exact conclusion | Premise or scope still required |
| --- | --- | --- |
| `signed_dot_congr` | Equal component residues modulo a modulus imply equal signed dot-product residues for the same integer weights. | Native negacyclic indexing and complete array/secret coverage must refine this finite dot product. The theorem can be instantiated at t or P; it does not validate a ciphertext. |
| `unwrapped_rounding_congr` | `rounded*t + (x mod t)` has residue `x mod t`. | Applies to the unwrapped integer before reduction modulo P. It does not prove nearest-rounding error or P-component congruence. |
| `wrapped_terminal_preserves_message` | If the unwrapped old/new phases use the same wrap integer at Q/P, Q and P agree modulo t, and their unwrapped residues agree, then the two phase messages agree modulo t. | Actual origin/noise bounds, correct paired lifts and centered-phase identification remain separate obligations. |
| `canonical_component_counterexample` | For the frozen profile and x1030, unwrapped rounding gives −1, while its canonical P-residue is 33,548,412. Their residues modulo t are 1030 and 703 respectively. | One public scalar component; no key, ciphertext, private operation or observed decryption failure. This refutes a proof shortcut. |

These are standard modular arithmetic facts supporting the security argument.
They are not claimed as original cryptographic techniques or a completed
native/model refinement, privacy reduction or production assurance.

## The wrap that must not be omitted

The actual scaler in
[shared_query.cpp](../../experiments/bfv_search_lab/_shared_query/shared_query.cpp)
uses Q1329227995784613643754746428306227201, P33548413 and t1031 on the
selected profile. For a canonical common-Q component x, set `r = x mod t`:

```text
k = floor((2*(P*x - Q*r) + Q*t) / (2*Q*t))
R(x) = k*t + r
wire(x) = R(x) mod P
```

`R(x) mod t = x mod t` is immediate and now formalized. The final `mod P`
operation can change that residue because `P mod t = Q mod t = 704`, not zero.
At the single registered public input x1030, `R(x) = -1` and
`wire(x) = P-1 = 33548412`; `wire(x) mod t = 703`.
This does not mean the decoder should return 703: centered reduction of P-1
returns −1, whose residue modulo t is 1030. The native BGV decoder performs
centered phase reduction; it does not decode each wire component modulo t.

The correct connection is at the complete signed secret-key phase:

1. Lift the common-Q ciphertext components and form their complete negacyclic
   phase. Express its raw integer coefficient as `phaseQ + Q*z`.
2. Use the **unwrapped** R-components. Their integer rounding errors must imply
   a corresponding phase `phaseP + P*z` with that same z. Establish that phaseP
   lies in the strict centered P interval. A signature does not supply this.
3. Canonical wire components additionally subtract P times their individual
   wrap integers. Linear phase evaluation preserves equivalence modulo P;
   these component wraps do not invalidate centered phase recovery. This is
   where `signed_dot_congr` is applied at P.
4. Apply the Q/P congruence and paired-lift theorem at t, then connect the native
   centered phase to the exact signed-score encoding and complete ordinal output.

The existing model proves the selected closed support inequalities, including
the terminal bound 8,450,122 below P/2. It does **not** yet prove that every
actual phase satisfies those boxes. The frozen seeded owner encryption has a
bounded symmetric-origin phase; the larger noise of ordinary public-key BGV
encryption cannot silently be substituted into that premise.

## Source-to-model obligations

| Actual boundary inspected | Source evidence | What remains unproved |
| --- | --- | --- |
| Honest owner origin | `complete_cost_tenant.py` calls `seeded_bgv.encrypt` with owner pk/sk; the seeded implementation uses a fresh public uniform seed and independent bounded secret error. | Distribution/PRG and augmented evaluation-key security; complete plaintext/query-layout and noise induction. Public fingerprints alone do not prove pk/sk consistency. |
| Admission before private work | `complete_cost_protocol._Attempt.finish` checks current captured metadata, signature, exact original-request payload and full frame before calling the callback. `OwnerAttempt.finish` supplies a fixed owner-custody target. | A native admission/release refinement and real attested custody. This source inspection is not another adversarial runtime test or formal control-flow proof. |
| Q-to-P terminal conversion | `Query::terminal` computes the public GMP floor expression above, then packs every canonical P coefficient. | Relate GMP division/remainder, complete coordinate coverage and rounding errors to the integer model. Preserve the individual component wrap terms. |
| Private phase | `bgv_private.h` uses the ternary secret, fixed-work NTT arithmetic and centered reduction modulo P, followed by reduction modulo t. | Actual NTT/CRT correctness, signed convolution bounds, masking/reducer implementation and private leakage assurance. Fixed work is not an end-to-end constant-time proof. |
| Complete result | `complete_scores` checks all groups/lanes, tail zeros, signed-score range/parity, and top3 ties by original ordinal. | Prove every admitted honest-origin decode yields the exact intended score, rather than relying on this post-decryption validation to reject malicious ciphertexts. |
| Freshness/consumption | Owner attempt state is consumed before public rejection/private work under local locks; descriptor equality checks the pinned revision. | Consumption is local to the live client object. Crash recovery, multi-device monotone authority and nonrollback are still required. |

The malicious-server reduction remains conditional on sound admission and
currentness: outside the specified bad events, only an authorized canonical
evaluation may reach private decoding. This module supplies part of the integer
correctness layer; it does not discharge those cryptographic or hardware
premises. The actual complete-cost study, one eligible creative extension and
full Q78/Q79 packages remain incomplete.
