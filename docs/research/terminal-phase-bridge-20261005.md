# Conditional terminal phase bridge

This independent Q78 component follows [its registration](phase-bridge-registration-20261005.json). The integer derivation below connects the existing conservative support formula to the paired Q/P phase lift. A four-assertion [Lean draft](../../../research-data/q78-phase-bridge-20261005/phase-bridge-draft.lean) is written but **not compiler/kernel checked**. Validation is deferred until the live Q77 timing action stops. No HE, native/private, GPU, test or performance operation is part of this derivation.

The earlier [four checked integer facts](terminal-assurance-20261005.md) remain unchanged. This argument does not establish the native implementation, actual noise induction, currentness, privacy or side-channel assurance, and it is not the required creative extension.

## Exact rounding residual

Let Q,P,t be positive. For an integer x define r=x mod t, D=2Qt, A=2(Px−Qr)+Qt, k=floor(A/D), and R(x)=kt+r. These are exactly the public scalar expressions in `Query::terminal` before its final reduction modulo P.

Euclidean division gives A=Dk+u for 0≤u<D. The scaled rounding residual is

```text
ε(x) = Q*R(x) - P*x
2*ε(x) = Q*t - u
-Q*t < 2*ε(x) ≤ Q*t.
```

This includes negative numerators and the actual upward tie convention. Consequently |ε(x)|≤Qt/2. It does not assert that `R(x) mod P` retains x's residue modulo t. The checked x1030 counterexample demonstrates that stronger assertion is false on this profile.

## Complete signed phase and the same wrap

For one negacyclic coefficient, use one finite signed weighted sum: c0 has weight 1, and the N c1 coefficients have weights equal to the appropriately signed ternary-secret coefficients. Write x_i for the complete unwrapped common-Q components and w_i for these weights. Then Σ|w_i|≤N+1. Native convolution indexing and ternary-secret coverage must actually refine this sum; the algebra alone does not establish them.

Define

```text
rawQ = Σ w_i*x_i
rawP = Σ w_i*R(x_i)
E    = Q*rawP - P*rawQ = Σ w_i*ε(x_i).
```

The triangle inequality yields `2*|E| ≤ (N+1)*Q*t`. This uses every component and the same weights. Neither a sampled coordinate nor a bound on only one ciphertext component suffices.

Assume the honest-origin/complete-operation argument establishes `rawQ = phaseQ + Q*z` with `|phaseQ|≤B`. Set `phaseP=rawP−P*z`. Cancellation gives

```text
Q*phaseP = P*phaseQ + E
|phaseP| ≤ P*B/Q + (N+1)*t/2
         ≤ ceil(P*B/Q) + ceil((N+1)*t/2) = T.
```

Thus `2*T<P` implies the strict centered-P interval `−P<2*phaseP<P`. This derives the **same z** in the old/new unwrapped phases from the residual and public support bound. It supplies the missing algebraic implication; it does not prove that actual admitted native phases satisfy its origin/aggregate premises.

The frozen profile has:

| Quantity | Exact public value |
| --- | ---: |
| N | 16,384 |
| t | 1,031 |
| Q | 1,329,227,995,784,613,643,754,746,428,306,227,201 |
| P | 33,548,413 |
| B, existing complete output support | 144,762,438,280,919,092,281,917,477,552,128 |
| ceil(PB/Q) | 3,654 |
| ceil((N+1)t/2) | 8,446,468 |
| T | 8,450,122 |
| 2T | 16,900,244 < P |

The one [public closed calculation](../../../research-data/q78-phase-bridge-20261005/public-bound01.json) reproduces the existing formula. It is not sampled noise, an observed decryption, a timing, or parameter-security approval. The earlier `Model.lean` already kernel-checks the selected support value; the new draft has not yet been checked.

## Canonical wire components and private decoding

Each wire component is `R(x_i) mod P = R(x_i)−P*j_i`. The raw phase of wire components differs from rawP by `P*Σw_i*j_i`. Therefore their residues modulo P agree. Apply the existing complete `signed_dot_congr` fact at P; do not demand component agreement modulo t.

Centered reduction of either phase recovers `phaseP=rawP−P*z`, because phaseP lies in the strict centered interval. The private decoder's final reduction modulo t then gives the message.

Before canonical wire reduction, `R(x_i) mod t=x_i mod t`, so complete signed phases agree modulo t. Since Q mod t=P mod t, subtracting Qz/Pz preserves that agreement:

```text
phaseP mod t = (rawP-P*z) mod t
            = (rawQ-Q*z) mod t
            = phaseQ mod t.
```

Here both moduli have residue 704 modulo 1031. This proves a conditional message-preservation statement. Connecting phaseQ's message to the exact score/zero tail/all-ordinal output remains a separate origin/layout/refinement obligation. Post-decryption result validation cannot substitute for that argument in the malicious-server threat model.

## What the draft must actually prove

| Assertion | Proposed precise scope | Still outside the assertion |
| --- | --- | --- |
| `native_rounding_residual` | Exact one-component floor expression and residual interval on the fixed profile, for every integer x. | GMP/native scalar refinement and array coverage. |
| `paired_phase_bounds` | Existing noise box and complete aggregate residual box imply the same wrap's centered-P interval. | Derivation of those boxes for every native admitted execution. |
| `centered_phase_recovers_lift` | A rawP whose proposed lift is in the strict centered interval decodes to that lift. | NTT/CRT/private reducer correctness. |
| `admitted_phase_message` | The paired bound, unwrapped modulo-t agreement, and canonical wire modulo-P agreement imply identical final messages. | Actual complete signed sums, score semantics, authorization and privacy. |

The draft contains no admissions or user axioms, but that source property is **not a successful Lean validation**. Retain any failed executed source and diagnostics; only promote a checked module after the bounded registered validation passes. Keep the existing sixteen checked assertions distinct from these four drafts.

## Next concrete obligation

After timing stops, freeze the actual draft/toolchain inputs and use at most three 60-second compiler invocations. Then connect the signed aggregate relation and existing source/noise induction to the native arrays. The whole source-to-admission-to-private-consumption argument, augmented HE reduction, real attestation/currentness/nonrollback and complete private leakage remain open.

The active scientific dependency remains the completed separately registered R3 comparison and its read-only analysis, followed by one eligible creative mechanism. This independent support component neither selects R4 from a partial prefix nor expands its experiment reservation.
