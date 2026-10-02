# Q18/E92: precision-targeted partial packed switching

2026-10-02. **Proposed, not implemented.** This is the R6 return after
[E91](quadratic-drift-screen.md). It tests a concrete saved-work consequence,
rather than treating a better known norm as a conference contribution.

## Candidate mechanism and exact basis

Start with a direct BGV product **after** the known unit conversion: its
components C0,C1,C2 have phase under (1,S,S-squared). Let T be an independent
owner-approved target secret with a public prefix D_T; S has its own approved
support D_S. Ordinary keys encrypt r^l*S and r^l*S-squared under T.

Switch C1 completely. Switch only the upper balanced gadget levels of C2,
leaving the exact low residual P. The resulting mixed phase is

```
B0 + A*T + P*S-squared = original unit phase + switching error (mod q).
```

It is **not** a ciphertext under (1,T,T-squared). Bind both key identities,
both support classes, the actual balanced integer decomposition and carry
conventions. Multiplying by t-inverse after taking low residuals can destroy
their smallness; unit conversion must happen first.

At a target dyadic modulus B, every residual coefficient can have rounded
mask zero when `abs(P_i) < q/(2B)` (use the exact nearest-rounding condition,
not a floating estimate). Its hidden S-squared phase effect still remains.
A valid all-source-key quadratic residual bound, target-key linear rounding
bound and honest switching/source-noise bound must fit the actual precision
budget before releasing a two-component target-key result. E91's same-prefix
approval cannot be reused for two different source/target key classes.

The possible new step is a complete, public, source-bound **admissibility rule
for a mixed-key partial release** with a useful consequence after every cost.
Ordinary truncated/approximate switching, canonical norms and gadget omission
are known controls; their composition alone does not pass originality gate B.

## Falsifiers and strongest controls

1. At B=2^64 and q<2^64, zero rounding requires integer P=0. This eliminates
   the proposed omitted residual unless a changed, paid context is justified.
   Preserve it as an explicit stop region, not an assumed optimization.
2. Smaller B permits residuals but increases target rounding/PBS error.
   Large N and actual source S-squared can consume all lookup margin.
3. Source and target secrets must be independent when that reduction is
   invoked. Exposed auxiliary keys, honest key errors and epoch lifetime are
   paid premises; no circular-key security is inferred.
4. Compare full once-packed switching, ordinary truncated/approximate/RNS
   switching, relin-then-switch, exact coefficient boxes and a tighter
   certified canonical/Fourier or prefix-matrix control. Do not weaken a
   competitor by giving it independent per-slot keys or only D-squared boxes.
5. Every saved C2 level still leaves all required C1 levels. Charge exact
   decomposition/certification/proof, switched-key generation/traffic/state,
   private provisioning, actual key error and complete score/PBS/ID binding.
   No zero-cost source proof, plaintext score witness or private callback.

## Finite execution and return rules

**Component A — targeted review and algebra.** Pin the closest ordinary
truncated-switch/approximate/RNS sources. Specify the new admissibility
claim and compare it with their exact residual/error semantics. Independently
exhaust small balanced carries, mixed phases, both secret classes, original
unit conversion and zero-mask boundaries. Retain wrong-key-basis, wrong-order,
unsigned/carry and round-zero-but-nonzero-phase counterexamples. Return to R6.

**Component B — public certificate.** Only if the first relation survives,
build a homemade full public verifier. Approve original input, keys, supports,
levels, q/B, budget and epoch before any opaque callback. Exact integer moment
and strong box controls are available; certified Fourier/prefix envelopes are
an additional control subtask if their tighter precision changes admissibility.
No approximate FFT can authorize a bound. Return to R6.

**Component C — paid useful-effect screen.** Enumerate original E72 parameter
contexts and public residual geometries, separating real product fixtures from
synthetic shapes and conditional input noise. Count both key families,
products, bytes, certificate work and complete downstream obligations.
Compare all valid control paths at equal contract/security premises. A smaller
key or count is not a measured latency. Preserve any no-margin/no-saved-level
region. Return to R6 before native/CUDA or larger experiments.

Stop this recipe if stronger known controls explain it, no complete useful
effect survives, the proof is missing, or the usable parameters are unassured.
Keep exact adapters as company controls. Q6 reference, Q7 native, Q8 security,
Q9 matched evaluation and Q10 paper remain conditional. The broader fixed
owner-private operator question can then choose another finite mechanism;
there is no claim that all possible hypotheses have been exhausted.
