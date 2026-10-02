# E85: the paid score-to-selection bridge

2026-10-02. Q11 completed its bounded arithmetic/count review. No new complete
shared conversion/coverage mechanism was selected. The
[preregistration](score-phase-bridge-preregistration-20261002.md),
[oracle](../../experiments/bfv_search_lab/score_phase_bridge_oracle.py),
[tests](../../experiments/bfv_search_lab/test_score_phase_bridge_oracle.py),
[runner](../../benchmarks/score_phase_bridge_lab.py) and immutable
[initial result](../../benchmarks/results/publication-score-phase-bridge-screen-20261002.json)
record the exact scope. These are homemade public controls, not a TFHE backend.

## What survived

For `C0 + C1*S + C2*S²` in `Z_Q[X]/(X^N+1)`, extracting coefficient k
copies `C0[k]` and sign-permutes each of C1/C2. The resulting scalar sample
has secret vector `(coeff(S), coeff(S²))`. Independently multiplying in the
ring matches extraction on **14,580** coefficient phases: all degree-two
ciphertexts and ternary keys over F3, with both two and three components.
Tests additionally cover nontrivial degree-four wrap signs and squared keys.

BFV's phase is `floor(Q/t)*m + e`. For public componentwise switching
`c -> round(B*c/Q)`, the distance of the switched phase from `B*m/t`, modulo B,
is at most

```
(B/Q) * (E + (Q mod t)*(t-1)/t) + (1 + ||u||_1)/2.
```

Here `|e| <= E`, u is the entire signed extracted secret and nearest rounding
uses the repository's ties-toward-positive-infinity convention. Integer Q
carries become multiples of B. If this bound is strictly less than `B/(2t)`,
nearest-message decoding is correct. All **2,160** declared mask/key/message/
noise cases at Q=101, t=5, B=256 satisfy the condition and round-trip exactly.
The worst-case bound is 6123/1010 versus margin 128/5. This is a conditional
arithmetic lemma; it excludes key-switch noise, PBS and security parameters.

These are known controls. [CHIMERA](https://eprint.iacr.org/2018/758) already
connects BFV and TFHE via compatible plaintext spaces and switching primitives.
Its abstract/introduction, section 2.2 sample extraction/functional key switch
and section 3 plaintext correspondence were read; the full proof/parameter
analysis and author artifact were not reproduced. The
[TFHE developer explanation](https://www.zama.org/post/tfhe-deep-dive-part-4)
also specifies sample extraction, modulus switching and the LUT restriction.

## What the proposed shortcuts missed

Our shallow BGV phase is the centered representative of `m + t*e`. Ordinary
Q-to-B switching does not turn it into `B*m/t`: Q=101, t=5, B=256, a=0, b=1
is BGV message 1, but scaled-message decoding after that switch returns 0.

Scaling each component by `B/t` removes multiples of t only before a Q wrap.
With secret 1, `(a,b)=(0,0)` and `(100,1)` both have original phase 0 modulo
101. The first proposed scaled output decodes to 0, the second to 1. The
unknown integer carry cannot simply be discarded. This rejects these two
adapters, not published BGV/TFHE switching or programmable modular reduction.

The underlying elementary obstruction is that a nontrivial additive map from
Z_Q to Z_B cannot exist when Q and B are coprime: Q times the image of 1 must
be zero, which forces that image to zero. Rounded switching can preserve a
*scaled* phase with controlled error; extracting BGV's low-modulus residue is
a different, generally nonlinear relation. Changing characteristic is likewise
not a free authentication/carry conversion.

Other required boundaries remain explicit:

- Dropping C2 changes the original phase. A three-component extraction uses
  correlated derived secret S², whose coefficients and norm are not the usual
  independently sampled binary TFHE key. An ordinary TFHE parameter set cannot
  silently be reused. Compare relinearizing each packed reply once, then normal
  sample extraction/key switching, with any supported direct derived-key route.
- All 323 canonical CRT values over 17*19 reconstruct exactly; changing one limb
  changes all 323 reconstructed values. Canonical parsing and reconstruction
  provide no authentication of the original limbs or index/query/epoch.
- A single negacyclic LUT has a forced negative second half. The full-domain
  threshold `1[h<3]` on 0..7 cannot be the table `(1,1,1,0)`. Restricting the
  admitted domain to 0..3 in the first half works, with paid padding/encoding.
  Other PBS variants are controls; no arbitrary-LUT impossibility is claimed.
- Linear checks of original ciphertext arithmetic do not by themselves prove
  that a server-supplied winner is the decrypted exact stable-ID top-3. A
  coverage proof needs all inputs, exact counts/carries, IDs and threshold
  binding. The server has no private score witness without another protocol.
  E84's extension-field challenge fixes one algebraic collision, not this gap.

## Count ledger and its limits

Sixteen retained E72 geometry cards distinguish two/three-component extraction
of every reply coefficient as a **dense control**, rather than calling those
coefficients useful Hamming scores. A separate declared 8192-score/N=16384,
64-bit design point expands to 1,073,807,360 bytes with two components or
2,147,549,184 bytes with three if all scalar samples are materialized as u64s.
That is optional intermediate storage, **not network traffic or a lower bound**.
Shared ring views, fused or batched switching are mandatory implementation
controls. Setup, key switches, bootstraps, relin, proof and ID work are unpriced
here; these counts establish no timing or complete-cost winner.

Eight fully split plaintext cards use the same E72 one-product correctness law
`N*columns*(floor(t/2)+t*eta)^2`, recomputed at the smallest larger prime t
congruent to 1 modulo 2N. N=16384 uses t=65537; N=2048 uses t=12289. New minimum
Q, before NTT-prime rounding, keys and index are charged as changed contexts.
This is only the same linear circuit, **before additional encrypted selection**.
Neither those Q bounds nor TFHE conversion parameters are security-approved.

## Return decision

Stop the two cheap BGV scaling recipes. Keep known BFV extraction as a company/
reference interface. Do not mistake a working known switch plus known selector
for a new construction. The Q11 acceptance allows a scoped no-survivor return;
that is the outcome, while broad P-package/security gates remain unmet.

The next design question is a **carry-aware, authenticated fused conversion**:
can one relation over the original coefficient/RNS ciphertext simultaneously
justify modular score extraction and an exact bounded-score predicate, with
shared work across a packed batch? Compare complete known BGV conversion and
CHIMERA-style BFV switching followed by the strongest key-value selector and
proof. State a genuinely different algebraic step before implementation. The
[updated R6 decision](construction-selection-20261002.md) governs that packet.


Final source-pinned repeat: [immutable result 02](../../benchmarks/results/publication-score-phase-bridge-screen-20261002-02.json). Exact experiment/count fields agree with the initial run; Q0's archive cohort grows from 40 to 46 papers. The [execution receipt](fixed-function-execution-validation-20261002.json) records source closure, preservation and checks. The [latest return](construction-selection-20261002.md) governs current priorities.

**Subsequent Q12 return:** [E86](bgv-unit-bridge-screen.md) supplies the cheap correct known modular-unit map; its carry handling requires no private witness. The two naive-map negatives above remain valid. Use E86, rather than this historical unresolved generic carry interface, as the strong conversion baseline.
