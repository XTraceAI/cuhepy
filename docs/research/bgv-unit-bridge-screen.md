# E86: a correct cheap BGV-to-scaled-phase control

2026-10-02. The next closest-control check found a cheap correct conversion;
E85's two failed adapters did not exhaust the available methods. This is a
useful **known baseline**, not a claimed original construction. It strengthens
the selection plan and removes an unnecessarily expensive carry-witness
requirement for this phase conversion alone.

Sources: [preregistration](bgv-unit-bridge-preregistration-20261002.md),
[homemade public adapter](../../experiments/bfv_search_lab/bgv_unit_bridge.py),
[tests](../../experiments/bfv_search_lab/test_bgv_unit_bridge.py),
[runner](../../benchmarks/bgv_unit_bridge_lab.py),
[initial immutable result](../../benchmarks/results/publication-bgv-unit-bridge-screen-20261002.json).
The adapter is bounded experimental Python; no SEAL/TFHE encryption code is
imported and no production file changes.

## Exact identity

Let gcd(t,Q)=1 and lambda=t^{-1} mod Q, with lambda*t=1+kQ. Then k is invertible
modulo t, since kQ=-1 mod t. Multiply **all** ciphertext components by lambda.
The original centered BGV phase phi=h+t*e, with |phi|<Q/2, becomes

```
phi' = lambda*phi mod Q
phi'/Q = k*h/t + phi/(t*Q) mod 1
round(t*phi'/Q) mod t = k*h mod t.
```

Multiplying that decoded value by k^{-1} recovers h. Q carries are already
accounted for by modular-unit arithmetic; they need no secret server witness.
The negative unit gives the corresponding negated permutation. With Q=1 mod t,
the negative unit is `(Q-1)/t` and the permutation is identity, producing the
ordinary BFV scaled-phase form with negated error.

[Threshold (Fully) Homomorphic Encryption](https://eprint.iacr.org/2025/699),
section 5.6.2, Figure 11 and Lemma 7, documents the Q=1 mod t conversion and
credits earlier work. Only that conversion passage and its premises were read;
the 259-page document is not fully audited. Our arbitrary-coprime permutation
identity is independently derived as a baseline adaptation; no novelty claim
is inferred. CHIMERA's compatible BFV/TFHE spaces are also a mandatory control.

## Executed checks

- **1,602** full centered scalar phases/both-sign cases across five Q,t pairs,
  including composite Q=17*19; **867** small mask/key/phase decompositions.
- **14,580** exhaustive ring coefficient phases, including unrelinearized C2.
- **3,024** safe unit-then-torus round-trips. A deliberately inadequate torus
  B=8 causes **2,207/10,201** failures in the full-phase/mask control, while
  unit conversion at the original Q still decodes correctly.
- **323** exact limbwise inverses agree with canonical CRT unit conversion.
- One fresh-key, actual homemade BGV depth-one product at N=8, t=17, Q about
  32 bits: all eight coefficients match independent schoolbook decryption
  against the existing GMP BGV decoder. This randomized trusted local
  correctness check is not a production parameter or timing panel.

Seventeen scoped tests pass. The public map is invertible (inverse multiplier
t), adds no secret auxiliary key, and preserves standalone IND-CPA *if* the
original encryption is IND-CPA: apply the public map to a simulated challenge.
This does not make the original experimental parameters assured, or prove a
protocol with observable acceptance, new bootstrap keys or private side channels.

## Paid margin and setup ledger

For public B/Q switching after the unit map, a sufficient error bound is

```
B*phase_bound/(t*Q) + (1 + ||u||_1)/2 < B/(2*t).
```

It includes the full extracted secret. A direct C2 route has conservative
ternary bound `||S||_1 + ||S²||_1 <= N+N²`; once relinearized it uses N, with
**relinearization noise and cost still additional**. Key-switch/PBS noise and
LUT constraints are not included in this preliminary bound.

Eight retained E72 cards charge `3*N*replies` public modular coefficient
products for the unit map, no extra body bytes and no changed keys/index for
the map alone. Scalar multiplication commutes with the public NTT/RNS layout;
fusion is possible but unbenchmarked. Every execution proof must bind that
map/permutation to the original input, not accept an unrelated scaled ciphertext.

Thirty-two margin cards separate 32/64-bit torus and direct/once-relinearized
routes. At the recorded conservative phase bounds, four of eight direct
64-bit routes pass the sufficient bound; all eight relinearized 64-bit routes
pass **before added relin/KS/PBS noise**. None of the 32-bit routes passes at
existing Q. Six N=16384 direct 32-bit cards fail even the rounding-only
worst-case feasibility bound for any larger Q; this is not an actual failure
probability or impossibility for better secrets/converters.

The optional newly generated Q=1 mod t NTT-prime contexts that satisfy this
rounding-only bound keep the modeled Q bit count on these cards. Changing Q
requires new keys/index and an actual parameter/noise analysis. No same-key
rescale, extra selection depth or security equivalence is assumed. For general
Q the public message permutation may be folded into a suitable LUT, but a
first-half padded threshold cannot be assumed after an arbitrary permutation.
Strong arbitrary-LUT/padding and generic switching controls must be paid.

## Return to the research plan

Retain E85's exact findings about naive maps, C2, CRT binding and LUT padding.
Replace its unresolved generic carry conversion as the immediate bottleneck
with this correct known baseline. The open question is now narrower: **can
authenticating this public unit/extraction/switch/PBS path and exact stable-ID
winner coverage share a cheaper specialized relation across a packed batch?**

The server can witness public conversion/evaluator arithmetic; it cannot
witness plaintext secret-key decryption. Proving the former is the viable
interface. Compare unit-converted BGV plus generic authenticated switching/
selection, BFV/CHIMERA plus the same selector, fully split plaintext selection,
and permitted authenticated caches. A new shared relation must beat those
complete controls before a Q6 full implementation. E86 advances a control;
it does not select an original main mechanism or close any production gate.


Final source-pinned repeat: [immutable result 02](../../benchmarks/results/publication-bgv-unit-bridge-screen-20261002-02.json). Exact experiment/count fields agree with the initial run; Q0's archive cohort grows from 40 to 46 papers. The [execution receipt](fixed-function-execution-validation-20261002.json) records source closure, preservation and checks. The [latest return](construction-selection-20261002.md) governs current priorities.
