# E87 bounded arithmetic, authentication and count session

2026-10-02. Recorded before oracle/results. Branch
`experiment/batched-score-bridge-20261002`, parent `d032925`. No production
source is changed. Q13's proposed complete authenticated interface is not yet
supplied by the identity below.

## Controls and specified difference

Read the downloaded current 2023/979 revision: sections 3.2.1, 3.2.2 and
3.2.5, Algorithms 1–3, Theorems 2/5 and Remark 4. It already supplies FFT
switching through a partial GLWE key. Read HERMES sections 4.1–4.5 and
Tables 3–5: its principal direction is LWE to RLWE, not the inverse. Keep
CHIMERA, E70–E72 quotient/fingerprint controls and HasteBoots as recorded
strong controls. The newly located common-mask paper is an additional
packed-bootstrap control, pending targeted reading. No author code is run.

Two exact homemade controls will be compared with the proposed convolution:

1. Ordinary independent scalar switching keys for every coefficient, digit
   and C1/C2 family; literal extraction/switch versus shared negacyclic
   convolution, matching every public mask/body and exact error.
2. Once-packed polynomial switching under a target secret polynomial with
   a supported nonzero prefix, followed by extraction at every requested
   coefficient. This uses **different switching keys** from control 1.
   Toy zero padding proves arithmetic only; the partial-key paper's security
   premises, noise floor and parameter study cannot be assumed for our keys.

For odd Q and odd radix r use the centered representative in
`[-(Q-1)/2,(Q-1)/2]`, unique balanced digits in `[-(r-1)/2,(r-1)/2]`, and
L minimal with `r^L >= Q`. Prove negation equivariance and charge L. No
truncated binary shortcut is substituted. All phases use `body+mask*secret`.

## Finite checks and failure conditions

Exhaust all admitted residues of selected small Q/r pairs, all N=2 inputs
over Q=3 for both two/three-component inputs, all tiny source secrets and
score positions, plus independently seeded key masks/errors. Include
composite Q and limb reconstruction. Compare exact phase to independent
schoolbook original phase plus explicit key error; include a fresh actual
homemade BGV product as a trusted local differential if its noise admits it.

Supply a **full recomputation receiver control**, with owner-pinned epoch,
keys, original components and ordered required positions. Reject missing
components/limbs/levels/positions, swapped keys or epoch, noncanonical
digits/carries, output/proof corruption and wrong dimensions. It has no
private-key callback. It is not a succinct protocol; charge its full data
and recomputation. Merely accepting a public statement's own digest is not
authentication.

For a possible smaller interface test exact counterexamples to:
`digit(C)(z) = digit(C(z))`, root-only output checking, and range/modular
reconstruction alone. Challenge after binding; a known/disclosed point is
not a reusable secret verifier. No PBS trace, winner/ID coverage or encrypted
top-3 authentication is claimed without an actual complete verifier.

## Paid count and return

Use the unchanged eight E72 modeled geometries, not approved security sets.
For each use radix 3/257, target dimensions 512/1024 (illustrative, not
approved), direct C2 and once-relinearized routes. Count dense/sparse and
1/16-batch modes; all keys, coefficient/NTT storage, digit products,
transforms, streamed/materialized outputs, relin/KS/PBS noise, and full
recomputation verification traffic. Pretransformed keys still cost setup,
resident memory and transfers. Report separate operation types, not a
fabricated time ratio. Unknown proof/PBS costs remain explicit.

Return to R6 after reading, oracle and counts. Known convolution alone does
not pass originality; a faster arithmetic component with a missing compact
digit/input/PBS/coverage proof cannot activate Q6. Preserve it as an
engineering control if useful, and specify the next different question.
