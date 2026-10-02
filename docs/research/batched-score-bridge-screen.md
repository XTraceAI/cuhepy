# E87 return: known shared switching survives; compact authentication does not follow

2026-10-02. [Preregistered scope](batched-score-bridge-preregistration-20261002.md),
[closest controls](batched-score-bridge-closest-work-20261002.md),
[initial exact/count result](../../benchmarks/results/publication-batched-score-bridge-screen-20261002.json).
Thirty scoped tests pass. No timing, GPU, complete encrypted top-3 or
production-security result is claimed.

## Exact homemade controls

For odd Q and odd r, centered x has a unique balanced integer expansion
with L minimal such that `r^L >= Q`. The least digit is the unique residue
in `[-(r-1)/2,(r-1)/2]`; removing it and dividing by r repeats the argument.
Negating every digit is the unique expansion of -x. Odd Q has no ambiguous
centered half residue, and odd r has no half digit tie. Therefore gadget
decomposition commutes with every extraction sign/rotation.

For scalar keys with phase `r^l*S[j]+e[j,l]`, the literal switch's full
mask/body equals coefficient k of each public polynomial
`sum_l d_l(C1)*K_l,v`, plus C2's independent family and C0 in the body.
Noise is precisely the same signed digit combination of scalar-key errors.
These remain ordinary scalar-LWE keys; treating coordinate v as a polynomial
does not turn them into compact RLWE switching keys.

A stronger separate control encrypts whole `r^l*S` and `r^l*S²` polynomials
under a target polynomial secret, performs the polynomial switch once and
extracts each coefficient afterward. Its noise is the digit/error convolution.
Different keys and the partial-secret security/noise premises are explicit.
Both are homemade schoolbook reference arithmetic, not imported SEAL code.

Checks: **692** complete residue/negation cases; **30,312** literal/convolution
public-coordinate equalities; **29,928** independent original-plus-error
phase equalities, including all tiny inputs/keys and seeded composite-Q/larger
cards. A fresh actual homemade BGV product passes unit→packed-switch decode
against GMP decryption. Fresh random test keys are not production keys.

## Binding and noise results

A full recomputation receiver pins owner-approved original components, key
format/context/epoch and ordered score positions. It checks exact digits
and every output before any private callback; **146** corrupted transcripts
are rejected. Canonical types, missing families/limbs/levels, incorrect keys,
positions and noncanonical carries have separate tests. This receiver pays
full public inputs, keys and recomputation. Upstream input authentication,
PBS and winners are outside its implemented subrelation.

Three shortcut negatives are exact, not security impossibility claims:

- `(0,1)` and `(2,0)` agree at z=2 over F17, but their lowest radix-3 digit
  polynomials evaluate differently. An original polynomial fingerprint cannot
  supply digit fingerprints without an additional valid relation.
- Integer lifts -8 and +9 have distinct in-range radix-3 digits but the same
  residue mod17. Digit range plus modular reconstruction alone omits centered
  carry binding. The full receiver rejects the alternate expansion.
- A disclosed point z admits nonzero output error `X-z`. It must not be used
  as a freely reusable verification challenge. Unsigned binary digits also
  fail the exact negation property; other binary switching algorithms remain
  valid controls with their own carry/rounding treatment.

Across **64** conditional cards (eight E72 geometries, radix3/257, target512/
1024, direct/relinearized), scalar-column key residency is **50.43–8598.32 MB**;
packed key residency is **0.197–16.777 MB**. These are modeled uint64 array
sizes, not RSS or matched secure key sets. The coefficient ratio is 256.5
or 512.5 because the two key constructions differ. In a mushroom/direct/
radix257/target512 card, this is 941.36 MB versus 3.67 MB; sending all scalar
outputs would cost 52.53 MB versus 204.8 KB for the packed output. Neither
intermediate must be downloaded in a valid succinct full selection protocol.

No existing near-minimum modeled Q card satisfies the sufficient worst-case
post-unit bound after even illustrative bounded key error 1 (**0/64**);
torus counts give **0/128**. This is a failed *sufficient bound*, not observed
decoding failure or proof of impossibility. Larger Q can retain the same
bit width in this model, but changes keys/index, and actual secure noise,
relinearization/PBS and failure probabilities remain unpaid. The raw cards
retain the required Q inequality rather than silently making switch noise free.

Counts separate dense/sparse/16-batch modes, cold/resident keys, transforms,
pointwise versus schoolbook work, streaming/materialization, full-recompute
traffic and known quotient costs. Sparse three-output extraction does not
prove that three winners are correct among all candidates. Compact digit/
original-score/PBS/ID proof costs are **uninstantiated**, not zero.

## R6 decision and next question

Keep the known exact switches as useful reference/engineering controls.
Stop the recipe that infers a novel compact authenticated interface merely
from shared convolution or a single original-input fingerprint. Q6 remains
conditional: no original complete mechanism was supplied.

Next finite question: the original coefficient ciphertext is already a common
mask with *signed orbit-related secrets*. Can its group structure share
nonlinear selection/evaluation keys while preserving valid authentication?
Compare against the downloaded common-mask construction before calling it
new. First prove the public view equivalence and test whether necessary
slot-diagonal operations actually remain in the compact ring algebra. Do not
assume independent Matrix-LWE keys or free CM packing/PBS.
