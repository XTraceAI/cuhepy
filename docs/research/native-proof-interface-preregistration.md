# Q34/E108: complete native relation under a scalar R1CS interface

2026-10-03 UTC. Freeze before new adapter source or evaluation. Parent
`be8e275d5b06e14c78652ce6e19856836c618a2f`; experimental branch
`experiment/native-proof-interface-20261003`. Follow the
[native opening plan](native-opening-discriminator-plan-20261003.md).

## Selected contract and known controls

Use a homemade transparent scalar constraint adapter compatible with the
Spartan R1CS interface, over its prime scalar field
F=2^252+27742317777372353535851937790883648493. The author Spartan artifact
and primary2019/550 supply a concrete interface, not imported HE arithmetic.
Selecting the interface does not instantiate a PCS, proof, setup, ROM/lifetime
argument or security target. No cryptographic proof backend is executed here.

The current corrected2025/286 §4.3 is a mandatory specialized control: it uses
an auxiliary prime-field range lookup plus paid integer consistency, and its
Remark6.1 excludes old application estimates as updated corrected costs.
Current GlueLUT2026/494 is another mandatory cross-modulus consistency control.
Pin their exact new versions; preserve all77 older source records/pairs. Native
fully splitQ and radix30 canonical digits must retain their actual premises.
Generic R1CS gets the SAME common bits, slack elimination, sparse affine map,
centered terminal remainder, fixed index preprocessing and public input handling.
No baseline is priced by an unavailable complete proof implementation.

Use the unchanged frozen E106 N8/D4/t17/Q120/two-prime/P32 corpus, keys and
all8 original compressed query packets. The owner/verifier locally expands the
original pinned bytes and regenerates SHAKE; charge this public work outside
the circuit. The16 canonical expanded coefficients and32 parsed canonical
compact output coefficients are public inputs, not server-chosen trusted data.
Context/key/index/layout/epoch/ID order and exact packet grammar are externally
owner-pinned. Public input validation and full packet parse/reserialization
must precede private callbacks. Static constraint shape/index constants may be
reused across the8 queries; do not silently redo owner setup per query.

## Complete constraint relation

For each80 switching source coordinates, supply ONE120-bit scalar string.
Its four30-bit slices are the common global digits for bothQ limbs. Pair its
value S with120-bit nonnegative slack Q−1−S. Boolean constraints b(b−1)=0
are in primeF, notQ or independently in the twoQ fields. Do not introduce a
separate unbound source or permit S=canonical source+Q.

For32 preterminal coordinates, supply canonical120-bit value C plusQ slack.
For32 terminal remainders, supply u=r+(Q−1)/2 in[0,Q−1], again with120-bit
value/slack. Link the complete E106112-row affine map in BOTHQ limbs, with
fixed original public query inputs and source-digit/terminal columns. Link
`t*r+P*C=pi*z_i` for bothpi and `Q*y−t*r=P*zP` for terminal outputs.
The reduced E107 relation derives the integer lift; no lift/wrap/modt tape.

Every modular row has a supplied integer quotient z=L+v, with v and its slack
encoded in bits in[0,U−L]. Derive conservative exact L/U and row error bounds
from admitted input ranges. Check |D|<F so field equality implies integer
zero; never infer integer equality from field congruence alone. Canonical
range and shared bits precede using those bounds. A small-field or unbounded
quotient counterexample must be retained. Compile linear/Boolean rows to a
transparent satisfaction interface; this is not a succinct cryptographic proof.

## Frozen evaluation and falsifiers

Eight frozen queries must match every full native-agreed coefficient, all72
scores/stable ties and exact211-byte compact response. Preserve partial-tail
rotations, all112 affine rows and every terminal output including unusedscore
coordinates. The verifier must not call the public graph evaluator/replay to
check the witness; compare it independently to the E106 replay oracle.

Reject before callback: each80 source bit/range mutation, each32 preterminal
and32 centered-remainder mutation, each320 modular quotient mutation, malformed
Boolean/field/container types, falsecanonical honest-output kernel, one-limb
error, independent CRT bits, Q21 idempotent7, source+Q/digit reconstruction
alias, missing quotient bound/field wrap, missing remainder center, original
query/context/key/index/ID/epoch swap, omitted/duplicated/reordered groups,
noncanonical packet/modulus and unusedcoeff/padding alterations. Omissions
are diagnostic seams only, never a release mode. Exact counts depend on test
parameterization and must be reported as observed, not promised pass counts.

## Paid ledger and bounded return

Record basic144 value/slack pairs,34,560 Boolean gates before quotient bits,
320 modular integer equations, actual quotient widths/bounds, sparse matrix
nonzeros, public inputs, serialized transparent tapes/constraints and field
residual bounds. Price instance/preprocessing, witness/bit generation, client
public expansion, range/opening, proof links, checker, private release and
lifecycles separately. All backend proof/state/wire/time not executed stays
unknown. No timing panel/GPU/BFV/production edit or parameter approval.

Initial cap: one primary/interface component and one complete tiny relation/count
component. If the generic compiler contains the adapter, retain it as a strong
known control and stop originality. A distinct surviving mechanism needs its
own precise closest-work difference and complete paid advantage before next
implementation. Return to R6 and the research plan after the cap.

Proposed files: `native_opening_constraints.py`, `test_native_opening_constraints.py`
in `experiments/bfv_search_lab`, runner `benchmarks/native_opening_lab.py`, raw
`benchmarks/results/publication-native-opening-20261003.json`, and report
`docs/research/native-proof-interface-screen.md`. Existing homemade HE backends,
all older raws/checkpoints and frozen timing summaries remain unchanged.
