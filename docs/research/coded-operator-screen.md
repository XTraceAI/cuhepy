# E83: structured codes survive; literal authenticated row access does not

2026-10-02. Q3 finite return. Homemade
[oracle](../../experiments/bfv_search_lab/coded_operator_oracle.py),
[tests](../../experiments/bfv_search_lab/test_coded_operator_oracle.py),
[runner](../../benchmarks/coded_operator_lab.py),
[immutable raw](../../benchmarks/results/publication-coded-operator-screen-20261002.json).
Twelve scoped tests pass. This is a public arithmetic/authentication control,
not an enabled private-key receiver or a new code/proof construction.

## The representation attempt

Choose a systematic negacirculant code
`E(e)=(e,a1*e,...,ak*e)` in `F_q[X]/(X^n+1)`. It commutes with every signed
shift, so `E(Du)` can use transformed column generators rather than a dense
expanded ED matrix. Combine with an outer Reed–Solomon code across output
blocks to spread a one-block error; a block-only code loses relative distance
by the number of blocks. This is a known code/product construction used as an
E83 control. Its generator commutation is not a novelty claim.

[Double negacirculant codes](https://arxiv.org/abs/1606.00815v1) and
[quasi-cyclic product codes](https://arxiv.org/abs/1512.06690v1) are newly
downloaded and pinned in the [archive](prior-work-archive.md). Their parameter
premises differ from our large split-NTT fields. Targeted reading does not
transfer an asymptotic distance guarantee to our chosen ciphertext ring.

The independent dense-matrix and signed-shift checks agree. Five all-error
cards enumerate **84,534 nonzero errors**. The F5 length-four inner example
has distance three; its two-block tensor has length sixteen and distance nine,
matching the product. A bad commuting code has distance one. The pure NTT
example maps every basis error densely but still has **distance one** among
all 83,520 nonzero F17^4 errors. Basis-only tests would have missed it.

## Complete public authenticated-access control

The owner generates ED and commits its rows in a domain-separated SHA-256
Merkle tree. A local immutable answer snapshot pins the original public query
and response **before** challenge indices. Each opening needs both a valid
path and a matching field dot product. All 25 toy inputs accept; all **600**
nonzero-error answers reject when all four rows are checked. The largest
single-row miss probability is exactly **1/4**. These are exhaustive finite
facts, with hash binding/approved registration as premises.

Negative tests reject a true answer with a bad path, wrong epoch, wrong row
position, missing component and a malformed field value. A challenge supplied
before the answer allows an error in its kernel, as expected. A root to a
server-chosen ED alone would not prove its relation to D. Full-RNS soundness
must cover an error in one limb; the bound cannot be multiplied across limbs
as if that error occurred in all of them. The local fixture has no private-key
operations, network lifecycle, durable state or reviewed release proof.

## The decisive dimension distinction

Q0's smaller W values describe **token/delta** operators and retain their
trusted token factory. E83's preparation-removing mode must instead match
[E72's actual original encrypted query](encrypted-query-gate-control.md):
`W=2*N*F`, with full output upper bound `L=3*N*R`. Publicly checking an
independent RNS digit or a server-supplied expanded query is not equivalent.

The raw counts all eight retained E72 geometries at expansion factors 2/4/8:
**24 complete dimension cards**. Give the proposal the best possible MDS
distance `length-L+1` and omit path bytes, code evaluation and extra RTT.
Even then the row values alone cost **54.15–233.99× the whole existing
query-plus-reply upper-bound body**. Real projected output is no larger, so
using that upper bound favors the proposal. The Q values are old unapproved
depth-one count models, not new parameter choices or measurements.

Retaining all transformed generators at the client avoids downloads by paying
their full state. A succinct evaluated-row/quotient opening is a different
construction with its prover and client costs still unknown; neither a Merkle
membership path nor generator commutation supplies it.

**Q3 → Q4/R6:** stop literal coded-row fetch as the main system mechanism.
Keep the structured code oracle and full-cost control. No new complete
authentication step survived; no CUDA port is justified for this recipe.
Combined with the bounded E82 failures, activate Q5/E84's exact-selection
algebra/count fallback, keeping broader PCF/succinct-proof paths open.


Final source-pinned repeat: [immutable result 02](../../benchmarks/results/publication-coded-operator-screen-20261002-02.json). Exact experiment/count fields agree with the initial run; Q0's archive cohort grows from 40 to 46 papers. The [execution receipt](fixed-function-execution-validation-20261002.json) records source closure, preservation and checks. The [latest return](construction-selection-20261002.md) governs current priorities.
