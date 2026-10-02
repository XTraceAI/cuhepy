# Q18/E92 return: mixed-key control is ordinary approximate switching

2026-10-02. **Bounded execution complete; proposed original mechanism stopped.**
The [preregistration](partial-packed-switch-preregistration-20261002.md),
[plan](partial-packed-switch-plan-20261002.md) and
[initial raw receipt](../../benchmarks/results/publication-partial-packed-switch-screen-20261002.json)
retain the hypothesis, exact source hashes, positives, negatives and count scope.
The deliverable is homemade Python/GMP arithmetic; no SEAL code is imported.

## Exact relation and containment

The original, unit-converted components have phase under (1,S,S-squared).
All C1 balanced levels and only upper C2 levels are switched to independent
target T. If P is the exact omitted low C2 polynomial and E is the actual
honest key error, the mixed phase satisfies

```
B0 + A*T + P*S-squared = original unit phase + E (mod q).
```

Ordinary approximate switching outputs (B0,A), with the source residual
absorbed in its error. The proposed route rounds those same two components
and additionally requires the rounded residual mask to be zero. Its output
is **identical**, and its admissibility region is a subset of the known control
when both use the same residual bound. The zero-mask condition saves no further
key row or polynomial product. This containment, rather than an unsuccessful
benchmark, stops the proposed mechanism as an original contribution.

Let d0,d1 be exact rounding numerators at target B. The two-component released
phase has error numerator

`d0 + d1*T + B*E - B*P*S-squared`, modulo q*B.

The public control pays body rounding, target-prefix linear error, original
source-prefix quadratic error, and all retained key-row errors separately.
The source prefix cannot be replaced with the smaller target prefix.
Original S-squared is not T-squared. A zero rounded P does not make its hidden
phase zero. Under q<2^64 and B=2^64, the candidate's zero-mask condition forces
P=0; **ordinary approximate switching does not require that condition**.

## Implemented controls and exact checks

[partial_packed_switch.py](../../experiments/bfv_search_lab/partial_packed_switch.py)
implements strict bounded (N2–16) key/input frames, balanced low residuals,
homemade GMP convolution, exact rounding, deterministic mixed-key bounds and
a full public receiver. Both key identities, both supports, all selected rows,
epoch, precision, condition and budget are approved before its opaque callback.
The callback is not decryption authorization. Honest row noise and upstream
score/query/key registration are external premises, not proved by a hash.

| Independent check | Retained count |
|---|---:|
| Whole small residues and balanced low carries | 1,222 |
| Exact zero-rounding boundary tests | 6,110 |
| All small source/target secret-class phase cases | 2,430 |
| Whole mixed-phase/rounding/bound coefficient checks | 8,748 |
| Identical candidate/known-control outputs and bounds | 2,430 |
| Complete certificate cell/framing corruptions rejected | 62 |

Twenty-eight new tests pass. A fresh local homemade BGV product (N8, t17,
q4294967291), an independent fresh prefix3 target and one omitted C2 level
match all eight decoded coefficients and the literal integer drift. That toy
trusted differential is positive evidence for the adapter, not a production
parameter/PBS/security claim.

Counterexamples preserve nonzero S-squared phase after zero mask rounding,
wrong target-squared basis, source/target prefix substitution and unit-after-
decomposition order. Existing E87/E91 signed/carry/moment negatives still apply.
The full receiver recomputes the switch, four integer moment products, two
pair-box products and every bound; no succinct proof is implemented.

## What the larger cards do and do not establish

The 180 synthetic cards cover eight retained E72 contexts, every possible C2
omission level at radix257 and target precisions 12/14/64 bits. Original masks
and synthetic switched body/mask arrays are seeded public geometries, **not
actual encrypted search or switched samples**. Honest key error uses eta1
only as an unassured model premise. Source phase bounds are also conditional
premises for these synthetic arrays.

Neither route passes its stated sufficient margin in these cards. A more
important qualification is that **all inherited source budgets are already
negative, even before switching**: each E72 bound is near q/2, whereas the
specified odd-domain signed lookup needs the stricter quarter-domain margin.
Thus these original-q cards cannot discriminate which switching bound is
useful. They do not show that approximate switching fails on the real BGV
workload, nor that a smaller measured source error or a paid changed context
would fail. E91's zero original-q margin count has the same source prerequisite.

Selected rows, two-component polynomial products and uncompressed u64 key
bodies are counted. Any nominal saving is a count, not measured time, full
traffic or an approved parameter reduction. Both C1 and C2 families are paid;
all C1 levels remain. Certification and full-verifier recomputation are extra.
Actual key codecs/generation/residency, source authentication, final small-ring
modulus switching/PBS, winner IDs, lifecycle/caches and complete elapsed remain
unpaid. The strong canonical comparator can only improve the norm bound; it
cannot repair a negative source budget.

## Closest work and R6 return

[CHIMERA](https://eprint.iacr.org/2018/758) already treats functional switching
at paid approximation precision (§2.2). [Approximate CRT-Based Gadget
Decomposition](https://eprint.iacr.org/2024/909) gives a generic bounded
residual definition (§2.1) and radix/CRT controls. Its approximate CRT method
must not be replaced with simply deleting an arbitrary CRT limb.
[Mean compensation](https://eprint.iacr.org/2025/809) supplies another strong
noise control (§2.3.1/§3/§3.1); its secret-law/variance premises are not
deterministic all-key guarantees. Two more primary PDF/text pairs are cached
(58 total), with targeted reading and author execution recorded separately.

**Keep** the exact mixed-key/company adapter. **Stop** the zero-mask mechanism
and any parameter conclusion from the non-discriminating inherited budgets.
**Next:** [Q19/E93](committed-precision-epoch-plan-20261002.md) first resolves
source headroom, then asks whether a committed finite precision family before
a fresh target-key epoch can justify a dependence-aware statistical budget
and pay for an actual smaller bridge. Commitment order, full binding, adaptive
feedback, source/target/noise dependencies, known controls and epoch costs
are the question; Gaussian substitution is not an answer. No original main
mechanism, broad assurance gate or production change is accepted.
