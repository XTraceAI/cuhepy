# E68: distinct-field registration and the packing obstruction

2026-09-30. Follow-up R3 subcomponent after the
[operator screen](structured-operator-results.md). Homemade
[oracle](../../experiments/bfv_search_lab/structured_registration_oracle.py),
[tests](../../experiments/bfv_search_lab/test_structured_registration_oracle.py),
[runner](../../benchmarks/structured_registration_lab.py) and
[raw](../../benchmarks/results/publication-structured-registration-screen-20260930.json)
at source HEAD `aeb02df`.

## Exact result and domain

H=D A and Z=C D can be computed using forward and adjoint convolution without
materializing D's signed shift matrix. Six N=8/16/32 registrations, full and
projected, match an independently constructed **signed integer matrix** for
every H and Z entry. Forty-eight public input identities Z u=C(D u) pass.
This is ordinary linear algebra, not a private-query/verification protocol.

D retains its centered inner-Q integers; all registration arithmetic uses a
distinct outer prime. Reusing inner-Q residues for an outer integer fingerprint
fails the equality test. The toy signed Z norm must fit before outer centering.
The owner binding includes the public operator, CRS, field, projection and
epoch. Stale epoch/projection, changed fingerprint and out-of-bound integer
controls reject. This hash binds supplied owner-approved objects; it does not
implement a malicious registration/extraction theorem.

Equal outer residues do not identify an admissible integer lift: D and D+q_o
can have the same outer image but different inner-Q results. This domain
counterexample is why the [cards](protocol-baseline-cards.md) retain extraction
and correctness on the appropriate bounded class. It is not an attack on a
theorem that already requires those bounds.

## Price the objects beyond D

Eight retained profiles are screened with **demonstration dimensions only**:
q_o=2^61-1, d=2048, ell=3, kappa=128. They are not an admissible/security-reviewed
parameter tuple. Counts include the known ReinsPIRe coefficient-norm packing
bound; full-width H' storage is not the strongest baseline.

On the selected Mushroom geometry, generators occupy 4 MiB instead of a
128 MiB literal D. However, materialized H occupies **488 MiB**, and H' at the
known norm bitpacked bound still occupies **792 MiB**. The selected Semeion
geometry has smaller generators but the same H/H' dimensions; the larger
Connect-4 row geometry doubles these H/H' counts. Streaming/compression might
change these objects. They are **not universal lower bounds** or measurements
of the author library, and auxiliary LHE/keys/work are not included.

The count also prices binary C/signed Z and the known prime-field mixing
control. In particular, gamma is computed by the exact inequality
q_o^gamma>=2^kappa, rather than rounding modulus bit length into a false target.
Seed regeneration can avoid materializing C; no mandatory-memory claim follows.

## Candidate factorization rejected

One tempting next step would express the packing map as D times a single
public map independent of D. A gadget **limb** cannot obey that universal
factorization. With A=1 and low base-B digit, D=1 forces T=1; D=B has low digit
0 but D*T=B. This exact scalar contradiction occurs for bases 4 and 16 over
the toy prime 97. Reconstructing **all** digits remains exact; the contradiction
does not rule out another packing algorithm or the actual ReinsPIRe protocol.

Inspection of the pinned author's `crypto/lwes_to_rlwe.cc` finds signed gadget
inversion in packing preprocessing; its client builds the compiled H' matrix
from those bounded polynomial/digit objects. Therefore commuting every stage
as a field-linear map is not justified. The known compilation and ring FFT
preprocessing are already credited in the closest comparison.

## Return to the plan

The H/Z operation-map subtask is complete. **Stop the universal per-limb
factorization.** R3 remains open for a genuine carry-aware packing/registration
algorithm and proof, or a different public-ciphertext-arithmetic verification
layer. The [interim mechanism review](publication-mechanism-review-20260930.md)
introduces E70's bounded quotient-certificate screen for the latter. Neither
this algebra nor fast ring products remove per-query trusted preparation by
themselves. No packing, encryption, proof, latency or security approval is
claimed by this module.

```bash
.venv/bin/python benchmarks/structured_registration_lab.py \
  --json-out /tmp/e68-registration-new-run.json
```
