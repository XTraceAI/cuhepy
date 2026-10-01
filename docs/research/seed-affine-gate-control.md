# E77: seed-conditioned affine gate shrinks one receiver, not the whole system

2026-10-01, R3-B1/B2 return after the strong enrolled service control.
[Preregistered discriminator](seed-affine-gate-preregistration-20261001.md).
Homemade [oracle/factory/receiver](../../experiments/bfv_search_lab/seed_affine_gate.py),
[tests](../../experiments/bfv_search_lab/test_seed_affine_gate.py),
[runner](../../benchmarks/seed_affine_gate_lab.py),
[raw](../../benchmarks/results/publication-seed-affine-gate-control-20261001.json).

```sh
.venv/bin/python benchmarks/seed_affine_gate_lab.py --json-out benchmarks/results/publication-seed-affine-gate-control-20261001.json
```

## The precise identity

Every E73 expansion gadget decomposition acts on C1. For a fixed original C1,
its carries/key-switch offsets are independent of original C0. The complete
expanded query has the form

```
E_j(c0,c1) = (S_j(c0),0) + delta_j(c1),
S_j(c0)[i] = H*c0[i+j] mod Q if i = 0 mod H, else 0.
```

Delta is canonical expansion of `(0,c1)`. That synthetic input is **public
algebra only**, never decrypted or claimed to be a valid fresh encryption.
The identity is field-linear in c0 **conditioned on c1**; it does not commute
gadget digits or carries through an arbitrary input matrix.

For an old private projected fingerprint `(Z0_j,Z1_j)`, compile
`v = sum_j S_j^T Z0_j` once. For each independently fresh C1, prepare
`beta = sum_j(<Z0_j,delta0_j> + <Z1_j,delta1_j>)`. The expected full projected
body fingerprint is `<v,original_c0> + beta`. This is the same public circuit
relation as the canonical expansion/multiplication gate, not a check of a
server-chosen expanded query. No omitted C1, C2 or supported C0 is trusted.

## Executed boundary

**112 searches** over the seven retained toy layouts pass every coefficient
product, compiled fingerprint identity, exact score/ID and stable top-3
comparison with the full E73 circuit. Sixteen scoped tests also cover arbitrary
C0 affinity, literal selector/adjoint basis columns, mixed-degree and three/four
column cases, every output component, false expansion, malformed/replayed
release, changed C1/context, missing beta and reused C1.

The online receiver stores vectors/challenges and pinned original queries. It
retains no HE secret, encrypted index, expansion keys or expanded fingerprints.
A **separate trusted private factory** retains the old large fingerprints and
does a complete canonical zero-C0 expansion for every fresh C1. Owner identity
separates factory registrations; the local binding hash is **not a MAC** and
cannot authorize hints from an untrusted helper. Private provisioning and
durability remain protocol work. The same lifetime object is shared; rejected,
malformed and replayed release attempts burn before any key use. No extra
proof-round predicate is exposed. The ideal full-body fingerprint argument
still requires hidden uniform challenges and a matching seeded/feedback/timing
composition; these regressions do not prove that composition.

## Paid state and work

All tiny cases have N32,h4,H4,Q32,k4. Online compiled vectors shrink
**4,096 -> 512 B (8x)**. But the trusted factory still keeps4,096 B, plus shared
private challenges1,152–4,192 B, vector state, per-seed16 B scalar constants,
seed digests/IDs/lifetime sets and pinned original ciphertexts. Counts are body
models, not Python RSS. Receiver currently stores full vectors and original
two-component ciphertexts; possible sparse/vector or seed-only storage is a
separate model, not implemented compression.

The smaller gate/decrypt/decode stage takes median0.152–0.358 ms instead of
0.240–0.453 ms. The complete **client + trusted seed-factory** stage sum is
**4.7–7.8% slower** across the toy cases: fresh seed expansion/digest work costs
1.319–1.341 ms. Public query packets231 B and projected responses288–1,048 B
are unchanged. These are toy paired stage observations, not service, large
system or GPU confidence estimates.

| Retained profile, count only | Online full compiled vector body | Old fingerprints still at trusted factory | Fresh trusted seed expansion products | Fresh scalar constants |
|---|---:|---:|---:|---:|
| Mushroom selected,N16384,Q72,k2 | 294,912 B | 18,874,368 B | 1,116 | 18 B |
| Semeion selected,N16384,Q72,k2 | 294,912 B | 13,565,952 B | 1,116 | 18 B |
| Connect-4 global raw,N2048,Q70,k2 | 35,840 B | 9,031,680 B | 4,572 | 18 B |
| Connect-4 global affine,N2048,Q69,k3 | 52,992 B | 8,690,688 B | 4,572 | 26 B |

All eight geometry screens inherit E73's conservative correctness modulus,
evaluation-key/public wire costs and unapproved related-secret assumptions.
They do not measure large expansion or show parameter assurance. The online
vector has at most N active coefficients; inactive-residue packing is counted
separately. Whole unique state increases by that vector; the factory is not free.

## R6 decision and next discriminator

**Keep the exact factoring control; stop the literal helper version as a
whole-system or paper winner.** It moves the large private fingerprints and
full per-seed expansion to an owner-controlled verifier. Affine hoisting,
selection and Freivalds checking are known ingredients, not an originality
claim. It is nevertheless a sharper construction interface than duplicating
the entire query-bearing expansion at the online client.

Next ask whether canonical public-seed offsets can be **certified or generated
with genuinely cheaper total trusted work/state**, while preserving fresh
encryption and full rejection-safe release. A certificate must bind digit
canonicality/ranges and all C1 branches; a linear product check alone is
insufficient. Compare ring-native public proofs and existing reusable vLHE,
charge setup/commitments/RTTs and test adversarial intermediate traces before
any acceleration. Reusing seed offsets across queries is rejected, not an
amortization method. R3-A0's carry-aware outer registration remains a separate
open construction. No original useful mechanism is selected yet.
