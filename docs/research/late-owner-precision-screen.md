# E95/E96: reusable target precision and its security prerequisite

2026-10-02. Parent `2290f4b`, branch
`experiment/late-owner-precision-20261002`. This executes Q21, returns to R6,
then executes the Q22 parameter prerequisite revealed by that return.
**Keep the exact controls; stop generic shared rerandomization as an original
mechanism, and exclude the small target prefixes from 128-bit design claims
under the named classical model.** No original complete main protocol is selected.

The [restricted lemmas](late-owner-precision-lemmas-20261002.md),
[E95 preregistration](late-owner-precision-preregistration-20261002.md),
[E96 preregistration](target-prefix-security-preregistration-20261002.md) and
[isolation refinement](target-prefix-isolation-preregistration-20261002.md)
state assumptions and immutable execution scopes. The
[validation receipt](late-owner-execution-validation-20261002.json) and
[identity manifest](publication-late-owner-execution-manifest-20261002.json)
pin sources, raw results, literature and preservation checks.

## E95A: fresh rounding for any fixed target key

Fix the entire original input/key/reply family before a fresh honest owner
samples independent uniform coefficients rho and independent CBD error E0.
One owner zero `(-rho*T+E0,rho)` is added to every compatible switched reply.
For odd Q and dyadic rounding modulus B, every fixed offset plus rho is
uniform, and its rounding numerators permute the centered residues modulo Q.
This supplies a conditional fixed-T law without assuming that T remains IID
after the public key history. Old switching error and the actual derived S-squared
residual are bounded deterministically. Common views are covered by a union
event, without assuming independence between views.

The independent finite oracle covers 350 all-offset scalar contexts, 6,750
residues, 225 fixed-secret/offset families, 50,625 fresh-coin support branches
(90,000 weighted coin outcomes), eight shared views and **810,000 integer
phase identities**. Tiny bounds are vacuous, not negligible-failure experiments.
An N128/Q3/B2 case has a genuinely nonzero exact rational tail of approximately
`7.955e-8` at threshold 49. It is an arithmetic control, not a cryptographic
failure estimate for the larger contexts.

Choosing an input after rho, or reusing rho at a new adaptive input, forces
error 2,048 against an incorrectly applied threshold 272 in the registered
falsifier. This shows why the ordering premise matters. Two masks sharing a
zero have a fixed difference, unlike independent fresh ciphertexts. Adding a
bounded zero also preserves old noise. Consequently the full statistical
fresh-encryption premise of [the drift paper, Proposition 3.5](https://eprint.iacr.org/2024/1718)
is not established; neither its complete ACER conclusion nor confidentiality
follows from this restricted rounding lemma.

## E95B: bounded homemade interface and receiver controls

The reference is in `experiments/bfv_search_lab/late_owner_precision.py`.
Owner generation uses true per-coefficient OS sampling and homemade GMP ring
arithmetic, with no SEAL scheme import or public seed replacement. It is a small
private diagnostic implementation, not a constant-time production backend.

A full public recomputation certificate binds originals, reused keys, owner
packet, switching, rounding and precision events. All **65 corruptions** reject
before an opaque callback. A valid callback executes once; replay rejects.
Reservation precedes generation, abandoned slots are burned, and consumption
precedes the callback, including callback failure. The tested volatile ledger
does not provide durable rollback/fork assurance. An owner label or digest
does not prove honest sampling, zero encryption or chronological provenance;
those are trusted input assumptions here. The callback is not permission to
decrypt an untrusted response.

A fresh ordinary public-key **homemade BGV** toy differential reuses one target
and switching-key set across two adaptive query families and two fresh owner
zeros. It checks all 16 decoded coefficients and 32 mixed/rounded phase
coefficients. It does not execute PBS, a compact verifier or an approved scheme-
switching protocol. Source/zero lifetime allocation bounds two arithmetic terms
by a sum at most `2^-128`; proof, PBS, hardness, sampling, seeds, lifecycle and
private failure terms remain separate and uninstantiated.

## E95C: paid counts and strongest known controls

There are 160 geometry/lifetime/sparsity/omission tuples and 1,600 degree points.
At the historical prefix p512, 50 tuples use half the first passing degree of
the deterministic reused-key control. The late-zero and fresh-target bounds
have identical first passing degrees in all 160 tuples. An equally shared
standard rerandomization adapter has identical arithmetic, binding subrelation
and resources. **Stop the generic composition novelty claim.** These numbers
are sufficient-bound/count comparisons, not measured elapsed or PBS feasibility.

An unseeded zero adds 1.58–8.69% to the registered seeded-query coefficient
body, before framing/proofs. In the mushroom baseline it is 204,800 bytes per
family versus 1,434,048 bytes for a fresh target-key packet with seeded masks.
At 4,096 queries the cold product counts are 4,110 versus 57,344. Counts include
setup and do not establish client runtime or overall usefulness versus a
permitted plaintext cache. The small target support is qualified by E96 below.

The stronger colocated owner/client control can pin the original query locally
and send **either** a new zero **or** fresh keys with that query. Both have zero
extra RTT in this model. Earlier E93/E94's separate-provisioning RTT is a
deployment assumption, not an inherent lower bound for fresh keys. Preserve
those old receipts while using this stronger control going forward. Public
seeded zeros need their own ROM/provenance argument; the unseeded law is not
silently transferred to a public deterministic expansion.

## E96A/B: exact independent samples and a limited negative security screen

A publicly known zero suffix changes the unknown key dimension. For prefix p,
select zero-body positions `p-1,2p-1,...,floor(N/p)*p-1`. Their equations use
disjoint, unwrapped uniform mask blocks, with independent CBD errors. L fresh
zeros therefore supply `L*floor(N/p)` genuine independent p-dimensional LWE
rows. No assumption that all N ring rotations are independent is needed.
An exhaustive N4/p2/Q3 oracle checks **59,049 complete cases and 118,098 row
equations**. This is an exact sample relation, not an executed recovery attack.

The external lattice-estimator revision
`53da5982597709ba0fdf94ea37a84d822310fd84` is a reference cost tool, not an HE
scheme dependency. Using Sage 10.9, MATZOV-classical/GSA, CBD21, uniform ternary
unknown prefix, the six exact E94 Q/N contexts and a 4,096-zero lifetime gives
22 profiles. The table reports the minimum returned `log2(rop)` among the
four selected usvp/bdd/dual/dual-hybrid calls:

| Source N | Exact Q | p512 | p1024 | p2048 | p4096 |
|---:|---:|---:|---:|---:|---:|
| 16,384 | 644344206950401 | 42.55 | 69.57 | 139.36 | 302.08* |
| 16,384 | 18050398289921 | 42.75 | 77.33 | 156.66 | 342.04* |
| 16,384 | 463122399035393 | 42.57 | 70.21 | 140.73 | 305.38* |
| 16,384 | 23006066442241 | 42.73 | 76.74 | 155.26 | 339.01* |
| 2,048 | 8884180307969 | 42.83 | 79.15 | 160.27 | unsupported |
| 2,048 | 5781768241153 | 42.88 | 80.26 | 162.97 | unsupported |

`*` The isolated dual-hybrid call timed out; the minimum uses returned attacks
only. These are **heuristic classical cost estimates**, not measured attack
times or proven security levels. All twelve p512/p1024 profiles fall below 128
and are stopped as 128-bit candidates under this model. Larger supports pass
only the returned estimates; quantum/other attacks, structured algebra, key
graphs, proof/seed/sampling and private implementation remain open. No context
is approved. This concerns experimental target keys, not a finding against
production full-ring BFV/BGV or Paillier keys. The targeted
[HE security guidelines](https://eprint.iacr.org/2024/463) reading distinguishes
secret/error distributions and parameters; it is not a full parameter audit.

The initial soft timer was swallowed in a Sage C call: one finite dual-hybrid
result took 16.64 seconds despite a ten-second cap. The initial result and
runner are preserved. Two subsequent cohorts use parent-enforced isolated
workers. Both return the same 84 finite costs and four timeouts. Every finite
cost also returned by the initial cohort agrees; the over-budget initial call
is unavailable under the hard cap. Its missing cost explains the changed
minimum in the second p4096 row. Estimator execution time is execution metadata,
not HE performance. Archive the exact external tracked source for reproducibility.

## E96C: precision repricing, then R6

An independent integer runner reproduces all 1,600 E95 points before expanding
to **720 support/geometry tuples and 8,640 degree points**, through `2^22`.
At p2048, 140 of 160 tuples first pass the late-zero bound at degrees between
262,144 and 2,097,152; the remaining 20 do not pass the declared grid. At p4096,
100 of 120 pass between 262,144 and 4,194,304. A full-N16384 control passes
90 of 120; two more have a passing fresh-target bound only. No actual lookup
ring/PBS is implemented. Named security statuses refer to the registered
4,096-zero horizon, not newly estimated costs for every lower lifetime.
The equally shared known-zero control retains the same frontier everywhere.

The p512 advantage must not be sold as an equal-security result. Larger-support
cards expose a real precision/assurance bottleneck; their limited positive
estimates do not close it. Return to the earliest unmet mechanism/assurance
gate, rather than optimize another unapproved small key.

**Next:** [Q23/E97](owner-bound-rounding-plan-20261002.md), proposed and
unimplemented, compares a complete owner-bound stochastic-rounding control.
Standard randomized rounding may avoid owner zero products and additional
public LWE samples; unseeded coins still cost traffic and seed compression needs
a separate proof. First review and prove its fixed-input law, then exact controls
and complete costs against shared rerandomization. It is a missing strong
baseline, not automatically an original contribution. Compact original-score
binding/shared proof or a justified compressed-query construction remains the
possible new step. All broad Q6–Q10 gates remain conditional.

**Validation:** 365 tests pass across sixteen specified CPU files, including 56
new tests; explicit Ruff includes eight new Python paths. E95, isolated estimates
and coupled precision repeats match in their stated semantic scopes. Seven raw
receipts retain parent HEAD plus exact working-source hashes. Sixty-two primary
PDF/text pairs, earlier scopes/receipts, company code, main/staging and frozen
timing measurements are preserved. No new cryptographic timing, complete security
reduction or original conference contribution is claimed.
