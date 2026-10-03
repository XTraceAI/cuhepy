# Q51 first component: source-certificate eligibility premise card

2026-10-03. **Outcome: explicit unmet premises; no source certificate is
activated.** This closes only the first static source/prior/assumption ledger
component of the [Q51 plan](source-certificate-eligibility-plan-20261003.md).
No parameter, root, probability, Fourier exponent, constant, lifetime union,
test, HE/key/seed, estimator, native/GPU, proof, service or timing calculation
was performed. Numbers below are copied recorded inputs, not recomputed
results. Existing guards, samplers, code, registry and governance are unchanged.

## Fixed recorded source and the intended event

Reuse [E120's recorded source](multilimb-consequence-screen-20261003.md), without
another selector: N16384, d512, count8192, D512, t1031, CBD parameter21,
requested RNS120, common radix30 and terminal25. The recorded source-order
primes are `1152921504606748673`, `1152921504606683137`; the recorded product
is `1329227995784613643754746428306227201`, and terminal P is `33548413`.
The unchanged prospective owner candidate is drop87; the registered
deterministic baseline is drop81. No different profile, root, precision,
favorable key, unit rejection or field conditioning is selected here.

Source law: [shallow_bgv.key_gen](../../experiments/bfv_search_lab/shallow_bgv.py)
calls `_ternary_poly` at78. The helper in
[scheme.py](../../src/cuhepy/bfv/scheme.py), lines245-246, samples each
coefficient using `secrets.randbelow(3)-1`, then represents it modulo the
whole Q. Under the explicit honest independent-OS-coins model this is raw IID
uniform ternary S, including zero, with no secret-dependent rejection.
The same integer S reduces into both limbs; limb/root independence does not
follow. The source implementation's OS calls are not an entropy assurance proof.

The intended setup bad event is zero S or a nonzero S with at least four
distinct roots of `X^N+1` vanishing in either source prime field. A quartet
bound must cover EVERY prescribed four-root subset, not average subsets,
structured binomial packets or sampled roots. It is a once-per-generated-key/
enrollment event, not a fresh event charged per query. A good setup would
permit a stronger common-window premise, but neither its probability nor the
subsequent owner correctness/decoder implication has been certified here.

## Eligibility ledger

| Premise | Recorded support | Present status / missing item |
|---|---|---|
| Fixed prime/source graph identity | E120 records source-order selector reproduction, unsigned64 prime/splitting/congruence checks, schemas and source hashes. `_rns_coefficient_primes` is deterministic with GMP probable-prime selection (`scheme.py:197-218`). | Recorded evidence retained; no new prime/order/root computation or parameter-security assurance. A later proof must bind the exact prime-validation method, field and graph. |
| Raw secret law | Whole-Q ternary helper above; no unit rejection. | Source match under honest independent OS coins; actual entropy/adversarial setup provenance remains separate. |
| HPX law/degree match | Degree-at-most `n=N-1`, four distinct simple prime-field roots; H4, d4, derivative parameter K0, extension degrees1. Prime-field anti-subspace parameter is `eta_HPX=2/3`, distinct from CBD parameter21. | Algebraic/model match only. No numerical threshold/exponent comparison was performed. |
| Cyclotomic high order | Target root set is the split two-power cyclotomic set, with order `2N`; E120 records splitting/congruence checks. | HPX's QUANTITATIVE high-order and degree-range conditions remain unverified with a coherent explicit constant. Merely naming that order does not verify them. |
| Coherent quantitative HPX certificate | Proposition6.2(2), Definition6.1 and Theorem4.1, archived exact v2. | Final C is unprovided; the full sign/index/constant chain is not an executable reviewed certificate. Local coefficient200 is not final C. |
| Honest generated-key/enrollment bound | Q49 proposes a global epoch budget; the source audit finds no total global enforcement. | Unenforced/unresolved. Failed, abandoned, retried, updated and re-enrolled setups must count. New instance/local query caps do not establish a total. |
| Allocated root-defect failure budget | Q49 proposes per-event192 targets for other setup/query concentration terms. | No source-specific quartet-defect allocation or complete-system failure allocation was established. Do not infer one from those targets or copy an earlier query-only ROM exponent. |
| Owner-index origin and phase | Hypothetical new owner enrollment has M+tE. Historical owner-pipeline index uses PUBLIC encryption. | Actual typed owner enrollment/provenance is unimplemented. Public phase terms cannot be relabeled M+tE. |
| Seed/lifecycle transfer | BGV OwnerClient/seeded_bgv share the exact frame; the completed read-only audit lists extra draws. | `A_other` UNKNOWN/unbounded by source. Concrete SHAKE, OS coins, durable counters/admission, rollback and concurrency are not certified. |
| Complete terminal/decoder implication | E120 complete graph/schema/all-choice maintenance controls and general guards are retained. | Candidate87 remains rejected by existing complete product/terminal metadata guards; a root lemma alone cannot change that. Q49 statistical/typed certificate remains unexecuted. |
| Paid application/verification frontier | Existing plans require enrollment, updates, keys/state, packets, authentication/proofs, trusted work and permitted cache comparisons. | No matched complete frontier or device/lifetime restriction selects this application. Unknown verification/lifecycle costs are not zero. |

## Strongest primary control and the precise unproved target

The [retained HPXv2 comparison](joint-root-census-prior-comparison-20261003.md)
pins the exact primary PDF SHA256
`4d843340d54cdcbb3c8fd6104d5ebc7669b14afe94946aebf396d09148e7af6b`.
The relevant full pages were previously rendered/read; this component reread
the retained theorem text and reading, and fetched no new source.
Theorem4.1 states a degree condition `n >= C*d*log(p)*log(d*log(p))`;
Definition6.1 uses high-order threshold
`C*H*(K+1)*e*log(p)*log(H*(K+1)*e*log(p))`. Matching constants and exceptional
boundary conventions must be resolved coherently. Proposition6.2(2)'s stated
negative error form is

    exp[-eta_HPX*n/(C*d*log(p)*log^5(d*log(p)))].

The exact PDF also has apparent positive-sign displays in Theorem4.1/equation4.2
and a multiplicity index inconsistency; these are not silently repaired.
The explicit negative Proposition6.2 claim and direct prescribed multiple-root
method remain prior containment. There is no permission to guess C, treat200
as final C, or infer source usefulness from the finite census.

A potentially useful stronger target, still **UNPROVED**, would supply explicit
finite constants and source-applicable bounds U_i simultaneously for ALL
quartets under the unchanged raw law, strong enough for a declared enrollment
budget and allocated defect term. The proposed plan's ordinary implication is

    beta_setup <= 3^-N + sum_i choose(N,4)*max(0,U_i-3^-N).

The atom is charged once; U_i must be a valid unconditional quartet bound and
cannot lie below the zero atom. No root/limb independence is assumed. A complete
certificate must multiply a valid setup bound by the declared GENERATED-epoch
budget and pay all remaining correctness/admission/seed/verification terms
separately. Since that epoch bound and failure allocation are unresolved,
this card does not derive a numerical required U_i, select an optimistic C
envelope or evaluate the formula.

An explicit all-subset certificate is not automatically original: the generic
joint near-uniform theorem and multivariate Fourier/recurrence mechanism are
already known in HPX. A contribution would require a PROVED concrete-strength
difference from that informed prior, or a distinct fully paid system consequence.
Neither exists in this card. The finite N16/q97 census is supporting evidence,
not an all-subset/source-prime theorem or parameter estimator.

## Equal controls and the usefulness obligation

The equally informed generic receives the same source/raw law, any proved
certificate, the deterministic nonzero-secret norm/CRT bound and every cyclic
window/regular-cover Bernstein/Hoeffding control. E120's recorded deterministic
caps(1911,1911) and common window14473 remain the existing control; their known
derivation and E121's window machinery are not a new algorithm. E102's
restricted-conditioning/L1 evaluation-key control is not substituted for an
owner-index squared-error event. A proposed smaller defect bound alone does
not establish a new compression, verification or performance theorem.

The unchanged drop87 candidate has a recorded HE-format exchange192708 B
against204996 B for baseline81; this is a copied packet ledger, not measured
network benefit or an admitted encrypted query result. Full response positions,
owner re-enrollment, every key, persistent state, updates/rebases, original-query/
response/epoch binding, actual receipt/proof transport, trusted compute and
rollback must remain paid. Do not extrapolate tiny E109 proof or E117 protected
state counts as this large-profile verifier. Those controls and a reviewed ring
proof adaptation remain strong comparators with unknown matched costs.

[The user-authorized contract](exact-search-contract.md) permits retaining the
full plaintext index. Full-cache/download-once exact search and durable protected
replay therefore remain required competitors. No invented memory/retention
restriction justifies an outsourced result. Project decision thresholds are
not evidence of a matched useful deployment or an original main.

## Executable requirements for a later component; no automatic GO

1. Freeze one source/law/owner-origin and lifecycle contract: actual admitted
   producers, global generated epochs and polynomial counts, retries/updates,
   seed-domain address convention and enforcement versus explicit assumptions.
   If no finite trace or scoped assumption is justified, retain the unresolved
   status. Do not set A_other=0 by convenience.
2. Register the complete correctness/verification failure allocation and a
   matched usefulness objective with permitted cache/protected/proof controls.
   Specify which existing constraint or resource the certificate would improve;
   unknown costs stay unknown. No probability application precedes this contract.
3. Either audit one coherent explicit HPX constant/premise chain, or state one
   exact stronger target and compare it to that same-informed known control.
   Keep theorem form, boundary/zero/reduced-root issues and all subsets/limbs
   explicit. If a certificate is known/applicable, classify it as supporting.
4. Only after those gates, freeze one scalar method/input/resource cap and obtain
   separate root GO for any later numerical diagnostic. Before such GO, stop on
   unmet constants/range/lifecycle/usefulness rather than search a toy grid,
   change the profile, reject secrets, tune precision or start a backend.

The present outcome is itemized unmet premises, not impossibility of a stronger
bound and not an accepted stronger theorem. Q49 numerical work and all scientific
operations remain closed. The [source-hashed external receipt](../../../research-data/joint-root-census-20261003/source-certificate-eligibility/component-receipt.json)
authenticates this first static component; root owns later governance/checkpointing.
