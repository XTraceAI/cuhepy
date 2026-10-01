# Construction hypotheses and finite execution packets

2026-10-01. Companion to the [contribution review](contribution-reassessment-20261001.md)
and [canonical plan](publication-research-plan.md). Every experiment below is
initially proposed. E80's [first finite screen](structured-module-screen.md)
is executed, as is E78's [relation screen](seed-composition-screen.md).
E79/E81 remain unimplemented at this return. E78/E79 retain
their earlier meanings; E80/E81
are new IDs. Ordinary algebra in a construction sketch is not an established
cryptographic construction or a novelty claim.

## Shared contract and acceptance rules

Start from the [exact owner-search contract](exact-search-contract.md): one
untrusted compute server; encrypted owner index and private adaptive queries;
every exact score and stable ID, then local top-3; owner-pinned epoch; observable
accept/abort. The owner/client may retain all plaintext. A distinct helper,
public candidate set, approximation, or top-3-only output needs a separate row.
TEE execution is an allowed separate trust mode, not a proof of an untrusted GPU.

Use homemade arithmetic and relation oracles in `experiments/bfv_search_lab/`,
runners in `benchmarks/`, and reports here. External implementations are controls.
Do not change production `src/`, existing BFV/BGV/Paillier paths, or old raws.
Do not implement a mock commitment and label it a secure protocol prototype.
An ideal-commitment experiment must be named and priced as such.

Each packet must return: exact input/output relation, all public/private objects,
closest construction and proposed difference, independent oracle/counterexample,
complete cost ledger, proof obligations, and continue/stop decision. Then update
the machine tasks and return to the plan. A stopped recipe is not an impossibility
result for its entire research family.

## H1 / E80: subring-preserving verified linear evaluation

**Priority: first constructive screen.** R3-A1, P02/P03/P07. Extends the E68
registration question; it does not overwrite that experiment.

### Proposed mechanism

The public encrypted operator is a collection of negacyclic products with
queries embedded in known subrings. E68 makes its forward/adjoint products
implicit, but its generic outer verification still operates on scalar matrices.
Try retaining a *common subring* through the outer protocol as well.

Let the inner ring be `R_Q = Z_Q[X]/(X^N+1)`. A query component of degree `n_j`
is embedded using powers of `X^(N/n_j)`. For `m` dividing every `n_j`, set
`s=N/m`, `Y=X^s`, and use `S_q = Z_q[Y]/(Y^m+1)` for outer arithmetic, with a
**separate** outer modulus q. The identity

```
f(X) = sum_(r=0)^(s-1) X^r f_r(Y)
```

expresses the full ring as a free module of rank s over its subring. Signed
rotations and multiplication can therefore be represented by matrices of
polynomials in Y. Query coordinates in a larger subring are split into
`n_j/m` module entries. This is known polyphase/module algebra; its use alone is
not the contribution.

For a **full-output, unprojected** coefficient operator of height L and actual
query width W, take `a=L/m`, `b=W/m`, and total outer lattice dimension
`d_o=r*m`. Candidate objects are

```
D_m in S_q^(a x b)       A_m in S_q^(b x r)
H_m = D_m A_m            C in {0,1}^(kappa x a)
Z_m = C D_m              Z_m u = C(D_m u).
```

C initially contains binary **constant polynomials**, not arbitrary ring
elements. This avoids treating NTT slots as independent security repetitions.
All integer lifts of D are still the prescribed centered inner-Q lifts, and
the outer plaintext encoding must recover the exact inner-Q result.

### Start with owner-generated registration

The owner knows the index and can compute/authenticate H and privately provision
C/Z once during enrollment. Use that permitted trust boundary first. It is
distinct from E77's **per-query** trusted seed factory. Do not require the owner
to prove to itself that it formed the intended index. Server-generated
registration is a separate, stronger outsourcing mode, not the default.

The first complete *known-composition control* is the following outer linear-HE
transcript, to be specified and checked before optimizing it:

1. Owner fixes the coefficient lift, module map, approved index/IDs/epoch, A,
   H and private C/Z. The client receives their authenticated registration.
2. For encoded query x, client samples fresh outer secret s and error e and sends
   `u = A*s + e + Delta*x (mod q)`, where `Delta=floor(q/p)` and p is the
   chosen outer plaintext modulus. These symbols describe a candidate LHE
   interface; they do not specify an approved sampler or parameter tuple.
3. Server returns `y = D_m*u`. Client checks `Z_m*u = C*y` before applying either
   its outer secret or long-lived inner secret to a server-supplied response.
4. Client removes `H_m*s`, performs the proved outer rounding/recovery into
   the prescribed inner-Q ciphertext, then runs the checked inner decoder.
   Setting p=Q is a candidate, not a free field identification.
5. Any failed verification retires that C/Z registration before another
   attempt; fresh private check state and all recovery work are charged. A
   different bounded-reuse policy requires its own feedback proof. H need not
   be regenerated solely because C/Z is refreshed if its binding remains valid.

This pays retained H and online H*s, but does not require an unspecified
H-prime packing function. The required decryption inequality must include both
`D_m*e` and the remainder from `q != Delta*p`: if an integer product is
`D_m*x = p*k + r`, the residual includes `-(q-Delta*p)*k`. Modular algebra alone
does not justify dropping that term. Explicitly count a full outer response and
every subsequent inner ciphertext, not only the small score result.

Owner-generated private checks initially need an appropriate module-LWE query
privacy argument, enrollment authenticity and a feedback-safe checking proof;
they do **not automatically require** a malicious-digest module-SIS extractor.
That additional obligation belongs to the server-generated-registration mode.
For that mode, specify auxiliary ciphertext safety, admissible extraction and
binding rather than assuming a public digest is correct. Compare each mode
against prior work with the *same* registration trust. The owner-generated
control is elementary composition and must not itself be advertised as a new
primitive.

Two concrete opportunities to investigate:

- At equal W, L and `d_o`, a module H has `L*d_o/m` coefficients instead of
  `L*d_o`. This is an algebraic object count for H, **not a total memory or
  protocol speedup**. Keys, other objects and larger moduli remain unpaid.
- If every coefficient of D_m has magnitude at most B_D, binary row sums obey
  `||C D_m||_coeff,infinity <= a*B_D`. The analogous scalar count uses L.
  Ask whether extraction/binding can use this smaller module-row bound while
  the encryption remains correct on the entire extracted class. Do not copy
  a scalar SIS theorem onto module-SIS parameters.

The research step beyond this control is a cheaper **complete** registration
and release representation. Investigate whether already-ring-valued responses
avoid the particular LWE-to-RLWE conversion producing H-prime, or whether
equivalent auxiliary material returns elsewhere. For a compressed-finalization
variant, H-prime is **unknown, not zero** until specified; the retained-H
transcript above is its paid fallback. A nested ring ciphertext is another
paid control, including width, query and decryption-boundary costs.

### Early falsifiers and controls

1. **No structure on the strongest profile.** Global scalar query coordinates
   have `n_j=1`, hence m=1. They get no module gain. Do not pad scalar queries
   into full polynomials and hide the upload inflation. Compare against the
   strong global E76 profile, as well as mixed and uniform subring layouts.
2. **Projection breaks closure.** E64's selected C0 relation need not be an
   S-module. Begin with full ciphertext outputs; charge every extra coefficient.
   A second variant may use unions of module-compatible coordinate groups, with
   an independently proved decoder and explicit padding costs. It is not
   permission to omit C1 or carries.
3. **The CRS/security dimension changes.** Structured A requires a specified
   module/ring assumption, adequate rank/dimension and norm estimates. Smaller
   m must not silently shrink security; infeasible parameter tuples are rejected.
4. **Short response sums are not a proof of extraction.** For a fixed nonzero
   ring-error tuple, toggling one binary coefficient shows at most 1/2 survival
   per independent row. This elementary observation does not prove reusable
   privacy, a malicious registration extractor or auxiliary-key safety. An
   owner-generated and a server-generated registration need separate theorem
   statements; the stronger registration problem must not be silently imposed
   on the simpler owner mode or silently removed from the outsourced mode.
5. **Gadget digits remain nonlinear.** The E68 scalar counterexample still
   applies. A signed digit convention may commute with signed permutations; it
   does not commute with arbitrary sums/products. Count the actual packing.

Closest controls: vReinsPIRe and small-state vLHE, with VeriSimplePIR's
extraction/reuse argument reviewed at the exact adaptation points; construction
links and execution status are in the [comparison](contribution-reassessment-20261001.md).
Use the best coefficient-packing bounds, not a full-width strawman.

### First finite deliverable

Proposed paths: `structured_module_oracle.py`, `test_structured_module_oracle.py`
under the experiment package; `benchmarks/structured_module_lab.py`; report
`docs/research/structured-module-screen.md`. These files now exist; see the
[execution report](structured-module-screen.md).

- Independent signed-integer matrix versus module oracle for N=8/16/32,
  m=1/2/4/8 where admissible, mixed degrees and multiple output blocks. Verify
  basis columns, H/Z, forward/adjoint identities, centering, and norm bounds.
- Negative controls for incompatible m, partial projection, D versus D+q, and
  illegal per-limb factorization. Exhaust tiny challenges to check the limited
  fixed-error statement separately from any feedback theorem.
- A ledger for all eight retained E68 geometries **and** E76's global scalar
  geometries. List L/W/m/r, both fields, generator/digest/auxiliary/key/state,
  setup work, online upload/reply/check work, and correctness constraints.
- A construction card that either completes the query/packing/release path or
  identifies the exact missing primitive. Supply two costs: optimistic
  necessary costs and the complete specified fallback. Neither is a benchmark.

Advance only with closure, a nontrivial protocol step beyond the known module
rewrite, and a plausible complete advantage. Stop after two focused sessions
if only H is smaller while another object or query is larger. A restricted
operator family can survive; it must have a justified workload and be compared
against the best layout, rather than relabeled as a universal replacement.

## H2 / E78: prove the composed seed-to-answer relation

**Priority: competing construction screen after H1's first decision.** R3-B3,
P02/P03/P07. E78 continues to mean certified public-seed-offset generation;
this packet sharpens what would actually solve it.

For fixed index D, projection P and expansion keys, E77 gives

```
E_j(c0,c1) = (S_j c0, 0) + delta_j(c1)
Y = A_D c0 + b_D(c1),     where A_D = P D S, b_D = P D delta.
```

These are public ciphertext relations. Neither D nor b_D is a plaintext index
or decrypted synthetic query. E77's small private gate computes
`<rho,Y> = <v,c0> + beta(c1)` using a paid private factory. **A proof that delta
is correct does not by itself produce the private scalar beta.** The new card
must solve this interface or explicitly retain/pay the factory.

Try certifying the **composition**, rather than materializing and authenticating
every expanded ciphertext as a separately consumed result. Enumerate a trace
with linear maps folded through fixed index multiplication and terminal
projection, while retaining every necessary gadget/range constraint. Separate
public seed-only work from query-bearing C0 work; seeds must remain fresh and
independent. Index/evaluation-key commitments may be reused only under a stated
proof and epoch policy. Processing batches of independent seeds is an option,
with queueing, unused preparation and failed-batch recovery charged.

Compare three complete designs before writing a proof backend:

1. Canonical expansion plus separate multiplication proof, using the best
   existing ring arithmetic/range proof as the known control.
2. Full composed proof of Y from the original `(c0,c1)`, D, keys and projection.
   Any smaller verifier state is paid for by prover work, commitments and bytes.
3. Seed-only offset certificate plus an online affine gate. If b_D is sent in
   full, count the extra reply-sized object. If it is committed, specify how
   the receiver obtains/checks the needed evaluation without exposing rho or
   reintroducing its large private vectors. An unspecified opening is a blocker.

Candidate novelty must be a new elimination/factoring of **complete proof
work or state** specific to this operator family. General proof batching,
ordinary circuit simplification, removing NTT commitments, or delaying key
switches is insufficient: the newly pinned prior constructions already occupy
those directions. Challenge domains and all original-input links remain bound;
E71's true-output/bad-proof feedback regression remains mandatory.

First deliverable: a typed relation DAG, counted witnesses/commitments/ranges/
openings for the three designs, and an independent small trace oracle. Proposed
paths are `seed_composition_relation.py`, its test, and
`docs/research/seed-composition-screen.md`; these are now implemented as a
bounded relation/count control, not a proof backend. The DAG must
carry original request, index/ID/epoch, keys, RNS moduli, canonical digits,
all branches, projection and accepted output. No long-lived secret use precedes
its matching check. At most two focused sessions before the R6 return.

Stop if a generic wrapper explains all savings, any private-beta interface is
left unpaid, or the optimistic complete count cannot improve the baseline.
Only after a surviving new step should a homemade proof/reference path and a
pinned external PCS/prover control be implemented.

## H3 / E81: bounded trace freedom with exact BGV decoding

**Priority: conditional mathematical alternative**, R3-B4, P03/P07/P10.
Activate only if canonical digit/range enforcement is a demonstrated bottleneck
in E78 or H1. This is not a plan to switch the application to approximate scores.

Question: can a larger *publicly checkable* family of evaluation traces be
proved cheaper while every admitted trace still decrypts to the exact same
Hamming scores? For a gadget relation, one could require bounded digits and
correct recomposition, allowing several representatives instead of enforcing
the canonical integer decomposition. Switching then changes the error term;
the whole circuit must satisfy a uniform bound, including an adversary's choice
of representatives. Known relaxed CKKS maintenance proofs are the direct control.

The desired theorem has universal quantification over the admitted witnesses:

```
ValidEnrollment and Relation(original_request, output, witness)
    imply Decode_sk(output) = ExactScores(index, query),
except for the separately bounded key/encryption failure event.
```

It needs a phase/noise margin for every relevant coefficient and all allowed
queries, exact integer/RNS reconciliation, and the final t>d score range.
Centering modulo Q can change reduction modulo t; a congruence alone does not
prove correctness. An adversary must not be able to choose a legal witness that
makes a private accept/reject or decode-failure bit depend on the key.

First deliverable: exhaustive tiny enumeration of canonical and alternative
decompositions, independent phase arithmetic, and a symbolic worst-case bound.
Attack controls include recomposition to x+Q, per-RNS-limb valid but globally
unbounded witnesses, negative/boundary digits, maximum-depth paths, partial
outputs and repeated rejected traces. Price increased Q, keys, HE work, ranges
and proof work at the new bound. Proposed paths: `admissible_trace_oracle.py`,
its test, and `docs/research/admissible-trace-screen.md`; not implemented.

Stop after one mathematical screen if universality fails or increased modulus
and proof work erase the benefit. Simply porting the published relaxation to
BGV is a known-method adapter, not enough for the paper. A surviving contribution
would need a new exact bound/representation consequence and complete improvement.

## Independent work and alternatives

**E79 / R2-C1:** finish real cold/new-client private provisioning and isolated
endpoint resources using the existing service harness. All keys/maps/IDs/checker
material must actually be delivered through the appropriate trusted channel.
Compare retained-owner data, authenticated snapshot acquisition, raw/compressed
retention and ordinary updates. Distinguish client, owner and server CPU/RSS,
full application bytes, wall latency and amortized enrollment. Run independent
process repetitions; size the final sample from a pilot instead of manufacturing
p95 from three observations. Keep starting states identical. This is a necessary
evaluation task, not a claimed new protocol.

**R4:** secret/recursive/block-preserving correlations remain possible outside
BFV/BGV. Revisit only with a concrete conversion for the actual F32/F23 matrices,
fresh independent ciphertexts and the full-Q gate. Original EMVP compressed
corrections and recursive BNTM are strong controls. A new public low-entropy mask
recipe is not justified by a generic LPN citation.

**R5 / E46:** exact top-3 is a separate output contract. A construction must
locate the threshold, resolve stable-ID ties, cover every omitted row, and price
comparison/conversion/proof/rounds before compressing winners. Retain dense ties,
duplicate vectors and adversarial rank/occupancy. The existing negative moment
and two-round controls prohibit treating a short answer as a free selector.

Do not run all alternatives indefinitely. After the first two construction
screens, select one survivor, or explicitly pivot to R4/R5 with a new bounded
question. Further low-level CUDA tuning stays behind that choice.

## Integration and paper milestones after selection

| Milestone | Deliverable | Completion evidence |
|---|---|---|
| M0: this planning revision | Closest-work delta, hypotheses, paths and stop rules | Review/task/link/source checks; no new crypto result claimed |
| M1: construction decision | E80 and E78 cards, optional E81; one selected resource objective or a documented pivot | Exact oracle/counterexample, full cost ledger, assumptions and one-sentence difference from each closest construction |
| M2: complete reference protocol | Homemade enrollment/query/evaluate/verify/release plus immutable contexts and private-state lifecycle | Independent score/ID oracle, malformed/adaptive/epoch/rollback tests, correct field and key ordering; no ideal proof component left unlabeled |
| M3: complete native system | C++/RNS implementation using established repository boundaries | Paired reference agreement, all setup/proof/check costs measured; GPU only for the remaining measured bottleneck |
| M4: matched evaluation | E79 complete; scale, reuse, updates and CPU/GPU/concurrency panels | Same contracts and declared security targets; holdout workloads, immutable raws, repetitions, confidence intervals and ablations |
| M5: security and paper | Conditional reduction, parameter analysis, private implementation review and artifact | Independent review of the actual accepted relation and assumptions; every paper claim mapped to evidence |

Security proceeds alongside M1–M3, not after choosing a fast but unverifiable
wire format. Begin with correctness and owner/input binding. Then argue that
an accepted bad output requires breaking the verifier/commitment; replace valid
decryption by the authorized ideal result before HE privacy hybrids. Separate
base HE, related-key/seed assumptions, module-SIS/LWE (if used), proof-system
assumptions, authenticated enrollment, failure probability and lifetime loss.
Rejections, malformed proofs, concurrency and epochs belong to the game.
Timing/access and durable state require implementation assurance beyond a
reduction. [Existing security game](exact-search-security-game.md).

For initial selection, retain the project's ≥20% complete-cost or ≥2× meaningful
state/preparation reduction targets, with an explicit bound on other costs.
They are project screening targets, not conference criteria. Report the whole
Pareto frontier and all losses. A reduction on an unused state object does not
qualify; a valuable restricted theorem can merit separate review even without
passing this engineering screen.

The minimal ablation set is: strongest generic protocol; proposed structure
disabled; equal approved parameter/profile; packing/projection on and off;
fresh-preparation costs included; full cold and returning lifecycle; cache
controls. Validate uniform/scalar/mixed subrings, full and partial replies,
small and large real data without duplicated-row scaling, dense ties and updates.
Use author timings only as cited context, never as local benchmark points.

No venue deadline licenses weaker security or a novelty assertion. Select a
venue after the main contribution and evidence stabilize; a presentation and
an archival paper are different deliverables.
