# Q41/E115: one seed-blind complete-admission implication card

2026-10-03. **Conditional deterministic relation lemma, not an implemented
relaxed verifier or a security theorem.** One exact card uses the existing
[E114 drop23 profile](query-quantizer-law-screen.md); it adds no parameter/drop
grid, key generation, native/GPU workload, proof attempt or timing. The fixed
ordinary norm/disjoint-support control receives the same lemma. No original
contribution or production admission is established.

This supplies the mathematical implication required by the
[marginal mask card](query-mask-marginal-correctness-card-20261003.md): one event
that dominates failure for **every** subsequently admitted bounded witness.
Whether an actual service enforces that relation, and its authentication,
proof soundness, sampler, feedback and private side-channel properties, remain
separate obligations.

## 1. Owner and complete relation contract

Fix the owner secret, enrolled index, all evaluation-key bodies/errors, graph,
precision, IDs and epoch before the next query mask. Use the actual coefficient
query layout and the joint butterfly, including partial tiles/groups. The
dimension is d, its padded trace degree D is the next power of two, and N is
divisible by D. All binary messages and trusted padding are encoded correctly;
t>2d and D is invertible modulo t. The owner controls stable IDs and tie order.

The owner index assumption is essential. Its tile phase is
I_i=M_i+t*e_i with |M_i,j|<=1 and |e_i,j|<=eta, so |I_i,j|<=W=1+t*eta.
This is the owner-encryption law in
[OwnerClient.encrypt](../../experiments/bfv_search_lab/owner_bgv.py) and
[seeded_bgv.encrypt](../../experiments/bfv_search_lab/seeded_bgv.py), not the
larger public-encryption error law. In particular the E106/E109 disclosed
public-encrypted index cannot silently instantiate these numerical owner bounds.
The owner query has phase u+t*E before compression, with d signed nonzero
message coefficients and CBD-support query errors. Its ORIGINAL locally pinned
bytes determine mask expansion and codec reconstruction, not a server-supplied
expanded ciphertext or RHS. The actual coefficient codec adds the small lift
delta(c0), a multiple of t; write Z=E+delta/t. The implication below does not
assign a probability law to Z.

An admitted complete response must have a witness satisfying all of these:

1. Owner-approved immutable context, exact original query, complete index/key
   enrollment, layout/ID/count coverage, graph, request and epoch are bound to
   the exact instance and ALL returned bytes. Context digests are local pins,
   not substitutes for trusted enrollment or durable authentication.
2. Every ciphertext product, monomial, addition, automorphism, relinearization
   and rotation relation is the named exact operation in R_Q. Sources correspond
   to the actual preceding graph values in order. No nonlinear cut, tail or
   unused output coordinate is omitted. Named RNS limbs must refer to the same
   global integers rather than independent limb digit strings.
3. Each cut has one COMMON integer digit tensor d_j,l, with
   0<=d_j,l<B_radix for every plane/coefficient and
   sum_j B_radix^j*d_j,l congruent to its source modulo Q. All L planes, including
   high planes, are covered. Canonical decomposition is a subset; the present
   lemma also allows the bounded common recompositions with total word>=Q.
4. Honest relin keys have phase B_radix^j*s^2+t*e_j; rotation keys have phase
   B_radix^j*sigma_g(s)+t*e_j. Every fixed key error has full coefficient support
   |e_j,l|<=eta, or a separately established uniformly bounded norm. Public-key
   bodies, guessed noise metadata, or an unauthenticated enrollment cannot
   establish these private setup premises.
5. Every final component is canonical modulo Q. Every compact-v1 component is
   EXACTLY the nearest congruent Q-to-P lift modulo P, with P<Q odd,
   P congruent Q modulo t, and the complete canonical serialization. A terminal
   modular congruence without the nearest-cell/range condition is insufficient.
   The decoder uses the matching signed ternary secret modulo P and the declared
   original score positions; it performs no earlier private operation.
6. A sound pre-private admission mechanism enforces this complete statement.
   Its proof oracle, ranges, field/no-wrap conditions, public input derivation
   and context must all be the same objects. A host acceptance flag or unrelated
   attested tape hash is insufficient. Attempts/epochs/replays are handled by a
   separately reviewed lifetime contract.

Source paths for the actual operations are
[butterfly_bgv.search](../../experiments/bfv_search_lab/butterfly_bgv.py),
[trace_bgv._switch/evaluation_keys/decode](../../experiments/bfv_search_lab/trace_bgv.py),
[native_boundary_oracle.replay/round_lift/parse_response](../../experiments/bfv_search_lab/native_boundary_oracle.py)
and [compact_bgv](../../experiments/bfv_search_lab/compact_bgv.py).
No code is changed by this card.

## 2. Pointwise algebra, including post-seed witness choices

At a switch, recomposition modulo Q makes the target contribution correct:
the difference from canonical evaluation is only the integer error lift

    t*sum_j d_j*e_j.

The negacyclic convolution triangle inequality gives, for EVERY bounded tensor,

    ||t*sum_j d_j*e_j||inf
       <= t*(B_radix-1)*sum_j ||e_j||1
       <= S=t*eta*N*L*(B_radix-1).

This is the pointwise mechanism underlying
[E102 uniform_switch_cap](../../experiments/bfv_search_lab/finite_lifetime_noise.py).
It extends to bounded noncanonical COMMON recomposition because it uses only
the digit support and the modular key target identity. It needs neither
independence of digits/errors nor fresh evaluation-key errors. Digits may be
arbitrary functions of the entire public seed, expanded mask, key bodies,
query errors, previous transcript and adversary coins; the inequality still
holds for each accepted tensor. The response need not equal the canonical
ciphertext bytes. Its plaintext correctness follows from the same uniform bound.

The established [E15 support identity](../../experiments/bfv_search_lab/support_bounds_bgv.py)
and [independent symbolic all-tail tests](../../experiments/bfv_search_lab/test_support_bounds_bgv.py)
give the complete final integer phase lift. Each final coefficient contains
D times ONE shifted input product coefficient, or no input coefficient; shifts
are signed permutations. At rotation level j the switch contribution has
remaining trace degree D/2^(j+1), with disjoint shifted supports. Consequently
the relin and rotation contributions together are bounded by

    maintenance = D*S+(D-1)*S = (2D-1)*S.

They are not D times a sum of all input tiles. Missing tails and unused output
coefficients remain covered. Multiplicative cross terms of query/index noise
are already in the original product I_i*(u+t*Z); they are not omitted from the
fresh contribution. Fixed index noise is part of its fixed weights.

For every selected product coefficient k, define its fresh pretrace term

    X_i,k = t*sum_l a_i,k,l*Z_l,   |a_i,k,l|<=W,

with the exact negacyclic wrap signs. Its nonfresh message term has magnitude
at most d*W. The coefficient-weight rule is explicit in
[finite_lifetime_noise.coefficient_weights](../../experiments/bfv_search_lab/finite_lifetime_noise.py).
Define GOOD by |X_i,k|<h for every product coordinate selected by the COMPLETE
final output map. There are at most U=N*ceil(count/N) such final coordinates;
unused output positions with zero input contribution impose no additional
random event. Bounding all U positions conservatively is valid.

GOOD depends on the fixed setup/message and expanded query phase. It does not
need a seed string, a server strategy, a target response, a target proof,
acceptance selection or an existential search over witnesses. In particular
it can be evaluated in the stopped-prefix proof calculation from the challenge
mask and independent query errors. It is not a cheap online certificate.

For every admitted bounded witness on GOOD, one final lift F has

    |F_k| <= D*(d*W+h-1)+(2D-1)*S.

Intermediate integer lifts or ciphertext components may wrap modulo Q many
times. No intermediate centered decryption or no-wrap condition is needed:
exact public ring equalities and each switch's target congruence preserve the
integer-lift relation modulo Q. Only the complete final lift bound justifies
private centering. Existing Python metadata/API guards may still reject this
profile; this algebra does not bypass them.

## 3. Terminal/private margin and exact single card

Each nearest congruent component lift has scaling error at most t/2. A signed
ternary secret has norm1<=N, so private compact phase scaling error is at most
C=ceil((N+1)*t/2). Source-component Q carries become P carries. After centered
decryption the selected integer phase is congruent to F modulo t because
P congruent Q modulo t. These carries must not be discarded before that step.

The largest sufficient final radius is

    B_safe = min(floor((Q-1)/2),
                 floor(Q*(floor((P-1)/2)-C)/P)),
    h = floor((B_safe-maintenance)/D)-d*W+1.

Require h>0. With the strict integer GOOD threshold the final raw phase is
below Q/2 and ceil(P*||F||inf/Q)+C is below P/2. Therefore compact centering
preserves the correct plaintext polynomial modulo t. The inverse of D, t>2d,
and the original parity/range/position rules yield every true Hamming distance;
the owner-local ID map yields the declared stable top-k. This is correctness
of the function for all admitted witnesses, not canonical ciphertext equality.

The preregistered exact calculation uses the existing drop23 owner profile:
N16384,d512,count8192,t1031,eta21,radix15,L4,D512,
Q1152921504606748673 and P4294953991.

| Quantity | Exact integer |
| --- | ---: |
| W |21652|
| S |46493749542912|
| Complete maintenance |47563105782398976|
| Message contribution before trace d*W |11085824|
| Terminal rounding C |8446468|
| B_safe |574193413656199173|
| First unsafe fresh magnitude h |1028574808980193|
| Last-safe final envelope |574193413656199168|
| First-unsafe final envelope |574193413656199680|
| Last-safe compact phase bound |2147476995|

All quantities match the final E114 card exactly. The last-safe compact bound
satisfies strict2G<P=4294953991 by one integer unit. The +1 and integer floors
are material. No statistical probability is calculated anew here. E114's
unit/full-uniform-mask certificate is one conditional probability control for
this event; a different nonunit/prefix/ROM control requires its own derivation.
The deterministic implication itself does not require IID Z or a unit secret.

## 4. Direct range-omission diagnostic and present implementation stop

`native_boundary_oracle.replay(canonical=False)` is an omission seam, **not**
an implemented bounded semantic admission gate: it checks each digit row as
an exact integer polynomial but supplies no coefficient modulus/range. In
contrast E108's compiler derives digits from one Boolean, range-bound source
string, and E109 proves that complete CANONICAL relation. Neither existing
proof adapter accepts the following witness.

At a source0 cut, the balanced carry d0=B_radix*H,d1=-H,other planes0
recomposes exactly0 while adding t*H*(B_radix*e0-e1) to the phase. Thus modular
recomposition alone does not bound maintenance. The frozen public integer
diagnostic uses the same numerical profile and legal all+1 query/index vector
messages. Choose secret1, zero owner/query errors and ideal query/index masks0;
raw key masks0; only the first relin error is X^(D-1), all other key errors0.
These are supported algebraic realizations, not sampled setups. All256 index
tiles are full, with allN message coefficients1, in one partial512-tile group.
The original query has512 signed coefficients1 and16384-512 zero coefficients.
Literal drop23 compression adds delta4194108 to EVERY query coefficient,
including the unused positions. Its fresh product magnitude is at most
N*delta68716265472<h, so this query is GOOD; the complete envelope is
47598294186262528<B_safe. Every graph C1 is identically0 because the original
and all switching-key masks are0. The diagnostic therefore rounds the actual
canonical C0 component and the zero C1 component, rather than substituting
rounding of a two-component phase.
The monomial/trace map places the extra error in final coefficient0 with
factorD. The calculator uses

    H=ceil(3Q/(5D*t*B_radix))=39991937,
    (d0,d1,d2,d3)=(1310455791616,-39991937,0,0).

The honest selected product coefficient is
`d+delta*(2D-N)`, including the negacyclic wraps of the allN index polynomial;
the final honest phase is D times that integer. Removing the digit bounds
admits the SAME fixed carry:

| Affected coordinate | Honest | Range omitted |
| --- | ---: | ---: |
| Signed integer final phase coefficient0 |-32983807164416|691719935824756736|
| Nearest congruent lift of canonical C0 |4294831572|2576849709|
| Centered compact phase |-122419|-1718104282|
| Decoded correlation |512|148|
| Hamming distance |0|182|

The wrong correlation148 passes the ordinary dimension/parity tests. This is
a concrete full-graph phase-algebra falsifier for unbounded admission; decoder
range checking is not a substitute for the missing witness range. All other
coordinates can follow the honest graph. The query/index/key ideal masks and
error realizations are explicitly chosen, and no actual SHAKE seed preimage,
compressed packet, large API execution, native run or cryptographic proof was
produced. The actual generic keygen still refuses these large parameters.
This is not an attack claim against E108/E109 or the deployed Paillier fallback.

E106/E108/E109 therefore supply source-linked canonical controls and a known
proof-interface reference, not a present large owner-only relaxed admission
service. [E109 release](../../experiments/bfv_search_lab/proof_backend_adapter.py)
does derive the original/full-wire statement locally and verify before its
diagnostic callback, but its pinned instance is the tiny E106 Q120 fixture.
Its tests and eight actual proofs do not assign an adaptive soundness budget.
[E112](tee-oracle-partition-screen-20261003.md) additionally stops the proposed
TEE/affine split until the attested tape equals the actual proof oracle.

## 5. Probability, false admission and feedback remain distinct

Pathwise, under the preceding semantic relation contract,

    admitted wrong decoding
      implies bad setup/provenance OR not GOOD OR false admission
              OR implementation/private-finish contract failure.

This implication allows unconditional union accounting across generated
queries/attempts/epochs. It does not say that correctness conditional on a
server-selected response subset has the same probability: a server can respond
only on rare bad masks. Count generated/abandoned queries, seed grinding,
replays and every new setup according to the reviewed experiment. Pointwise
witness coverage removes a probability union over digit strategies; it does
not remove authentication/proof/callback/lifecycle budgets.

Only after defining suitable games and budgets may a correctness bound have
the schematic form

    epsilon_setup + sum_i(delta_i+alpha_i+Adv_i)
      + epsilon_admission/lifecycle + epsilon_implementation.

Here delta_i is the eligible ideal GOOD-complement bound, alpha_i is bounded
stream exhaustion, and Adv_i is the explicitly applicable marginal PRG/ROM
term. The publicly revealed pair(seed,SHAKE(seed)) cannot be replaced by an
independent joint pair through an ordinary PRG hybrid. This card needs only the
seed-blind sufficient event, with uniform coverage of subsequent seed-dependent
responses. It provides no concrete SHAKE advantage or quantum model claim.

Feedback security is a separate reduction. One must specify observable
verification/decoding/result bits, permitted ideal-function leakage, proof/PCS
extractability or semantic simulation, setup/KDM assumptions, attempt state,
and private constant-time behavior. Sound admission plus GOOD prevents a
chosen witness from changing the mathematical decoded result. It does not
prove that secret-dependent timing, parsing, crashes or memory accesses are
simulatable, or turn a correctness budget into a confidentiality theorem.
No separate finite feedback advantage is assigned by this card.

## 6. Preservation and bounded return

The calculator uses only exact scalar integer arithmetic and reads fixed prior
JSON/source hashes. The original calculation/draft were preserved when final
review caught a component-rounding error: a delta0 nonzero-mask query can have
nonzero C1, so rounding its final phase directly was not a valid compact-v1
diagnostic. The correction was frozen before execution; it uses mask0, retains
the actual nonzero codec delta, rounds the actual sole C0, and keeps the same
profile/H formula without an endpoint search. The deterministic implication
and boundary card did not change. Both exit0 records remain outside Git under
`../research-data/seeded-correctness-20261003/admission/`:

- `preregistration.md`, frozen before calculation, SHA
  `1b7846632c874cfba326c191e8a9d7dc2923ae8aeda1df5917948b0dc82255c9`;
- `component-rounding-amendment.md`, SHA
  `1a88b7cbbc552c3a7d160446cd24c65f2d8cc282d8f78679abcb5b772a008e8f`;
- `component-rounding-freeze.json`, final source/context/calculator pins, SHA
  `33820f3b28c57cc87ca71b77c2abd389169fe3321feee6e6daff2ff988ab1610`;
- `admission_calc.py`, final SHA
  `b3f5991be4d0aabdf5c218f937993aadac1395f8bad7a13317203f84c1acbec7`;
- `raw-component-rounding-fixed.json`, final exact fields, SHA
  `fb3fec2a7cc4e468fd09b4e6b8757333fdf500fb71e4859a64f217cb9a1cc373`;
- `before-component-rounding-correction/`, the old calculator/raw/freeze,
  original preregistration, first report draft and preservation receipt. The
  original `raw.json` is retained as the superseded diagnostic, not final evidence.

No earlier implementation, report, fixture or raw was modified. This bounded
mathematical component is complete. A real relaxed proof/admission adapter,
owner-only large setup, actual entropy/seed model, false-admission/lifetime
reduction, complete paid costs and private-side assurance remain unimplemented
or unapproved. The result is a standard conditional composition control;
there is no original-main or production-security pass.
