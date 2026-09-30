# Executable mechanism hypotheses after E65

2026-09-30. Companion to the [canonical plan](publication-research-plan.md).
Everything labeled E66–E69 below is **proposed**, not a new measurement or
implemented protocol. E47 has only its recorded algebra oracle; E46 has earlier
selection-related ingredients, not the complete construction specified here.
Paths listed as deliverables do not imply those files exist.

## Entry task R0: construction cards before implementation

Proposed output: `docs/research/protocol-baseline-cards.md`, with any executable
adapters and reproduction receipts linked from that file. Start with the
vReinsPIRe and small-state vLHE constructions that could instantiate track A;
then the relevant EMVP compression/recursive BNTM and terminal-release modes.
Reuse the existing source registry and author runs. A full reproduction of
every alternative is not a prerequisite for the first algebraic screen.

Each card records the exact paper version and construction/theorem, setup and
key holders, who knows the matrix/query/result, output and leakage, observable
accept/abort behavior, owner binding, admissible versus honest input norms,
arithmetic fields, and reusable versus consumed material. Give formulas for
all setup/private state/query/reply work and bytes. Identify which operation
needs an explicit matrix and whether the proof requires more than fast forward
and adjoint products. Record the adapter needed for our owner-encrypted index
and its additional assumptions and costs.

An executable comparison also records the artifact commit, parameter tuple,
exact invocation, score/ID check and source/raw hashes. A theorem-only card
states which construction components remain unimplemented; unavailable code
does not justify treating that competitor as slow. R0 is complete when these
premises are clear enough to instantiate or rule out the selected comparator,
with the outstanding reproduction work explicitly assigned.

## A. E68: preserve operator structure through verified private evaluation

**Question.** Can we remove the owner's per-query encrypted answer factory
without recreating its cost as a large outer matrix, an outer ciphertext, a
private hint or a client-side computation?

Let the public encrypted index have F column ciphertexts across R replies of
ring degree N. Let a(w) be the W actual centered coefficients of the private
query forms, with the correct subring embeddings. The prescribed public
operator A_C over F_Q consists of signed negacyclic shifts of those ciphertext
columns. An honest direct result is

```
z = A_C a(w) mod Q.
```

The server knows A_C but not a(w) or the plaintext index. A verified private
linear-evaluation layer could deliver z; its acceptance and owner binding must
precede inner secret decryption. This is the E47 composition idea, not a new
claim. Its [implemented screen](backend-frontier-results.md) gives a literal
matrix of 2RNW entries versus 2RNF stored index coefficients: 32–64× expansion
on the old public profiles. Inner Q is not interchangeable with plaintext t.

The outer layer must hide its result z from the server as well as hide a(w).
Publishing z can reveal a(w) by solving A_C a=z when A_C has full column rank.
The intended inner result becomes known to the client through the outer
protocol; calling it an inner ciphertext does not make public release safe.
This simple linear-algebra condition belongs in the transcript tests and
rules out a naive output-unmasking optimization.

### A1. Three representations to compare, not three assumed wins

1. **Literal outer vLHE:** materialize A_C only for bounded toys; otherwise use
   a count model. This is the reference construction and expansion control.
2. **Implicit operator and adjoint:** retain encrypted column generators,
   subring embeddings, signed shifts and decoder projection. Apply A_C and
   A_C^T without materializing every shift. Determine exactly which outer
   preprocessing, commitment, extraction and verification operations accept
   this representation. Supporting fast multiplication alone is insufficient.
3. **Bounded-digit operator:** split ciphertext coefficients into balanced
   base-B digits before outer evaluation. If A_C = sum_j B^j A_j (mod Q),
   compute digit products and reconstruct the exact Q-residue. For integer
   representatives bounded by |A_j| <= b and |a| <= a_max, each coordinate
   has the conservative bound |A_j a| <= W*b*a_max. An outer plaintext
   modulus exceeding twice this bound permits signed reconstruction of that
   digit product; otherwise a proved CRT/rounding mechanism is needed.
   Charge all digit outputs, keys, setup and reconstruction. Do not mistake a
   smaller database norm for a smaller complete protocol.

The last inequality is an elementary screening bound, not a parameter choice
or novel theorem. The outer malicious-security proof may allow extracted
matrices with a larger norm than the honest digits; correctness must cover that
class too. A subring, digit or NTT transformation changes distributions/norms
and must not inherit an assumption by name alone.

**Proposed point of invention:** a structured registration/evaluation/release
construction that preserves the outer proof's binding and admissibility while
avoiding explicit shift/digit expansion. A more efficient ordinary convolution
or application of existing vLHE is an attributed implementation result. Compare
ReinsPIRe's compilation lemma and full vLHE construction before claiming a new
implicit-matrix technique. Compare original EMVP including its HE compression
option, not only its large uncompressed response.

### A2. First executable discriminator

Proposed outputs: `experiments/bfv_search_lab/structured_operator_oracle.py`,
its tests, `benchmarks/structured_operator_lab.py` and
`docs/research/structured-operator-results.md`.

- Enumerate N=8/16/32 toys, mixed correction degrees, both signs of wrapped
  shifts, nonzero inactive CRT components and all small binary queries.
  Compare literal F_Q multiplication, schoolbook integer arithmetic, implicit
  forward/adjoint products and every digit reconstruction.
- Compose with the fixed supported decoder only after its selected-phase
  relation is pinned. Check all C1 dependencies and full-Q centering. Include
  a changed epoch, an influential omitted coordinate and the old mod-t carry
  counterexample. A toy ideal outer verifier must be labeled ideal.
- Build a ledger for honest and admissible norms, plaintext/ciphertext moduli,
  sample/secret distributions, setup, outer private state, reply expansion and
  all work. Separate a demonstrably admissible candidate from an unsupported
  parameter tuple. Run no expensive dense full-size allocations to discover
  a dimension blowup already apparent from the formula.
- On recorded Mushroom/Semeion/Connect-4 geometries, compare optimistic bounds
  with the complete direct-fresh, general-BGV, original EMVP and cache controls.
  A losing optimistic bound is a stop signal; a winning one only authorizes
  an actual outer-protocol prototype.

**Advance:** a precise new structured protocol step survives the closest
construction and has a credible complete resource margin. Then implement its
homemade reference and an independently checked reduction interface.
**Stop/pivot:** outer field/norm requirements destroy the margin, private state
recreates the database, only the dense wrapper works, or the same mechanism is
already supplied by a reviewed competitor. Preserve exact negative artifacts.

## B. E69: generate the exact authenticated correlation, not an easier proxy

This alternative attacks the same preparation cost while keeping E29's fast
online evaluator. Its required functionality is the
[authenticated correlation contract](authenticated-correlation-contract.md):
for a fixed private M, produce fresh private r, a fresh encryption of Phi(Mr),
and hidden full-Q checking material with binding and one-use state.

Generic matrix triples use random matrices/shares. We need a repeated *fixed
owner matrix*, an encryption-randomness distribution, two arithmetic fields and
a particular recipient for each value. Programmable PCGs supply useful known
ingredients; none of these requirements follows merely from their existence.
The [comparison supplement](closest-work-comparison-20260930.md) identifies
the ring-LPN and any-field PCG constructions to instantiate or rule out.

### B1. Proposed conversion choices and a cheap rejection rule

First express a complete ideal conversion using the chosen PCG's actual
outputs. Specify whether fixed-M programming is possible, whether it costs a
whole matrix per batch, and who sees each seed/share. Consider:

- Fixed-matrix or matrix-triple conversion followed by authenticated exact
  encryption inside the owner domain; evaluate whether it saves anything over
  vectorized plaintext products and fresh encryption.
- Producing secret shares in the ciphertext field and composing with a
  different release protocol. This changes the reference functionality and
  needs a new proof; it cannot reuse E29's noise/privacy argument unchanged.
- A declared two-helper mode if the single-server owner-only conversion fails.
  Noncollusion must be explicit; compare it with a known MPC baseline and keep
  it out of the primary single-server claim.

An elementary obstruction should reject a tempting shortcut before coding.
If a public full-column-rank matrix A and the public packet Au are both given
to the server, it can solve for u. Releasing delta=a−u then exposes a. Moving
masks to F_Q and sending their deterministic image is therefore not a free
replacement for fresh encryption. Rank deficiency does not by itself prove
privacy. This is a derived planning counterexample, not a new executed
experiment or an attack on a PCG construction.

### B2. First executable discriminator

Proposed outputs: `docs/research/fixed-matrix-correlation-reduction.md`,
`experiments/bfv_search_lab/correlation_conversion_oracle.py` and tests.

Write the recipient-by-value table and corruption/collusion cases first. Then
implement an **ideal-correlation oracle**, separate from a real PCG, for small
fields. Track centered lifts, carry corrections, fresh bounded errors, exact
verification equations and every mask exposure. Check repeated queries,
malformed setup, stale epochs and the public-image obstruction. Count actual
fixed-M programming, hidden hint delivery, expansion and authenticated setup.

**Advance:** the full conversion works and provides a nontrivial cost bound
against vectorized fresh generation under an explicit, defensible assumption.
**Stop:** a generic generator's shares cannot supply our distribution, carries
are ignored, secrecy depends on an undeclared helper, or setup/expansion simply
relocates the same work. A seeded sampler is not a correlation generator.

If the ideal conversion passes, the next stage is a homemade implementation of
the precisely selected published primitive plus the proposed new conversion.
Primitive parameter review and protocol review are independent tasks. Reuse
neither a new assumption nor a paper's timing as evidence of local assurance.

## C. E46 continuation: exact winners, including ties and omitted-row coverage

This changes the transmitted output to exact top-k, with the owner's ordinary
permission to learn the data retained. It does not create database privacy
against that owner. The stable comparison key is (distance, ID), not distance
alone. Pinned row/ID order must be preserved through selection and decoding.

Sparse homomorphic compression is a strong **baseline component**: once a
correct sparse winner indicator exists, use the SIMD-aware index/payload
compression controls. Do not claim that sparse output makes producing the
indicator cheap. Earlier E18/E21/E23/E39 already expose that distinction.

### C1. Candidate mechanism to screen

Exploit the bounded integer score domain d+1 using authenticated histograms or
radix refinement of stable comparison keys. Try to fuse winner discovery with
the final sparse encoding so that an intermediate full score/Boolean conversion
is avoided. Compare against a standard tournament/selection network, all-score
download, and ordinary two-round threshold plus exact refinement.

For every version, explicitly answer how the kth threshold is found, how the
required subset of threshold ties is chosen, and how every omitted row is
certified. An all-tied dataset must still produce exactly the correct k IDs.
Selection of a sparse index cannot be replaced by a histogram or moments that
lose identity. An adaptive prefix request can leak the threshold; encrypt/pad
it under a justified protocol or declare that changed leakage.

The known power-sum index control requires a field large enough to distinguish
all encoded positions. Our small score field is not automatically that field.
Price larger fields or index limbs and the authenticated position-to-ID map;
mapping to positions cannot change 64-bit-ID tie order. Zero-valued payloads
also need their separate correct winner indicator. See the
[SIMD compression construction, §III](https://arxiv.org/html/2408.17063v1).

Proposed first output: `docs/research/exact-selection-screen.md` with a complete
tiny circuit/certificate and independent plaintext exhaustive oracle, followed
only if viable by a reference module in the lab. Price all arithmetic-to-Boolean
conversion, range checks, depth/noise, public/evaluation keys, rounds, proof,
decryption and payload retrieval. Compare dense ties, random near-equal scores,
k=1/3/16 and k=m; sample favorable low-output cases only as one stratum.

**Advance:** a new selection/coverage method materially changes a full cost
term or yields a useful proved bound. **Stop:** comparison/conversion work or
RTTs exceed sending all scores, the method is just known counting/selection
plus known compression, or correctness depends on favorable gaps/recall.
Approximate arithmetic is E45 and must supply exact rounding/refinement bounds.

## D. E66: close the terminal-release controls before claiming compression

The purpose is to set a hard baseline for tracks A–C. Begin with existing E48
public C1 reconstruction and E64 supported C0. Evaluate full replies, each
method alone, their correctly typed combination, and locally known rows.
Add counts for ordinary LWE extraction/repacking, smaller terminal contexts
and additive-HE linear-decryption compression. Implement only the promising
applicable controls, giving reasons and missing premises for the others.

For an uncompressed honest response z, a public linear projection P can inherit
an adjoint check: beta^T Pz = (P^T beta)^T z. The old restricted omission identity
is D_t Z_K = D_t after selected phases are properly centered and reduced.
Neither identity permits nonlinear rounding to be pushed through the check,
public exposure of related randomness, or verification after arbitrary use of
the long-lived secret. This distinction is the starting point for a possible
safe-release theorem, not that theorem's claimed novelty.

Classify each transformation by (1) equality/rounding relation, (2) needed
secret keys and order of use, (3) seed/randomness visibility, (4) noise/range
premises, (5) authenticated public and private state and (6) observables on
failure. A smaller packet must be checked against the exact relation its
dedicated decoder accepts. Switching to an independent key merely relocates
the question unless the whole composition handles malicious responses.

Proposed deliverable: `docs/research/terminal-release-controls.md`, a separate
reference adapter and exhaustive relation tests. Include a valid alternative
encoding of the same score, a rounding-boundary input, C1 substitution, stale
recipe and public factory-zero-seed misuse. Distinguish output soundness from
exact ciphertext equality; restricting to one honest representation is allowed
but its cost and scope must be explicit.

## E. E67 and the go/no-go record

Extend the existing acquisition and full-cost runners rather than inventing
a fresh incompatible harness. Give each candidate a matched contract card and
measured cold/enrolled/returning-client panel. Include private bytes and native
memory as well as response bodies. At least one actual transfer run is needed
before calling a link crossover measured; loopback alone is not an AWS/mobile
deployment. Label controlled link emulation separately from a real WAN.

For each R-task completion, record:

```
hypothesis / closest construction / exact new step
contract + leakage + starting state + assumptions
mechanism bound / independent oracle / strongest simple control
all charged costs / raw and source hashes / reproduction command
result: algebra | measured | modeled | rejected | unresolved
next: advance to named task | stop this track | revise this premise
```

The first review selects one main mechanism. Alternatives may remain open;
neither exhaustive experimentation nor guaranteed publication is a finite
acceptance condition. Strong negative findings prevent spending the next
cycle accelerating an explanation we already know is insufficient.
