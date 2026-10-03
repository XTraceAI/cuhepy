# Q32/E106: frozen native compact-v1 boundary discriminator

2026-10-03 UTC. Frozen before fixture sampling and any new oracle run. Follow
the [adapter plan](native-boundary-adapter-plan-20261003.md) and return to
[R6](boundary-reuse-selection-20261003.md) after each bounded component.
This is a homemade **known-control adapter**, not an originality pass.

## Selected executable graph

Use existing native CPU persistent-RNS BGV with N8, dimension3, padded4,
t17, eta1, q_bits120 and actual Q equal to the two repository-generated
60-bit NTT primes. Generate toy keys with `shallow_bgv.key_gen`, evaluation
keys with `trace_bgv.evaluation_keys(digit_bits=30)`, and index messages
with `shallow_bgv.coefficient_inputs`. Enroll all eight ordered binary words
plus a duplicate 000 as row8. Stable IDs are original positions0–8, matching
the native owner finish; do not substitute an external ID comparator.

Tile capacity2 gives five tiles, group sizes4/1 and two responses. Product/
relinearization cuts:5. Butterfly cuts:3+2=5, including two rotations for the
one-tile tail. No SealPIR query expansion is executed. Each switching source
is a unique canonical full-Q polynomial decomposed into four radix2^30 rows.
Intermediate residue arithmetic and CRT composition must match exact
negacyclic integer arithmetic modulo Q; no BFV scale-and-round is present.

Owner queries use the existing fresh `OwnerClient.encrypt` envelope and
`compressed_query_bgv.compress(dropped_bits=58,backend='native')`. Server
coefficient expansion uses the same caller-pinned drop through the native
codec. This coefficient reconstruction and SHAKE mask expansion are not
homomorphic packed-query expansion. Exhaust all eight legal binary messages.
Uniform seeds and CBD error draws remain those of the existing owner routine;
record query bytes rather than infer an entropy assurance or new security law.

Use `NativeServer(residue=True,device='cpu').search(joint=True)` and
`search_compact(joint=True,bits=32)`. Terminal modulus P is the existing
selected odd prime congruent to Q mod17. Serialize exact compact-v1 packets
through `compact_bgv.pack`. Compare native owner `finish_packed_fixture`
and the separate `PrivateDecoder(bits=32).decode_packed` against independent
integer phases, all72 Hamming distances and positional stable top-three.
Owner finishing is variable-time; the private decoder's fixed-work claims
remain its narrow arithmetic scope, not a proof for this complete harness.

Freeze all toy keys, public index, query packets, bounds/context and plaintext
diagnostics in `../research-data/native-boundary-20261003/frozen-fixture.json`
before the main experiment. This disclosed toy secret is not a production key.
No resampling for a favorable finding. Preserve exact source/binary hashes;
runtime binary agreement is not a reproducible-build claim.

## Independent relation and falsifiers

Implement a bounded integer oracle in
`experiments/bfv_search_lab/native_boundary_oracle.py`, with tests in
`test_native_boundary_oracle.py` and runner `benchmarks/native_boundary_lab.py`.
It must not call the native/reference evaluator, ring-product helper,
compressed-query expand, compact round, trace decode or private math for its
ground truth. Independently parse original bytes, regenerate the public SHAKE
mask, reconstruct compressed coefficients, evaluate all negacyclic products,
canonical switch digits, automorphisms/monomial butterfly nodes, CRT and
terminal rounding, serialize the exact wire and decode phases/scores/ties.
Existing routines are separately labeled differential comparators.

Pin owner-approved context/index/key/layout/epoch/ID order and original query
bytes. A complete local witness checker replays the same public graph before
any private work. Its direct recomputation is a strong known correctness
baseline, not an efficient remote proof. A strict canonical trace and an
affine-only falsifier are separate modes. Build an honest-output/false-digit
kernel using actual key rows and source-reconstruction equations; a single
RNS-limb error must not receive only an uncorrupted limb's guarantee.

Mutation controls cover every switching source/digit/output and every terminal
input/output, wrong original query, context/epoch/key/layout/ID order,
malformed/canonical query and response grammars, group omission/duplication/
reordering, substituted terminal modulus/bounds and fixed complete-packet
binding before private decoder invocation. Check decoder dependencies even
if a mutation preserves selected distances. Full coefficients are the chosen
statement; exact scores alone are a different contract.

Exhaust a declared small oddQ/odd-t terminal scalar space against an independent
nearest congruent representative. For real Q/P, check canonical extremes and
nearest reachable congruent rounding thresholds. Odd Q*t makes exact half ties
unreachable; verify floor division near negative numerators, not a fabricated
tie. A full-domain scalar law does not instantiate an approved HE profile.

## Complete costs and return rule

Record observed cut/coordinate/body counts for the actual fixture. Count cards
may extend to illustrative N8192/D512/8192-row geometry, explicitly distinct
from an approved profile, timing, actual RSS or a lower bound. Charge owner
registration, all original-query features, switching sources/digits, terminal
source/quotient/range information, protected hints, challenges, server witness
generation, checker and client work and every link. Derived witnesses receive
the same optimization in generic controls. Small final response bytes do not
price the complete verifier.

Compare full native recomputation, E13 fused product/relinearization, E72
compiled adjoints and equally optimized generic canonical cuts. Document their
missing rotation/terminal/range and lifecycle adaptations. Pin specialized
ring/double-CRT proof comparisons by their actual contracts; an unavailable
complete adapter is unknown, never an assumed slow competitor. Composite Q
needs limb-aware soundness and strict global CRT/canonical constraints.

Initial cap: one graph/preregistration and one independent tiny oracle/count
component. No timing panel, CUDA kernel, production edit, parameter approval,
durable lifecycle/security reduction or public proof implementation. BFV's
quadratic integer scaling and CUDA terminal are deferred separate adapters.
Retain successes/failures/source corrections. Return raw
`benchmarks/results/publication-native-boundary-20261003.json` and
`docs/research/native-boundary-screen.md` to R6. Select a successor only after
a precise unhandled mechanism difference and plausible complete consequence;
the adapter itself cannot satisfy an originality gate.
