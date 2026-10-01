# E72/E73: encrypted-query verification and packing discriminators

Preregistered 2026-10-01 before new code or measurement. Return to the
[plan](publication-research-plan.md) and
[handoff](mechanism-execution-handoff-20260930.md) after each subcomponent.
Existing results, company code and the E71 reference remain unchanged.

## E72 — the strongest simple projected linear-check control

R3-B1/B2 asks whether fresh owner answers and fresh private point hints can both
be removed. Before inventing a smaller certificate, establish the known dense
full-field fingerprint control for **actual encrypted queries**. Treat the two
public query components as a length-2FN vector. The public encrypted index maps
it linearly to three response components. Compile a private uniform-field
fingerprint of this map once. Retain exactly supported C0 and full C1/C2;
check their relation before using the inner secret. No quotient/proof API is
needed. This is known linear algebra, not an originality claim.

Required independent controls: signed negacyclic transpose versus a literal
integer matrix; complete three-component products and ordinary full decrypt;
seven mixed/empty/multi-reply CRT layouts, all sixteen four-bit queries,
scores/stable IDs; wrong C0/C1/C2, wrong context, malformed bytes, replay,
query substitution and a lifetime budget shared across epochs. Test that no
rejected attempt reaches private arithmetic. Exhaust a small field to check
the **single aggregate accept/reject** feedback bound, contrasting it with
E71's separately supplied bad-quotient control. Finite tests are not a security
proof or parameter assurance.

Report once-per-index preparation, actual query/response bodies, per-query
verification/decryption, retained private coefficient bodies, no owner work
per query, and real-geometry counts. Do not hide state behind a PRG seed or
claim Python object/RSS measurements from canonical body counts. Stop this
literal variant as a paper candidate if state/upload destroys usefulness.

## E73 — partial coefficient expansion of packed subring queries

R3-B0 requires the strongest ordinary query-packing control. Use the known
SealPIR-style coefficient expansion, with a homemade implementation. Pack
column j as X^j b_j(X), where b_j has support on powers of its declared
subring stride. A power-of-two expansion factor H must divide every stride
and have H at least the number of columns. Expand only log2(H) levels.
Predivide the plaintext query by H modulo t; preserve the full degree-N HE
ring and secret. No library HE implementation is imported.

Derive every automorphism/key switch, the exact output and cross terms, fresh
and expanded phase bounds, coefficient/evaluation-key bytes, expansion
products, server products, and required Q. Compare to E71 at the **same toy
key and field**, plus separate large correctness/count screens. Mixed column
degrees and non-power-of-two column counts must not silently mix residues.

Verification is an explicit discriminator: an E72 check of multiplication on
server-supplied expanded queries does not certify that those queries came from
the original packed ciphertext. Show this substitution failure. Price trusted
client expansion as one valid control; do not claim this is a succinct proof
or that it removes all trusted online computation. Stop unverified expansion;
do not optimize kernels until a useful, original, safe mechanism survives.

## Return decisions

Fill these in after execution, with links to immutable raw results. If both
literal variants fail, return to R3-A0's actual carry-aware construction or
R4's programmed correlations, with the closest known construction priced
first. The matched R2 acquisition service remains a required independent
control. No entire P-package or Gates A–D will be accepted by these controls.
