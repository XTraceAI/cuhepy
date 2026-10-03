# Q36/E110: bounded functional-orbit control screen

Frozen before execution,2026-10-03. Branch
`experiment/verification-aware-screens-20261003`. This follows Track A1–A2 in
[the contribution plan](contribution-plan-20261003.md). A3 is conditional and
is **not authorized by a correct external-product identity alone**.

## Prior return and difference card

The proposed product key `K_i,j=RawEnc_s(B^j*s*phase(A_i))` and once-per-query
decomposition are known functional/gadget preprocessing. Full two-component
functional-orbit keys are a GGSW/RGSW external-product control. Current Bae
arXiv2503.16080v2, Sections3.4/5.4–5.5, explicitly covers matrix RGSW, different
key/degree/input formats, four modular products and auxiliary-modulus noise,
plus coefficient/slot integration. E07/E29/E72, ordinary hoisting, equal
index preprocessing, and shared graph elimination also receive their standard
optimizations. **No original algebra has survived this prior return.**

This component retains a homemade integer adapter to determine what those
known controls actually buy and cost at the unchanged tiny graph's boundary.
It does not implement a new optimizer, RGSW security theorem, native kernel,
PCS, TEE, constant-time private operation, or production parameter approval.
The Bae control is compared by its stated external-product/formats/noise
premises; its CKKS implementation and GPU performance are not reproduced.

## Frozen geometry and actual graphs

Use the E106 disclosed fixture at
`../research-data/native-boundary-20261003/frozen-fixture.json`, SHA256
`0a49605dd8d26d0e73e38c681013e83a64801df4c95b62fab80bf7b81beeb4a1`.
N8,D3,padded4,t17,Q120,P32, radix2^30/four rows; five tiles, groups4/1,
eight original compressed queries, nine records with duplicate000 and
stable positional ties. No new owner/query fixture is sampled. New raw gadget
keys use disclosed deterministic toy masks/errors and are frozen before the
main run. Their errors are fresh relative to the unchanged original relin keys,
not copied/multiplied from ordinary keys. This law is a reproducible diagnostic,
not cryptographic entropy or the production key distribution.

Compare these equally shared representations:

1. Ordinary: exact E106 replay, five product cuts and five rotation cuts.
2. Product-only: `c0*A_i+sum_j digit_j(c1)*K_i,j`, followed by exactly the same
   butterfly/rotation keys and terminal conversion. The public query digit
   source is charged once; all five downstream rotation sources remain.
3. Full functional-orbit GGSW-style control: compile the complete linear phase
   map per response as `sum_g sigma_g(phase(C))*F_g`. Aggregate terms with the
   same orbit **before** generating keys. For each retained term prepare both
   `RawEnc_s(B^j*F_g)` and `RawEnc_s(B^j*sigma_g(s)*F_g)`, and bounded-decompose
   both original query components in that orbit. Charge every key and public
   transform/digit source; no full-Q component multiplies independent fresh
   key error. No old rotation-key output noise is claimed to be preserved.

The full control is the equally optimized feature-major/linear-map control;
counting separate per-tile orbit keys would artificially weaken it. Retain all
nonzero polynomial coefficients, including the partial tail, and compare all
plaintext coefficients and scores/ties. Candidate ciphertext/compact bytes
may differ from E106: each graph is a separately pinned enrollment/evaluator
statement and is bound to its own complete wire relation.

## Algebra, error and statement obligations

`RawEnc_s(M)` constructs `(M-mask*s+t*E,mask) mod Q`, so its phase is
`M+t*E mod Q`. Product-only must satisfy the **actual fresh-error identity**
`phase(Y_i)=phase(C)*phase(A_i)+t*sum_j digit_j(c1)*E_i,j mod Q`.
The target includes the index phase's existing error. Copying plaintext-only
targets breaks the cancellation. Every full-orbit term must satisfy its exact
two-component identity with all weighted fresh errors included.

Digits are derived from canonical full-Q coefficients. Reconstructing CRT
residues must yield the same global source/digits; independent limb digits,
numeric aliases, missing/high digits, wrong owner keys or orbit order are
rejected. Explicit negative controls expose full-Q fresh-error amplification
from naive rotated/fresh index encryption and multiplying ordinary keys by
uniform index coefficients. These are public toy phase diagnostics, never
malicious ciphertexts delivered to a real private decoder.

All graphs use the existing independent nearest-congruent Q→P conversion and
strict complete response grammar. A locally trusted enrollment pins the graph,
keys/context/epoch/query bytes; complete public replay must reject key or output
substitution before a private callback. This recomputation is a paid known
control, not a succinct proof or reviewed malicious-server protocol. Correlated
secret/data-dependent key-message security/KDM, adaptive release security,
side channels and lattice parameters remain unproved.

## Cost ledger and stop

Record actual Q-polynomial convolution/automorphism/monomial/addition counts,
query digit sources/words, owner target/mask products, key families/coefficient
storage in packedQ120 and two-word RNS, old context retention, per-index and
whole-epoch rebuild counts, terminal coefficients/body/packet bytes, and
remaining non-query canonical sources. Report circuit-bit inputs only as a
shared E108-style model, with no PCS/proof byte, latency, NTT or security claim.
Full-Q schoolbook products are **not** native NTT operation measurements.
Query expansion, enrollment authentication/hashing, source/terminal ranges,
proof/PCS work and private finish remain paid or explicitly unimplemented.

Cap one difference card and one tiny integer/count component, plus meaningful
scoped tests and explicit nonempty Ruff checks. Stop E110's literal novelty
claim if the full control supplies the same representation or the result is
ordinary external products/sharing. Do not proceed to A3 unless a distinct
uncontained rewrite/state/theorem remains. A correct contained adapter is a
valid negative result, not a reason to widen the experiment.

No timing, GPU/native modification, benchmark forecast, Git staging/commit,
production edit or new paper acquisition belongs to this component. Preserve
failed runs and source hashes in the external E110 receipt directory.
