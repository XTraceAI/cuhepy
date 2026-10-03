# E113 one-prime complete feasibility preregistration

2026-10-03. Frozen before the count-panel runner and tiny differential experiment.
Parent evidence8fdc431; experiment/verification-aware-screens-20261003. No timing,
GPU, estimator, build, large key generation, security approval, or production
change is authorized by this screen. The same tuned ordinary one-limb BGV and
native-prime proof control receive every arithmetic improvement; choosing one
prime or tightening elementary support/digit bounds is not an original result.

## Complete law and derivation

Use the actual owner seeded law from seeded_bgv.encrypt/owner_bgv.OwnerClient:
uniform public SHAKE-derived a with fresh256-bit seed, independent OS CBD_eta
coefficient errors, ternary secret coefficients, and phase m+t*e modulo Q.
Index owner encryption uses this same law; general public index encryption
uses phase m+t*(e*u+e0+e1*s) and is a separate strong failure/control case.
Signed coefficient query has exactly dimension d entries of magnitude1 and
zeros elsewhere; an index tile has entries in{-1,0,1}, including partial tails.
The metadata t//2+t*eta bound must not be confused with message magnitude1.

For query drop r>0, let R=2^r,K=floor((R-1)/t). The existing codec changes c0
by t*(floor(K/2)-floor(tail/t)) before reduction; added radius
E=t*ceil(K/2). Drop0 is the original seeded packet with E0. All lifted phases
are interpreted modulo Q until the final decryption; signed carries are not
silently discarded. Let A=t*eta+E, I=t*eta for owner index, and
I_public=t*eta*(2N+1) for general public index. Expanding the product and using
query support gives the entire-coefficient bound

    M = d*(1+I) + N*A*(1+I).

The generic metadata control instead uses N*(t//2+t*eta+E)*(t//2+I).
Both controls get the same sharper actual signed-layout bound where applicable.

For radix B=2^b,L=ceil(bit_length(Q)/b), canonical digits satisfy
sum_j B^j*d_j=C in[0,Q). Compute the exact maximum scalar digit sum H_Q over
all C in[0,Q) by a finite base-B prefix argument. Each gadget error satisfies
S=t*eta*N*H_Q without coefficient independence. The legacy API's bound is
S_api=t*eta*N*L*(B-1). For a semantic relaxed common integer digit witness with
0<=d_j<B and recomposition modulo Q, S_relaxed=S_api. Verify explicitly whether
S_relaxed<=2*S; do not assert a factor2 without this inequality. This is a
relation-only alternate-witness bound, not an implemented malicious protocol.

For D=next_power_of_two(d), the E15 joint support identity bounds the complete
final polynomial, including unused positions and partial groups, by

    F = D*M + (2D-1)*S.

D*S accounts for relinearization and (D-1)*S for all rotation levels. This is
not the larger count-summed butterfly schedule, nor permission to bypass the
existing Python/keygen validation. All operations are modulo Q, so intermediate
lift wrap is permitted when the full identity and final no-wrap bound hold;
there is no intermediate private decryption. Record the ordinary conservative
schedule as an additional distinct control and count every actual rotation.

The compact-v1 modulus is the existing terminal_modulus(Q,t,32), an odd prime
P<Q with P=Q modulo t. Its signed nearest-congruent per-component error is at
most t/2. With ||s||1<=N the complete compact phase has bound

    G = ceil(P*F/Q)+ceil((N+1)*t/2).

Require strict2F<Q and2G<P. This centering removes the original Q carry as a P
carry; matching residues requires P=Q modulo t. Decode by D inverse modulo t
at every actual output position, require t>2d, restore all exact distances and
stable IDs, and include the full packet. Raw-Q success alone is insufficient.

## Frozen count panel and stops

One deterministic derived count panel only. Large N8192,16384,32768; d512;
t1031; eta21; counts8192,32768. Q is the existing first deterministic60-bit
NTT prime from _rns_coefficient_primes(N,60), so Q=1 modulo2N. Radix widths
10,12,15,18,19,30. Screen drop0..59 and choose the greatest admitted drop for
canonical and bounded-alternative relations separately. No data-driven tuning,
additional rings/moduli/terminal widths, security estimates or timing follows.
All profiles also record public-index and generic keygen-guard outcomes.

Exact64-bit primality validation and a primitive2N-root witness check are public
arithmetic diagnostics, not a lattice/security parameter approval. Record
current native RNS source compatibility and current shallow keygen guard:
2*N*(t//2+t*eta*(2N+1))^2<Q. Do not monkeypatch this guard. Meaningful-large
profiles that pass owner math but fail this API are not executable large-profile
results. Any future owner-only key generator is a separate task.

Count and disclose coefficient-body versus complete byte envelopes separately:
public a/b; owner index ciphertexts; relin/rotation key families; raw/rounded
seeded query; all compact-v1 response coefficients and headers; native RNS
coefficient slots; full source/digit/terminal witness coordinates; static IDs,
owner plaintext and peak workspaces/PCS/setup state as priced or explicitly
unknown. Give the ordinary one-limb/native-prime proof control equal counts;
no actual proof or low-state registration cache is implemented. A60-bit field
needs repeated independent challenges; count actual potential residual claims
and all lifetime attempts instead of equating field size with128-bit security.

Cap tiny differential panel: one honest existing shallow key_gen context
N16,d3,t17,eta1,Q60,rns_modulus=True,radix10,drop8,9records with partial tiles,
all8 binary queries, owner-encrypted index and original owner query. Compare
actual per-tile trace and butterfly complete decrypted polynomials; compact-v1
full coefficients/packet; independent schoolbook signed phase/rounding/distance
oracle and stable nonpositional IDs. Fixture key/error/seed draws are sampled
once, disclosed and frozen before the main run. No private assurance follows.
Use existing APIs unchanged; no new HE implementation or kernel.

Meaningful tests: signed canonical Q-1 secret, a terminal coefficient crossing P,
rounding-cell endpoints, parity/ties/partial positions; alternate common digits
with recomposition modulo Q and bounded errors; public-index/large API guard
failure; strict near-Q/P margins; NTT prime/root admissibility; and an independent
tiny full-original-query/actual-API oracle. No tests merely mirror formulas.

Stop/advance: if complete owner bound fails, stop before any implementation.
If it passes but tuned generic controls have identical saving, report known
feasibility and no originality pass. Current generic-keygen rejection remains
an explicit practical blocker. Performance, complete proof cost, conditional
setup validity, adaptive lifecycle/reduction and private side channels remain
unknown. Raw results must pin every source/preregistration/fixture hash and
report exact accepted/rejected outcomes, not only successful profiles.
