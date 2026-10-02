# E97 preregistration: fixed-input owner rounding control

2026-10-02, parent `ae7934709fd1b286cc5cd6bf6daa3c2d2e46f047`, branch
`experiment/owner-bound-rounding-20261002`. Freeze before running the oracle.
This executes [Q23](owner-bound-rounding-plan-20261002.md), a missing **known
strong control**, not a new FHE scheme or selected paper mechanism.

## Primary review and premises

Hash-pin FHEW ePrint2014/816 (latest2015-03-02) and FINALLY ePrint2024/1505
(latest2025-05-26), preserving retrieval/PDF/text receipts. Read FHEW section3
Equation3/Lemma5 and its whole proof/heuristic caveat, and FINALLY section3.5
Definition3.9/Lemma3.5 and its whole proof. Full relevant pages5/6 and16/17 are
visually inspected. Revisit cached drift/mean-compensation and complete verified
FHE controls. No author protocol/artifact or reported runtime is reproduced.
Do not adopt a paper's whole Gaussian/key-noise independence analysis as ours.

Condition on arbitrary fixed target T, old key errors, original ciphertext/key
history and the prescribed finite original reply family. Honest independent
uniform coins U follow original binding; hashes/labels do not prove this order.
Round x by `floor(B*x/Q)+int(U < (B*x mod Q))`, with U uniform0..Q-1.
Its numerator d is either -r or Q-r, with exact conditional mean zero and
variance r(Q-r). Within one view, each component coefficient has its own
independent coin. Shared coins across replies/stages are correlated; cover the
finite family by a union bound, not independent-view probabilities.

For sign -1 use U'=Q-1-U at each coefficient. Test the proposed exact signed
integer error/rounded-mod-B identity, including r0, wrapping and even moduli.
Unchanged coins need not preserve negation. Signed permutations need matching
coin permutations/complements; no generic nonlinear map is inferred.

## Finite registered implementation and independent controls

1. Scalar Q2/3/4/5/7/9/15, B2/4/8/16/32, every canonical input and every coin:
   mean/variance, support, Euclidean integer quotient and signed complement.
   Include noncoprime contexts; unbiased rounding does not require coprimality.
2. N2/Q3, all9 fixed ternary targets, all81 two-component origins, all81
   two-component coin vectors, source offsets0/1, signs+/- and B4/8. Check full
   integer phase identity, conditional coin means and the correlated family.
   Bounds can be vacuous at this toy size; explicitly label them as such.
3. N128/Q4/B2/p128 plus one body coefficient, remainder2 in every term:
   exact129-term symmetric Bernoulli tail, kappa8/single event. Also compute an
   N64/Q5/B4 post-coin choice/reused-coin distribution; demonstrate that its
   invalid use of the fixed-input threshold can exceed the claimed tail.
   Server all-zero coin selection, repeated coefficients, duplicate views and
   public deterministic seed relation are additional premise falsifiers.
4. Homemade GMP mixed (1,T,S-squared) switching/rounding and a full public
   diagnostic certificate. Bind original family/keys/coin packet and every
   event; bind the exact sampled packet into the volatile owner reservation.
   Check mutations, same-ID replacement, wrong contexts/labels/coins, replay, maximum generated
   families, abandoned reservations, callback failures and concurrency. No
   private secret/error witness enters the certificate. Volatile state is not
   attestation, compact verification, decryption permission or rollback safety.
5. One fresh ordinary public-key homemade BGV toy differential, reused target
   and switching keys across two adaptive query families, fresh rounding coins
   after original binding. Check decoded coefficients and exact mixed phases.
   OS coins represent ideal independent sampling in the restricted law; no
   public SHAKE expansion, PBS, approved parameters or constant-time claim.

## Precision and costs, before inspecting the expanded results

For support cap p, uniform twice-proxy is ceil(Q^2*(p+1)/2). At each actual
public original view, zero remainders contribute nothing; conditional variance
is the sum of r(Q-r) over body and the p signed-convolution positions. The
public Bernstein bound uses this variance and maximum supported absolute error
Q-min(r,Q-r), with integer threshold sqrt(2*v*L)+(2*c*L/3), rounded upward.
Compare this valid fixed-input bound with active-term Hoeffding and pointwise
all-T support bounds. The minimum of two pre-coin statistical thresholds is
chosen from fixed originals, not from a realized secret-dependent noise test.
Old switching errors and actual S-squared residual remain deterministic charges.
No reuse of a fresh-key noise MGF; all old key/public dependencies stay fixed.

Independently reproduce all8640 E96 support/degree points, then add stochastic
uniform bounds at exactly the same720 tuples/grid2^11..2^22, source budgets,
support statuses, lifetime allocation, sparse/dense views and C2 omission.
Historical p512/p1024 are excluded from equal128-bit comparisons. Removing
owner zeros changes the public transcript: E96's particular zero-sample costs
are not automatically a security estimate of a newly enrolled no-zero route.
Keep its labels as historical comparison scope, and separately audit actual
switching-key samples before any new assurance claim. p2048/4096 and full-N
controls remain unapproved. Do not invent realized public remainders
for those geometry cards or credit a toy Bernstein gain to a real workload.

One shared full coin packet has2*N*ceil_log_Q coefficient bits like E95's
unseeded zero; no encrypted-zero owner product/CBD draws or extra raw zero rows
are added. Retain reusable key setup, source preparation, switch products,
full-recompute verifier work, all coin sampling and traffic, framing/proof/PBS/
private/durable costs and permitted plaintext caches. Both routes have zero
extra RTT with local owner binding. Standard shared stochastic rounding gets
identical coins, exact sign mapping, binding relation and lifetime controls.

Run initial/repeat exact/count receipts with fresh paths and exact source
hashes. Check scoped tests/lint, preserve all earlier identities/measurements/
production refs and return to R6 after review, oracle, receiver and cost panels.
These results are not HE timing or a128-bit security approval.

**Stop generic randomized-rounding originality if the known control supplies
the same full step.** Keep useful company interfaces. Next prioritize an actual
new original-score/shared proof or correlated compressed-query construction,
with a concrete restricted law/resource difference and strongest closest
baseline, rather than repeatedly renaming an MGF. A public seeded-coin route
needs its own ROM/provenance/schedule proof before being counted as compression.
