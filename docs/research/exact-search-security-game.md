# P07: adaptive exact-search game and conditional reduction agenda

2026-09-30. This is a proof outline for the [frozen contract](exact-search-contract.md)
and E41/E43 prototypes, **not a completed security theorem or parameter review**.
The [existing correlation contract](authenticated-correlation-contract.md)
still applies. The production BFV/BGV paths are unchanged.

## Functionality and observable history

The trusted owner enrolls binary rows with unique stable IDs and approves a
representation, field, key, leakage policy and bounded lifetime. The authorized
client may choose queries adaptively from prior authorized scores and aborts.
An untrusted single server stores the encrypted index and fresh offline
answers, and chooses arbitrary replies. Owner/client corruption, rollback and
private implementation side channels are outside this first game.

`F_exact` records the current owner-approved epoch, row/ID list and plan. For a
valid client query it privately computes the complete ordered score array and
stable `(distance, ID)` top-k. The ideal adversary may deliver that result or
cause an abort; it may not substitute a different array. Approved fixed-map
edits replace the relevant owner rows. Arbitrary edits, insertions, deletions
and plan migrations require a new version of this functionality/implementation.

The simulator receives public geometry, fields/key context, the approved
update/epoch schedule, pool sizes/token IDs, packet sizes, acceptance/abort
events and declared later retrieval leakage. It does not receive private maps,
rows, pads or queries. The leakage schedule also contains rank/equality/fit
decisions, rebase decisions and update ciphertext bound growth. Private timing
must either be excluded as an implementation assumption or explicitly modeled;
the current Python/GMP implementation cannot exclude it in a production claim.

The owner and client need an authentic binding from random epoch handles to
the exact public ciphertext index, key/parameters, complete response relation,
private plan/ID interpretation, pending answers and lifetime budget. A local
Python object, digest or passing fingerprint is not this channel.

## Exactness and bounded soundness

E41 proves finite-grammar correctness by composing four identities: every row
has certified coordinates in its private affine map; the CRT embedding covers
each row exactly once; the full-ring linear circuit reconstructs the prescribed
field dot product; the anchor offset yields Hamming distance in `[0,d]`, since
`t>d`. Selection sorts by `(distance, ID)`. The schoolbook oracle, exhaustive
queries and encrypted native/GMP comparisons test these identities independently.

For frozen-map edits let `M'=M+Delta M` in `F_t`. A previously unexposed pad r
may retain its value, while the owner adds fresh independently encrypted
`Phi(Delta M*r)` to its answer, and fresh encrypted difference columns to the
index. Then the old-plus-patch answer and index decrypt to the new prescribed
linear result. Actual centered coefficients and added noise are retained in
the full-Q circuit; an F_t tag cannot verify that circuit. The universal bound
is checked before any local target changes. A full re-encryption resets noise.

This identity concerns an **unused** r. Once any delta involving r escapes,
it is consumed forever, including on timeout, rejection or update. Two released
deltas sharing r expose their query difference. E43 tests this negative control
and rejects consumed or stale tickets. Its transition lock is volatile; crash
atomicity and rollback resistance remain P08 obligations.

For r independent secret vector challenges over prime Q, a nonzero error in
the complete prescribed coefficient vector passes with probability `Q^-r`.
For at most T attempts, including malformed and rejected attempts, the
first-false-accept bound is `T/Q^r`. This uses an all-reject counterfactual path:
before the first false acceptance, each adversarial error can be fixed from
public history without the hidden challenges. Honest acceptances are deterministic.
Reject bits do not justify assuming that a fresh conditional probability is
still `Q^-r`; the counterfactual/union argument is needed. Private checker
timing, leaked tags or reset budgets invalidate its premises.

This credits ordinary secret linear fingerprinting. Multiple components and
updates must share a global attempt budget or pay a union bound over independent
check epochs. Polynomial hashing needs its degree/root-count bound instead;
one cannot reuse the vector family's scalar collision estimate for it.

## Privacy hybrid, with obligations made explicit

The intended proof order is:

1. Condition on authentic approved setup and exact local state transitions.
   Bound the first false complete-response acceptance before touching a
   long-lived HE key. Rejects invoke no secret HE decryption.
2. Until that event, replace every authorized client result with the ideal
   functionality's exact result. This is justified by the exact verified
   ciphertext relation and universal honest phase bounds. Future adaptive
   queries must depend on these same ideal results/aborts. There is no
   adversary-chosen ciphertext decryption oracle in this step.
3. Replace each fresh index, initial answer and update-patch encryption with
   an encryption of zero using a **multi-message IND-CPA** assumption for the
   actual seeded symmetric scheme. Updated ciphertexts are public sums of
   those fresh samples. Count every fresh sample and distinct key, not merely
   each request. Plaintexts can be related through the hidden index and pad;
   their fresh encryption randomness is independent.
4. Only in that encryption hybrid, replace private mask expansion with fresh
   uniform pads. Choose token IDs in a predetermined or query-independent
   policy. An unused pad's extra patch ciphertexts have already lost their
   pad dependence in step 3. At its sole release, `delta=w-r mod t` is uniform
   even for an adaptive w. Preserve all public geometry and update leakage.
5. Simulate zero encryptions, uniform deltas, the prescribed complete-response
   checks and ideal outputs/aborts from public contexts and the leakage
   schedule. A simulator must not require the private map or plaintext index
   to construct a published epoch or to interpret hidden score hashes.

The argument is still conditional. It needs a complete game/reduction that
handles malicious delivery, multi-key enrollment, adaptive authorized updates,
token selection, checker state and observable retries. The prototype proves
neither the encryption assumption nor the final simulation equivalence.

There is a subtle seeded-encryption assumption: the ciphertext publishes the
seed used to expand its uniform ring polynomial. Ordinary secret-seed PRG
security does **not** let a proof replace `(seed, SHAKE(seed))` with
`(seed, uniform)`; an observer can recompute SHAKE. A random-oracle/lazy-sampling
argument with fresh-seed collision and prior-oracle-query bounds, or a direct
reviewed seeded-IND-CPA assumption, is required. The private pad seed is hidden,
so its expansion is a separate secret-seed pseudorandomness obligation. Neither
is established by a test or by an RLWE estimator alone.

The concrete encryption uses ternary full-ring secrets and centered-binomial
errors. Since Q is prime and distinct from t, multiplying an RLWE sample by
`t^-1 mod Q` explains the t-scaled-error relationship algebraically. It does
not certify the concrete distribution, ring dimension, sample count or
hardness. Private HE/check arithmetic remains variable-time.

## Owner-local hashes are not public commitments

E41's workload and plan digests include plaintext rows, IDs and private maps.
They are useful for owner-local stale-state checks. Publishing such an unsalted
digest lets a server test guessed small indices/maps. This defeats a simulator
that knows only the declared geometry. Likewise, a published hash of secret
distances can be a query oracle on a small candidate space.

E43 therefore uses independent random 32-byte epoch handles, and retains the
plaintext-derived digests locally. Remote authentication must bind those
handles to randomized ciphertexts and to the client's private interpretation.
Benchmarks on public fixtures may retain private diagnostic hashes; that does
not authorize exporting them in a deployed service. Earlier local experiments
using row-derived epoch hashes are not silently promoted to this privacy game.

## E47 outer-layer composition

The literal ciphertext matrix has `2*R*N` rows and W columns over F_Q. Its
input is the actual centered CRT vector `alpha(w)`, not a naive linear lift
from F_t. Complete full-Q output and owner binding are necessary. The outer
vLHE must authenticate the owner's approved matrix, rather than merely bind a
malicious server to some admissible matrix. ReinsPIRe's registration/databound
and selective-failure game cannot be transplanted without checking that point.

An outer privacy/integrity theorem must cover the actual ciphertext-coefficient
database norms, query bounds, parameter choices and output interpretation. The
public ciphertext matrix does not require server plaintext-index access, but
that observation alone proves no composition. The inner checker stays in place.

## Proof/code coverage and next review

### E48/E49 execution supplement

E48 reconstructs a fresh fixed-index response's prescribed C1 from **public**
index/answer encryption seeds and public delta, then invokes the unchanged
complete checker. It discloses neither a mask seed nor a checker challenge.
Caching/streaming changes work/state, not the checked coefficient relation.
Dynamic additive seed manifests and authenticated delivery remain unresolved.

E49 instead uses `Y_r=C*alpha(r)+Enc(0)` in a trusted local factory. Its zero
seed must remain private: the new negative regression recovers a private pad
and query when that seed is exposed. Its simulation needs an explicit joint
fresh-ciphertext pseudorandomness hybrid with honest index auxiliary data,
before applying a uniform-pair shift. The fresh-plaintext IND-CPA outline above
must not be silently reused for this different construction. All pad-dependent
norms are hidden behind universal bounds, and complete response verification
still precedes HE decryption. Private-zero ciphertext recipes, factory
corruption, dynamic repaired-index composition and durable state are not proved.

The stronger E49 control uses vectorized **plaintext** owner dot products with
the original fresh seeded encryption. It does not inherit E49's additional
homomorphic-noise or privacy-hybrid premise. It is currently faster and cheaper
on the larger tested rank, so E49 is not promoted for performance.

See [the complete construction/control report](ciphertext-factory-results.md)
and [cache viability evidence](coordinate-cache-results.md). Passing those
regressions does not complete this game or its independent review.

| Obligation | Present evidence | Remaining work |
|---|---|---|
| Exact static representation | Exhaustive finite grammar, integer oracle, native/GMP encryption tests | General grammar / scale limits |
| Frozen-map edit identity | Encrypted before/after tests and sparse/full control | Insert/delete/reserve and basis migration |
| No exposure reuse locally | Lock, irreversible consume, stale/consumed tests | Durable journal, process/concurrent recovery, rollback trust |
| Full response soundness | Existing secret-vector family and bounded-attempt argument | Formal game tying all epochs and visibility to code |
| Adaptive privacy | Hybrid order above, seeded-XOF and one-use premises explicit | Complete reduction and independent review |
| Authentic setup | Required trust boundary; existing company TEE baseline retained | Authenticated experimental producer/migration implementation |
| Parameters / private timing | Research-only classification | Independent estimator/model review and private backend audit |

The appropriate next security claim is a **conditional protocol theorem with
explicit assumptions**, followed by independent review. Production assurance
or a claimed new cryptographic primitive would be unsupported.
