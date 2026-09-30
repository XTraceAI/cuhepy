# P07: conditional bounded-lifetime argument for direct fresh correlations

2026-09-30. **A draft mathematical argument under explicit assumptions**, not
an independently reviewed theorem, concrete HE-security estimate, production
endorsement or new cryptographic primitive. It narrows the earlier
[security agenda](exact-search-security-game.md) to the direct fresh owner
construction used by E54/E56/E59. The encrypted-index factory E49, arbitrary
backend/representation migrations and external code-based protocols are
outside this statement. Ordinary masking and secret linear checks are credited
to prior work, including [Slalom](https://arxiv.org/html/1806.03287v2).
Consumable preprocessing and selective-failure-aware verification are also
covered by [small-state vPIR](https://eprint.iacr.org/2025/1714.pdf); this draft
does not transplant its assumptions or auxiliary decryption argument.

## Restricted protocol and functionality

One honest owner and authorized client share a confidentiality domain and
retain authentic local state. One malicious server sees the encrypted index,
owner-produced encrypted answers, requests, replies and declared leakage.
The client may access/cache all its rows. Its current functionality is every
exact current Hamming score with stable IDs/top3, or an abort chosen by the
server. Privacy concerns the server, not this authorized client.
The owner generates the one fresh honest key/context during enrollment; the
simulator can generate that same-distribution context and encrypt zeros under
its simulated key. A game with externally fixed owner keys requires an
additional setup/oracle argument and is not silently covered here.

Fix one approved prime plaintext field t>d, one prime coefficient field Q,
full-ring key/context, certified private maps, CRT cover and row/ID order.
For a mask r independently sampled in the private query-coordinate space,
the owner directly and freshly encrypts the exact answer Phi(Mr). Initial
index columns, new full/selected-tile columns and repaired unused answers use
independent direct fresh encryption samples. Public evaluation is the approved
full-Q coefficient relation Y(index,answer,delta), with delta=w-r mod t.
The client pins its own request and verifies **every coefficient of both
components of every reply** before long-lived HE secret-key use.

Approved fixed-map encrypted updates can change fresh columns and unused
answers, provided complete trusted checking hints are prepared for the new
random epoch. Unaffected old columns may remain. Pads whose deltas have escaped
are retired forever. Locally private E54/E59 changes instead leave the checked
base fixed: correction, tombstones and inserted rows update current output
only after that complete base relation has passed and decoded exactly.

Leakage L includes approved public geometry/plan labels, fields/context,
public index/answer/epoch/token lengths and schedules, disclosed encrypted
update locations, attempt timing/count, accept/abort and subsequent retrieval
metadata. Private-buffer epochs/values are not automatically public. If local
timing reveals buffer counts, that must be excluded explicitly or included in
L. Public benchmark diagnostic hashes are not deployable protocol messages.

## Assumptions to discharge before claiming the result for deployed code

1. **Authentic owner interpretation and state.** The approved binding covers
   key/context, exact index/answer relation, maps/IDs, base epoch, current
   private snapshot and global budget. Owner changes are atomic and authentic.
   Every remote candidate that can reach a challenge-dependent verdict is
   charged to one retained bounded lifetime; crashes/retries cannot roll back
   pads, hints or the budget. The server cannot register answers/checkers.
2. **Certified exactness.** Every base row reconstructs, CRT placement covers
   every row once, canonical ciphertext/field parsing is exact, and a universal
   honest-circuit bound stays below Q/2 for every approved request/update.
   The integer score range fits t. Metadata/cost choices do not use hidden mask
   values, check challenges or sampled errors unless explicitly analyzed as
   leakage. Queries are fixed before exposure to their current mask.
3. **Actual encryption privacy.** Let epsilon_Enc bound a joint adaptive,
   multi-message IND-CPA experiment for the **actual direct seeded symmetric
   encryption**, in the presence of its public-key samples and declared public
   metadata. Count all fresh index, answer and update encryptions, including
   related Mr and DeltaM*r messages; their randomness is independent and their
   messages are not functions of the HE secret key. Plaintext-related hashes
   and private correlations are absent from auxiliary server data.
4. **Private expansion privacy.** Let epsilon_mask bound replacing all hidden
   pad expansions by independent uniform field pads. Let epsilon_check bound
   replacing all hidden seeded-check expansions, across epochs/answers, by
   independent uniform vectors in the *whole* F_Q coefficient space.
   Domain separation, unbiased rejection sampling, seed freshness and the
   relevant query/sample limits belong in these assumptions.
5. **No unmodeled private observation.** The server sees no private check
   hints/seeds, mask seeds, HE secret or secret-dependent timing/memory/cache
   trace. Owner/client corruption, rollback and implementation side channels
   are outside this restricted game. They remain actual engineering problems.

The public polynomial expansion seed is a distinct matter. One cannot use
ordinary hidden-seed PRG security to replace `(seed,SHAKE(seed))` with
`(seed,uniform)`, because a receiver can recompute it. Assumption3 requires a
direct seeded-encryption theorem, or an appropriate random-oracle argument
including seed collisions/prior oracle queries. A concrete RLWE estimate alone
does not discharge it. An N2048 correctness/heuristic performance experiment
does not establish epsilon_Enc or production security.

## Conditional statements

Let B be the total permitted verification attempts across all relevant
epochs, and let c be the number of independent full-vector field challenges.
Under the assumptions above, for this restricted direct-fresh protocol:

```text
Pr[accepted current output differs from authorized F_exact output]
    <= epsilon_check + B / Q**c.

Real/ideal server-view distinguishing advantage
    <= epsilon_Enc + epsilon_mask + epsilon_check + B / Q**c.
```

epsilon_Enc is already a **joint multi-message advantage**, not an unexplained
single-sample constant. If reduced to a single-message assumption, explicitly
multiply by the number of hybrid encryption replacements and bound their
auxiliary/adaptive setting. Multiple keys/fields require a separate sum; for
epoch-specific fields the soundness term is sum_e(B_e/Q_e**c_e), bounded by
B*max_e(Q_e**(-c_e)) if sum_e B_e<=B. Authentication/state failures would add
their own terms in an enlarged game. They are premises here, not silently zero
in a deployed system. PolynomialCheck requires its different collision bound.

### Exactness and integrity argument

When a returned coefficient vector equals Y, the certified full-Q linear
circuit and universal phase bound yield the exact pinned-base field products.
Private map/anchor decoding yields the integer Hamming scores because t>d.
Every row is covered. With trusted snapshots, private bit-mask corrections
are the identity

```text
H(q,new)-H(q,base)
  = pc(positive)-pc(negative)
    -2*(pc(positive&q)-pc(negative&q)).
```

Filtering approved tombstones and appending exact local inserted-row scores
gives the current authorized row set; stable pair sorting gives top3. No new
server ciphertext or HE decryption input is introduced by the private buffer.
Thus a wrong accepted current result implies a wrong coefficient vector was
accepted, or an assumption about owner interpretation/exactness/state failed.

In the ideal-check game fix adversarial coins and all public/owner history
independent of hidden weights. Follow a counterfactual which accepts exact Y
and rejects every nonzero error. Before the first false acceptance the real
and counterfactual histories coincide. Its j-th nonzero error is therefore
fixed without the hidden weights. A nonzero vector over prime Q has inner
product zero with a uniform vector with probability1/Q; all c rounds pass with
probability Q**(-c). Union over at most B counterfactual attempts yields
B/Q**c. Honest acceptance does not disclose weight information. This argument
does **not** assume each later error remains independent after conditioning on
the real rejection event. New epochs neither erase past attempts nor authorize
more total trials. The private-check expansion hybrid adds epsilon_check.

### Privacy argument and why the order matters

First replace private-check expansion by ideal independent vectors. Except
for the bounded first false acceptance, a malicious server can only deliver
the exact authorized coefficient relation or cause an abort. Replace HE
decryption/score recovery on accepted replies by the ideal current exact
result, and reject every nonzero error by **public relation equality**. The
coupling changes the view only on that first false acceptance. Adaptive future
queries still depend on the same authorized result/abort history; the reduction
never decrypts an adversary-chosen ciphertext under an unknown long-lived key.

Now apply the actual multi-message encryption assumption to each direct fresh
sample, replacing its plaintext by zero. Retained columns and updated sums
are deterministic public functions of these samples; old/new answers sharing
an unused r are related messages covered by the joint assumption. Public
phase bounds and approved schedules must remain reproducible from L. The
client's ideal result has already replaced real decryption, so zeros do not
silently change future query selection.

Only **after** encrypted pad-dependent auxiliary data have been removed,
replace hidden pad expansions with uniform independent r. At a token's sole
release, w was selected without its r; delta=w-r is uniform in its coordinate
space. Unused pads can survive trusted owner updates because their extra
direct encryption samples were already replaced. Exposed pads cannot survive
as fresh tokens. The remaining server view consists of approved public
contexts/zero samples, uniform deltas, public evaluation/error equality,
ideal result/abort history and L. A simulator samples those objects without
private maps, rows, queries, check hints or unauthorized HE decryption.

This is a single-key, fixed-representation conditional simulation argument.
The full formal environment/oracle specification, extraction of code-level
assumptions and independent review remain unfinished; it is not a universal
composition theorem for arbitrary cost-planner rewrites.

## Executable evidence and the limits of that evidence

- E54/E56/E59 independently check every score/ID, native/GMP coefficients and
  unrounded integer phases; consumed/stale tokens reject. This supports code
  correspondence/correctness, not encryption indistinguishability.
- `verification_lifetime.AttemptBudget` burns before checker calls, including
  malformed objects, rejection and exceptions, and shares its allowance across
  new epochs. Thread tests pass. It is volatile trusted-object state, not a
  persisted receiver/rollback defense. A deployed receiver must also handle
  parse failures, disconnects and multiple processes without revival.
- `soundness_lifetime_oracle.py` exhausts684 tiny ideal-field all-reject paths.
  For Q3/c2 and three attempts the maximum is25/81, below3/9. After two real
  rejects, a third conditional probability can be1/8 rather than1/9. Two
  independent epochs with three attempts **each** yield3425/6561, exceeding an
  incorrectly claimed three-attempt lifetime bound1/3. These exact controls
  explain the proof order and global budget, not concrete128-bit assurance.
- E53's hypothetical exposed factory-zero seed and the reused static EMVP
  mask update lie outside the construction and violate its premises. Do not
  reuse this hybrid for them. AES cache delivery has separate AEAD/freshness/
  compressed-length assumptions and never decrypts a server HE result.

Raw: `publication-soundness-lifetime-oracle-20260930.json`. Return to P07/P12:
use this scoped draft for formal review and an optimizer transition-contract
design. Preserve unresolved seeded-HE, durable authorization, concrete
parameters and private-side-channel obligations. Gate D remains open.
