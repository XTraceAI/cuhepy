# E54: private client deltas are a required stronger update control

2026-09-30. [Ledger](../../experiments/bfv_search_lab/client_delta.py),
[tests](../../experiments/bfv_search_lab/test_client_delta.py),
[complete native harness](../../benchmarks/client_delta_lifecycle_lab.py).
This follows the [vectorized repair regression](vectorized-update-controls.md).
It is ordinary delta caching, not a new cryptographic construction.

## Exact mechanism and contract

Keep a verified encrypted **base** index and its one-use masks/checker fixed.
For each changed stable ID, the trusted owner supplies two private bit masks:
positive bits changed 0→1 and negative bits changed 1→0, measured against the
base row, not against the previous revision. For query q the score correction is

```
popcount(positive) - popcount(negative)
  - 2 * (popcount(positive & q) - popcount(negative & q)).
```

After complete base verification and decryption, add this correction to the
appropriate row. Returning a row to its base value removes its exception.
The full-score contract, exact binary domain, IDs and stable ties are preserved.
New rows may be outside the old affine span because no new row is encoded in
that span. No unused answer or ciphertext changes, no noise accumulates, and
the single base checker retains its lifetime attempt budget across edits.

This is allowed by the primary contract's shared owner/client confidentiality
domain and private owner-to-client state. It would not be the same control if
the application forbids such state or hides rows from an authorized client.
The additional private state and traffic are explicitly charged; the owner
still retains base/current rows and coordinates. No artificial memory limit
is introduced to exclude this control or the complete plaintext cache.

## Matched measured lifecycles

| Synthetic workload | Vectorized full rebuild | Private delta control | Paired median complete CPU saving | Peak extra private body |
|---|---:|---:|---:|---:|
| m4096/d128/rank32/N2048, pool16, four edits | 3.193 s | 1.226 s | **61.60%** | 224 B |
| m8192/d512/rank128/N2048, pool24, four edits | 37.425 s | 23.894 s | **36.15%** | 608 B |

Two rotating pairs each, t1153/Q40/eta21. The stage sum charges affine discovery,
compilation, key generation, initial index/pool and complete checker/native
preparation, every update and every original token. Each revision includes
adaptive queries; all remaining tokens are consumed on the last. All 160 queries
pass the complete gate before secret decryption and match every score/top-3.
GMP coefficients and unreduced phases agree once per revision, outside timings.
This harness also charges initial checking/native preparation and queries before
the first edit; its absolute totals are not identical to E43's schedule.

Private delta update body models total 416/800 B. The fresh control sends
3,558,336/24,329,088 B of seeded update packets. These are different channels
and body models, not measured encrypted transport. Extra private body excludes
Python objects/RSS, complete base maps/keys/IDs and compiler scratch. Counts are
fixed by changed owner IDs and do not depend on private query values.

Raw: [rank32](../../benchmarks/results/publication-client-delta-rank32-20260930.json),
[rank128](../../benchmarks/results/publication-client-delta-rank128-20260930.json).

The result exceeds 20% in these synthetic screens **for a known strong control**.
It does not establish Gate C for a new algorithm, useful outsourcing over local
cache, real update frequencies or an original paper contribution. Selective
encrypted-tile updates and complete raw/zlib caches remain additional controls.

## Conditional composition argument

Assume the base protocol is correct and privately handles adaptive queries;
the trusted owner's patch snapshot is pinned to the exact base/current epoch,
dimension, stable IDs and authorized binary rows; and the complete base gate
has first-false-accept probability epsilon across its one lifetime budget.
Conditioned on no false acceptance, the decrypted base scores are exact.
Expanding each changed coordinate proves the identity above, so every corrected
score equals the authorized current row's distance. Thus an incorrect accepted
current score requires a base false acceptance or a violated trusted-snapshot
premise. There is no new server-controlled input to secret HE decryption.

For privacy, the server sees the original base protocol with adaptive queries;
the correction state remains inside the trusted owner/client domain. A reduction
runs the private patch/query logic locally and forwards the base transcript.
It adds no public plaintext update matrix or zero-encryption seed. Query timing,
the base profile/epoch and any later ID retrieval retain their declared leakage.
If a policy rebuilds an index or exposes update counts, that is a different
transcript and must add those events to the leakage function.

This is a **conditional local argument**, not a reviewed full protocol proof.
The code does not authenticate remote snapshots, persist one-use state, enforce
rollback/deletion erasure or provide private timing. P07/P08 must supply those
premises before deployment. A malformed or replayed private patch channel is
not handled merely by the base server-response gate.

Return to P04/P05: exact checkpoint/exception planning must preserve which
rows the encrypted base represents. Current rank or current exception count
cannot determine future cancellation or rebuild costs. Price this strong
control before claiming benefits from reserved spaces or correlation repair.
