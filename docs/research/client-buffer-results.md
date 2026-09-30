# E59: arbitrary private inserts, deletes and edits beside a verified base

2026-09-30. Returned to P05 after E54–E58 and the user's clarification permitting
client data retention. `experiments/bfv_search_lab/client_buffer.py` is an
ordinary base-plus-private-buffer control. It extends functionality without
refitting an encrypted representation for every arbitrary new row.

The base remains a complete fixed-ID encrypted index. Before each long-lived
HE decryption, the client checks the **whole old-base ciphertext relation**.
After exact base decoding, private positive/negative masks correct edited
live base rows, tombstones remove deleted base IDs and inserted rows receive
local XOR/popcount scores. New rows need not lie in the old affine span.
Output IDs are explicit: surviving base IDs retain enrollment order; live
inserted IDs follow in ascending ID order. Top3 uses `(distance, ID)` and
returns fewer entries for smaller/empty current indices.

Transactions are trusted owner-approved, atomic and immutable after commit.
Deleting a row permanently retires its ID; no historical ID may be reused.
Edits/inserts/deletes are validated before commit, including conflicting
operations, missing/duplicate IDs and binary/uint64 widths. Restoring a base
row removes its correction. A result requires both current private snapshot
epoch and pinned verified base epoch. Old snapshots remain immutable history;
current approval is a trusted caller premise.

This provides **logical deletion only**. Old encrypted rows still reside at
the server and the authorized client still holds old state/keys. There is no
erasure, network update authorization, durable freshness or HE base migration.
Private transport/timing and owner historical-ID state are charged/declared.
No client buffer reaches the server. This changes the current functionality
while leaving the server's checked base relation, noise, key, unused pads and
index geometry unchanged. Complete relation coverage is never replaced by
checking only currently live rows.

Four meaningful tests cover exhaustive small binary queries after arbitrary
operations, stable ties and empty results, atomic invalid operations and
historical-ID reuse, stale/invalid full-base inputs, and eight real encrypted
native/GMP/phase/full-gate queries with unchanged geometry and one-use tokens.

## Matched measured lifecycle

`benchmarks/client_buffer_lifecycle_lab.py` uses8192 synthetic d128/rank32 base
rows, N2048/t1153/Q40/eta21,24 original tokens, four batches of64 edits,64
deletes and128 inserts. New/edited values are unrestricted128-bit rows, so
they can leave the original span. Final live count is8448. Queries adapt to
prior top IDs; two rotating repetitions compare the same mutation and query
feedback trace against an **allowed full cache** acquired through AEAD.

| Method | Pair mean complete compute | What is charged |
|---|---:|---|
| Frozen encrypted base + private mutable buffer | 4.059 s | Discovery, compile, key/owner setup and close, full index, all24 original tokens/hints, checker/native prep, all mutations and queries |
| Authenticated full cache | 0.02659 s | Owner AEAD serialization/encryption, client authentication/parsing, mutable state preparation, identical private mutations and all queries |

Every96 full-current score arrays/stable top3 across both arms agree, as do
cross-arm per-query hashes. Every48 encrypted queries has a full base gate
before HE decryption; native/GMP/integer-phase diagnostics pass once per
revision. One lifetime budget records24 attempts per encrypted case and all
original pads are consumed. Diagnostic integer/GMP/reference work is separate,
not included in the lifecycle time. This is CPU compute, not network timing,
equal-assured-security comparison, production assurance or a population estimate.

The full cache is about153× cheaper in this complete-compute pilot. That ratio
includes different necessary setup work and must not be called a server-kernel
speedup. Additional buffer bodies are **in addition to** the encrypted base's
IDs, maps, keys, checker and tokens; the raw report lists those separately.
Private update body models and historical-ID state are paid for both paths;
Python RSS/allocator objects are unmeasured. Authentication/key/current-epoch
delivery for later private updates is a premise shared by both paths.

Raw: `benchmarks/results/publication-client-buffer-lifecycle-20260930.json`.

Return to the plan: P05 now has a tested private-buffer insertion/deletion
control, while encrypted-base insertion/deletion, rebase, durability and erasure
remain separate unimplemented tasks. The control is useful exact engineering;
it does not pass a novelty or complete-cost improvement gate against permitted
caching. Future lifetime policies must include this control and full caching.
