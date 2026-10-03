# Q29 / E103: bounded owner-summary coverage and traffic count screen

Preregistered 2026-10-03, before implementing or executing this packet. This
is Route C of the [current roadmap](contribution-roadmap-refresh-20261002.md),
with a separate exact-top-three-plus-records contract. No HE, PIR, networking,
GPU timing, new parameter choice or production code is in scope.

The literal candidate is the **known** centroid/radius triangle bound plus
minimum stable ID and owner-pinned complete block coverage. This is a control,
not a new cryptographic construction. The closest-work comparison already
identifies [PANTHER](https://eprint.iacr.org/2024/1774), SANNS, verified PIR and
mutable owner caches as mandatory controls. The user permits plaintext caching.

## Frozen scope and decisions

1. Implement one plaintext owner-enrollment/coverage component and one exact
   candidate/count component. Enrollment must compare the partition with the
   entire trusted live owner dataset, bind block contents, radius, count,
   minimum ID, dimension and epoch, and reject omissions/duplicate IDs. Client
   metadata is owner-pinned. Server self-declared metadata cannot pin itself.
2. Exhaust every ordered binary corpus of length 0 through 3 in dimension 3,
   including duplicates, and every one of its 8 queries. Test both one-group
   and uneven three-group partitions. Exhaust dimension 4 queries for explicit
   tied-ID, fewer-than-three, empty group and deletion cases. Compare to an
   independent full scan. Reject stale/mutated manifests, malicious omitted
   blocks, row mutations, duplicate replies and fake undersized radii.
3. Separate variable-work oracle mode from **public fixed-budget** schedule
   counts. Budget B means exactly B equal-capacity slots, including dummy
   slots after logical certification. If B is insufficient, return a local
   inconclusive result; never add a query-dependent fallback. Each public slot
   pays capacity Hamming evaluations and record payload. Address privacy is an
   unimplemented PIR premise; fixed counts alone do not hide address/timing.
4. Count two frozen known owner layouts: sorted balanced blocks of capacity
   128, and nearest-prototype groups using 16 deterministic index-only seeds.
   No tuning to held-out queries. Use UCI Semeion and Mushroom split seed 3001,
   queries heldout indices 32:40. If the cached larger Connect-4 file exists,
   use the first 4096 enrolled rows and the same held-out query slice, recording
   that cap. No artificial retained-cache prohibition.
5. Include seeded uniform binary rows (1024x64, 16 queries), a deliberately
   favorable low-radius duplicate cluster corpus (256x32, 16 queries), and
   complementary-pair adversarial geometry (all 256 dimension-8 words, every
   query). Retain all outcomes, including padding blowups and inconclusive
   budgets. All synthetic seeds and generating rules enter the raw receipt.
6. Compare serialized metadata and padded downloaded records against a raw
   mutable owner cache. Explicitly charge client summary distances, real row
   distances, padded row distances, public rounds, summary rebuilds after
   updates, IDs/records and epoch/digest bytes. PIR queries, proof/hints,
   cryptographic authentication, RTT, private provisioning and durable
   freshness are not implemented; mark their costs unknown, never zero.

Budgets are the distinct values 1, ceil(G/4), ceil(G/2), G for each layout.
Report every query, not only successful cases. An all-query exact service
requires a public budget covering every query; exhaustive adversarial and
small-universe maxima are exact, held-out maxima are only observed maxima.
Full-budget padding can defeat pruning even if variable oracle counts look
good. Distances/counts are exact discrete observations, not wall-clock speeds.

## Acceptance and stopping

Exactness and rejection checks must pass. Stop the literal candidate at the
mechanism gate if it is ordinary triangle bounds plus authentication/PIR, even
if some geometry saves variable row visits. Do not upgrade it to a new protocol
or hide its unknown PIR costs. A later contribution must introduce and compare
a distinct summary/block/coverage mechanism, pay fixed traffic, prove complete
coverage and safe release, and survive the permitted mutable cache control.

The preregistration hash and UTC notification are archived outside Git under
`../research-data/owner-summary-20261003/`. Any changes after execution must be
explicitly recorded rather than silently rewriting the frozen scope.
