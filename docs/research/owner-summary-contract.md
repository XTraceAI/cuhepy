# E103 owner-summary exact top-three contract

This is a plaintext exact/count oracle for Route C, distinct from the primary
all-score HE search. Its output is at most three live `(distance, stable ID,
binary record)` triples, ordered by `(distance, ID)`. Equal records with
different IDs remain separate. Empty datasets return an empty result. A
fixed budget may instead return a local inconclusive outcome without a
query-dependent fallback. Such a budget is not an all-query exact service.

## Trust and coverage boundary

The owner possesses the entire current live dataset and may retain any part,
including the complete raw mutable cache. Trusted enrollment checks that a
partition covers **every** owner row exactly once, with unique uint64 stable
IDs, matching contents and binary dimension. Each group has a centroid,
maximum exact radius, live count, minimum ID and SHA-256 content digest. A
client-pinned manifest includes every group, the total live count, dimension,
public padding capacity, random/revision epoch and complete ordered metadata
digest. Empty groups have no minimum ID and cannot affect the top-three.

The pinned object represents trusted owner provisioning; this oracle does not
deploy signatures, AEAD, a trusted enrollment channel or durable freshness.
SHA-256 equality to trusted metadata is a known content-binding control, not
a newly proved protocol. Accepting a server-supplied manifest would invalidate
the boundary. A fetched row's membership alone cannot certify omitted rows.
After deletion/update, the owner must issue and pin a new complete manifest;
old blocks or old summaries must reject against that pinned revision.

For nonempty group j, every contained record has a lexicographic lower bound

```
(max(0, Hamming(query, centroid_j) - radius_j), minimum_ID_j).
```

The client computes exact scores of fetched records. It may certify an answer
only if all omitted groups have a strictly larger lower bound than its kth
`(distance, ID)` pair. If fewer than three records have been fetched, every
remaining nonempty group must be fetched. Strict comparison preserves ties.
The minimum ID is a safe conservative bound even when its record is not the
closest in the group. A radius supplied without owner coverage is unsafe.

## Traffic and cryptographic boundary

Variable fetch order/count/stopping are explicitly query-dependent diagnostics.
The fixed-budget count mode pays exactly B rounds with identical public record
capacity, including dummy fetches and dummy distance operations after logical
completion. It assumes an eventual private address-selection primitive and
does not implement one. Server scans, PIR request bytes/hints/proofs, RTT,
cryptographic gates and constant-time client execution remain unknown. Python
control flow and metadata/address observations are not claimed private.

No HE decryption exists in this oracle. Authenticating recovered records does
not authenticate a malicious outer BFV/BGV reply before secret use. Adding an
HE PIR backend requires a reviewed release gate or separately reviewed key
lifetime protocol. A server-visible success/failure signal or query-dependent
retry can leak; no client outcome is sent back by this oracle.

## Cache and updates

A raw mutable owner cache is a permitted exact control: serialized IDs and
rows cost `N * (8 + ceil(d/8))` bytes and queries need N Hamming evaluations.
Those byte counts exclude Python overhead, authentication framing and live
device memory. Retained summary metadata and padded record downloads are
charged separately. Mutable cache insert/delete/update counters are logical
operations, not latency bounds. The literal summary implementation rebuilds
the owner partition and metadata after every batch of changes, and counts that
work. Persistent enrollment, incremental authenticated summaries and private
updates would be additional work, not free baseline capabilities.

The [preregistration](owner-summary-preregistration.md) fixes the finite screen.
The [closest-work comparison](closest-work-roadmap-refresh-20261002.md#6-closest-work-for-owner-summary-assisted-exact-retrieval)
states why ordinary clustering, triangle bounds and private retrieval do not
alone establish novelty.
