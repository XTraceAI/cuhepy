# Q76.5 owned resources and lifetime handoff

This ledger uses the frozen [specification](native-shared-query-certificate-spec-20261004.md),
the completed Q76.3b/Q76.4 public cohorts, and the Q76.5 retained metadata run.
It inventories counted components and exposes unmeasured components. It does
not certify a native stage peak, transport latency or secure-service cost.
The [certificate return](native-shared-query-certificate-return-20261004.json)
pins the execution freezes, reports and sources. Earlier raw reports stay intact.

## Actual preparation, traffic and client provisioning

All rows below use the retained N=16384/d=512 owner-canonical Q120 profile.
One logical owner controls the data and may keep every plaintext row.
The three HE methods use the same reference graph, actual prime basis and
complete compact terminal frame. Separate snapshot/policy/code bindings are
necessary because their authenticated runtime implementations differ.

| Component | 8,224 records | 16,384 records | 32,768 records | What the number counts |
| --- | ---: | ---: | ---: | --- |
| Evaluation-key common-Q coefficients | 19,660,800 B | 19,660,800 B | 19,660,800 B | 80 polynomials, 15 bytes/coefficient; no packet header |
| Unseeded expanded index coefficients | 251,658,240 B | 251,658,240 B | 503,316,480 B | Two complete polynomials/feature/group, including partial groups |
| Signed seeded enrollment wire | 145,612,826 B | 145,612,826 B | 271,695,130 B | Archived full-relation owner enrollment; headers and keys included |
| Signed original query wire | 246,076 B | 246,076 B | 246,076 B | Archived authenticated seeded request |
| Expanded original query encoding | 491,520 B | 491,520 B | 491,520 B | Two full common-Q polynomials; temporary preparation input |
| Native owned original-query payload | 524,288 B | 524,288 B | 524,288 B | Two N-element vectors of 128-bit `Wide`; excludes vector capacity/headers |
| Resident public RNS row payload | 423,624,704 B | 423,624,704 B | 826,277,888 B | 1,616/3,152 rows; actual two-prime UInt64 payload |
| Resident maps and shift payload | 3,538,944 B | 3,538,944 B | 3,538,944 B | Nine levels; N size_t entries and two N-word shifts/level on this host |
| Prepared forward prime NTT count | 2,226 | 2,226 | 4,274 | Observed native stats; operation count, not elapsed time |
| Full relation witness body | 126,320,640 B | 126,320,640 B | 127,057,920 B | Every expansion/C2 source plus two final Q polynomials/group |
| Exact aggregate claim body | 737,280 B | 737,280 B | 1,474,560 B | Three canonical common-Q aggregates/group; before wrapper/frame |
| Prepared replay source-witness wire | 0 B | 0 B | 0 B | The protected evaluator receives only the original request |
| Client ciphertext coefficient body | 102,400 B | 102,400 B | 204,800 B | Two complete 25-bit component polynomials/group |
| Complete compact terminal frame | 102,488 B | 102,488 B | 204,895 B | Archived complete frame with its canonical header |
| New signed compact client descriptor | 66,854 B | 132,134 B | 263,206 B | All ordered IDs, selected profile, cache binding and three mode bindings |
| Ordered ID bytes within descriptor | 65,792 B | 131,072 B | 262,144 B | UInt64 labels in original row order |
| Permitted cache complete acquisition | 592,467 B | 1,179,987 B | 2,359,635 B | Binary rows, IDs, encrypted packet, authentication and cache descriptor |

The descriptor's extra metadata is 1,062 bytes in each large row. Its three
certificate bodies are independently reconstructed and discarded by the client;
they are not downloaded/retained alongside the descriptor. The retained full
certificate sizes are 22,244/22,247/28,316 bytes, replay certificates
22,294/22,297/28,366 bytes, and aggregate certificates 22,393/22,396/28,466
bytes at these counts. A verifier's enrollment certificate remains a separate
provisioning artifact. A static description is not the large execution witness.

These links are distinct: enrollment is owner-to-prepared-service setup;
the query is client-to-service; full/aggregate claims are producer-to-admission;
the compact frame is admission-to-client. Co-location changes paid transfer,
copy and isolation costs, not which bytes exist. Descriptors/private context
are device provisioning, and cache acquisition/update is a competing path.
Do not label all of them one ambiguous response number.

## Owned and transient lifetimes

| Owner/object or stage | Definitely owned/live components | Release/invalidation and unclosed accounting |
| --- | --- | --- |
| Honest owner | Plaintext rows/query, HE secret, signing key, evaluation-key generation inputs; optional cache key | Provisioning and private objects are not in the public checker. Private key representation, crypto objects and secure erasure remain unmeasured/reviewed. |
| Authenticated HE enrollment | `OwnerEnrollment._public_wire`, public metadata/IDs, native preparation, factory anchor/policy | The retained signed packet is additional to RNS payload. Native `Query` uses `shared_ptr<const Context>`; closing the context handle does not free preparation while a query still references it. Python/public-wire references can also survive close. |
| Enrollment parsing/preparation | Incoming packet, unpacked payload/key/seeded packets, expanded index bytearray/bytes, public temporary coefficient objects, RNS preparation | Canonical re-encoding creates another packet buffer. Exact overlap and native capacities are not instrumented. These are paid setup costs, not part of online arithmetic alone. |
| Native context | Prepared key/index/sum rows, maps, shifts, two `PrimeNTT` plans, key/index locations, graph ops/bindings/roots/use counts and interning map | The row/map payload formulas omit plan storage, container headers/capacity, map nodes and allocator bookkeeping. Those remain explicit resident components. |
| Authenticated original request | Signed seeded wire, request binding and native query original vectors; shared preparation reference | Seed expansion/common-Q encoding and parser/framing copies are preparation work. Query close releases the native query; callers may retain immutable packet/binding objects. |
| Genuine expansion/producer | Current and next levels of RNS ciphertext pairs, rotated pairs, four digit rows, switched pair, plus/minus branches, inverse/forward transforms and common-Q composition | Final expanded-query payload is `4*D*N*8` = 268,435,456 B. It is not the stage peak: the prior level and new level coexist, with local temporaries/capacities. |
| Full relation admission | Whole canonical claim, both-prime complete affine graph values, remaining-use counters and root lists, per-input forward transforms | Completed values are released according to use counts. Graph node totals 22,525/26,650 are recorded native stats, not a mechanized exact liveness/capacity model. Missing coordinates/limbs are not permissible streaming. |
| Prepared replay | Genuine protected expansion, three products/feature/group, canonical C2 decomposition/switch, two final-Q polynomials/group | Final-Q dedicated buffer is 491,520/983,040 B, not total scratch. Replay writes no source witness and does not perform an invented second evaluator pass. |
| Exact aggregate admission | Same protected genuine prefix and all three products, three common-Q claims/group, six claim forward-prime NTTs/group, equality checks and protected suffix | It pays the protected arithmetic already needed by replay and additional claims/parsing/transforms. Smaller witness traffic supplies no protected arithmetic-saving claim. |
| Public terminal codec | Complete final-Q input, two P output buffers/group, GMP rounding temporaries, packed complete frame | ctypes output buffers and `.raw` immutable copies coexist; MessagePack framing may add another copy. The deterministic codec is paid in every HE mode. |
| HE packet parsing | Original wire, unpacked body/frame fields and canonical `_pack(fields)` temporary | Full packets contain large binary fields. Canonical checks do not make their live copies free. Exact overlap depends on caller/wrapper lifetime and is not certified here. |
| Lifecycle controller | Current enrollment, durable attempt journal, bound request/frame authorization and callback state | Local tests support intended state transitions. Host rollback, actual attestation/freshness, crashes/delivery and private release remain Q78. |
| New descriptor client | Owner anchor, current pin, public geometry, packed complete IDs, Python ID tuple, three small mode/cache bindings | No HE enrollment, evaluation keys or certificate bodies retained. Caller packet, unpacked payload, signature-message concatenation and reconstructed reference dictionaries/certificates are transient. Python/crypto objects and simultaneous parser peaks are unmeasured. |
| Cache acquisition | Owner anchor/AES key/current pin, incoming packet, authenticated decrypted body, parsed complete IDs/rows and duplicate-ID set | Publish only after complete authentication/context/grammar checks. Old state can coexist during acquisition; a late acquisition cannot republish an invalidated pin. |
| Cache returning query | Packed rows/IDs, local scores and ordinal top3 | Zero remote search response for this path. Charge its initial acquisition, private key/context provisioning and local compute. |
| Cache update | Old rows, plaintext patch, full row-copy bytearray and replacement bytes | 32-row complete patch is 2,683 B at d512. At 32k, each full row-copy component is 2,097,152 B; old/temporary/new rows may coexist. A missed epoch requires reacquisition. |

Native pointer inputs are borrowed immutable bytes during synchronous calls.
Containers and Python metadata can share references; encoding size does not
count the number of simultaneously resident copies. No secure erasure, DSO
unload or allocator decommit is inferred from clearing Python references.

## Q77 accounting rules

1. Charge preparation and its invalidation to the actual reuse horizon, and
   separately identify first-device, returning-device and update events.
2. Account for producer and protected work, both transfer directions, parser/
   framing copies and private client work. Record actual co-location/channel
   assumptions. The protected checker/replay is not an uncharged second server.
3. Give every compatible method the same permissible preparation, representations
   and observations. The generic selector receives exactly the same legal plans
   and costs. Exact aggregate claims do not receive a fictitious product saving.
4. Grant cache its own compact current context/key provisioning. Do not require
   the full three-mode HE descriptor or HE enrollment for a cache-only client;
   its authenticated backup already contains complete IDs. Charge shared
   frontend descriptors only if the measured implementation actually needs them.
5. Report the canonical component counts above, process high-water RSS and any
   separately instrumented stage/allocation measurements under different names.
   RSS is neither an exact native stage peak nor a proof of lifetime bounds.
6. The selected timing profile is a local prototype under declared native and
   owner-origin premises. Secure-service performance needs the Q78 deployment.

This completes the bounded resource handoff by enumerating the required
components and recording the unclosed measurements. It does not discharge
those unclosed components through an RSS value or a structural formula.
