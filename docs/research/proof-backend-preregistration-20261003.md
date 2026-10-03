# E109 capped complete proof-backend control

2026-10-03. Frozen before acquisition/build/export/prove. Evidence parent
`95f857b9c4a788eeafd28e1e5816a3ad04b45d56`. Known comparison component under
the [current plan](contribution-plan-20261003.md), not an original construction.
Homemade HE and the frozen E106/E108 fixtures/relations remain unchanged.

## Scope, controls and limits

Use Microsoft Spartan exact source head
`d62b961f9497e3c07a921b6da1457cad467598d9`, MIT, package0.9.0. Retain source
archive, full source/dependency hashes, Cargo lock and compiler/binary identity.
The external library is a proof control, not an imported BFV/BGV implementation.
Confirm the downloaded relevant source matches the earlier read-only snapshots.
Build in a separate workspace with workspace-owned Cargo cache/target directory;
no system installation or source modification is required.

First instantiate the strongest folded-width E108 relation with28,879 variables,
29,247 constraints,256 public inputs,515,086 A entries,58,126 B entries and empty C.
The registered backend is Spartan SNARK (preprocessed instance commitment), not
a matrix-resending NIZK. Charge generator construction, instance encoding,
commitment/decommitment, padded dimensions, retained full Context, static rows,
host original-query expansion/full response parsing and field inputs.
Padding/bytes are measured serialization facts, not performance predictions.

The owner-local adapter supplies the exact pinned instance and derives public
inputs from the original frozen query and full canonical response. Bind context,
key/layout/epoch/IDs, instance stream hash, original-query bytes and every response
byte in a domain-separated transcript. Do not accept an unauthenticated circuit,
backend public RHS or transcript domain from a server. The backend's internal
instance commitment also enters its transcript.

If integration succeeds, one cohort contains all eight unchanged E106 original
queries. Save actual proofs and verify deserialized proofs with canonical bounded
encoding. Test original-query/response/epoch/context/instance/domain substitution,
all32 response coordinates including unused ones, public-input substitution,
proof-byte/length mutations, proof replay and an actual unsatisfied-witness proof
attempt. Rejection must precede the diagnostic private callback. Each proof binds
its own declared complete statement; transparent satisfaction alone is not counted
as a cryptographic proof. Honest decoded distances/ties must match the frozen oracle.

Resource cap: one source/dependency integration and one proof cohort; isolated
proof process at most8 GiB virtual memory and1,200 s wall time, maximum eight honest
proofs plus one unsatisfied attempt. Build at most10 minutes with bounded parallelism.
Stop on incompatible zero-C/interface, failed binding, unavailable dependencies or
resource cap; retain unsuccessful receipts. No repeated backend tuning, optimized
proof implementation, GPU kernel, lattice estimator or alternative large proof
backend is part of this component.

## Claim and advancement gate

Report actual proof/setup/field/matrix bytes, satisfaction and proof-negative
outcomes, dependency/source provenance and explicit unknowns. This is not a timing
benchmark: concurrent independent correctness screens may run, and diagnostic
process duration/RSS are resource accounting only. Later speed claims require
a separate monitored serial idle-window registration.

BitZ, corrected ring/CMC and GlueLUT controls remain unimplemented comparison
obligations where applicable; their missing adapters are unknown, not presumed
slow. Spartan costs do not establish a proof lower bound or original winner.
The pinned artifact is not independently security reviewed here. No ROM/lifetime
soundness, private side-channel, parameter approval, durable lifecycle or actual
attestation follows. Return to R6 after this component and route using complete
costs rather than generic constraint counts.
