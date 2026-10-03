# Pinned external proof control

This Rust program tests Spartan proofs for the homemade E108 relation. It does
not implement or replace BFV/BGV/Paillier, and is not a production service.
The [report](../../../docs/research/proof-backend-screen-20261003.md) gives exact
scope, bytes, source/dependency identities and failed-run preservation.

Cargo's local dependency expects the preserved source at
`../research-data/proof-backend-20261003/spartan` relative to the repository,
exact upstream head `d62b961f9497e3c07a921b6da1457cad467598d9` (MIT). Restore the
checkpoint source/cache in that layout. Build offline with the committed lock
and separately preserved64 checksum-verified registry crates. The artifact is
a comparison control, not an independently audited security dependency.

The Python exporter supplies an owner-local manifest; the prover never chooses
the instance or statement pins. `verify` is a separate offline operation with
owner-local generators/commitment/field-file/domain/proof paths. The private
decoder exists only in the Python release adapter, after real proof verification.
Do not expose these command-line or manifest paths as an untrusted service API.
