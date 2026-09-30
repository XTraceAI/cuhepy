# E64: verified support deletion on mixed and legacy layouts

2026-09-30. The [relation specification](supported-decoder-relation.md) precedes
this separate homemade prototype. It extends E62's single full-leaf experiment
without changing an existing client, full-response verifier or production code.
The [E63 support certificate](decryption-projection-results.md) remains an
independent algebra oracle, not a retrospectively claimed implementation.

`experiments/bfv_search_lab/supported_decoder.py` pins the key, random index
epoch, full query space, decoder support, exact per-leaf IDs and local private
plan identity. The server supplies supported C0 coordinates and **all C1**.
Canonical parsing, the original exact bound, hidden linear checking and the
shared lifetime allowance precede secret-key arithmetic. Only selected phases
are centered/reduced. The zero-filled carrier contains field values for CRT
decoding; it is never passed to ordinary ciphertext decryption.

Completed raw: `benchmarks/results/publication-supported-decoder-oracle-20260930.json`.
Seven N32/t17/32-bit-Q/eta1 **toy** layouts execute all16 four-bit binary queries:
**112 encrypted searches**. Native public evaluation agrees with GMP at every
coefficient. A separate native full gate passes before full secret diagnostics;
unreduced integer phases, complete decoder matrices, every score/ID and stable
top-three agree with independent references. One shared128-attempt object
records all112 calls across the different keys/epochs. These dimensions are
arithmetic tests, not cryptographically assured parameters.

| Layout / counts | Full coefficient body | Supported body |
|---|---:|---:|
| Full leaf, legacy,19 | 256 B | 204 B |
| Two equal leaves, legacy,12/4 | 256 B | 224 B |
| Mixed-degree leaves, legacy,6/3/1 | 256 B | 184 B |
| Multiple replies, legacy,35/9 | 768 B | 664 B |
| Two leaves, score-only,12/4 | 256 B | 224 B |
| Dense score-only,16/16 | 256 B | 256 B |
| One empty score leaf,0/4 | 256 B | 160 B |

Body sizes are actual canonical coefficient encodings; envelopes, setup,
private delivery and service transfers are additional. The Python/GMP checker
does not constitute a native speedup. Dense supports save nothing.

Eleven tests cover the above arithmetic, active-C0/C1 tampering, missing fields,
wrong key/epoch/space/bounds, malformed wire bodies, replay and exhausted global
allowance across a newly created gate. A secret-arithmetic spy remains untouched
on rejection. Another test combines an exactly decoded split-affine base with
private edits, insertion/deletion and an empty **current** result; its complete
encrypted base is still checked. Owner-local invalid ID/count/identity inputs
are rejected. A completely empty encrypted base is outside this helper.

The supporting omission identity and first-failure bound are conditional
arguments, not a reviewed full protocol. Provisioning authenticity, related
seeded encryption, private timing, concrete parameters and durable/multi-process
anti-rollback remain open. Row/map approval is a trusted owner premise, not
public commitment verification. Known sample extraction/support and fingerprint
ingredients are credited; this is not an originality claim.

Return to plan: the safe static domain is now executable. E65 must survive
simple balancing/alignment controls before any larger optimizer or new native
kernel is justified. See [the updated priorities](publication-research-plan.md).
