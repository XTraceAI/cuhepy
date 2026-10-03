# E112 protocol card: authenticate the actual proof oracle

2026-10-03. Q38's bounded protocol/cost screen is complete; the service is not
implemented. [Raw control](../../benchmarks/results/publication-tee-oracle-partition-20261003.json),
[preregistration](tee-oracle-partition-preregistration-20261003.md),
[runner](../../benchmarks/tee_oracle_partition_lab.py).

## Exact objects and trust

The owner controls data, HE key, original requests, enrolled index/graph/epoch
and allowed code/parameters. An untrusted host/GPU can replace, combine, reorder
and replay every packet. This card gives a protected checker **no HE secret or
plaintext**. Side channels, platform compromise and durability are additional
assumptions to review. A plaintext TEE is a separately permitted stronger-trust
control, not evidence for the no-secret protocol.

Let S contain the domain, owner/key/layout/index/graph/parameter/instance digest,
epoch, unique owner request identifier, ORIGINAL query bytes, ALL response bytes,
and proof-generator/encoding identifiers. Let W be the complete padded witness
in its exact ordering, including source/slack/quotient/range coordinates and
specified zero padding. Let C=Commit(W;rho) be the **actual witness oracle** used
by an affine proof. An instance commitment is a separate object. An attested
SHA digest of W is also a separate object.

## Proposed message sequence and rejection rule

1. Owner enrolls approved image/code/graph, immutable context and PCS parameters;
   checks real attestation chain, measurements and the owner challenge. Code
   binds its receipt key to that evidence and the enrollment digest. Updating
   keys/index/layout invalidates dependent preprocessing and advances an
   owner-maintained epoch. Nitro offers signed measurements and protocol fields;
   the application still defines and checks the protocol.
   [AWS specification](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html).
2. Owner creates S's request domain from its original query and one-use request
   state. Host supplies the complete response and exact W (or a separately sound
   all-coordinate range/common-lift argument). Owner/checker derives public
   affine inputs locally; server-supplied RHS/domain values are inadmissible.
3. Checker parses every coordinate, reconstructs the common integers and the
   declared scalar bit/range/slack representation, including unused output
   coefficients and terminal remainder dependencies. In the E108 bit
   representation it can instead parse a canonical packed Boolean tape: the
   affine proof must then link its value/slack sums to that SAME tape. Packing
   changes transport; it does not remove those linkage equations.
4. Checker reconstructs **C in the proof's exact PCS, layout, generators, padding
   and blinding convention**, or verifies a reviewed commitment-equality
   argument. Host proves affine rows against C. Checker signs (S,C,PCS/layout,
   enrollment, request/epoch) only after complete range/common-lift admission.
   If the PCS needs rho, its ownership, transfer and entropy have to be defined.
   Merely signing a host-provided C or hashing another W is insufficient.
5. Client checks real attestation/receipt and enrollment, locally reconstructs S,
   enforces one-use durable request/epoch state, and verifies the affine proof
   with C explicitly pinned as its oracle. **Every rejection occurs before any
   private-key operation.** Consume/invalidate the attempt under an owner
   transaction before release; crash/retry/rollback behavior must be reviewed.

Conditional invariant: if attestation/receipt unforgeability, commitment binding,
all-coordinate admission, affine-proof soundness and durable state hold for the
same S,C, accepted W is canonical and satisfies the complete relation. This is
an obligation list, **not a security reduction or adaptive-lifetime guarantee**.
Do not add errors as probabilities until the exact extraction/commitment and
attempt-composition definitions are reviewed.

## Source/interface discriminator

The exact pinned Spartan control stores its witness commitment privately in
`R1CSProof.comm_vars`; `SNARK` contains that proof privately. `SNARK::prove`
constructs a new random tape internally; `R1CSProof::prove` commits the supplied
witness and its internally generated blinds. Its public verify API accepts an
**instance** commitment and public inputs, with no supplied trusted witness
commitment equality check. Inspect the unchanged
[pinned primary source](https://github.com/microsoft/Spartan/tree/d62b961f9497e3c07a921b6da1457cad467598d9)
in the E109 source cache: `src/lib.rs` and `src/r1csproof.rs`.

Therefore this card cannot be implemented by appending a signed digest to the
existing adapter. A supported external-oracle PCS adapter or reviewed backend
extension is required; its complete cost is presently unknown. The existing
complete Spartan control retains Boolean constraints and needs no such TEE
shortcut. No backend source was modified here.

## Paid ledger and controls

| Item, unchanged N8 folded-width fixture | Count or byte fact/model | Interpretation |
|---|---:|---|
| Complete relation | 29,247 constraints | 28,879 Boolean +368 affine |
| Proposed affine partition | 368 affine constraints | 28,879 Boolean admissions move to protected code; they do not disappear |
| Literal scalar witness | 924,128 B | Actual transparent serialization, not a proof |
| Canonical bit tape | 3,610 B | Minimum packed transport MODEL before headers |
| Padded backend bit tape | 4,096 B | MODEL for 32,768 coordinates; padding must be bound |
| Original query / full response | 172 /211 B | Actual unchanged toy packets |
| Local public field inputs | 8,192 B | 256 locally derived scalar words |
| PCS equality/blinds/MSMs/peak memory | Unknown | Cannot replace with a SHA hash or sampled opening |
| Attestation/receipts/durable lifetime | Unknown | No enclave was launched or authenticated |

The executable omission control changes one source bit to7 and adjusts field
quotients/slack so every affine row still holds. The complete Boolean relation
rejects it, and its tape digest differs from the honest tape digest. A valid
receipt for the honest tape would say nothing about a proof for the unrelated
tape without C equality. This is a **logical omission demonstration** with
literal affine checking, not an executed forged signature or cryptographic
affine proof. It makes no claim that an invalid output passed the complete
system.

Full CPU/native replay, complete scalar proof, best corrected ring/BitZ adapter,
an equally optimized Slalom-style protected linear checker, ordinary hybrid
partitioning, permitted plaintext TEE and client cache must receive identical
preprocessing/fusion/packing opportunities. The underlying delegation pattern
is established by [Slalom's authors](https://github.com/ftramer/slalom); the
specific required oracle equality is derived from our actual relation and
pinned API. No complete cost comparison or new contribution is established.

A stronger control can avoid the external-proof oracle interface entirely:
the protected checker admits the complete canonical tape **and checks the
affine equations itself**, using protected Freivalds/adjoint preprocessing
where applicable, then authenticates the complete statement/response. That is
a known Slalom-style full protected verifier. It must pay full tape transport,
matrix-free adjoint setup, private checking vectors, all prime/common-lift
checks, lifetime/feedback and actual attestation/state. Its soundness and cost
have not been implemented or reviewed in E112. The API stop here is specific
to the proposed external-affine-proof partition, not an impossibility result
for TEE verification.

## Return to R6

Stop before service implementation. Q38's first card is complete and exposes a
real interface obligation. Advance only after selecting a reviewed PCS equality
interface and showing that complete protected admission/commitment work beats
the strongest hybrid/full-replay control. Actual Nitro/GPU attestation, durable
state, private side-channel assurance and protocol reduction remain separate.
