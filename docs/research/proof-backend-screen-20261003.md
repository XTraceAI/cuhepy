# E109 actual complete scalar proof control

2026-10-03. The capped known-control pilot produced actual Spartan SNARK proofs
for all eight unchanged E106 original queries and the strongest E108 folded-width
relation. [Raw](../../benchmarks/results/publication-proof-backend-20261003.json),
[preregistration](proof-backend-preregistration-20261003.md),
[owner adapter](../../experiments/bfv_search_lab/proof_backend_adapter.py),
[runner](../../benchmarks/proof_backend_lab.py),
[Rust control](../../experiments/bfv_search_lab/proof_backend_control/src/main.rs).
This is a proof-library control; homemade Paillier/BFV/BGV/native/CUDA remain
unchanged. It is not an original construction, timing benchmark or deployed
verified service.

## Actual proof and binding results

The pinned unmodified Microsoft Spartan head is
`d62b961f9497e3c07a921b6da1457cad467598d9`, package0.9.0/MIT. Its scalar field is
`2^252+27742317777372353535851937790883648493`. The offline setup/prove/verify
diagnostic uses preprocessed **SNARK**, with an owner-pinned computation
commitment, rather than a matrix-resending NIZK. An external proof backend is
not an imported implementation of HE.

Each proof binds the unchanged exact instance, locally reconstructed public
inputs and a domain containing owner Context/index/key/layout/IDs/epoch,
instance stream hash, original query bytes and **every** response byte. The
owner never accepts server-supplied RHS/domain/instance parameters. Backend
verification also binds its actual computation commitment. The complete
Boolean/range/slack/quotient relation remains; the TEE shortcut was not used.

- Eight honest proofs satisfy the actual backend and verify after bounded
  canonical serialization/deserialization. Separate local verifier child calls
  then authorize eight diagnostic private callbacks, matching72 distances and
  stable top-three IDs. Exact response hashes match the immutable E106 native
  golden record; no new native or GPU output run is inferred.
- **52 backend negative checks** reject: all32 response coordinates (including
  unused coordinates), seven domain changes, seven other-query replays, a public
  input change, four proof-format mutations and a changed computation commitment.
  Rust has no private callback. These tests do not replace a soundness proof.
- An actual ninth proof attempt uses an unsatisfied bit-flipped witness. The
  prover produces a proof; its verifier rejects it. This is one tested
  unsatisfied witness, not all possible forged witnesses or an executed attack.
- **Six owner release checks** reject wrong epoch/key/original query/full
  response, a trailing response byte and a truncated proof, with zero private
  callbacks. Eleven separate verifier-child calls are retained in the final
  release run; some metadata/grammar cases reject before invoking a backend.
- **12 unit tests** cover local admission and callback ordering only. Their mock
  Boolean verifiers are explicitly separate from the actual proof cohort.

The E106 false-canonical/single-limb families remain preserved prior tests.
They were not each sent as fresh cryptographic proof attempts in this capped
cohort; the complete E109 deployment/attack-family contract remains partial.
No lifetime-security, low-state-client or protocol-package acceptance follows.

## Fully visible bytes and setup

| Object | Actual bytes | Role |
|---|---:|---|
| Original query / compact response | 172 /211 | Frozen toy HE packets |
| Each actual proof | **135,200** | All eight have the same serialized length |
| Response plus proof | 135,411 | Before protocol/transport/attestation headers |
| Locally derived public inputs | 8,192 | 256 scalar words; not server wire |
| Literal witness per query | 924,128 | 28,879 scalar coordinates; prover input |
| Static sparse instance stream | 23,501,692 | Exact transparent enrollment/source artifact |
| Public generators | 222,128 | Serialized retained verifier/prover parameters |
| Computation commitment | 73,792 | Owner/verifier retained instance commitment |
| Prover computation decommitment | **553,648,696** | About528 MiB; stored setup object, not client reply |

The actual backend pads28,879 variables and29,247 constraints to32,768 each.
A has515,086 nonzeros, B58,126, C0; the zero-C interface works. Costs above are
serialized object facts, **not RSS or peak-memory measurements**. Setup,
static-instance construction, full owner context/index/key residency, repeated
admission/hash traversal, local original-query expansion and all public-RHS
products remain paid. The literal3,610-byte bit tape from E108 is not a proof.

For this tiny fixture, the proof is much larger than the211-byte encrypted
response. That does not establish a lower bound, large-dataset ratio or that
BitZ/corrected-ring/GlueLUT controls are slow. Those applicable adaptations
remain unexecuted/unknown. Process caps were respected; concurrent screens
prevent interpreting process duration as a matched timing benchmark.

## Provenance, failures and review

Source archive SHA256:
`3adc72875da476122acab6f84daf3f053e7818b1286b4f3ef287e5f7dda65541`.
All36 upstream files are retained, unchanged; ten exact files match the prior
read-only snapshots. The new Cargo lock resolves64 registry crates plus the
root and local Spartan packages (66 total). Each downloaded crate is checked
against its lock checksum. This is a **freshly resolved, then locked dependency
closure**, not reproduction of the authors' original dependency lock.

Compiler is rustc1.98.1; its full identity/hash, Cargo hash, actual binary hash,
Cargo lock, source acquisition and dependency receipts are under
`../research-data/proof-backend-20261003`. No system install occurred. Retained
build failure01 was an adapter borrow error, fixed without changing Spartan.
Its exact source is reconstructed and hash-checked against the original build
receipt. Unmodified upstream warnings are retained rather than patched away.

The first Python finalizer looked for a golden property at the wrong JSON
level **after all eight proofs and52 backend negatives completed**. Its exact
source, receipt and prior outputs are retained. Later finalizers reused those
same proofs, fixing the property path and adding review-driven source/backend
pins and numbered verifier logs; **no extra prove attempt** occurred.
The selected raw distinguishes original cohort source from finalization source.
The final loaded repository preprocessing closure has28 files; old E108
relation/exporter hashes are checked before reuse. Python optimization is
rejected, and locally selected binary/generator/commitment hashes are checked
before and after each final release sequence.

Read-only review confirmed original/full-wire binding and callback ordering;
its concrete receipt/guard recommendations were incorporated. Explicit
nonempty Ruff scope covers the three new Python files (and the separate E112
runner). Proof deserialization is capped/canonical and rejects trailing bytes;
this is not a complete hostile-service resource-hardening audit.

## Return to R6

The first actual proof control is now available for company/research comparison.
The wide gap between bit-tape counts and proof/setup bytes makes complete costs
essential before selecting another compiler. Do not widen to timing or native
proof optimization merely because one backend works. Current BitZ/ring controls,
actual TEE witness-oracle equality, durable attempt state, private side channels,
parameter/reduction review and a useful original algorithm remain open.
