# Complete GPU-admission selection: checked products and a trusted suffix

2026-10-03. **Design-only feasible prototype; execution awaits a separate root GO.**
This proposal closes one complete original-query-to-response path using the existing
homemade BGV product checker and a trusted public CPU continuation. It is a known
Slalom-style control and an explicit system-selection falsifier, not an original
algorithm, executed prototype, reviewed reduction, production release or timing
result. No old code, guard, key, fixture, measurement or checkpoint is changed.

## 1. Decision and precise contribution question

Implement one complete hybrid path before another literal full-trace or scalar
proof service: the untrusted GPU computes product/relinearization tiles; a protected
checker verifies every tile block; the checker then computes the butterfly,
canonical terminal conversion and exact complete response itself. The GPU's claimed
final response is never a signing input. The protected checker has the encrypted
index and public evaluation keys, but no HE secret or plaintext index.

The immediately feasible result would be a complete source-bound admission control.
The open performance question is whether verified GPU products plus the trusted
suffix beat equally optimized full native public replay after internal traffic,
setup, updates, concurrency and all client costs are charged. The open originality
question is a source-specific complete architecture or useful tradeoff beyond known
trusted-nonlinear/untrusted-linear partitioning. Neither answer is assumed.

[Slalom](https://arxiv.org/abs/1806.03287) already delegates linear layers to an
untrusted accelerator and retains trusted work; its fixed-map batching and
preprocessing are controls. Our existing [E13 product checker](bgv-checked-product.md)
specializes this pattern to canonical BGV multiplication/relinearization.
[E106](native-boundary-screen.md) supplies complete graph/terminal obligations.
The new step proposed here is their complete protocol integration and matched
cost decision, rather than a new randomized-check identity.

## 2. Exact graph and source interfaces

For trusted ordered index tiles A_b=(a0_b,a1_b) and the independently expanded
owner-original query x=(x0,x1), define unshifted product/switch tiles in R_Q:

```
c2_b = a1_b*x1
D_b = canonical base-2^30 digits of canonical_CRT(c2_b)
y0_b = a0_b*x0 + sum_j D_b[j]*K_relin[j,0]
y1_b = a0_b*x1 + a1_b*x0 + sum_j D_b[j]*K_relin[j,1].
```

Q is the actual product of the two existing approximately 60-bit NTT primes. Every
coefficient in both components and both limbs is part of the statement. Use the
existing local-c2 checker: c2 and its common full-Q canonical digits are computed
inside the trusted checker before batching. No server digit tape is admitted.

The existing `NativeServer.product_switch_rns` is restricted to padded=1, CUDA
level4, N<=16384 and at most64 index tiles. It returns this **unshifted** y. A full
search with padded trace degree D first applies X^(1-D) to each y. Passing unshifted
tiles directly into the existing full-D butterfly would be incorrect. A proposed
continuation must apply that monomial independently in both limbs, then execute the
exact existing joint butterfly, rotation/key-switch and partial-group schedule.
It must retain all rotation levels even for a one-tile tail.

Source boundaries to inspect/adapt, without editing the historical files:

- `experiments/bfv_search_lab/checked_product_bgv.py`: immutable packet, local-c2,
  fresh post-output challenges and one-use arithmetic request.
- `experiments/bfv_search_lab/native_check_bgv.py` and `_verify/product.h`:
  resident index/key NTTs and whole-polynomial checks in both primes.
- `experiments/bfv_search_lab/_native/cuda_trace.cuh`: existing padded=1 direct-RNS
  product stage; no new full-GPU trace exporter is required for this proposal.
- `experiments/bfv_search_lab/_native/residue_trace.h`: exact monomial and butterfly
  schedule. Its private loop is not currently a continuation API.
- `experiments/bfv_search_lab/_native/compact.h`, `compact_bgv.py`, `transport_bgv.py`:
  exact nearest-congruent terminal lifts and complete compact-v1 framing.
- `experiments/bfv_search_lab/attested_bgv.py` and `security_bgv.py`: separate existing
  CPU-only Nitro authentication, setup authorization and original-request binding.
  This proposal does not alter their accepted circuit or authorize CUDA receipts.

A new separate extension/module can ingest already checked canonical RNS tile
snapshots, apply the trusted continuation and export the exact compact packet.
The first reference can implement this independently with schoolbook ring arithmetic.
The native continuation must not call product generation again or silently regain
full replay cost without recording it. A public low-level continuation accepting
unchecked bytes is an arithmetic API; only the composed admission controller may
invoke it for an authorized final result.

## 3. Enrollment and complete message sequence

The owner enrolls immutable source/build/graph/encoding/parameter identities, exact
ordered encrypted index, public/switching keys, row IDs, count, dimension and epoch.
Owner authorization precedes expensive setup parsing. Trusted setup reconstructs
key fingerprints and all derived schedules; caller labels/digests are not evidence
of owner origin. An actual deployment separately verifies the attestation chain,
measurements, challenge and receipt key. A local process cannot stand in for that
hardware trust claim.

The proposed request protocol is:

1. Pin an owner-authorized original query byte snapshot, a fresh owner request ID,
   enrolled epoch and complete context digest. Independently expand the seeded or
   compressed query under the locally fixed encoding. Do not trust host-expanded
   coefficients, phase bounds, terminal modulus or RHS.
2. Create an exact covering block schedule of the enrolled tile array, with each
   block of size1..64 and named global `[start,end)` positions. Bind each stage
   request to the parent request, epoch, full enrollment digest, ordered block
   index digest, exact query digest, global positions and mode. Stage nonces alone
   are insufficient to establish global coverage.
3. Receive each complete canonical RNS product/switch output as an immutable trusted
   memory snapshot. Validate complete grammar and canonical residues, then sample
   fresh independent uniform weights for that block. Use the existing three
   whole-polynomial repetitions in each prime. Consume each stage attempt before
   validation; malformed packets and entropy failures cannot retry its challenge.
4. Maintain a trusted coverage state: reject missing, duplicate, reordered,
   overlapping or differently bound blocks. Do not pass any unchecked tile to the
   continuation. If any block fails, invalidate the entire parent attempt before
   further release. Parsing failure is public failure, never an HE decryption probe.
5. On complete admission, apply X^(1-D), the exact whole-index butterfly/rotation
   schedule and canonical terminal packing inside trusted execution. Derive all
   bounds locally. This is the authoritative complete response, including unused
   coefficients and metadata. A host-provided final ciphertext is ignored or
   separately required to equal the authoritative full byte snapshot.
6. A deployed protected service authenticates this same complete response and original
   request only after all checks and the trusted suffix finish. The owner independently
   checks attestation/receipt/enrollment/request/epoch, durably consumes the parent
   attempt and invokes private decoding only after acceptance. No raw OwnerClient
   fallback or unauthorized host receipt is enabled.

Streaming admission may bound product-block memory, but butterfly pairing crosses
block boundaries. Until a reviewed streaming scheduler exists, retain all checked
unshifted products for a trace group and pay that memory. A successful early block
does not authorize a prefix response. Pipeline overlap is a later measured choice,
not free work or a security premise in this first prototype.

## 4. Conditional authenticity argument and unresolved assurance

For a fixed immutable incorrect product block, local-c2 computes the unique correct
canonical source and digits. At least one native-prime output error matrix is
nonzero. One fresh uniform batch row misses with probability at most1/p for that
corrupted limb; three independent rows give at most1/p^3. Do not multiply the bound
by an honest limb's success. The same error matrix includes all tile/components/
coefficient equations in the block.

Fresh post-snapshot challenges give this bound conditionally on the preceding
transcript for each attempted block. If J is the globally accounted number of
attempted block checks across all requests and epochs, the ordinary union bound is

```
Pr[any false product-block admission] <= J/min(p0,p1)^3.
```

J counts rejected/retried/abandoned/concurrent attempts and all fresh service epochs;
it is not the number of successful user searches. Fresh challenge use avoids the
reusable-secret-adjoint privacy requirement, but it does not establish a durable
attempt budget by itself. The historical per-process/per-session counters are not
an enforced global lifetime bound. No numerical production budget is assigned here.

Conditioned on correct enrollment, no false product admission, correct trusted
continuation and exact final-byte binding, deterministic induction through the
canonical public graph makes the response equal the enrolled public evaluation of
the owner-original query. This is an output-authenticity invariant. HE parameter
assurance, fresh-error correctness, owner seed-law/epoch assumptions, signature/
attestation forgery, rollback resistance and implementation/private-side-channel
assurance remain separate obligations. Wrong honest decoding from inadequate
parameters is not repaired by checking canonical computation.

The checker contains no HE secret. Challenge secrecy is needed until its immutable
output snapshot is fixed; there is no persistent secret adjoint to leak into future
attempts. Still, entropy, compiler/native memory safety, actual protected execution
and transcript interfaces need review. Local arithmetic success alone is not a
malicious-server confidentiality reduction or deployed pre-decryption guarantee.

## 5. Full paid graph and strongest controls

| Phase | Paid work/state/traffic | Required comparator treatment |
|---|---|---|
| Owner setup | Key/evaluation-key generation, index encryption, IDs and authorization | Same corpus, encryption mode and profile; do not relabel public index as owner-encrypted |
| Enrollment | Complete setup transfer/parsing, source pins, NTT index/key preparation in GPU and checker, enclave memory | Charge once and amortize only over a stated query/update workload |
| Query | Owner encryption/codec, authorization, original bytes to checker, trusted expansion and raw-RNS GPU upload | Match packet and seed domain across variants |
| GPU product | All covered blocks; allocations/workspace, transfers, kernels, synchronization, canonical direct-RNS output | Use the existing strongest direct-RNS stage, not Python/GMP conversion as the main baseline |
| Checking | Packet snapshot/hash/parse, fresh weights, local c2 products, canonical CRT/digits, batch checks | No expected-output equality inside admission; all block checks charged |
| Internal boundary | GPU-to-parent copies plus parent-to-protected-checker block transport | Ordinary host copying is not measured Nitro/vsock throughput |
| Trusted suffix | Initial monomial, all full/tail butterflies, rotations/digits/key products, CRT, terminal rounding and full packing | Full native replay gets identical prepared NTTs, fusion and packing |
| Release | Attestation/session amortization, receipt construction/check, durable request state and private decoder/top-k | Include client work and all WAN hops; no simulated hardware claim |
| Updates/concurrency | Index/key/graph epoch rebuilds, invalidated preparations, actual peak state and isolated leases | Same update rate and CPU/thread/memory budgets for controls |

For N16384, D512 and8192 vectors, tile capacity is32 and there are256 tiles. The
proposed direct-RNS output body is `tiles*2 components*2 limbs*N*8 bytes`, or128 MiB
before stage headers. The final one-group25-bit compact coefficient body is
`2*N*25/8`, or102400 bytes before framing. These are **geometry models**, not a new
measurement or byte optimization claim. Four64-tile blocks do not remove the128 MiB
protected boundary or the trusted continuation's group storage. Historical E13
stage medians are context-specific evidence, not predictions of this full path.

Required matched controls are complete prepared native CPU public replay; existing
unchecked full-GPU search labeled unsafe for adversarial release; the proposed
checked hybrid; complete proof admission where applicable (E109 is an actual tiny
Spartan control, not a measured large proof); equally specialized protected
Slalom/Freivalds partitions; permitted owner plaintext caching; and plaintext search
in a protected service. Unknown BitZ/ring-proof adaptations or enclave costs remain
unknown, not automatically slower. Local caching is permitted by the user.

[E117's complete protected-affine ledger](protected-affine-ledger-20261003.md) is an
additional known control. Its large literal witness/hint costs motivate this
smaller implementation boundary, but neither that ledger nor this geometry proves
that a succinct proof or optimized complete affine checker must be expensive.

## 6. Bounded activation and falsifiers

**Proposed first GO:** one complete public reference controller on the unchanged
E106 disclosed N8/D4/dimension3/count9/eight-query fixture. It has five index tiles,
groups4/1, all canonical cuts and all terminal bytes; no resampling or profile search.
Use fresh block checks rather than archived fixed checker rows. Compare complete
outputs against the existing independent full oracle only as external truth, never
as the admission decision. No native/GPU build, timing, new security level or service
activation follows automatically from reference success.

Before that GO, root should freeze the exact new-file closure, fixture/source hashes,
resource cap, single cohort, independent test scope and expected stop rules. Proposed
new paths are a separate `complete_checked_bgv.py`, independent tests and one bounded
runner; their precise names and all activation details belong to root's contract.
A following explicit GO may add the separate native continuation and one actual GPU
cohort; source correctness and complete canonical equality must pass before a
monitored matched timing panel is activated.

The first controller must reject each omitted/duplicate/reordered block and tile,
wrong original query/enrollment/key/epoch/global position, malformed/noncanonical
limb, mutation of every component/limb, parent/nonce/mode replay, entropy failure,
concurrent duplicate attempt and unchecked continuation call. Whole-packet callback
sentinels must stay zero for all rejected requests. Include D>1 monomial, full-group
and one-tile-tail cases, all unused response coordinates, complete terminal
serialization, and stable positional ties. Deterministic arithmetic tests may use
explicit checker rows; only the composed controller generates actual challenges.
An all-zero low-level row remains a negative control, never an exposed protocol mode.

Stop the architecture's performance claim if the complete hybrid, with its internal
traffic and trusted suffix, fails to beat strongest full native replay in a useful
matched workload. Stop any originality claim if equally specialized Slalom/control
partitioning has the same method and frontier. A successful reference is a complete
control integration, not a reason to start another unrestricted parameter grid.
Return to the system-selection plan after each explicitly bounded component.

## 7. Platform scope and source record

AWS describes Nitro Enclaves as isolated CPU/memory environments with no persistent
storage or external networking; parent communication uses vsock. Durable lifecycle
and parent-to-enclave coefficient traffic therefore require actual application
mechanisms and measured transport, rather than a trusted parent pointer.
[AWS concepts](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html),
[AWS vsock guide](https://docs.aws.amazon.com/enclaves/latest/user/enclave-networking.html).

NVIDIA's attestation SDK documents supported confidential-computing hardware/SKUs,
including Hopper H100 or later with the appropriate configuration. This proposal
assigns no GPU attestation capability to the local RTX3080; a future confidential-GPU
mode is a separate deployment and comparison.
[NVIDIA attestation prerequisites](https://docs.nvidia.com/attestation/attestation-client-tools-sdk/latest/gpu_and_switch_attestation.html).

Primary browser/source cards and baseline source hashes are recorded in
`../research-data/system-selection-20261003/gpu-admission-design/`. Slalom is already
in the immutable prior-paper archive; this design adds no literature registry entry
or downloaded paper. The plan authors did not run science, tests, native builds,
proofs, CUDA, enclave execution, challenges, timing or a new count program.
