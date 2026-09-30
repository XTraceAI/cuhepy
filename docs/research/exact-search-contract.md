# P00: exact outsourced search contract

2026-09-30. Execution begins at `00a6362`; the E01–E40 implementation snapshot
is `02e06c0`. This contract governs the proposed publication experiments in
[the plan](publication-research-plan.md). It does not upgrade existing research
parameters or clients to a production security claim.

## Functionality and parties

An owner enrolls an ordered collection of binary vectors and unique unsigned
64-bit identifiers. An authorized client submits binary queries of the same
dimension. For a pinned epoch, the client receives every exact Hamming distance
in enrolled order and selects the lowest k pairs by `(distance, identifier)`.
The initial k is three; when fewer rows exist, all rows are returned.
Duplicates in vector values are allowed; duplicate identifiers are rejected.
An empty index has an empty answer and requires no encrypted scan.

The owner and client belong to the same confidentiality domain. The owner
may retain plaintext coordinates offline and authorize private maps on the
online client. One compute server may alter, omit, reorder or replay messages,
including adaptively after earlier accept/abort events. Availability is not
guaranteed. A separate factory, additional non-colluding helpers and output-only
top-k are changed contracts, each with its own label and analysis.

The user clarified on 2026-09-30 that the online client queries its own data
and may access or retain any part of it. Plaintext caching is permitted. No
data-retention prohibition or customer memory cap is assumed. The existing
`cuhepy.hamming.paillier` and `paillier_lookup` clients accept plaintext
embedding vectors for encryption, hold owner keys and decrypt server results;
they impose no prohibition on retaining the inputs. These SDK interfaces do
not establish an application-specific device budget or deployment frequency.

Experiments must therefore include full-cache and download-once controls,
including authenticated encrypted cache delivery, acquisition/setup cost and
updates. Compare cold sessions, reuse and measured storage/compute/traffic as
resource axes without inventing a mandatory tiny client budget. A practical
resource limit, if studied later, must be declared and justified separately.
When local caching is allowed and cheaper, recommend it for that profile;
production's current outsourced Paillier flow alone does not prove that
outsourcing is necessary or a paper contribution.

Full-score access is not database privacy against the authorized client.
Indeed `H(e_j,x)=H(0,x)+1-2*x_j` reveals each bit after d+1 queries. Privacy
claims here concern the compute server; a multi-client authorization theorem
would require a different functionality.

## Index and query semantics

Inputs are integers in `[0,2**d)`, with `1 <= d <= 512` in the current research
oracle. Enrollment rejects values of the wrong width and repeated IDs. Every
compiled plan includes the complete ordered row/ID digest, private transforms,
public context and position permutation. A compiler's local hash detects
stale fixtures; cryptographic owner authorization is a separate protocol step.

For unrestricted binary queries, the score field satisfies `t>d`. A schema
restriction may justify a smaller range only after both enrolled rows and
queries are validated. Such a profile is separate. Affine certificates are
refitted in each field, and every enrolled row is reconstructed exactly.
Rank estimates, approximate recall, and observed small noise are insufficient.

Queries are adaptive after enrollment. For a masked-query profile, the policy
fixes its query before learning or choosing based on the current mask. Masks
are independent across released queries; consuming a mask is irreversible.
Neither an abort, retry, update nor crash can restore a released mask.
Current local research tickets are not a durable network journal.

An accepted server result must cover every row exactly once for the authorized
epoch, query and plan. Complete verification precedes use of the long-lived HE
secret on a remote result. An alternative vLHE layer may change this procedure
only under its complete reviewed composition argument. Detecting a fraction of
bad calls, verifying a subset, or checking only decrypted score plausibility
does not satisfy this integrity requirement.

## Leakage policy

The first algorithmic experiments use the policy `public_geometry_v1`. Its
allowed server metadata is:

- Row count, dimension, parameter context, public CRT cover, ciphertext counts
  and feature/rank dimensions.
- Public component-to-map labels and equality labels for reused private query
  forms; values of the bases and anchors are private.
- Epoch/version identifiers, request count/timing/length, token identifiers,
  public update batches and any disclosed component invalidation locations.
- Accept/abort events and any later item retrieval that the application exposes.

The leakage function includes the chosen plan, not just `(m,d)`. A plan can
therefore leak index structure. Comparing plans under this *policy* does not
assert that their exact metadata leaks identical information. A padded/raw
public-profile control reports the cost of a more restrictive leakage policy.
No query-dependent row routing or early exits are allowed in the primary scan.

Private maps, masks, check keys, expected tags and HE secret keys are outside
the server view. The owner/client/factory must not expose them through debug
packets or pass them to an untrusted GPU. Private timing and memory-access
behavior remain explicit implementation review obligations.

## State, cost and admissibility

Charge online-device IDs/permutations, private maps, verification material,
HE secrets and unused token material separately. Charge offline-owner row
coordinates, full retained corpus and temporary compiler state. On the server,
separate canonical wire bodies, seeded storage and expanded resident arrays.
An O(m) position/ID table is real client state, even when maps are small.

Report query upload, response download, their sum, encrypted-index provisioning,
public/evaluation keys, token provisioning, proof/attestation, updates, framing
and retries. Report actual bytes separately from count models. Static oracles
may model codec/checker bodies but do not model RSS, transport or service time.
Amortization pays for every prepared token, including unused/invalidated ones.

Default production eligibility requires reviewed protocol, parameters and
private implementation. No new profile in this cycle has those endorsements.
Pure algebraic/count experiments opt into `research_only` explicitly. A
fingerprint's formal 128-bit collision target is not 128-bit HE assurance.

| Profile family | Current status | Comparison rule |
|---|---|---|
| E35/E37 full N=16,384, Q32/35/36/40, eta=21 | Implemented research circuit; deterministic correctness, conditional checker bound | Reproduce with exact recorded fields/schedules; no production-security label |
| Tiny rings/fields used in exhaustive oracles | Algebra/correctness fixtures | No secure-performance or production claims |
| EMVP/BNTM unified artifact's `Sec128` | External artifact targets with its own assumptions; BNTM hardness estimate explicitly incomplete | Preserve tuple and disclose status; do not inherit its label as independent assurance |
| vLHE reference modes | Different database/commitment and parameter premises | Record honest-digest vs theorem assumptions; adaptations require separate review |
| New or changed `(N,t,Q,eta)` | Unreviewed research candidate | Recompute exactness/phase/checker and reject from production allowlist |

## Completion evidence

This freezes P00's research contract and candidate classification, including
the clarified permission to retain all authorized data. Useful resource ranges
and customer relevance still must be demonstrated in P01/P06. The compiler/oracle enforces binary
width, stable IDs, complete row coverage, pinned contexts and research-only
classification. The service proof, parameter review and durable authorization
remain tasks P07/P08, rather than assumed consequences of this document.

Venue context checked on 2026-09-30: [CSF 2027](https://csf2027.ieee-security.org/cfp.html)
seeks foundational security results; [FHE.org 2027](https://fhe.org/conferences/conference-2027/call-for-presentations)
welcomes theory, algorithms and practical FHE presentations. These are different
submission formats. We prioritize a justified result; deadlines do not justify
removing a necessary baseline or claiming an unfinished proof.
