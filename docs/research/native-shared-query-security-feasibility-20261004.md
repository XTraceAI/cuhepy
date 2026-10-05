# Q76.5 pre-evaluation security and prior-work decision

This is the required feasibility card before registering Q77. The selected
methods have bounded correctness evidence and a public static certificate;
none is approved for production confidentiality, actual attestation or private
release. The [specification](native-shared-query-certificate-spec-20261004.md),
[resource ledger](native-shared-query-resource-ledger-20261004.md),
[closest-work matrix](closest-work-contract-matrix-20261004.md) and
[finite execution plan](system-contribution-execution-plan-20261004.md)
control this interpretation. Q76.5 is supporting assurance, not an accepted
new cryptographic primitive or a general FHE semantic-validity proof.

## Selected functionality, adversary and explicit premises

One honest owner has an ordered binary index, unique UInt64 row labels and a
binary query. The authorized client may retain any plaintext and obtain all
exact Hamming distances, then rank by `(distance, original row ordinal)`.
IDs are labels. Approximate search, server-private data, malicious owners,
encrypted top3-only selection and content retrieval are separate contracts.

An untrusted store/evaluator can replace, omit, reorder, replay or delay public
messages; choose arbitrary claimed sources/results; observe public admission
outcomes and deny service. It cannot provision/advance the trusted owner pin,
sign as the owner/protected authority, replace the trusted executable, or read
the owner/client HE secret under the proposed deployment contract. These last
restrictions are deployment assumptions, not properties enforced by a hash.

Declared leakage includes public profile/count/group/shape and packet sizes,
record labels when supplied as public metadata, snapshot/key/policy identifiers,
request identity/scheduling, preparation/update/device events and public
admission outcomes. ID hashes are public bindings, not hiding commitments.
Vector/query privacy and private outputs require the separate encryption,
channel and client assumptions below. Denial of service is not prevented.

| Premise | Current evidence and boundary |
| --- | --- |
| Honest owner origin | Binary/predivided signed encoding, zero plaintext tails, independently OS-sampled bounded errors, ternary secret support, correct key targets and seed basis are required. Signatures authenticate bytes, not these private statements. |
| Correct fixed runtime | Public native/reference/frame/coordinate faults passed earlier bounded gates. The static checker imports no optimizer/HE/native code. Actual C++/NTT/CRT/gadget/codec refinement is not mechanized and remains a trusted-code premise for local evaluation. |
| Complete public predicate | Full relation checks common-Q bounds and both complete actual prime transforms; replay computes the canonical result; exact aggregate recomputes all protected products and suffix. Runtime equality and frame binding still must execute. A certificate digest cannot replace them. |
| Signature/hash binding | Standard Ed25519 and SHA256 binding are used. The descriptor authenticates its bounded outer envelope, checks the exact separately provisioned payload pin before parsing, and independently reconstructs all three certificate digests before publication. |
| Currentness/authorization | A trusted current pin and nonrollback at-most-once attempt controller are required. Existing local lifecycle tests and new metadata race/fork tests do not establish adversarial-host rollback resistance or deployed freshness. |
| Matching private context | HE secret/key/profile and request-signing context are separately provisioned to the authorized client. The new descriptor owns only public metadata and supplies no decryption or callback capability. Actual secure private provisioning/release remains Q78. |
| HE/cache logical equivalence | The honest owner asserts that the distinct cache and HE snapshots represent the same logical revision. Matching shape/IDs is not a plaintext-equivalence proof. Opaque cache key/snapshot IDs are independently provisioned, not publicly derived from an HE key or ciphertext. |
| Cryptographic confidentiality | Augmented RLWE assumptions for secret-dependent evaluation-key targets, actual sampler law, seeded expansion and parameter assurance remain open. No security level follows from Q120, a successful decryption or the correctness support box. |
| Private side channels | Private-key timing, RNG/error paths, memory ownership and telemetry remain separate audit/deployment work. Public admission reduces an oracle interface but does not make GMP/Python private operations constant-time. |

## Conditional correctness and public-reaction argument

The intended argument has four separate steps. Their open premises remain
visible rather than being replaced by successful test counts.

1. **Static reference.** The independently reconstructed certificate fixes the
   three eligible profiles, actual ordered prime basis, original query, full
   expansion branches, every feature/group and tensor term, canonical four-digit
   maintenance, complete terminal rule and ordinal output contract. It recomputes
   the conservative fresh/expansion/contraction/output/terminal supports.
2. **Runtime relation.** Assuming the fixed native primitives implement that
   reference, complete same-source both-prime equality and unique canonical
   lifting imply equality with the intended full-Q computation. In replay this
   is the protected computation itself; exact aggregate additionally compares
   all protected products. Full deterministic terminal equality fixes the frame.
3. **Message semantics.** Assuming valid owner inputs/key/noise semantics, the
   public strict Q/P guards prevent the admitted reference's phase wrap. Its
   centered signed score is `d-2*Hamming`; parity/range decoding gives every
   exact distance and zero unused plaintext tails. Nonzero ciphertext tail
   coefficients are permitted. The general BGV/model and codec proof is not
   mechanized by the closed arithmetic guard checks.
4. **Authorized private work.** Assuming an authenticated current owner context,
   a correct nonrollback authority and a matching private client, only the exact
   current request/frame can reach private work, and an attempt is consumed at
   most once. Actual private release, hardware attestation and secure channels
   remain Q78 rather than being supplied by `DescriptorClient`.

Under those premises, the observable accept/reject computation uses public
inputs and no HE secret. A simulator with those same public inputs can compute
that verdict. Thus the proposed public gate does not deliberately expose the
secret-dependent predicate exploited by the earlier malformed-ciphertext
reaction regression. This is a conditional protocol explanation, not a proof
that an arbitrary ciphertext, buggy decoder or deployed private side channel
is safe. A valid static certificate alone supplies no response authentication.

A future confidentiality reduction must define the full ideal functionality,
permitted leakage and adaptive scheduling, then separate signature forgery,
hash collisions, the actual augmented-RLWE/seed assumptions and trusted
implementation/freshness failures. No numerical bound for the latter failures
is invented here. A malicious-owner input-validity extension needs its own
protocol and cannot reuse honest-owner origin merely because a signature verifies.

## Scoped Lean result and remaining refinement

The workspace-local official Lean 4.34.1 distribution and checksum were frozen
before implementation. Four actual model invocations were retained: the first
failed the CLI source-root check; the second failed finite-guard decidability;
the third and final fourth passed. The final model has twelve named theorems:

- Three closed profile guards and the exact large terminal support 8,450,122.
- A bounded digit lemma and four unsigned radix-30 digit reconstruction of
  every 120-bit whole integer before actual-prime lowering.
- Signed-score range and injectivity under their explicit arithmetic hypotheses.
- Complete representation equality under stated CRT/NTT left-inverse hypotheses,
  then deterministic-frame equality for the complete result.
- No second release after an abstract consume transition, and stale-pin rejection.

The final `#print axioms` output is retained. There is no user axiom or
admission in the accepted model, and no `native_decide`. Some proofs use Lean's
standard `propext`, `Quot.sound` and `Classical.choice`; the closed numeric
guards and terminal value use no axioms. The failed second invocation's
diagnostic `sorryAx` output is preserved as a failed build, not accepted proof.

This does not prove actual-prime primality in Lean, concrete NTT/CRT algorithms,
FHE semantic-model validity, the polynomial noise/rounding derivation, C++
memory correctness, parser/signature soundness, sampler distributions, RLWE/KDM,
private side channels, SQLite nonrollback or attested execution. The public
Python/native prime checks and earlier tests remain separately scoped evidence.
General representation lemmas take left-inverse validity as theorem hypotheses;
they do not discharge it by assuming a new axiom.

## Early claim-to-prior decision

The stronger [counterconstruction](paper-contribution-discriminator-20261004.md)
remains mandatory. An unknown predecessor's adapter cost is unknown, not a
scientific gap or a defeated benchmark.

| Current interface/result | Classification | Closest credited predecessor and remaining distinction |
| --- | --- | --- |
| Feature-major matching, coefficient query expansion and delayed maintenance | Inherited mechanism | HERS/SealPIR/MulPIR and retained maintenance methods; no new packing or gadget headline. |
| Conservative semantic bounds and independent static validation | Adapted supporting assurance | [ILA](https://arxiv.org/html/2509.11559v1) and corrected ring-verification methods. Our closed screens and fixed-reference checker do not establish a new general model/type system. |
| Integrity-only protected computation and verification before private decode | Inherited architecture, adapted protocol | [Argos](https://petsymposium.org/popets/2025/popets-2025-0099.pdf) and [vFHE](https://arxiv.org/html/2301.07041v2). No first TEE/FHE or oracle-defense claim. |
| Full common-Q/actual-limb relation and deterministic aggregate admission | Adapted supporting assurance | Corrected maintenance verification and vFHE delegation; complete native adaptation and its charged boundary are our engineering obligation. The randomized compatible adapter remains unexecuted. |
| Ownership/current-context descriptors and independent schedule/lifetime checks | Inherited methods, adapted effects | Stateful authenticated storage and FlowCert/CirC/Silph; a signature, affine annotation or journal is insufficient as a novel contribution. |
| Permitted mutable plaintext cache | Inherited strongest control | Authenticated storage and ordinary local exact search; its data access is authorized, and acquisition/prefetch/update must be paid fairly. |
| A useful paid verification-placement/retained-state operating region | Unestablished systems hypothesis | Equally optimized protected execution/delegation, conversion-aware assignment and cache/prefetch. Q77 must identify an actual justified crossover and evaluator-only decision failure; Q79 must assess whether that specific finding is prior-separated. |

No row is presently an established substantive new theorem or measured main
result. Supporting assurance can use existing methodology. Originality still
requires a specific complete-execution finding and external closest-system
review; the formal-paper branch requires a nonroutine assurance result beyond
these conditional composition lemmas.

## Evaluation selection and stops

The three fixed HE modes and the permitted authenticated cache may enter a
separately registered **local prototype** Q77 cohort under the premises above.
The static metadata/core/model gates justify that bounded handoff; they do not
grant secure-service status. Q77 must preserve actual source hashes, measured
roles, setup/acquisition/update costs, all failed blocks and a true calibration/
held-out split. It must not import author performance estimates into this table.

Stop a secure-service claim until Q78 closes actual attestation/private release,
secure owner provisioning/currentness, parameter/sampler/KDM and private-side-
channel assurance. Stop any plan that changes the input law, omits a prime/
coordinate/source, accepts sampled noise instead of the public guard, substitutes
top3 for complete distances, silently adds a new placement, or treats descriptor
validation as private authority. Stop the positive outsourcing/paper headline
if strong cache/protected controls contain its useful region or its novelty.
Company engineering and negative findings remain preserved if that occurs.
