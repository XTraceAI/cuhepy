# Q76.5 reference, certificate and client-context specification

Registered at `367230e`, after the verified cache checkpoint `6cffed1`.
This is the specification to freeze before implementing the checker/model.
It does not claim either exists yet. The
[registration](native-shared-query-certificate-registration-20261004.json)
caps this same remaining milestone; its internal components are not new
preliminary experiment queues. No fresh HE work, native evaluation/builds or
timing is authorized here.

The local model is supporting assurance. ILA already supplies quantitative
FHE correctness/translation validation under a valid model, and vFHE plus
full protected execution supplies compatible integrity controls. This gate
does not claim a new general type system, gadget identity or primitive. A
specific useful complete-execution result remains unestablished.
See the [closest-work matrix](closest-work-contract-matrix-20261004.md),
[ILA](https://arxiv.org/html/2509.11559v1) and
[vFHE](https://arxiv.org/html/2301.07041v2).

## Reference semantics and explicit premises

An honest owner holds an ordered snapshot of binary rows, unique UInt64 IDs,
one binary query and a ternary HE secret with coefficient absolute support
one. At dimension `d`, define `Search(i) = popcount(row_i XOR query)` and
rank by `(Search(i), i)`. Returned IDs are the original labels at these
ordinals. Complete scores and all unused feature/record tails are part of
the contract; a correct top3 alone is insufficient.

Let `D` be the least power of two at least `d`. The query plaintext is
`D^-1 * sum_j (1-2*q_j) X^j mod t`, zero outside its first `d` coefficients.
The owner index contains, in group-major feature order, polynomials with
coefficients `1-2*row_ij`, zero outside occupied record slots. `N >= 2D` and
odd `t > 2D` make the predivision valid and the signed score interval unique.
Canonical expansion yields constant features `1-2*q_j` and zero padded
features. Contraction plaintext is `d-2*Search(i)`; centered decoding and
parity/range checks recover every distance.

`OwnerOrigin` includes correct binary/predivided encoding, zero padding,
independent OS-backed centered-binomial errors with absolute support `eta`,
ternary secret support one, correct relinearization/automorphism targets and
a consistent HE key/seed basis. Seeded owner encryption uses independent
fresh 32-byte seeds, domain-separated rejection sampling and independent
secret errors. No zero-token reuse or correlated encryption is introduced.
Signatures bind ciphertext/context bytes; they do not prove these private
semantic statements. Owner/cache/HE plaintext equivalence remains an honest
owner premise, not a public ciphertext-equivalence proof.

Only the three retained profiles are eligible:

| N | d | t | eta | Actual Q | P |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 16 | 3 | 11 | 1 | 1329227995784911300417119789528939649 | 33554267 |
| 32 | 5 | 19 | 1 | 1329227995784909824677593892767984513 | 33554291 |
| 16384 | 512 | 1031 | 21 | 1329227995784613643754746428306227201 | 33548413 |

The actual ordered prime pairs come from the pinned public fixture/source
records. Record count must be an exact integer in `[1,2N]`; group and last
occupancy/tail counts are recomputed, not supplied as authority. Q has exactly
120 bits and common-word width is 15 bytes. The prime product must equal Q,
each prime must be distinct, in
`[2^59,2^60)`, and `2N` must divide each `prime-1`. P must be an odd prime
in the selected range, with `P < Q` and `P == Q mod t`. No three-prime,
public-key-origin or derived-last policy becomes an option by changing a
certificate field. Toy profiles supply correctness controls, not production
security parameters.

## Checker API and bounded certificate grammar

Implement a standalone `shared_query_certificate.py`, importing no optimizer,
`Profile`, `Profile.envelope`, native adapter or HE backend. Public arithmetic
and ordinary hashing are permitted. A trusted caller supplies selected
geometry, actual prime basis, record coverage and execution mode. A peer
certificate cannot choose any of them, a library, code path, graph or weaker
bound. The checker reconstructs the authoritative expected specification
and checks every supplied obligation, including when a supplied old digest
is otherwise valid.

Use canonical JSON for the public certificate: ASCII keys/enum values,
lexicographically sorted exact field sets, separators `,` and `:` with no
optional whitespace, integer types excluding booleans, no duplicate fields,
floats/constants or trailing material. Reject nesting deeper than 16,
integers longer than 64 decimal digits and arrays beyond the fixed selected
schedule/coverage caps; validate limits before accepting metadata. Its maximum
is 2 MiB. Large integers represent Q/bounds, never polynomial payloads. Digest
the complete domain-separated canonical bytes, but independently validate
the contents rather than accepting a digest as semantic authority.

The signed client descriptor uses a domain-separated canonical MessagePack
array envelope of fixed arity with a raw payload and 64-byte Ed25519 signature.
Bound the outer envelope before verifying its signature, then parse its fixed
version/context payload and compare it with the separately trusted current
owner pin before publishing complete metadata. Payload fields use bytes for
tags/IDs/digests and large Q, ordinary bounded unsigned integers for shape/
epoch, and fixed-arity arrays for the three named mode bindings. Disallow
maps, strings, extensions, extra/truncated fields and boolean integers. Full
packed IDs are raw UInt64 little-endian bytes; the entire signed descriptor
is capped at 278,528 bytes. Canonical re-encoding must match every received
encoding. Decode/authentication errors do not create a validated certificate
or partially publish client metadata.

The immutable validation result is a **public static plan description**. It
is not a decryption, callback, attestation or lifecycle capability. Every
authority entry still needs the authenticated factory, actual response
predicate, current-context/attempt state and later reviewed private release.
A static certificate cannot replace any of those checks.

Required certificate sections and falsifying mutations are:

| Section | Independently reconstructed obligation | Required rejection |
| --- | --- | --- |
| Version/context | Exact selected geometry, count, ordered prime basis, key/context binding and trusted mode | Unknown field/version, boolean integer, cross-key/profile/mode or changed prime |
| Origin | Fixed selected owner encoding/sampler/key/secret-support premise, stated as an assumption | Public-key origin, derived policy, absent zero-padding or larger secret/error support |
| Representation | Canonical 15-byte whole-Q integers in `[0,Q)`, four unsigned radix-30 digits shared before both-prime lowering, complete invertible NTT vectors | Independent limb digits, noncanonical lift, missing limb/frequency or free expanded input |
| Expansion | One original query; every level, input, source, automorphism and both signed branches | Missing/reordered source/edge, wrong parent/exponent/monomial, free expanded query or missing padded feature |
| Contraction | Every real feature and occupied/padded group, all three tensor terms, canonical C2 relinearization per group | Missing feature/group/middle cross term or relinearization |
| Phase | Recomputed fresh/each-level/contraction/output/terminal support and strict Q/P guards | Lowered declared bound, incomplete stage, wrong origin or failed guard |
| Terminal/message | Exact congruent nearest Q-to-P rule, both complete components per group, all coefficients/tails, full canonical frame and signed score/parity decoding | Different conversion, accepted top3-only frame, absent tail/header or numeric-ID tie key |
| Placement | Only full relation, original-request-only protected replay or exact three-aggregate prefix/suffix | Random challenge, free claim, response-selected code, unimplemented query-custody placement or unpaid protected work |
| Authority/client | Current owner pin, exact request/snapshot/frame/ID/mode context and at-most-once authorization assumptions | Self-promoting descriptor, stale/foreign epoch/query or duplicate authorization |
| Resources/custody | Explicit owned/resident/scratch/input lifetimes and trust/secret/entropy premises, with unknowns exposed | Treating RSS as exact stage peak, omitting acquisition/witness/preparation, hidden challenge from readable future state, or claiming no CPU secret for a CPU signer |

## Canonical graph and integer boundary

At level `l`, there are `2^l` input pairs. Input `k` binds source ordinal
`2^l-1+k` to the canonical lift of the automorphed C1. The automorphism
exponent is `1+N/2^l`. The switched rotation produces both
`C+Rotate(C)` and `X^(-2^l)*(C-Rotate(C))`. Their next-level positions are
`k` and `2^l+k`, respectively. Check the entire schedule through `log2(D)`;
its final natural feature order is authoritative. Evaluation-key schedule is
one relinearization key and one rotation key per level, each with four radix
columns and both ciphertext components. No graph supplied by the producer
overrides this tree.

For each group and feature, form A=`q0*i0`, C=`q1*i1` and
B=`(q0+q1)*(i0+i1)-A-C`. Sum all three components over `d` features. The
canonical lift of summed C2 uses source ordinal `D-1+group`. Relinearization
uses the shared four-digit decomposition and both key components. Complete
final coverage has two Q polynomials per group, even for partial groups.

Unique canonical lifting and complete both-prime relations rely on coprime
actual moduli and invertible negacyclic NTTs. Checking only a subset of
frequencies, primes or source positions is not this predicate. Every source
integer is bounded before lowering, so the gadget error support follows for
all accepted witnesses, not only an honestly produced or sampled transcript.

## Public effects and proof scope

With B=`2^30-1`, ell=4, F=`floor(t/2)+t*eta` and
E=`t*eta*N*ell*B`, reconstruct:

```text
F_0       = F
F_(l+1)   = 2*F_l + E
F_pre     = N*d*F*F_log2(D)
F_output  = F_pre + E
F_terminal = ceil(P*F_output/Q) + ceil((N+1)*t/2)
```

Check `2*F_l < Q` at every expansion level, `2*F_output < Q`, and
`2*F_terminal < P`. These follow from signed permutation norm preservation,
the N-term negacyclic convolution bound and bounded switch errors, subject to
`OwnerOrigin` and actual semantic correctness of the primitive/key basis.
The selected large terminal support is 8,450,122. Sampled successful private
noise is neither needed nor sufficient for admission.

Terminal rounding is the existing complete componentwise rule: for canonical
`x` in `[0,Q)`, let `r=x mod t`, set
`k=floor((2*(P*x-Q*r)+Q*t)/(2*Q*t))`, and output `(k*t+r) mod P`.
Pack all N coefficients of each of the two components, with exact bit width,
zero physical padding and complete headers. Ciphertext coefficients in unused
record slots need not be zero; their **decrypted messages** must be zero.
Do not accidentally reject a valid noisy ciphertext tail as nonzero plaintext.

Use the pinned Lean 4.34.1 core/Std toolchain for a small explicit model.
Initially mechanize selected arithmetic guards and abstract representation/
state/refinement lemmas with their premises visible. No `sorry`, `admit` or
user-added axioms; publish axiom output. Do not replace kernel proof by
`native_decide` and claim the same trust boundary. This is not, by itself,
an established BGV/ILA model validity proof, RLWE/KDM reduction, C++ binary
refinement, randomness/side-channel audit or deployed authority proof. List
the remaining obligations as such. General lemmas may take semantic
validity/NTT/CRT conditions as explicit theorem hypotheses; do not conceal
them as a new axiom or present them as discharged conclusions.

## Three legal placements and paid resources

| Mode | Public input/claim and complete predicate | Work/state that remains charged |
| --- | --- | --- |
| Full relation | Signed original request, immutable enrolled context, `D-1+groups` canonical source polynomials and two complete final-Q polynomials/group; both-prime full relation plus complete terminal equality | Untrusted source production and witness link, protected canonical-digit relation work, public/key preparation, complete codec and authorized release |
| Protected original request only | Same original signed request and trusted enrolled context; protected native code computes the complete canonical result directly | Whole expansion/product/relinearization/codec and preparation; no invented duplicate producer, source witness or second replay |
| Exact three aggregate | Untrusted three common-Q aggregates/group and proposed complete frame; protected genuine prefix, exact full aggregate comparison and protected suffix | Producer and three protected products/feature, complete claim NTT/comparison/links and shared prefix/suffix. Current implementation saves no protected aggregate arithmetic versus replay |

Publish a resource/lifetime ledger using pinned native source/stats and actual
archived packets: original key/index/enrollment bytes, seeded/expanded inputs,
resident RNS rows/maps/NTT plans/graph, request/producer/check/codec scratch,
framing/parsing copies, owner private context/IDs, cache acquisition and full
row-copy updates, invalidation and closures. Where native allocator capacities,
Python/crypto overhead or stage peaks are unmeasured, state the unknown and
the conservative counted components. RSS and canonical encoding counts do
not close those gaps. Costs cannot be called free because the checker omits
them from its arithmetic model.

## Compact client descriptor

The owner signs a domain-separated bounded canonical descriptor containing
logical namespace/revision and epoch, complete ordered UInt64 IDs, dimension,
HE key/profile basis, certificate digest, and a separate snapshot/policy/code
binding for each legal HE mode. Cache context uses its own domain-separated
ordered-ID digest. Check that it equals the digest recomputed from these same
packed IDs; the HE transcript ID hash uses its existing SHA256 convention.
Matching ID/shape metadata is not proof that ciphertexts encrypt the same
rows. State honest-owner logical equivalence explicitly.

The current logical descriptor/pin is provisioned independently of the store;
an apparently valid newer packet cannot advance it. Verify owner signature
and exact trusted context before parsing/publishing the complete metadata.
Do not expose an API that decrypts merely because this descriptor verifies.
The online client needs this compact metadata and its separately provisioned
matching private context, not the full encrypted index/evaluation keys. Charge
descriptor/IDs, private-context acquisition and request signing/provisioning.
Actual secure owner channel, attestation/release receipt, rollback-resistant
currentness and client-private ownership remain Q78 obligations.

## Completion and paper decisions

Gate the 22 retained public cases across the three legal modes, at most 66
case/mode combinations and 256 falsifying metadata/context mutations. Reuse
the independent saved correctness evidence; do not generate new HE keys,
encrypt/decrypt or rerun native evaluation to validate static declarations.
Freeze executed sources and preserve failed attempts. A resource/semantic
obligation that cannot be justified is a limitation or stop, not an inferred
pass from a digest or test count.

Before Q77, provide the security-feasibility card: origin correctness support
does not approve RLWE parameters, augmented evaluation-key/KDM assumptions,
seed distributions, private timing or real TEE freshness. The local timing
study may test a clearly labeled prototype contract; a secure-service latency
claim requires later actual deployment. Classify each interface as inherited,
adapted or substantively new against the preserved primary prior construction.
Do not keep a new certificate/theorem claim if it is contained.

Return this same Q76.5 milestone to the ledger. Q77 still requires its own
frozen method/workload/arrival/device/update registration and genuine
calibration/held-out split. The experimental system may remain valuable company
engineering if no specific original main result survives.
