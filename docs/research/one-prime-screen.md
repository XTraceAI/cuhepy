# E113: complete one-prime feasibility screen

2026-10-03. **Known owner-only mathematical feasibility; current large general
key-generation API refuses; no originality or parameter-security pass.**

The [frozen preregistration](one-prime-preregistration.md) preceded the main
count/tiny run. The raw receipt is
[publication-one-prime-20261003.json](../../benchmarks/results/publication-one-prime-20261003.json).
No GPU, native kernel, timing benchmark, estimator, proof backend or large key
setup was executed. The actual tiny experiment uses the unchanged homemade
shallow/owner/trace/butterfly/query-codec/compact APIs, not SEAL.

## 1. Result and permitted next step

The frozen panel contains36 large profiles: N8192/16384/32768,512-bit vectors,
8,192/32,768 records, t1031, CBD_eta21, and radix widths10/12/15/18/19/30.
For each profile all60 query drops were screened for owner/public index and
canonical/bounded-alternative digits:8,640 exact integer bound evaluations.

-24/36 owner canonical drop0 profiles satisfy both the raw-Q and compact-P32
  margins. The same24 bounded-alternative profiles pass at drop0.
-0/36 general public-index profiles pass the complete envelope.
-0/36 current general shallow.key_gen guards pass. No guard was patched.
-All36 exact relaxed/canonical digit-cap ratios are at most2.
-The ordinary equally tuned one-limb BGV/native-prime control has the same
  bound/count result: ratio1. No new algorithm or proof saving is established.

This supports a separate future **owner-only setup/interface** task if useful to
the company, accompanied by appropriate parameter/reduction review. It does not
make the existing general API support these large profiles. Its guard includes
public-encryption correctness; the owner-only graph uses a narrower law. Default
NativeServer/butterfly metadata also uses a larger count-summed envelope. The
existing E15 support-bound path is the matching known graph control. These
mathematical, public API, native source compatibility and security statuses must
remain distinct.

No further screen grid, native implementation or performance optimization is
part of E113. Return to the canonical contribution plan: keep this known
feasibility result, and continue an uncontained creative gate or explicitly
register the narrower engineering task. Choosing one prime is not a paper main.

## 2. Complete deterministic derivation

The owner seeded cipher is `(c0,a)` with

```
c0 = m + t*e - a*s modQ,
phase = m+t*e modQ,
```

where each secret coefficient is in{-1,0,1} and e is the actual CBD_eta sample
with support[-eta,eta]. The public seed drives the existing SHAKE/rejection
sampler; pseudorandom-stream security is a separate assumption. The bound holds
for every a, so it does not require independent or perfectly uniform polynomial
coefficients. Index ciphertexts must use owner encryption too. General public
encryption instead introduces `e*u+e0+e1*s` and has the larger worst-case error
radius eta*(2N+1). The original E106 fixture's public-encrypted index cannot be
silently called an owner index; this screen generates a separately disclosed
tiny owner-index fixture and labels that difference.

The signed coefficient query contains d nonzero coefficients of magnitude1;
index message coefficients are in{-1,0,1}, including every tail/padding entry.
For query drop r, let R2^r and Kfloor((R-1)/t). The actual coefficient codec
adds a multiple of t before reduction, bounded by E=t*ceil(K/2). For drop0 use
E0 and the original seeded packet. Define A=t*eta+E and I=t*eta for owner index
(or t*eta*(2N+1) for the public-index control). Expansion of the complete
negacyclic product gives

```
||Mq*Mi||inf <= d,
||Mq*index_error||inf <= d*I,
||query_error*Mi||inf <= N*A,
||query_error*index_error||inf <= N*A*I,
M = (1+I)*(d+N*A).
```

These are support/triangle inequalities, not independence or Gaussian claims.
Both candidate and ordinary control receive the same sharper message law.
Legacy metadata uses t//2 for message magnitude and a larger product envelope;
its separate result is preserved in raw `generic_api_*` fields.

For B2^b and Lceil(bit_length(Q)/b), let H_Q be the exact largest sum of radix-B
digits among all integers below Q. The prefix extremum algorithm either uses
Q-1 or preserves its higher prefix, decrements its first differing nonzero digit
and fills all lower digits with B-1. Exhaustive independent small-domain tests
verify the attaining word. A canonical switch contributes at most

```
S = t*eta*N*H_Q.
```

This jointly bounds all planes and coefficients, including correlated errors.
A noncanonical COMMON integer digit witness with all L digits below B and
recomposition modulo Q has cap L*(B-1), the legacy API bound. The checked
factor2 is a numerical support inequality for this frozen domain. It neither
implements semantic-release verification nor proves HE confidentiality.
Independent RNS bit/idempotent claims cannot replace the common integer law.

The entire E15 butterfly, with all relinearization and rotation errors, has

```
F = D*M + (2D-1)*S,
D = next_power_of_two(d).
```

The factor D applies to product/relin phases; rotation-level contributions sum
to D-1. Tail groups and unused coefficients are covered. This is the existing
joint-support identity, not a novel trace algorithm. Intermediate values remain
modulo Q: a valid integer lift need not be centered after each public operation.
Only the complete final no-wrap margin justifies the final private centering.
All actual cut/node counts remain paid despite the tighter analytic support.

Compact-v1 chooses an odd prime P<Q with P=Q modt and rounds each component to
the nearest integer congruent modulo t. Each un-reduced rounding error is at
most t/2. The signed secret has norm1 at most N, so

```
G = ceil(P*F/Q)+ceil((N+1)*t/2).
```

Require strict2F<Q and2G<P. A source Q carry becomes a P carry under scaling;
private centering removes it, and congruence is preserved because P=Q modt.
Components can cross P or become negative before reduction. Odd Q,t make exact
half-cell ties unreachable, but endpoints and both carry signs are checked.
Decode every true output position by D inverse modulo t. Since t>2d, the signed
correlation is unique and parity/range checks yield exact Hamming distances.
Stable-ID ordering is an owner-local map in the diagnostic, not a newly
implemented remote ID protocol.

## 3. Exact selected results and terminal-only rejection

All entries below use the strongest shared support and canonical digit cap.
Counts8192 and32768 have the same final support envelope; actual tile/cut/body
counts remain different. A dash means even drop0 fails the complete margin.

| N | radix10 | radix12 | radix15 | radix18 | radix19 | radix30 |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
|8192|drop23 /48-bit query|drop23 /48|drop23 /48|drop23 /48|drop22 /49|—|
|16384|drop22 /49|drop22 /49|drop22 /49|drop21 /50|—|—|
|32768|drop21 /50|drop21 /50|drop21 /50|—|—|—|

For N16384, Q1152921504606748673 and P4294953991 are the actual source-selected
60-bit NTT prime and compact32 prime. With radix19 and drop0:

- F574708256562331648 is below Q/2; raw centering passes.
- G2149394929 exceeds P/2; compact/private centering is not assured.

This is an explicit **bound rejection**, not an observed wrong decryption or
attack. It demonstrates why raw-Q analysis alone misses a real condition.
For radix18 drop0 the complete bound passes. The bounded-alternative relation
at radix18,N16384 permits greatest drop20 rather than canonical drop21; its
extra switch-noise envelope costs a query bit. At other selected small radices
the cap difference may be only one unit; do not describe every relaxation as an
actual factor2 increase.

## 4. Byte/state/count scope, including strong control

For N16384, d512, count8192, radix15, canonical greatest drop22:

| Named resource | Exact arithmetic/model count |
| --- | ---: |
| Public a/b bitpacked coefficient-body model |245760 B|
| Owner index bitpacked coefficient-body model |62914560 B|
| All relin/rotation keys bitpacked coefficient-body model |9830400 B|
| Actual native bytealigned/uint64 index coefficient slots |67108864 B|
| Actual native bytealigned/uint64 key coefficient slots |10485760 B|
| Original/rounded query complete declared packet |100460 B|
| Full compact-v1 response complete declared packet |131164 B|
| Query + response packets |231624 B|
| Owner plaintext binary index, separately retained |524288 B|
| Stable64-bit ID body |65536 B|
| Product / rotation / total cuts |256 /511 /767|
| Canonical source / digit / terminal coordinates |12566528 /50266112 /32768|
| One-prime complete affine residual coordinates |12599296|

The query/response envelope sizes are exact for the existing codecs' schema,
not network transport/framing, proof or attestation bytes. The tiny real packet
sizes independently match this ledger. Public/index/key bitpacked models do
not imply an implemented enrollment serializer; the bytealigned native input
schema and uint64 slots are separately named. Python/GMP/object overhead is not
included in either coefficient-body count. Setup/encryption/key products and
hashing, NTT plans and constructor auxiliary bases, peak buffers, PCS/range/
terminal cross-field proof, authenticated registration, updates and private
state implementation remain explicitly unpriced. No complete runtime,
low-state service or total memory advantage is claimed.

A native prime removes cross-Q *limb* consistency but not scalar coefficient
ranges, exact canonical comparison, the NTT/coefficient representation relation,
or the distinct compact-P terminal bridge. Every such boundary remains part of
the strong proof control. The ordinary one-limb graph gets identical native
prime, radix, query drop, owner input law, partial support and range sharing.
Its modeled count ratio is1. Proof/preprocessing/commitment/opening costs are
unknown, rather than assumed favorable.

For an illustrative U2^32 attempts and only a fresh uniform global affine
residual dot after complete witness binding, three independent Q-field checks
satisfy U/Q^3<2^-128. Two do not. This is one ideal statistical component, not
whole-protocol128-bit security or a Fiat-Shamir/adaptive extraction argument.
Storing all three full uint64 adjoints at the above residual dimension costs
302383104 B, before other enrollment state. Challenge reuse, grinding, PCS,
canonical/range soundness and terminal field conversion need separate analyses.
A60-bit field is not by itself128-bit assurance.

## 5. Independent actual tiny differential and validation

Frozen main fixture: N16,d3,t17,eta1,Q60,radix10,drop8, nine rows including a
duplicate and a partial final tile, all eight3-bit queries, nonpositional stable
IDs. Existing key_gen succeeds unchanged; all index/query errors and seeds are
fresh OS draws. The secret/keys/packets are disclosed in the external fixture.
No security property follows from that disclosure or tiny dimension.

Sixteen observations compare the actual independent per-tile trace and joint
butterfly graphs with an integer schoolbook oracle. Every complete plaintext
coefficient, original-to-rounded query packet, signed phase/rounding radius,
all compact component coefficients and complete compact-v1 packet, all nine
distance positions/parity and owner-local stable-ID ranking are checked. Graphs
may have different ciphertext bytes while agreeing on the exact function;
each graph's own complete terminal map is checked rather than requiring an
artificial cross-graph byte equality. No native binary is invoked.

Scoped validation:32 tests pass; Ruff checks all four explicitly named new
Python files with `--no-force-exclude`, so excluded lab directories did not make
lint a vacuous success. Tests include exhaustive small canonical digit extrema,
actual NTT-prime/root witnesses, composites/types, the raw-pass/terminal-fail
case, public-index versus owner law, actual pre-sampling general-keygen refusal,
noncanonical common recomposition, negative/positive terminal carries,
canonical Q-1 secret signs, tails, exact packet lengths, lifetime repetition,
and complete actual-API score/ID differentials. QA fresh draws are separate
from the single frozen publication fixture; there is no statistical success
rate or repeated fixture selection.

Development failures were retained in raw scope: system Python lacked gmpy2,
and the first test run had an undersized carry example plus an mpz/plain-int
oracle shape mismatch. They were corrected only in owned new files; no existing
HE implementation changed. Final source labels distinguish bitpacked body
models from actual native bytealigned slots. Exact scientific bounds and frozen
main output were unchanged across that label correction.

A final independent review found that the public Miller--Rabin diagnostic
incorrectly rejected small genuine primes dividing a fixed test base, including
73. Zero reduced bases are now skipped; independent trial division establishes
all four genuine-prime regressions, while the composite73*193 remains rejected.
The selected60-bit primes were unaffected. The exact same frozen panel and tiny
fixture were repeated after the repair: every scientific/count field, scope and
tiny observation matched the previous raw. Previous source/report/raw/validation
receipts are preserved in the external `before-prime64-zero-base-fix` directory.

## 6. Provenance and security boundary

Preregistration SHA
`d9cea206ce7716564f07da4b30c9184378a1ba5f9f840655163a401b876ee570`.
Frozen main fixture SHA
`2eee3bf25c218cbc52c93a13477f0ab4583b324bc3baf5b61644668a680c4b99`.
Final raw SHA
`3d5df5cda42b95fed111bbe3be18f67ec096177647e36c6dab719ad69cc4f34f`.
All implementation/API/native-source hashes and exact accepted/rejected bounds
are in raw. External receipts live under
`../research-data/one-prime-20261003/`; the initial raw before body-label fixes
is preserved there. Source compatibility with one first-prime residue is read
from rns_ntt.h/native bindings; no large native setup or binary execution tested
it in E113. The actual existing keygen guard failure is preserved separately.

The deterministic envelopes condition on honest owner index/query generation,
ternary secret support, correct evaluation-key targets/CBD errors and accepted
COMMON bounded decomposition relations. They are not a proof that server wire
metadata establishes those premises. No new authentication, admissibility
proof, adaptive feedback reduction, approved sample/parameter distribution,
constant-time private code or lattice-security estimate is implemented. A future
owner-only setup or admission protocol must state/enforce these premises and
undergo independent review. This bounded feasibility screen is complete; its
ordinary control absorbs the claimed elementary saving.
