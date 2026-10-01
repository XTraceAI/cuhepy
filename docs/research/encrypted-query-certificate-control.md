# E71: encrypted-query certificate and one-use points

2026-09-30, bounded R3 follow-up to the [E70 screen](convolution-certificate-results.md).
This preregistration precedes the experiment. It is a homemade **known-control
composition**, not a claim of a novel protocol or production security.

## Discriminator

Replace public masked-query corrections and independently encrypted owner
answers by fresh owner-encrypted CRT query polynomials. Multiply each indexed
two-component BGV ciphertext by its query ciphertext and sum the products.
The result has three components; no relinearization, modulus switching or
secret-dependent server operation is needed. The owner prepares no encrypted
answer for this query. Verify all three ciphertext component polynomials using
the ordinary-field quotient identity before any response decryption.

Fix the complete response before sampling public batching weights. Each
prepared receiver has independent, **one-use hidden points** and evaluations
of the owner's enrolled ciphertexts at those points. A point ticket burns on
the first response attempt, including malformed input; the quotient stage is
also one-use. A shared volatile attempt budget spans receivers. Charge ticket
preparation and private provisioning. These local objects are not a durable
transport commitment or rollback-resistant service.

Do not transfer the multi-round wrong-output bound to arbitrary reused-point
feedback. A true output with only one corrupted quotient can expose one
round's acceptance predicate while all other rounds pass. Fresh points avoid
that reuse in this control, at the cost of preparing/provisioning a separate
hint table for every request. No reviewed privacy/parameter/side-channel
assurance follows from this design choice.

## Preregistered checks and stop rule

- Exact encrypted searches across the seven retained tiny CRT layouts, with
  all binary four-bit queries, all scores and stable IDs/ties checked.
- GMP ciphertext multiplication versus independent ordinary-product
  certificates and integer negacyclic reconstruction, including cross terms.
- Response body frozen before challenge; invalid output/quotient, shape,
  key/epoch/request substitution, stale/replayed stage, exhaustion and
  late output replacement cannot reach the response-decryption function in
  selected deterministic regressions. Finite-field tests are not a proof
  of zero false acceptance.
- Record all local stage timings without attributing small-fixture Python
  times to native/GPU or service performance. Record actual query packets,
  coefficient response/quotient bodies, public weights, one-use private
  hint bodies and full indexed ciphertext body counts.
- Price retained real-data geometries with conservative depth-one phase
  bounds, an explicitly chosen NTT prime and a lifetime algebraic target.
  Distinguish this count model from deployed parameters and measured results.

Stop this literal construction if whole-query traffic and per-request hint
work erase the proposed benefit. A negative result would focus further R3
work on succinct quotient openings or structured verified evaluation; neither
is supplied by this oracle. Do not accelerate this control or declare a paper
contribution merely because it removes an answer factory.

## Executed outcome and return to R3/R6

Preregistration/source commit: `5951d82`. New immutable raw:
`benchmarks/results/publication-encrypted-query-certificate-control-20260930.json`.
Reproduce with a fresh output path:

```sh
.venv/bin/python benchmarks/encrypted_query_certificate_lab.py --json-out /tmp/encrypted-query-certificate-new.json
```

All **112 encrypted queries** across the seven layouts match all scores and
stable top-3 IDs using the owner-local fixture ID mapping. Ordinary polynomial certificates independently reconstruct
every GMP output component. N=32, t=17, eta=1, Q=4,294,966,657 and four rounds
are **tiny correctness fixtures, not a 128-bit production profile**. The
receiver owns no plaintext rows or complete encrypted index after preparation;
it retains its space/metadata and one-use index evaluations. Owner query
encryption and later accepted response decryption use the existing homemade
BGV implementation. No SEAL/reference arithmetic is imported.

For one reply the modeled bodies are: seeded query coefficients/seeds 640 B,
three-component response 384 B, batched quotient 496 B, public weights 48 B,
one-use private hints/points 144 B. The raw separately records the **actual
query packets** (924 B per query), which also contain the existing seed/key/tag encoding. For
the three-reply case the response grows to 1,152 B, weights to 144 B and private
hints to 400 B; quotient length stays fixed. These are byte bodies, not a
complete RPC or resident-memory measure.

Small-fixture stage medians: owner ticket preparation 0.217–0.523 ms,
fresh owner query 0.352–0.382 ms, public GMP evaluation 0.397–1.039 ms,
reference quotient generation/packing 1.552–4.427 ms, client freeze/challenge
0.161–0.263 ms, verification/decryption/score decoding 0.314–0.574 ms.
The independent all-factor diagnostic is separately timed and excluded from
evaluation. Python schoolbook quotient generation is a control, not an
optimized proof generator. These are local stage observations, not confidence
intervals, native/GPU comparisons or service latency.

### Retained-geometry screen

This panel is a **correctness/count model**, not a large encrypted execution.
For h indexed columns and fresh phase bound F=floor(t/2)+t*eta, the conservative
depth-one sum bound is N*h*F^2. A new prime Q congruent to 1 modulo 2N exceeds
twice that bound and the old Q. All eight profiles require larger Q, hence
new keys/index enrollment and a new parameter review. Five fresh hidden
point/weight rounds meet the modeled 1,024-attempt / 128-bit algebraic target;
that target is not RLWE, seeded privacy or implementation assurance.

| Profile | New public online body | Separate private hint/ticket body | Old linear reply + public delta body | Public-body ratio |
|---|---:|---:|---:|---:|
| Mushroom selected t193 | 3,687,481 B | 1,829 B/query | 131,595 B | 28.02× |
| Semeion selected t257 | 2,857,753 B | 1,322 B/query | 133,874 B | 21.35× |
| Connect-4 global raw | 2,021,581 B | 110,908 B/query | 262,270 B | 7.71× |
| Connect-4 global affine | 1,489,968 B | 70,547 B/query | 262,226 B | 5.68× |

Across all eight profiles the public-body ratio is 5.68–28.37×. It excludes
the **old** answer factory/check provisioning, and both sides' framing, link
delay and memory overhead; it is not a total-cost or equal-security ratio.
New private hints and their preparation steps are explicitly listed. The
literal construction fails the intended wire/preparation discriminator, but
this is not an impossibility result for encrypted queries or certificate
systems. Packing multiple query polynomials into one encryption, statistical
noise bounds with explicit error budgets, and succinct quotient openings are
different, known-control obligations that this run has not implemented.

### Feedback counterexample

For a **true** output, corrupt just the constant coefficient of round one's
quotient; supply honest quotients for the other three rounds. In the N=8,
Q=97 exhaustive regression the combined decision accepts at exactly the eight
negacyclic roots: **8/97**, irrespective of the three honest rounds. This is
a predicate on the first hidden point. It does not contradict the E70 bound
for a fixed **wrong output** with fresh independent rounds. It demonstrates
why that bound is insufficient to justify arbitrary point reuse under visible
feedback. It is not an attack on the retained dense BGV gate or a reviewed
polynomial-commitment protocol.

The new local receiver uses fresh points and burns both stages once. Tests
cover malformed bodies/quotients, wrong context, key/bound substitution,
replacement after challenge, replay, global exhaustion and selected forgeries
before response decryption. Durable consumption, private timing, authenticated
hint provisioning, full privacy proof and parameter assurance remain open.

**Return-to-plan decision:** stop this literal full-query/full-quotient variant
as a proposed fast system; retain it as the end-to-end reference and reaction
counterexample. R3 next needs a carry-aware structured outer construction or
a succinct arithmetic certificate with packed queries. Price the strongest
known versions first. R6 still has no selected novel/useful mechanism; R2's
matched HE/cache acquisition remains open. No acceleration/promotion to
production follows from this oracle.
