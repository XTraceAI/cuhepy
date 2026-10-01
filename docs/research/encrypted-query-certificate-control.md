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

## Outcome

Pending at preregistration. Raw observations, validation and a return-to-plan
decision will be appended after execution; the original E70 raws remain intact.
