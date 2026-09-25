# BGV query communication experiments

This follow-up targets the query upload measured in the
[service study](bgv-service-results.md). The implementation is homemade and
opt-in under `experiments/bfv_search_lab`; the existing seeded format and all
package BFV/Paillier code remain available.

## Starting communication cost

The previous same-workload comparison used 8,192 vectors of 512 bits:

| Configuration | Query bytes | Response bytes | Query + response |
| --- | ---: | ---: | ---: |
| Paillier variants | 544 | About 4,226,950 | About 4,227,500 |
| Package BFV | 737,394 | 204,900 | 942,294 |
| Research BGV, seeded query | 245,866 | 102,488 | 348,354 |

BGV's download is about 41.2 times smaller than Paillier's and its total is
about 12.1 times smaller. Against this BFV configuration the ratios are 2.0 and
2.70. Paillier has the smallest query. BGV query upload accounts for 70.6% of
its recurring traffic at this count. These application payloads exclude index
and key setup, document retrieval, authentication and TCP/TLS overhead.
Parameters differ across schemes; communication comparisons do not establish
equivalent security. The CPU/CUDA choices preserve each scheme's wire format.

At 32,768 vectors the existing BGV query remains 245,866 bytes and its response
is 204,895 bytes. Packing makes responses grow in whole ciphertext increments,
so download does not grow linearly for every individual added vector.

## A bounded change to the ciphertext representation

The BGV decryption relation is `center_Q(c0+c1*s) = m+t*e`, followed by reduction
modulo t. Correctness requires the centered phase to stay within the signed
modulus interval. This is the standard relation described in the
[BGV textbook chapter](https://fhetextbook.github.io/EncryptionandDecryption3.html).
The derivation below applies that relation to our specific codec; the source
does not describe or validate this implementation.

For a public precision d, let `R=2**d`. Write each canonical c0 coefficient as
`c=R*h+r`, with `0 <= r < R`. The encoder sends the integer

`w = t*h + (r mod t)`.

The fixed width is the bit length of the largest possible w for `0 <= c < Q`.
The decoder recovers h and the residue by dividing w by t. Let
`K=floor((R-1)/t)` and reconstruct the integer

`c' = R*h + (r mod t) + t*floor(K/2)`,

then reduce c' modulo Q. Before that final reduction,

`c'-c = t*(floor(K/2)-floor(r/t))`,

so the change is divisible by t and its magnitude is at most
`E=t*ceil(K/2)`. This identity is coefficient-wise and independent of the
message, secret and actual encryption error. It also covers reconstruction
across Q: reducing a component modulo Q leaves the ring ciphertext unchanged.

Only c0 changes. The seeded c1 is exactly the old value, so no secret-norm
factor is needed for this additional phase error. An honest fresh owner query
has bound `B=t//2+t*eta`; the rounded query has bound `B+E`. When it remains
below Q/2, the centered phase still has the same residue modulo t. This is
lossy ciphertext encoding with **exact plaintext recovery**, subject to the
stated bounds, not approximate Hamming search.

The query bound alone is insufficient. Multiplication by an index tile of
bound I incurs at most `N*(B+E)*I`; relinearization and the actual packing
butterfly then add their existing public bounds. The planner reuses the native
evaluator's bound schedule and applies the existing terminal bound
`ceil(P*B_response/Q)+ceil((N+1)*t/2) < P/2`. An excessive precision reduction
is refused before native/GPU evaluation. Precision selection uses public
parameters, layout and honest index bounds, never an observed private noise
estimate or decryption feedback.

The ring N, arithmetic modulus Q, secret, evaluation keys and terminal response
format are unchanged. This operation increases noise while keeping Q fixed;
it is distinct from the modulus switching used by the terminal response.
Ciphertext rounding and compression are established ideas; no novelty claim
is made for this codec without further prior-art review.

## Optional owner-encrypted index

The original public-key index encryption has the conservative phase bound
`t//2+t*eta*(2*N+1)`, accounting for the public-key encryption products. If the
ingesting data owner has the secret key, the existing fresh seeded owner
encryption instead has bound `t//2+t*eta`. Applying that existing encryption
to each index tile leaves the server ciphertext shape unchanged and gives
query rounding more room under the same Q.

This second experiment creates a new encrypted index with fresh independent
randomness per tile. It requires secret-key access during ingestion; a party
holding only the public key must continue using the public-key path. No secret
is sent to the evaluator. Index encryption/expansion and GPU preparation are
setup costs recorded separately. The sum of individual seeded index packet
sizes is reported separately from unframed full coefficient bytes; an aggregate
index-upload protocol is not introduced here.

## Implementation and validation

- [`compressed_query_bgv.py`](../../experiments/bfv_search_lab/compressed_query_bgv.py)
  implements the separate envelope, fixed-width rounding and expansion.
- [`test_compressed_query_bgv.py`](../../experiments/bfv_search_lab/test_compressed_query_bgv.py)
  checks exhaustive small coefficient domains, wrapping, malformed packets,
  mixed-radix holes, exact encryption/search, ties and excessive bounds.
- [`test_cuda_compressed_query_bgv.py`](../../experiments/bfv_search_lab/test_cuda_compressed_query_bgv.py)
  compares full native CPU/CUDA ciphertexts, repeated workspaces and private
  finishing through degree 16,384, with both index encryption modes.
- [`bgv_query_compression.py`](../../benchmarks/bgv_query_compression.py) measures
  paired old/rounded queries and loopback TCP with application pacing.

The parser bounds the envelope before allocation, pins the tag/key/precision,
checks exact field types/lengths and rejects codes without canonical preimages.
Query expansion performs only public arithmetic. Deterministic public
post-processing cannot reveal more information than its original ciphertext
under the original confidentiality assumption; that observation does not prove
the assumption or establish chosen-ciphertext security, parameter assurance,
constant-time private arithmetic or secure erasure.

The TCP benchmark pins the complete expected ciphertext via an **excluded local
duplicate evaluation** before any private work. It closes the socket before
decryption and returns no decryption decision. This is a trusted test fixture,
not a remote verification protocol. A future authenticated integration must
bind the complete query envelope (including precision), index/version, circuit
and response before decryption. None of these experiments closes that existing
production requirement.

## Reproduction

Use the extensions built in the [lab README](../../experiments/bfv_search_lab/README.md).
Run timing experiments without competing builds/tests/profilers:

```bash
CUHEPY_REQUIRE_BGV_CUDA=1 .venv/bin/python -m pytest experiments/bfv_search_lab/test_compressed_query_bgv.py experiments/bfv_search_lab/test_cuda_compressed_query_bgv.py -q
.venv/bin/python benchmarks/bgv_query_compression.py --num-vectors 8192 --repeats 10 --transport-repeats 5 --json-out /tmp/bgv-query-8192.json
.venv/bin/python benchmarks/bgv_query_compression.py --num-vectors 32768 --repeats 10 --transport-repeats 5 --json-out /tmp/bgv-query-32768.json
```

Each index group has a seeded baseline, the maximum publicly admissible dropped
precision, and a variant dropping two fewer bits. A fresh owner query is shared
across the paired encodings in each round; its measured encryption cost is
charged to every total. Query and order RNGs are separate. All distances and
stable top-3 are checked. Local trials have ten measured rounds after one
warmup; TCP uses five measured rounds. Setup, excluded fixture-evaluation costs,
source hashes and all samples are saved without keys or ciphertexts.
