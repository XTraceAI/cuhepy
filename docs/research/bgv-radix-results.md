# E16: radix packing inside coefficient BGV search

This experiment continues `experiment/bgv-verification-packing` from checkpoint
`da41c63`. It retains the original one-vector layout, conservative/support
bounds, CPU/CUDA arithmetic and authenticated CPU protocol. New code stays in
the research lab; no Microsoft SEAL implementation is used for these results.

## Two layouts and their exact decoding

Let d be the binary dimension, g the number of vectors per coefficient block,
and `a[l,j]=1-2*x[l,j]`. Replace each index coordinate with
`A[j]=sum_l a[l,j]*B^l`. The unchanged reversed-query correlation, followed by
the existing trace/packing circuit, produces the residue of

```
D*S,  where S = sum_l (d-2*H_l)*B^l
```

D is the padded dimension. The client removes D modulo the odd plaintext
modulus t and then decodes g distances.

The initial **balanced** proposal takes `B=2*d+1`. Centered base-B digits lie in
`[-d,d]`; `|S| <= (B^g-1)/2`. An odd prime `t>B^g` suffices to recover the signed
integer and then each distance `(d-digit)/2`. Parity, range and remaining digits
are checked. This is an established packing construction, not a novelty claim.

The **direct-distance** alternative uses the known affine relation between
correlations and distances. Choose `B=d+1` and

```
K = d * sum_(l=0..g-1) B^l = B^g-1
(K-S) * 2^-1 mod t = sum_l H_l*B^l mod t.
```

The right side lies in `[0,B^g-1]`, so `t>=B^g` and odd t suffice for an
unambiguous nonnegative base-B expansion. S itself may wrap in the plaintext
ring; it need not fit in the centered interval. Multiplying by the modular
inverse of two is essential: integer halving of the reduced residue is wrong.
For a last group with h<g active vectors, the offset is `B^h-1`; absent vectors
contribute zero to the index and are not decoded or returned.

The current implementation also keeps the existing `t>2*d` wire contract. It
uses t≥1,031 for the one-vector control. It does not try to lower that baseline's
modulus through a change to the original decoder contract.

| Layout at d=512 | Base | Chosen t | t bits | Selected terminal bits at N=16,384 |
|---|---:|---:|---:|---:|
| One-vector control | 513 | 1,031 | 11 | 25 |
| Balanced, g=2 | 1,025 | 1,050,631 | 21 | 35 |
| Direct distance, g=2 | 513 | 263,171 | 19 | 33 |
| Direct distance, g=3 | 513 | 135,005,723 | 28 | 42 |

Balanced g=3 at d=512 exceeds the existing `t<2^30` policy and is rejected. The
direct-distance construction fits three digits under that limit. These are
correctness/representation observations, not security-bit estimates.

## Noise, context and client costs

N, Q120, ternary secret distribution, eta=21, gadget digit count and the server
circuit remain fixed. Each t/layout needs **fresh keys and a re-encrypted
index**. Increasing t scales the existing deterministic encryption and key-switch
bounds. The E15 support policy and joint precision planner propagate those full
bounds through multiplication, relinearization, packing, terminal reduction and
both codecs. No actual private noise is inspected to select precision.

The representation still returns all exact distances and stable top-three
selection by original vector index. It does not implement encrypted top-k or
change that output contract. Fewer virtual vectors can reduce tile work and
response count, but larger t widens both query and response representations.
At 8,192 vectors, the baseline already needs only one response ciphertext, so
packing two or three candidates cannot eliminate another response there.

[`radix_bgv.py`](../../experiments/bfv_search_lab/radix_bgv.py) contains the
layouts, integer decoder, bounded direction/layout/count envelope and public
precision planning. [`radix_client_bgv.py`](../../experiments/bfv_search_lab/radix_client_bgv.py)
retains a Python-coefficient reference and an optional packed native boundary.
The latter avoids unpacking ciphertext coefficients into Python and repacking
them before calling the same existing private decryption implementation.
Plaintext digit decoding has independent scalar Python and vectorized NumPy
paths. The NumPy path uses bounded 64-bit arithmetic, checks all plaintext
coefficients, and retains parity/range/tail rejection. No native secret
arithmetic changes.

Before either private path, the complete response must match a locally pinned
expected fixture. Every ciphertext is then checked for canonicality before the
first private operation. Tests put a noncanonical coefficient in the **last**
response to catch premature private processing. These local fixture gates do
not supply efficient remote authentication. Variable-time private owner code,
parameter assurance and authenticated GPU execution remain separate work.

## Measurement contract

[`bgv_radix.py`](../../benchmarks/bgv_radix.py) compares the optimized existing
g=1 decoder, a g=1 generic-decoder control, balanced g=2, direct-distance g=2 and
direct-distance g=3. Each uses the same synthetic plaintext index and fresh
matched query plaintexts. Keys and encryption coins differ across t contexts.
The two g=1 clients share identical ciphertext packets. These are concrete
parameter configurations, not independently established security-equivalent
scheme comparisons.

Ten shuffled local rounds and five rounds per paced link follow one excluded
warmup. Complete request costs include fresh query encryption, codecs, public
GPU work, parsing, private decryption, digit extraction and stable top-three.
Every distance is checked outside timing. Index/key/workspace preparation,
public planning and the duplicate expected-response evaluation are recorded
separately. Expected-response computation must not be represented as free
remote verification. Application byte counts include the new radix envelopes;
TCP adds eight framing bytes, while TLS/attestation/IP costs are excluded.

The initial runs use source `2459649` and retain the coefficient-export client
as a useful negative result. Follow-up packed/vectorized-client runs are
recorded separately and include matched scalar controls using identical
ciphertext packets. They must not silently replace those baseline artifacts.

## Reproduction

Use the existing native BGV builds. No private C++ rebuild is required for the
packed client: it calls the already-present canonical packed decrypt function.

```bash
CUHEPY_REQUIRE_BGV_CUDA=1 .venv/bin/python -m pytest \
  experiments/bfv_search_lab/test_radix_bgv.py \
  experiments/bfv_search_lab/test_cuda_radix_bgv.py -q
.venv/bin/python benchmarks/bgv_radix.py --num-vectors 8192 \
  --json-out benchmarks/results/bgv_radix_8192.json
.venv/bin/python benchmarks/bgv_radix.py --num-vectors 32768 \
  --json-out benchmarks/results/bgv_radix_32768.json
.venv/bin/python benchmarks/bgv_radix.py --num-vectors 8192 --packed-radix --vectorized-radix \
  --index-modes owner --json-out benchmarks/results/bgv_radix_packed_owner_8192.json
.venv/bin/python benchmarks/bgv_radix.py --num-vectors 32768 --packed-radix --vectorized-radix \
  --index-modes owner --json-out benchmarks/results/bgv_radix_packed_owner_32768.json
```

The reference tests exhaust small signed/distance digits and binary products,
test negacyclic boundaries and incomplete groups, and compare complete CPU/CUDA
ciphertexts at the new t/P values. Separate old/new client comparisons cover
all distances, ordering, framing and the check-before-private-work boundary.
