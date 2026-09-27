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

## Exact application traffic and encrypted index coefficients

The initial [8,192-vector](../../benchmarks/results/bgv_radix_8192.json) and
[32,768-vector](../../benchmarks/results/bgv_radix_32768.json) runs measure both
public-key and owner-encrypted index variants. Query encryption is performed by
the owner in both cases. The index mode changes the public correctness bound,
and consequently how much the query can be rounded. It does not change the
chosen response sizes in these runs.

| Vectors | Layout | Query, public index | Query, owner index | Response | Query + response, public index | Query + response, owner index |
|---:|---|---:|---:|---:|---:|---:|
| 8,192 | g=1 | 133,281 B | 102,561 B | 80,027 B | 213,308 B | 182,588 B |
| 8,192 | Balanced g=2 | 174,241 B | 143,521 B | 120,992 B | 295,233 B | 264,513 B |
| 8,192 | Distance g=2 | 166,049 B | 135,329 B | 112,800 B | 278,849 B | 248,129 B |
| 8,192 | Distance g=3 | 202,913 B | 172,193 B | 149,665 B | 352,578 B | 321,858 B |
| 32,768 | g=1 | 135,329 B | 104,609 B | 155,810 B | 291,139 B | 260,419 B |
| 32,768 | Balanced g=2 | 174,241 B | 143,521 B | 120,992 B | 295,233 B | 264,513 B |
| 32,768 | Distance g=2 | 166,049 B | 135,329 B | 112,800 B | 278,849 B | 248,129 B |
| 32,768 | Distance g=3 | 202,913 B | 172,193 B | 149,665 B | 352,578 B | 321,858 B |

At 32,768 vectors, distance g=2 removes one response ciphertext, saves 43,010 B
of response traffic (27.6%), and adds 30,720 B to the query. The net saving is
**12,290 B per request**, or 4.7% for the owner index and 4.2% for the public
index. At 8,192 vectors, it adds 65,541 B per request. Increasing g therefore
does not monotonically improve communication. The direct-distance base also
saves 16,384 B per request relative to balanced g=2 at either size/index mode.

These g=1 packet totals exceed the earlier E15 report by 109 B because this
experiment includes its radix context envelopes for both directions. The table
compares all layouts using those same envelopes. Packed/vectorized client
processing changes no packet bytes.

| Vectors | g=1 index coefficients | Either g=2 | Distance g=3 |
|---:|---:|---:|---:|
| 8,192 | 125,829,120 B | 62,914,560 B | 42,270,720 B |
| 32,768 | 503,316,480 B | 251,658,240 B | 168,099,840 B |

Index numbers count two full-Q coefficient arrays per tile, excluding framing,
metadata and prepared GPU copies. Radix packing changes the number of tiles.
Key coefficient dimensions remain the same; this is not a measured claim of
equal serialized setup-key sizes or permission to reuse keys between layouts.
The raw artifacts record fresh key, index and workspace preparation separately.

## Initial scalar-client result

The first implementation showed why a server-only comparison is insufficient.
At 32,768 vectors with an owner-encrypted index, the existing g=1 path spent
61.58 ms on the server and 9.37 ms finishing on the client (82.61 ms complete).
Distance g=2 reduced the server to 36.01 ms but spent 37.64 ms finishing
(84.92 ms complete). Distance g=3 took 31.30 ms server, 32.01 ms finishing and
74.60 ms complete. Exporting ciphertext coefficients through Python and
decoding every radix group erased much of the server gain.

The follow-up keeps these artifacts and independently removes those client
costs. It measures **owner-encrypted indices only**. Its timings are not
measurements of the optimized public-index variant.

## Packed/vectorized follow-up

The [8,192-vector](../../benchmarks/results/bgv_radix_packed_owner_8192.json) and
[32,768-vector](../../benchmarks/results/bgv_radix_packed_owner_32768.json)
follow-ups use source `e77573b`, an RTX 3080 10 GiB and Ryzen 7 5800X. All rows
below use owner-encrypted indices. Times are medians in milliseconds. The
asymmetric paced link is 10 Mbps upload/100 Mbps download with 40 ms RTT; the
symmetric link is 10 Mbps in each direction with 40 ms RTT. These are locally
paced TCP measurements, not measurements of an AWS deployment.

| Vectors | Layout/client | Local server | Client finish | Complete local | Asymmetric link | Symmetric link |
|---:|---|---:|---:|---:|---:|---:|
| 8,192 | g=1 existing native | 30.60 | 4.72 | 47.14 | 177.75 | 234.99 |
| 8,192 | Balanced g=2, packed/NumPy | 24.38 | 7.38 | 44.01 | 210.52 | 298.62 |
| 8,192 | Distance g=2, packed/NumPy | 23.63 | 7.45 | 43.62 | 202.68 | 284.96 |
| 8,192 | Distance g=3, packed/NumPy | 21.59 | 7.03 | 40.34 | 233.27 | 340.12 |
| 32,768 | g=1 existing native | 65.38 | 9.51 | 86.36 | 226.59 | 337.66 |
| 32,768 | Balanced g=2, packed/NumPy | 37.40 | 10.68 | 59.48 | 226.84 | 315.66 |
| 32,768 | Distance g=2, packed/NumPy | 38.44 | 10.88 | 61.20 | 220.52 | 301.29 |
| 32,768 | Distance g=3, packed/NumPy | 32.26 | 10.45 | 54.41 | 247.69 | 356.39 |

At 32,768 vectors, distance g=2 reduces complete local time by **29.1%** and
symmetric-link time by **10.8%** versus the matched existing g=1 client. Distance
g=3 reduces local time by **37.0%**, but its larger payload makes it slower on
both measured paced links. At 8,192 vectors, g=3 reduces local time by 14.4%,
but g=1 remains preferable on both links. These results support selecting a
layout for a declared workload/network budget, not replacing the default with
one universal winner.

To isolate plaintext decoding, the new runner also uses the packed native
private boundary with a scalar decoder on **the same packets**:

| Vectors | Layout | Packed + scalar client finish | Packed + NumPy client finish | Existing fused g=1 finish |
|---:|---|---:|---:|---:|
| 8,192 | g=1 | 16.29 ms | 7.44 ms | 4.72 ms |
| 8,192 | Distance g=2 | 11.90 ms | 7.45 ms | — |
| 8,192 | Distance g=3 | 10.76 ms | 7.03 ms | — |
| 32,768 | g=1 | 56.05 ms | 16.82 ms | 9.51 ms |
| 32,768 | Distance g=2 | 31.22 ms | 10.88 ms | — |
| 32,768 | Distance g=3 | 26.21 ms | 10.45 ms | — |

The generic g=1 control remains slower than the existing fused decoder, which
is retained. Scalar/NumPy controls are paired within the follow-up run; the
earlier coefficient-export measurements are separate runs and should not be
used as a precisely isolated conversion-only ablation. Independent phase
medians need not add to the median complete request. Ten local/five transport
rounds support this machine-specific comparison, not a tail-latency claim.

The next packing experiment should join layout choice with the existing
precision/network planner, charge re-encryption/setup for changing layouts,
and extend protected client/receipt contracts before any deployment use.
Changing t still requires independent security-parameter assessment.

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

At implementation commit `1917f99`, the complete package, BFV-example and BGV
research suite passed **955 tests**, with only the live AWS integration skipped
and the existing fork deprecation warning. The independent SEAL BGV test oracle
was enabled; these radix implementations themselves use homemade arithmetic.
Package/research Ruff and package mypy (34 files) also passed. See the
[full test log](../../benchmarks/results/bgv_radix_boundary_full_tests.txt)
and [validation record](../../benchmarks/results/bgv_radix_boundary_validation.md).
