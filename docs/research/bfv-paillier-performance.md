# BFV CUDA versus Paillier: complete local searches

This comparison measures the current CuHEpy implementations on the same
8,192-vector, 512-bit Hamming workload. It includes BFV with CPU and CUDA
evaluation, standard Paillier with CPU and CUDA, and Paillier-Lookup with CPU,
CUDA, and a CUDA client paired with a CPU server.

Unlike the [CUDA kernel comparison](bfv-cuda-fused.md), this experiment times
client query encryption and result decoding as well as server work. A fast
server alone does not determine which scheme completes a search sooner.

## Measurements

Warm medians in seconds for 8,192 vectors × 512 bits on the RTX 3080 / Ryzen
7 5800X. Every BFV row uses CPU client operations; "CUDA" in the Paillier rows
means CUDA client and server operations unless the row explicitly says hybrid.

| Configuration | Server (s) | Client (s) | Local total (s) | Response download (bytes) |
| --- | ---: | ---: | ---: | ---: |
| BFV, CPU server | 19.559 | 0.225 | 19.784 | 204,900 |
| BFV, CUDA server | 0.270 | 0.225 | 0.496 | 204,900 |
| BFV, CUDA server + resident index | 0.180 | 0.225 | 0.405 | 204,900 |
| Paillier, CPU | 0.052 | 57.221 | 57.276 | 4,227,028 |
| Paillier, CUDA | 0.089 | 2.182 | 2.271 | 4,227,023 |
| Paillier-Lookup, CPU | 0.051 | 8.939 | 8.990 | 4,226,874 |
| Paillier-Lookup, CUDA | 0.346 | 0.307 | 0.652 | 4,226,956 |
| Paillier-Lookup, CUDA client / CPU server | 0.051 | 0.306 | 0.358 | 4,226,917 |

The resident-index BFV search is **1.61× faster than Paillier-Lookup with CUDA
on both sides**, and **5.61× faster than standard CUDA Paillier**. The default
BFV CUDA path, which uploads the index for every query, also finishes sooner
than those configurations in this run (0.496 s versus 0.652 s and 2.271 s).

The fastest Paillier configuration is the Lookup hybrid at **0.358 s**. It is
about 47 ms faster locally than prepared BFV at **0.405 s**. Paillier's simple
public multiplication remains cheaper server work than BFV's packed circuit;
BFV substantially reduces result decoding and communication. The table therefore
supports competitive complete-search performance, not a claim that BFV wins
every local computation comparison.

BFV downloads **204,900 bytes**, versus approximately **4,227,000 bytes** for
Paillier: a **20.6× reduction**. BFV's larger query is included when comparing
both directions: **942,294 bytes** versus approximately **4,227,500 bytes**,
or **4.49× less recurring traffic**. Query upload alone is 737,394 bytes for BFV
and 544 bytes for Paillier.

At this point BFV query encryption is a major client cost: approximately
0.197 s, compared with 0.026 s for native response decoding and 0.179 s for
prepared server evaluation. This explains why an approximately 109× improvement
in server evaluation over CPU BFV becomes about a 49× improvement in the full
local search.

These are fresh measurements with the comparison harness. Their samples are
separate from the earlier server-only ablations in the CUDA report.

### Illustrating transfer costs

An idealized symmetric 100 Mbps link adds `8 * (query_bytes + response_bytes) /
100_000_000` seconds to each measured local query. Taking the median of those
per-query sums gives:

| Configuration | Local total + modeled transfer (s) |
| --- | ---: |
| BFV, CUDA server | 0.571 |
| BFV, CUDA server + resident index | 0.480 |
| Paillier-Lookup, CUDA | 0.991 |
| Paillier-Lookup, CUDA client / CPU server | 0.696 |

This is a transfer model, not a network benchmark. It assumes constant effective
bandwidth, full buffering and no overlap, with zero RTT and no transport framing.
It illustrates the I/O tradeoff: prepared BFV can finish sooner despite the
hybrid's lower local compute time. Actual bandwidth, asymmetry, RTT, queuing
and overlap change the outcome.

## What the columns include

- **Server:** deserialize the query, evaluate the encrypted Hamming circuit,
  and serialize the response. BFV raw CUDA includes index upload/conversion on
  each query; the prepared path uses its retained GPU snapshot.
- **Client:** encrypt/serialize the query, deserialize/decrypt/decode the
  response, and select the same stable top three by `(distance, index)`.
- **Local total:** elapsed time covering the entire sequence above. It excludes
  network transit, setup, attestation, HTTP/TLS and content retrieval. Both
  logical roles run on the benchmark host; this is not an EC2 measurement.
- **Response:** measured MessagePack download bytes, including ciphertext
  framing and an implicit candidate order. Query upload is reported separately.

Every table value is a median of three measured searches after one warmup. Role
medians are computed independently and need not sum to the median total.
The raw artifact also reports server evaluation alone and every client phase.

## Configuration and comparison limits

Hardware: AMD Ryzen 7 5800X, RTX 3080 with 10 GiB, driver 580.173.02. Software:
Python 3.12.3, GMP 6.3.0, CUDA 12.0, GCC 12.4.0. The two Paillier extensions
were built from this checkout with `KEY_BITS=1024`, `CGBN_TPI=32`, `sm_86`,
and `ALPHA_LEN=280` for Lookup. All requested GPU backends must actually load;
there is no silent CPU fallback in the harness.

Paillier uses `key_len=1024`, meaning the prime size in these APIs, with an
approximately 2,048-bit public modulus. Lookup uses the current
`alpha_len=280` setting on both CPU and GPU. Actual modulus and decryption
exponent bit lengths are recorded for every row. The older SDK measurements
with `alpha_len=50` are not used as current performance baselines.

BFV uses N=16,384, t=65,537, the 180-bit three-prime RNS coefficient modulus,
30-bit decomposition and 50-bit compact responses. CPU evaluation is the
optimized residue backend; CUDA uses the fused kernels at the default batch
limit of 32. All BFV rows use the existing native `BFVPrivateDecoder` on CPU.
Only the BFV server runs on the GPU; Paillier's CUDA rows use its GPU client
for encryption/decryption as well as GPU public evaluation. The hybrid Lookup
row uses GPU client operations and public GMP multiplication on the server.

These parameter choices compare implementations, not equivalent security
levels. They do not close the schemes' existing protocol/security review items.
Every decrypted response here is generated locally by the benchmark.

All variants use the same synthetic binary vectors and plaintext query from
seed 1337, including known zero/max-distance cases. Fresh randomized query
encryption is performed for every trial. BFV rows share one key/index and
alternate execution order. Paillier configurations have independently generated
keys and run sequentially; this is not an isolated estimate of GPU kernel speed.
No other benchmarks or tests run concurrently with the measurement.

## Setup and validation

Key generation, initial index encryption/serialization, public key import,
BFV server-plan creation, private-context creation and GPU index preparation
are measured separately in the artifact. They are excluded from recurring
search latency. The three BFV rows share their setup group; its costs should
not be summed across those rows. A resident index must be prepared again when
the index changes and adds device storage in exchange for avoiding repeated
uploads. In this run, preparing the BFV GPU index takes 0.218 s and retains
192 MiB. Paillier retains its normal client lookup tables between queries.

The full run checks every distance and the top three for every query, including
warmup: 32 searches and 262,144 distances. A separate 16-vector run exercises
all eight configurations before the full measurement. These checks validate
the comparison harness; this change does not modify encryption implementations.

The JSON contains every sample, setup measurement, configuration, and source/
binary hash. It records the preceding HEAD with a dirty tree; the hashes identify
the measured implementation. No keys, plaintext vectors, or ciphertexts are
written to the artifact.

## Reproduction

Build the BFV CPU/CUDA and Paillier CPU/CUDA dependencies using the existing
build instructions. Paillier GPU public evaluation batches all candidates into
one existing API call, including the normal Python/hex/integer conversions.

```bash
PYTHONPATH=src .venv/bin/python benchmarks/bfv_paillier_latency.py \
  --num-vectors 8192 --repeats 3 --alpha-len 280 \
  --json-out /tmp/bfv-cuda-paillier-comparison-8192.json
```

The raw data is archived in
[`bfv_cuda_paillier_comparison_8192.json`](../../benchmarks/results/bfv_cuda_paillier_comparison_8192.json).
