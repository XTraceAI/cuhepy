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

For N=16,384, t=1,031, Q120 and the 25-bit terminal response, the existing
public-key index permits d=58 at 8,192 vectors; d=59 is refused by the terminal
bound. With the owner-encrypted index below, d=73 is admissible and d=74 is
refused. These are conservative whole-circuit bounds, not empirical noise
thresholds. They are recomputed when the count or index encryption mode changes.

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
  implements the separate envelope, fixed-width rounding and expansion. Its
  default is the Python/GMP reference; `backend="native"` explicitly selects
  the separate homemade C++/GMP public codec in
  [`query_codec.h`](../../experiments/bfv_search_lab/_native/query_codec.h).
- [`test_compressed_query_bgv.py`](../../experiments/bfv_search_lab/test_compressed_query_bgv.py)
  checks exhaustive small coefficient domains, wrapping, malformed packets,
  mixed-radix holes, exact encryption/search, ties and excessive bounds.
- [`test_cuda_compressed_query_bgv.py`](../../experiments/bfv_search_lab/test_cuda_compressed_query_bgv.py)
  compares full native CPU/CUDA ciphertexts, repeated workspaces and private
  finishing through degree 16,384, with both index encryption modes.
- [`test_native_query_codec_bgv.py`](../../experiments/bfv_search_lab/test_native_query_codec_bgv.py)
  checks byte-identical encodings and complete expanded ciphertexts, zero/tail
  coefficients, unaligned widths, native allocation bounds and concurrent calls.
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

Rebuild both lab public extensions after updating their source. Add
`--native-codec` to either benchmark command to retain all three original
variants and also measure the C++/GMP codec at the same maximum admissible
precision. The compressed bytes are identical. Native encoding/decoding
operates on bounded public bit streams and releases the GIL; it receives no
secret key and adds no SEAL dependency.

Each index group has a seeded baseline, the maximum publicly admissible dropped
precision, and a variant dropping two fewer bits. A fresh owner query is shared
across the paired encodings in each round; its measured encryption cost is
charged to every total. Query and order RNGs are separate. All distances and
stable top-3 are checked. Local trials have ten measured rounds after one
warmup; TCP uses five measured rounds. Setup, excluded fixture-evaluation costs,
source hashes and all samples are saved without keys or ciphertexts.

## Validation at the native-codec implementation

At `d2f2159`, the focused reference/native/CUDA/owner/seeded run passes 85 tests.
The complete `tests`, `experiments/bfv` and `experiments/bfv_search_lab` run passes
**719 tests, with one live Nitro integration skipped**. Both Paillier CUDA
extensions, required BGV CUDA and the independent SEAL BGV oracle are enabled.
The expected multithreaded-fork regression produces one deprecation warning.
Explicit Ruff and mypy checks of the changed modules pass.

The public native extension is additionally rebuilt with GCC 12
`-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer`. Loading this
separate binary from `/tmp` into the Python process passes **53 reference,
native-codec and seeded-query tests**, without sanitizer diagnostics. The
PyCryptodome deepbind override is enabled and Python-hosted leak detection is
disabled; address and undefined-behavior checking remain enabled. This is finite
memory/arithmetic boundary coverage, not a security proof or private side-channel
audit. The optimized binaries alone are used in the timing experiments.

```bash
CUHEPY_REQUIRE_BGV_CUDA=1 CUHEPY_SEAL_BGV_ORACLE=/tmp/cuhepy-seal-bgv-oracle .venv/bin/python -m pytest tests experiments/bfv experiments/bfv_search_lab -q
.venv/bin/ruff check --no-force-exclude experiments/bfv_search_lab/compressed_query_bgv.py experiments/bfv_search_lab/seeded_bgv.py experiments/bfv_search_lab/test_native_query_codec_bgv.py experiments/bfv_search_lab/test_cuda_compressed_query_bgv.py benchmarks/bgv_query_compression.py
.venv/bin/mypy --explicit-package-bases experiments/bfv_search_lab/compressed_query_bgv.py experiments/bfv_search_lab/seeded_bgv.py
```

The public-codec sanitizer invocation on this GCC 12/Linux host is below. The
module is replaced only inside this one test process; normal extension files
are not overwritten. Run this separately from performance measurements.

```bash
g++-12 -std=c++17 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fPIC -shared -I/usr/include/python3.12 -Isrc/cuhepy/bfv/_cpu_ext experiments/bfv_search_lab/_native/bindings.cpp -lgmpxx -lgmp -o /tmp/cuhepy-query-codec-asan.so
PYCRYPTODOME_DISABLE_DEEPBIND=1 LD_PRELOAD=/usr/lib/gcc/x86_64-linux-gnu/12/libasan.so:/usr/lib/x86_64-linux-gnu/libstdc++.so.6 ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 .venv/bin/python - <<'PY'
import importlib.util
import sys
import pytest
name = 'experiments.bfv_search_lab._native._bgv_trace'
spec = importlib.util.spec_from_file_location(name, '/tmp/cuhepy-query-codec-asan.so')
module = importlib.util.module_from_spec(spec)
sys.modules[name] = module
spec.loader.exec_module(module)
assert module.__file__ == '/tmp/cuhepy-query-codec-asan.so'
raise SystemExit(pytest.main([
    'experiments/bfv_search_lab/test_compressed_query_bgv.py',
    'experiments/bfv_search_lab/test_native_query_codec_bgv.py',
    'experiments/bfv_search_lab/test_seeded_bgv.py', '-q']))
PY
```

## Python/GMP codec results

The first full run uses the committed implementation at `c661f52` on the same
Ryzen 7 5800X / RTX 3080 workstation as the service study. It retains N=16,384,
t=1,031, Q120, eta=21 and the 25-bit response. The two index modes share the
key context and plaintext corpus; each receives a separate fresh encrypted
index. Pairing within a mode uses identical fresh query ciphertexts across
codec variants. Ordinary benchmark runs are unprofiled and run separately
from builds and tests.

At 8,192 vectors:

| Query/index configuration | Query bytes | Response bytes | Total bytes |
| --- | ---: | ---: | ---: |
| Original seeded query, either index mode | 245,866 | 102,488 | 348,354 |
| Rounded query, existing public-key index | 149,612 | 102,488 | 252,100 |
| Rounded query, new owner-encrypted index | 118,892 | 102,488 | 221,380 |

Those are **27.6% and 36.4% less recurring traffic** than the seeded baseline.
The actual retained coefficient widths are 73 and 58 bits: the encoding keeps
the high part and a residue modulo t, so d dropped bits do not equal d saved
bits. The response format and payload are unchanged.

| 8,192 vectors, median | Public index, seeded | Public index, rounded | Owner index, seeded | Owner index, rounded |
| --- | ---: | ---: | ---: | ---: |
| Local, no TCP | 65.63 ms | 80.34 ms | 64.04 ms | 77.85 ms |
| Loopback TCP | 72.09 ms | 84.58 ms | 68.90 ms | 82.23 ms |
| 100/100 Mbps, 20 ms added RTT | 119.70 ms | 124.85 ms | 118.36 ms | 119.04 ms |
| 10 Mbps up / 100 Mbps down, 40 ms RTT | 317.21 ms | 252.91 ms | 316.54 ms | 227.54 ms |
| 10/10 Mbps, 40 ms RTT | 390.61 ms | 327.12 ms | 387.98 ms | 301.17 ms |

The Python codec pays roughly 5 ms for compression and an extra 8–9 ms for
expansion. That loses locally and on the 100 Mbps link, but saves time on the
10 Mbps upload. These real loopback transfers use application pacing, not WAN
congestion/loss emulation. The excluded expected-ciphertext evaluation makes
them trusted fixtures rather than deployment latency estimates.

Index encryption plus expansion takes 32.47 s with public-key encryption and
4.14 s with the existing native RNS owner. Both expanded indexes contain
125,829,120 coefficient bytes before framing; the owner's individual seeded
index envelopes total 62,941,696 bytes. GPU preparation takes 1.89/1.79 s.
These are one-time setup observations, not query latency or complete index
upload measurements.

See the [raw 8,192-vector results](../../benchmarks/results/bgv_query_compression_8192.json)
for samples, exact bound plans, refused precisions and source/binary hashes.

At 32,768 vectors the bound permits d=57 for the public-key index and d=72 for
the owner index. Query-plus-response traffic falls from 450,761 bytes to
356,555 and 325,835 bytes respectively (20.9% and 27.7% less). The response
remains 204,895 bytes. The larger public-key-index local median rises from
126.18 to 144.13 ms, while the 10-up/100-down Mbps, 40 ms RTT median falls from
393.82 to 330.41 ms. With the owner index those paired values are 123.99 to
137.65 ms locally and 380.53 to 295.77 ms over that paced link.
See the [32,768-vector artifact](../../benchmarks/results/bgv_query_compression_32768.json).

## Native public codec results

The second study at `d2f2159` adds `--native-codec`. Each index group now pairs
four encodings of every fresh query: seeded, conservative Python rounding,
maximum Python rounding and maximum native rounding. Python and native maximum
rounding use identical widths, bounds and payload sizes; only the public codec
implementation changes. The original Python results above remain a separate
earlier run. All values below compare variants within the new run.

| 8,192 vectors, median | Public index, seeded | Public index, native rounded | Owner index, seeded | Owner index, native rounded |
| --- | ---: | ---: | ---: | ---: |
| Local, no TCP | 65.53 ms | 68.48 ms | 63.85 ms | 67.52 ms |
| Loopback TCP | 71.01 ms | 75.19 ms | 66.63 ms | 71.01 ms |
| 100/100 Mbps, 20 ms added RTT | 119.70 ms | 115.70 ms | 114.81 ms | 108.30 ms |
| 10 Mbps up / 100 Mbps down, 40 ms RTT | 318.17 ms | 241.78 ms | 312.14 ms | 214.89 ms |
| 10/10 Mbps, 40 ms RTT | 391.47 ms | 316.19 ms | 385.75 ms | 288.68 ms |

Compression falls from 5.58 to 1.64 ms for the public-index case. Expansion,
including regeneration of the unchanged seeded component, falls from 12.69 to
6.08 ms (the unrounded baseline takes 4.18 ms). The added local request cost
falls from 14.51 ms with Python to 2.95 ms with native encoding. For the owner
index, the corresponding added costs are 13.03 and 3.67 ms. All are medians;
phase medians need not sum exactly to the median total.

This keeps the **252,100 / 221,380 byte** totals while making rounding useful
on the measured 100 Mbps link as well as the 10 Mbps upload. The 10-up/100-down
request median improves by 24.0% with the existing public-key index, and by
31.2% with the owner index, relative to the seeded baseline within each group.
The original seeded format is still faster locally and on loopback. Select the
representation according to actual link cost and ingestion constraints; a
smaller packet is not automatically a faster complete request.

The [native 8,192-vector artifact](../../benchmarks/results/bgv_query_compression_native_8192.json)
contains all variants, ten local/five paced trials after warmup, source/binary
hashes and setup costs. Every measured result matches all exact Hamming
distances and the stable top-3. The earlier trusted-fixture and excluded
verification-cost limitations apply unchanged.

The [native 32,768-vector run](../../benchmarks/results/bgv_query_compression_native_32768.json)
uses the same protocol and retains the 356,555 / 325,835 byte totals:

| 32,768 vectors, median | Public index, seeded | Public index, native rounded | Owner index, seeded | Owner index, native rounded |
| --- | ---: | ---: | ---: | ---: |
| Local, no TCP | 123.11 ms | 126.71 ms | 118.16 ms | 122.04 ms |
| Loopback TCP | 130.12 ms | 134.01 ms | 123.62 ms | 125.54 ms |
| 100/100 Mbps, 20 ms added RTT | 187.63 ms | 182.99 ms | 179.18 ms | 172.77 ms |
| 10 Mbps up / 100 Mbps down, 40 ms RTT | 385.84 ms | 312.33 ms | 375.41 ms | 279.52 ms |
| 10/10 Mbps, 40 ms RTT | 532.19 ms | 458.77 ms | 524.04 ms | 427.15 ms |

Native rounding adds 3.60/3.88 ms locally but saves 19.1%/25.5% on the
10-up/100-down link, relative to each group's seeded baseline. All measured
distances and selections remain exact. The direction of the tradeoff agrees
with the smaller workload: unchanged search work, slightly more CPU processing,
and lower transfer cost. These samples do not measure a real WAN, independent
client/server CPUs or an authenticated remote service.

The next communication experiment should jointly budget precision for the query
and terminal response, checking the complete no-wrap inequality and both codec
costs. A smaller response might be worth a slightly larger query on an asymmetric
link. That is a proposed experiment, with no further byte/time saving claimed
here. The original ring and public correctness limits remain the reference
until parameter assurance and protocol review justify any broader change.
