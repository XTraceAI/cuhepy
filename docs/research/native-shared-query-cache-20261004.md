# Q76.4c: authenticated mutable owner-cache control

The registered correctness, authentication and local-state gate passes. This
is a known-method comparison control for an owner who is allowed to retain
their plaintext. It is not an original cryptographic scheme, a latency result,
an HE response verifier or a deployed trusted service.

The [registration](native-shared-query-cache-registration-20261004.json) was
committed at `951ec39` before implementation. The four executed sources were
committed at `890b2810231540cbf2af4ead3b2ebe69cbdcd2c9`, then frozen with both
isolated binaries and dependencies before the gates. The
[return](native-shared-query-cache-return-20261004.json) and
[validation](native-shared-query-cache-validation-20261004.json) identify the
receipts. Evidence lives outside Git at
`/home/pete/yavor-projects/xtrace-work/research-data/q76-cache-20261004`.

## Implementation and authority

| File | Role |
| --- | --- |
| `experiments/bfv_search_lab/authenticated_cache.py` | Trusted owner snapshot/patch encoders, immutable context, bounded delivery parser, process-owned cache client and native wrapper. |
| `experiments/bfv_search_lab/_shared_query/cache_popcount.cpp` | Isolated stateless C ABI for complete XOR/popcount distances and ordinal-stable top3. No HE arithmetic or backend dependency. |
| `experiments/bfv_search_lab/test_authenticated_cache.py` | Authentication, grammar, updates, ownership, concurrency, direct ABI and independent score regressions. |
| `benchmarks/cache_shared_query_lab.py` | One retained-public correctness/accounting cohort. Despite its benchmark location, this gate records no timings. |

The honest owner provisions an AES-256-GCM-SIV key, Ed25519 public anchor and
current context over a separately trusted channel. The context binds opaque
namespace/key/snapshot IDs, a bounded UInt64 epoch, count, dimension and a
digest of the complete ordered UInt64 IDs. The digest is public metadata,
not a hiding commitment. Plaintext rows have no public digest in this protocol.
Standard `cryptography==50.0.1` provides AEAD and signatures; homemade HE
implementations remain unchanged and are not imported by this cache or runner.

A signed descriptor binds the delivery kind, full context(s) and hash of the
entire encrypted packet. The client checks signature, pinned context and
ciphertext digest before AEAD, authenticates before parsing, and validates
the entire body before publishing. A server cannot advance the current pin
by attaching a newer descriptor. Pinning a new owner context makes old
retained bytes inactive immediately.

An update replaces 1..32 sorted unique row ordinals at exactly the next epoch,
with a different snapshot ID and unchanged key, shape and ordered IDs. The
owner pins the new context first. The client validates every change before
copying and publishing the replacement rows. A malformed late entry leaves
all old bytes intact and inactive. Gaps or shape/ID changes require full
acquisition. Late downloads cannot republish an older snapshot.

Queries return every exact Hamming distance and rank by
`(distance, original row ordinal)`, then map the selected positions to bound
IDs. Numeric IDs are labels, never the tie key. Four-or-more equal-distance
rows with reversed/nonmonotonic IDs test both tie membership and order,
including the changed ties after updates. Existing cache controls keep their
historical numeric-ID contract; their APIs and test expectations are untouched.

The client and wrapper check PID before locks, reject copying/pickling and
reject operations after logical close. Queries, owner pins, acquisition and
updates linearize under the client lock. The native function validates all
lengths, geometry, output alignment/overlap and physical padding before
writing output. Direct C callers still supply valid allocated pointer spans;
the Python wrapper owns immutable byte inputs and output arrays. The trusted
explicit library path is not a peer-selected executable.

## Executed evidence

- **93 distinct new unit cases** pass normally and under UBSan with identical
  case identities; sanitizer repetitions are not additional experiments.
- **16 existing compatibility cases** pass normally: six backup-cache cases
  and ten coordinate/raw/compressed cache cases.
- **16 saved small cases** match independent literal-bit distances and the
  complete saved encoded HE score vectors after public decoding with `t,d`.
- **Six saved source searches**, at 8,224/16,384/32,768 rows and dimension
  512, match complete independent plaintext distances and historical HE top3.
  The complete historical large private distance vectors were not retained;
  there is no new comparison to such vectors or new HE decryption.
- **Three authenticated 32-row updates and six post-update searches** match
  every independent distance and the changed ordinal ties.

The cohort contains **28 searches and 229,980 distance comparisons**. It
archives 19 snapshot packets and three patch packets, their signed descriptors
and one public owner anchor. It generates one fresh standard signing key and
one fresh AES key, but serializes neither secret. Unit cases use two public
deterministic test-only contexts of each kind, reused across normal/UBSan.
Existing compatibility support keys are outside the new cohort caps. Fresh
support keys reproduce answers but do not restore the archived ciphertext's
key context.

Authentication/grammar cases include foreign signatures, keys and context,
wrong AAD, signed bad tags, extra/truncated packets, duplicate IDs, wrong ID
binding, last-row padding, replay/gaps and malformed final patch entries.
Thread gates cover late acquisition and query/pin linearization. A held-lock
fork gate requires child rejection before an inherited lock can be acquired.
Direct ABI failures preserve output sentinels. All 109 normal and 93 UBSan
cases pass with zero failures, errors or skips. These are bounded regressions,
not a general memory-safety or security proof.

## Actual bytes and accounting limits

Snapshot bodies contain all ordered IDs (8 bytes/row), then compact binary
rows. The packet overhead is 51 bytes, and its signed descriptor is 288 bytes.
These are actual archived sizes, not compressed-size estimates.

| Rows, dimension 512 | Retained row + ID body | Encrypted packet | Signed descriptor | Complete acquisition |
| ---: | ---: | ---: | ---: | ---: |
| 8,224 | 592,128 B | 592,179 B | 288 B | 592,467 B |
| 16,384 | 1,179,648 B | 1,179,699 B | 288 B | 1,179,987 B |
| 32,768 | 2,359,296 B | 2,359,347 B | 288 B | 2,359,635 B |

Each 32-row patch has a 2,178-byte plaintext body, a 2,229-byte encrypted
packet and a 454-byte descriptor: **2,683 bytes total**, independently of
these three dataset sizes. The context's full-snapshot geometry is recorded
separately from the patch body. A current returning cache needs no search
response from the remote evaluator. That does not remove acquisition,
trusted provisioning, authentication, updates or local search work.

At 32,768 rows, retained rows are 2,097,152 bytes and IDs are 262,144 bytes,
or 2.25 MiB together. Native query output buffers hold 65,548 bytes. The
166-byte context encodings and 64-byte key/anchor material are canonical
interface counts; two context references may point to the same object and
must not be counted as two resident encodings. These figures are not RSS or
measured stage peaks. Acquisition also holds old cache data, decrypted body,
parsed copies and an ID set. Updates hold old rows, a bytearray and new bytes.
Python objects and result tuples, crypto state, locks, DSO and caller-owned
inputs remain additional costs for Q76.5/Q77.

## Reproduction and next handoff

The evidence includes `build-and-freeze.py`, `run-gates.py`,
`run-retained-cohort.py` and their command/output receipts. Normal builds use
`-march=native`; UBSan adds `-fsanitize=undefined` and
`-fno-sanitize-recover=undefined`. Both use the existing Makefile with explicit
`SOURCE=cache_popcount.cpp` and separate absolute `TARGET` paths. The normal
DSO links libc only. No delivered HE library is rebuilt or overwritten.

For a new independently declared reproduction, build new isolated targets,
freeze source/dependency/binary hashes, then run:

```bash
CUHEPY_CACHE_LIBRARY=/absolute/new/libcache_popcount.so \
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
.venv/bin/python -m pytest -q \
  experiments/bfv_search_lab/test_authenticated_cache.py \
  experiments/bfv_search_lab/test_cache_snapshot.py \
  experiments/bfv_search_lab/test_coordinate_cache.py

CUHEPY_CACHE_LIBRARY=/absolute/new/libcache_popcount_ubsan.so \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
.venv/bin/python -m pytest -q experiments/bfv_search_lab/test_authenticated_cache.py

.venv/bin/python benchmarks/cache_shared_query_lab.py \
  --library /absolute/new/libcache_popcount.so \
  --baseline /absolute/path/baseline-inventory.json \
  --execution-freeze /absolute/path/execution-freeze.json \
  --output /absolute/new/cohort-directory
```

The runner refuses an existing output directory. Preserve failed attempts and
do not silently spend additional registered support contexts. Rerunning its
helper in the original evidence directory intentionally refuses overwrite.

This gate runs **zero fresh HE keys/encryptions/decryptions, timing panels,
CUDA or author artifacts**. It preserves all 411 preceding runtime source
pins, 66 company source/library pins, four isolated prior native libraries,
main/staging refs and the 120-record literature registry byte-for-byte.

It does not implement owner provisioning, host-resistant rollback, private
side-channel assurance, erasure, attestation, cache/HE ciphertext-equivalence
proofs or HE output authentication. Same logical cache/HE data is an
honest-owner premise to be bound in the next descriptor. Actual prefetch
overlap/contention and complete latency remain unmeasured.

The next task is **Q76.5 certificate/resource/client-context handoff, with the
early Q79.1 claim-to-prior discriminator**. Q77 stays conditional until that
gate. Keep this strong permitted control in Q77; do not manufacture an
outsourcing win by forbidding it or charging it an HE-index download.
