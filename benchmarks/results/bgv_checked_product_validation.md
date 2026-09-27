# Bound BGV product/switch validation

Implementation revisions:

- `dec0fe264717862c4100469d5132ecb2f01b8805`: reference/native bound product and
  switch checks, witness/local-c2 modes, direct native recomputation control,
  adversarial/lifecycle tests and initial measurements.
- `5077d39217b4d94dbe59d4a4e523f5485d36cfc9`: direct RNS CUDA product stage,
  batched dispatch, bounded native interface, differential/sanitizer harness
  and paired follow-up measurements.

See the [report](../../docs/research/bgv-checked-product.md) for the statement,
conditional checking argument, full timing scope and remaining protocol gaps.
The experiment remains on `experiment/bgv-verification-packing`.

## Artifacts and provenance

Both runs use N=16,384, Q120, t=1031, actual BGV encryptions of synthetic public
binary polynomials and ten paired rounds plus one excluded warmup at each
batch of 1/8/32/64 ciphertext tiles. Operation order is shuffled. All complete
outputs match the existing CPU/CUDA implementations, all honest checks accept
and all benchmark mutation checks reject. These are product/switch subcircuits,
not full Hamming-search or real enclave measurements.

| Artifact | Source | SHA-256 |
|---|---|---|
| [Initial export-heavy GPU path](bgv_checked_product_16384.json) | `dec0fe2` | `6af3c64e48e8ef377eafccc573e71b017c2c7049eec929037a2fb1be30c812c1` |
| [Paired direct-RNS follow-up](bgv_checked_product_rns_16384.json) | `5077d39` | `dd7f9400cc4ac0f41af0b8b8a34035e0cdc679dc05b71d361d2a2ad86a2a03b6` |

All 130/132 tracked source digests respectively match the recorded commit.
The initial CUDA extension hash describes the earlier binary, superseded by
the direct-RNS build. All follow-up binary hashes match the measured local
builds. Native binaries are not committed; source revisions/build commands
and hashes identify them. Reported speed ratios use comparisons within the
paired follow-up, not a subtraction between separate runs.

All correctness flags and sample counts were checked. Artifacts contain public
parameters, metadata, timings, counts, public synthetic-plaintext/order seeds
and source/binary hashes. They contain no HE keys, ciphertexts, witnesses,
verifier challenges or encryption seeds. Internal-link figures are labeled
analytical projections; ordinary host-copy timings are not called enclave or
DMA performance. Benchmarks ran serially, separately from builds, tests and
sanitizers.

## Full regression

```bash
CUHEPY_REQUIRE_BGV_CUDA=1 CUHEPY_SEAL_BGV_ORACLE=/tmp/cuhepy-seal-bgv-oracle \
  .venv/bin/python -m pytest tests/ experiments/bfv/ experiments/bfv_search_lab/ -q
```

At `5077d39`, exit 0: **1,118 passed, 1 skipped, 1 warning in 266.90 s**.
[Full output](bgv_checked_product_full_tests.txt). The skip is the live AWS
integration. The existing warning concerns an actual-fork private-state guard
test. No native/GPU checker tests were skipped. SEAL is an independent test
oracle; the implementations and benchmarks here use homemade arithmetic.

New checks include independent schoolbook tensor/switch truth, every output
component/limb/tile, every witness limb, a correctly switched wrong tensor,
query/index/order/epoch/context mutations, whole-output validation before
entropy, one-use rejection/retry/concurrency and copying/fork guards. Tiny
three-equation error matrices exhaust the rank/miss relation. Native tests
cover B=64, weights p-1, large 128-bit sums, malformed weights/capsules/bytes
and oversized constructors. Direct-RNS CUDA tests include batches 1/7/8/9/64,
N up to 16,384, concurrent calls, malformed queries and cross-index contexts.

## Native verifier sanitizers

```bash
mkdir -p /tmp/cuhepy-product-sanitize
g++-12 -O1 -g -std=c++17 -fPIC -shared -fsanitize=address,undefined \
  -fno-omit-frame-pointer -fno-sanitize-recover=all \
  -I/usr/include/python3.12 -Isrc/cuhepy/bfv/_cpu_ext \
  experiments/bfv_search_lab/_verify/bindings.cpp -lgmpxx -lgmp \
  -o /tmp/cuhepy-product-sanitize/_bgv_checked.cpython-312-x86_64-linux-gnu.so
LD_PRELOAD=/usr/lib/gcc/x86_64-linux-gnu/12/libasan.so:/usr/lib/x86_64-linux-gnu/libstdc++.so.6 \
  ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
  .venv/bin/python experiments/bfv_search_lab/_verify/run_sanitizers.py \
  /tmp/cuhepy-product-sanitize/_bgv_checked.cpython-312-x86_64-linux-gnu.so
```

Exit 0: **134 passed in 1.42 s**. [Output](bgv_checked_product_asan.txt).
The loader asserts that the exact instrumented extension is used, with no
release fallback. Address/UB checks are enabled; leak checking is disabled for
the CPython harness. Python and GMP are not themselves instrumented. Execution
required leaving the sandbox's ptrace restriction. Sanitized binary SHA-256:
`81c92db7dd7048614965710060ecceab4d3bc9ac813a3cf9ec5f537b007eeef3`.

## CUDA memory checking

```bash
make -C experiments/bfv_search_lab/_native product-stage-sanitizer \
  CUDA_CXX=g++-12 CUDA_ARCH=86
/tmp/cuhepy-sanitizer-12.9/cuda_sanitizer_api-linux-x86_64-12.9.79-archive/compute-sanitizer/compute-sanitizer \
  --tool memcheck --error-exitcode 1 /tmp/cuhepy-bgv-product-sanitizer
```

Exit 0, **zero errors**. [Output](bgv_checked_product_memcheck.txt). The standalone
harness compares every word against the existing native CPU evaluator at
N/B pairs 64/1, 64/7, 64/8, 64/9, 64/64, 2,048/8 and 16,384/9, with both
baseline/indexed NTT variants. It also rejects truncated and noncanonical
queries. This avoids the local Python process-attachment limitation. No new
CUDA arithmetic kernel is introduced: the new entry point changes dispatch,
buffer allocation and direct export. Standalone binary SHA-256:
`4cb21fb6d25dab3685d1bcb31fa11e3051cadd9b01e21b4854b228c41d29f66f`.

## Static checks and scope

All passed:

```bash
.venv/bin/ruff check src tests
.venv/bin/ruff check --config 'force-exclude=false' --config 'exclude=[]' \
  experiments/bfv_search_lab benchmarks/bgv_checked_product.py
.venv/bin/mypy src/cuhepy
git diff --check
```

Mypy checks 34 package files, not strict typing of all experiment modules.
Butterfly and terminal relations, global block coverage, complete receipt
binding, real enclave transport, independent cryptographic parameter review
and private-side-channel assurance remain separate work. These tests and
timings do not establish production readiness or a novel proof system.
