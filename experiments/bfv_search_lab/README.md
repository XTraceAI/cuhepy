# BFV search research sandbox

The [experiment plan](../../docs/research/bfv-search-experiment-plan.md) proposes
12 directions from the accepted BFV CUDA baseline. The first implemented batch
now includes encrypted CPU/CUDA partial sums, owner query preprocessing,
seeded queries, a native SIMD encoder, and a depth-one BGV-style alternative.
The [results report](../../docs/research/search-lab-first-results.md) records
measurements, unsuccessful tradeoffs, and the next experiments.
The [BGV follow-up](../../docs/research/bgv-butterfly-results.md) adds joint
packing, persistent RNS, CUDA, bounded terminal compaction and seeded queries.
The [public-pipeline follow-up](../../docs/research/bgv-public-pipeline-results.md)
records kernel ablations, native compaction, scaling, concurrency and terminal
precision under the same homemade BGV evaluation context.
The [owner follow-up](../../docs/research/bgv-owner-results.md) measures bulk
fresh sampling, exact ternary products and a separate private C++/GMP backend.

These are explicit research entry points, outside the default client and its
authenticated protocols. They operate on synthetic, owner-controlled data.
Partial scores and coefficient products expose additional information to the
decrypting owner; private Python/GMP and encoder code has no side-channel
assurance. The raw CUDA path does not provide attestation.

| File | Role |
| --- | --- |
| `layout_oracles.py` | Independent plaintext algebra and operation counts |
| `partial.py` | Layout, reference circuit, native/CUDA experimental servers and decoder |
| `query.py` | Public-key or seeded symmetric query, one-use preprocessing pool, native encoder wrapper |
| `shallow_bgv.py` | Depth-one RLWE reference, conservative correctness bound, signed coefficient layout |
| `trace_bgv.py` | Public evaluation keys, ring-trace projection and dense coefficient-result packing |
| `butterfly_bgv.py` | Joint trace/packing reference, public bound schedule and key validation |
| `native_bgv.py`, `_native/` | Isolated C++/RNS/CUDA evaluators with resident public keys/index |
| `_native/compact.h` | Exact terminal reduction in C++, before exporting the small result |
| `compact_bgv.py` | Congruence-preserving terminal modulus reduction and its correctness bound |
| `seeded_bgv.py` | Fresh owner-encrypted query; server regenerates the uniform component |
| `owner_bgv.py` | Bulk fresh sampling, identical public stream decoding, shifted-ternary multiplication and local owner |
| `native_owner_bgv.py`, `_owner/` | Separate optional private C++/GMP arithmetic; no SEAL/CUDA dependency |
| `seal_bgv_oracle.cpp` | Independent coefficient-layout/circuit check using official SEAL BGV |
| `planner.py` | Capability-filtered ranking under a modeled network connection |
| `test_*.py` | Differential, boundary, lifecycle and algebra tests |

The small C++ hooks live with the existing backends in
[`src/cuhepy/bfv/_cpu_ext`](../../src/cuhepy/bfv/_cpu_ext) and
[`src/cuhepy/bfv/_gpu_ext`](../../src/cuhepy/bfv/_gpu_ext). Rebuild **both** from
this checkout; old binaries do not have the experimental factories. The
accepted `create_server` path defaults to one complete sum as before.
The BGV follow-up has its **own** native extensions under `_native/`; it does
not add a BGV mode to the production BFV factories.

## Build, test and measure

Use an isolated virtual environment in this worktree. On the measured machine,
CUDA 12.0 used GCC 12 and the RTX 3080 used architecture 86:

```bash
uv sync --all-groups --extra bfv-nitro
make -C src/cuhepy/bfv/_cpu_ext PYTHON="$PWD/.venv/bin/python" CXX=g++-12
make -C src/cuhepy/bfv/_gpu_ext PYTHON="$PWD/.venv/bin/python" \
  CUDA_CXX=g++-12 CUDA_ARCH=86
.venv/bin/python -m pytest tests/ experiments/bfv_search_lab/ -q

# Run benchmarks separately, without concurrent builds/tests or other workloads.
.venv/bin/python benchmarks/bfv_search_lab.py --num-vectors 8192 --repeats 10 \
  --json-out benchmarks/results/bfv_search_lab_8192.json
.venv/bin/python benchmarks/coefficient_search_lab.py --num-vectors 8192 --repeats 5 \
  --json-out benchmarks/results/coefficient_search_lab_8192.json
.venv/bin/python benchmarks/trace_bgv_lab.py --num-vectors 65 --q-bits 96 --repeats 3 \
  --json-out benchmarks/results/trace_bgv_lab_65.json
```

The first benchmark reuses one index/key set across all CUDA/query variants,
warms each variant, shuffles paired query rounds, and verifies every distance
and stable top-three result outside timing. Index setup and factory setup are
separate. **Online pool timings exclude refill; `total_with_refill_s` includes
it.** Tokens must remain confidential on the client and are never reusable,
copiable or serializable. Forked processes must make new pools.

The coefficient benchmark is entirely **CPU reference arithmetic** and takes
considerably longer. It compares matched BFV/BGV layouts, a three-product BGV
variant, a smaller BGV plaintext/ciphertext modulus, and BFV terminal compaction.
It has no result repacking and does not claim to outperform the CUDA search.
For a quick functional smoke run, use `--num-vectors 7 --embed-len 3
--ring-degree 16 --repeats 2` (and a temporary JSON output).

The trace pilot adds encrypted projection/repacking and measures **65 vectors
at the full N=16,384, d=512 ring/layout**. It includes an explicitly analytical
8,192-vector payload/count/bound projection, not a runtime claim at that size.
Its public CPU key switching is a slow reference, without native or CUDA kernels.
The follow-up benchmarks below supersede that limitation; the original pilot
and its artifacts remain available as a reference.

Only timings, public parameters, byte counts and source/binary hashes are
saved. The repository ignores JSON globally: explicitly stage only reviewed
measurement artifacts, never keys or ciphertext dumps.

## Network projections

```bash
.venv/bin/python experiments/bfv_search_lab/planner.py \
  benchmarks/results/bfv_search_lab_8192.json \
  --upload-mbps 100 --download-mbps 100 --rtt-ms 20 \
  --allow-partial-scores --allow-symmetric --allow-precompute
```

Flags opt into additional owner capabilities/disclosure. By default the planner
excludes partial sums, symmetric queries and pools. Add `--include-refill` to
charge pool generation. The calculation adds serial transfer time and one RTT
to measured local time; **it is not a network measurement, throughput forecast,
security-parameter selector, or production routing policy**.

## Independent algebra model

Run with Python 3.11+ and no additional dependencies:

```bash
python3 experiments/bfv_search_lab/layout_oracles.py \
  --json-out experiments/bfv_search_lab/models/partial-reduction-8192.json
```

The script checks two hypotheses independently of the library:

- E01: keep several disjoint dimension sums in a packed response, then add them
  on the owner. It simulates slot rotations, masks, tile packing and decoding.
- E06: use signed-bit forward/backward coefficient packing to obtain many
  Hamming correlations in one negacyclic polynomial product. It deliberately
  does not solve encrypted result repacking.

The model counts rotations, relinearizations, response ciphertexts and raw
coefficient bytes. Framing, runtime, noise and security are outside its scope.
The tiny dimensions/plaintext moduli in the oracle are arithmetic fixtures.
Partial sums and unmasked correlations also disclose more to the decrypting
client than final distances, as described in the plan.

Change the modeled public workload without generating a large encrypted index:

```bash
python3 experiments/bfv_search_lab/layout_oracles.py \
  --num-vectors 32768 --embed-len 512 --ring-degree 16384
```

The repository excludes experiments from routine Ruff discovery. To check this
directory explicitly with the repository lint rules:

```bash
ruff check --config 'force-exclude=false' --config 'exclude=[]' \
  experiments/bfv_search_lab/ benchmarks/{bfv_search_lab,coefficient_search_lab,trace_bgv_lab}.py
mypy --explicit-package-bases \
  experiments/bfv_search_lab/{layout_oracles,partial,query,shallow_bgv,trace_bgv,planner}.py
```

## BGV joint packing, RNS and CUDA

These commands build only the isolated research extensions. Public evaluation
reuses existing modular/NTT code; SEAL is not linked into these extensions.

```bash
make -C experiments/bfv_search_lab/_native all cuda \
  PYTHON="$PWD/.venv/bin/python" CXX=g++-12 CUDA_CXX=g++-12 CUDA_ARCH=86
.venv/bin/python -m pytest experiments/bfv_search_lab/ -q

# Full-ring differential pilot: identical ciphertexts across Python/C++/GPU.
.venv/bin/python benchmarks/butterfly_bgv_lab.py \
  --num-vectors 65 --q-bits 120 --rns-modulus --terminal-bits 32 \
  --variants python-butterfly native-butterfly residue-butterfly cuda-per-tile cuda-butterfly \
  --repeats 3 --json-out benchmarks/results/bgv_rns_cuda_65.json

# Full workload, same keys/index/query for each paired CPU/GPU round.
.venv/bin/python benchmarks/butterfly_bgv_lab.py \
  --num-vectors 8192 --q-bits 120 --rns-modulus --terminal-bits 32 \
  --variants residue-per-tile residue-butterfly cuda-per-tile cuda-butterfly \
  --repeats 5 --json-out benchmarks/results/bgv_rns_cuda_8192.json

# Optional owner-only query encryption; fresh seed/error for every query.
.venv/bin/python benchmarks/butterfly_bgv_lab.py \
  --num-vectors 8192 --q-bits 120 --rns-modulus --terminal-bits 32 --seeded-query \
  --variants residue-butterfly cuda-per-tile cuda-butterfly \
  --repeats 5 --json-out benchmarks/results/bgv_seeded_cuda_8192.json
```

All ciphertexts within each run share the selected modulus. `--rns-modulus`
requires newly generated keys/index; it is not a reinterpretation of the old
prime-modulus ciphertexts. Native byte counts describe cached NTT storage,
while wire counts describe coefficient framing. `server_s` includes native
conversions and synchronized GPU evaluation; `server_compact_s` separately
charges terminal reduction. `local_phases_s` excludes wire parsing, network,
attestation and setup. Seeded query creation includes its packet encoding;
`server_query_expand_s` charges seed expansion.

Run this matrix without simultaneous tests, compilers or other benchmarks.
To inspect the earlier single-prime experiment, omit `--rns-modulus`, select
only Python/native variants and use `--q-bits 96`.

### Public pipeline ablations and concurrent requests

`NativeServer(..., device="cuda", residue=True, cuda_level=...)` preserves the
original baseline as level 0. The explicitly selected research variants are:

| Level | Change from the preceding experiment |
| --- | --- |
| 0 | Original coefficient/RNS CUDA evaluator |
| 1 | Transform the query on the GPU |
| 2 | Fuse butterfly sum/difference, permutation and gadget decomposition |
| 3 | Share evaluation-key reads across eight ciphertexts and both components |
| 4 | Gather with the inverse automorphism; coalesce gadget writes; fuse final addition and use two alternating work buffers |

Level 2 retains the initial scattered-write fusion for comparison. Level 4
replaces it: fewer kernel launches alone need not improve memory traffic.
All levels use identical keys, parameters, rounding and output coefficients.
`search_compact(..., bits=32)` runs exact public terminal reduction in C++ before
exporting; `compact_result()` exposes the same reduction for differential checks.
The Python bound check still runs before native evaluation. Neither interface
authenticates a response or introduces private-key operations in the server.

```bash
.venv/bin/python benchmarks/bgv_public_pipeline.py --num-vectors 8192 --repeats 10 \
  --concurrency-repeats 10 --json-out benchmarks/results/bgv_public_pipeline_8192.json
.venv/bin/python benchmarks/bgv_public_pipeline.py --num-vectors 32768 --repeats 10 \
  --variants baseline tiled gather gather-native-compact \
  --json-out benchmarks/results/bgv_public_pipeline_32768.json
```

The pipeline benchmark uses fresh seeded owner queries. It compares entire
full and compact ciphertexts, checks the CPU oracle on warmup, and verifies
every distance and stable top-three result. Native compaction is included in
`server_evaluate_s` for the `*-native-compact` variants; compare the common
`server_evaluate_and_compact_s` column across all variants. One warmup is
excluded and variant order is shuffled. Wire bytes and parameters are unchanged.

Optional concurrency trials submit the **same four distinct fresh requests**
to one, two and four worker threads in shuffled order. Each worker owns its
stream/workspace and shares the immutable encrypted index and evaluation keys.
This is concurrent service, not a fused multi-query kernel. The report separates
fresh query creation and client verification from server batch throughput.
Service times include host scheduling/GIL contention and device synchronization;
they are not interactive network latency. The experiment caps concurrent
coefficient workspace at 4 GiB. See `benchmarks/bgv_request_throughput.py`.

The separate terminal-precision sweep compares 24, 25, 26, 28 and 32 bits
under the **same** Q120 keys and encrypted index. It verifies every plaintext
coefficient before/after reduction and records bound refusals without decrypting
unsafe results. Its smallest passing size is specific to the ring, t, secret
distribution and public circuit bound; this is not a general parameter policy.

```bash
.venv/bin/python benchmarks/bgv_terminal_sweep.py --num-vectors 8192 --repeats 10 \
  --json-out benchmarks/results/bgv_terminal_precision_8192.json
```

## Fresh owner arithmetic

The owner experiments keep the seeded-query bytes, error distribution, Q120
evaluation parameters, ciphertext algebra and public server unchanged. Bulk
sampling uses new independent OS randomness on every call. The multiplication
identity `a*s = a*(s+J) - a*J`, for `J=1+X+...+X^(N-1)`, packs shifted secret
coefficients in `{0,1,2}` and computes `a*J` by public prefix sums. A public
worst-case coefficient width prevents carries in the GMP integer product.
The cache contains only reusable secret representations, never one-use masks.

```bash
make -C experiments/bfv_search_lab/_owner PYTHON="$PWD/.venv/bin/python" CXX=g++-12
.venv/bin/python -m pytest experiments/bfv_search_lab/test_owner_bgv.py \
  experiments/bfv_search_lab/test_native_owner_bgv.py \
  experiments/bfv_search_lab/test_seeded_bgv.py -q
.venv/bin/python benchmarks/bgv_owner_pipeline.py --num-vectors 8192 --repeats 10 \
  --json-out benchmarks/results/bgv_owner_pipeline_8192.json
.venv/bin/python benchmarks/bgv_owner_pipeline.py --num-vectors 32768 --repeats 10 \
  --json-out benchmarks/results/bgv_owner_pipeline_32768.json
```

Build the public CPU and CUDA `_native/` modules too, as described above. The
benchmark compares reference, bulk, Python/GMP ternary and C++/GMP native owner
paths under the same level-4 CUDA evaluator and explicit 25-bit terminal format.
Each variant receives a fresh encryption of the same plaintext query in each
shuffled round; ciphertexts therefore differ across variants. It checks every
distance/top-three and every returned plaintext coefficient against the original
decryption, plus exact CPU/CUDA ciphertext equality on warmup. Setup, including
the secret representation cache, is separate; no refill or randomness work is
omitted from recurring query times. Response parsing, transport, authentication
and concurrent load are outside this local phase-sum measurement.

`OwnerClient(pk, sk, native=True)` explicitly selects the optional backend.
The native extension is private and is never imported by the public evaluator.
Owner calls serialize under locks; inherited instances refuse work after fork;
copying/pickling is blocked; `close()` drops references. These controls are not
secure erasure or a constant-time guarantee. Python/GMP and native GMP arithmetic
remain variable-time. Use only local trusted fixtures: this helper does not
authenticate remote responses or connect the research BGV circuit to Nitro.

For address/undefined-behavior checks, build `_owner/bindings.cpp` separately
with `-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer`, preload GCC's
`libasan.so` and `libstdc++.so.6`, and load that extension under its qualified
module name before running the three test files above. Set
`PYCRYPTODOME_DISABLE_DEEPBIND=1` for the sanitizer harness so its CFFI loader
does not bypass ASan; `ASAN_OPTIONS=detect_leaks=0:abort_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1` keep address/UB checking enabled. This does not
instrument GMP/Python themselves and does not check leakage or secret erasure.

## Independent SEAL BGV oracle

TenSEAL 0.3.16's low-level wrapper exposes BFV/CKKS but not BGV. Build this
optional oracle against the official pinned SEAL release in a temporary tree:

```bash
git clone --depth 1 --branch v4.1.2 https://github.com/microsoft/SEAL.git /tmp/cuhepy-research-SEAL-4.1.2
cmake -S /tmp/cuhepy-research-SEAL-4.1.2 -B /tmp/cuhepy-research-SEAL-4.1.2/build \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=g++-12 \
  -DSEAL_BUILD_DEPS=OFF -DSEAL_USE_MSGSL=OFF -DSEAL_USE_ZLIB=OFF \
  -DSEAL_USE_ZSTD=OFF -DSEAL_BUILD_EXAMPLES=OFF -DSEAL_BUILD_TESTS=OFF
cmake --build /tmp/cuhepy-research-SEAL-4.1.2/build -j2
g++-12 -O3 -std=c++17 experiments/bfv_search_lab/seal_bgv_oracle.cpp \
  -I/tmp/cuhepy-research-SEAL-4.1.2/native/src \
  -I/tmp/cuhepy-research-SEAL-4.1.2/build/native/src \
  /tmp/cuhepy-research-SEAL-4.1.2/build/lib/libseal-4.1.a -pthread \
  -o /tmp/cuhepy-seal-bgv-oracle
CUHEPY_SEAL_BGV_ORACLE=/tmp/cuhepy-seal-bgv-oracle \
  .venv/bin/python -m pytest experiments/bfv_search_lab/test_seal_bgv_oracle.py -q
```

The oracle checks both circuits and every plaintext coefficient, including
tail and multi-response cases. Its SEAL parameters differ from our BGV keys,
so this validates the algebra/circuit, not our cryptographic security profile.

## Standalone CUDA arithmetic and memory checking

```bash
nvcc -O2 -lineinfo -std=c++17 -ccbin g++-12 \
  -gencode arch=compute_86,code=sm_86 -Isrc/cuhepy/bfv/_cpu_ext \
  experiments/bfv_search_lab/_native/sanitize_cuda.cu -lgmpxx -lgmp \
  -o /tmp/cuhepy-bgv-cuda-sanitizer
/tmp/cuhepy-bgv-cuda-sanitizer
compute-sanitizer --tool memcheck --error-exitcode 99 /tmp/cuhepy-bgv-cuda-sanitizer
```

The standalone oracle passes locally. The installed Compute Sanitizer 2022.4.1
cannot instrument it on this machine (exit 255 before the first API call),
including retries with the injection path and `--target-processes all`.
This command is provided for a working sanitizer environment, not as a claim
that GPU memory checking passed here.
