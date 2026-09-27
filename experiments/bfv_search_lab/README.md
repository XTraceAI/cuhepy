# BFV search research sandbox

The [current research priorities](../../docs/research/creative-experiment-priorities.md)
favor creative algebra, algorithms and protocols before further routine tuning
or completing the existing verifier. E20/E21 and the revised E17/E19/E14 cards
are proposals, not implemented results or established novel contributions.

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
The [result/batch follow-up](../../docs/research/bgv-finish-batch-results.md)
records client lookup/selection and distinct-query CUDA batching experiments,
including comparisons where the existing threaded server wins.
The [compute follow-up](../../docs/research/bgv-compute-followup.md) adds NTT
schedule choices, exact GPU terminal rounding and an unchanged-format packed
server/client path. Select `ntt_variant` explicitly on `NativeServer`, and
`gpu_terminal=True` on a workspace call; existing defaults remain the reference.
The [E15 support-bound experiment](../../docs/research/bgv-support-bounds.md)
adds a separately selected deterministic bound, symbolic support tests, and
paired precision/transport measurements. The
[E13/E14 verification inventory](../../docs/research/bgv-verification-relations.md)
starts with arithmetic oracles and a trusted-boundary cost model, not a complete
proof system or GPU authentication protocol.
The [E16 radix experiment](../../docs/research/bgv-radix-results.md) implements
balanced and direct-distance packing with independent scalar/vectorized
decoders, and measures client/server/traffic tradeoffs. The
[E13 boundary experiment](../../docs/research/bgv-digit-boundary-results.md)
measures exact CRT/digit work and four host/GPU transfer layouts; it does not
authorize GPU responses.
The [joint layout report](../../docs/research/bgv-layout-planning.md) measures
all radix/precision choices and includes fresh setup, directional links and
index-epoch projections. The
[checked-switch follow-up](../../docs/research/bgv-checked-switch.md) adds
independent reference and C++/RNS checks for one complete arithmetic stage.
Its inputs must already be trusted; it does not authorize full GPU searches.
The [bound product/switch experiment](../../docs/research/bgv-checked-product.md)
now establishes the tensor relation from pinned query/index inputs. It compares
a c2 witness with local c2 computation, and measures direct-RNS checked GPU
execution against native recomputation. This still covers the initial
subcircuit, before butterfly reduction and terminal output.

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
| `support_bounds_bgv.py` | Opt-in whole-polynomial support bound for the same joint native circuit |
| `verification_oracles.py` | Toy field checks, exact integer relations and internal-traffic model; no authorization API |
| `radix_bgv.py`, `radix_client_bgv.py` | Separate radix index layout, precision plans and gated local-fixture decoder; scalar and packed/vectorized paths |
| `radix_planner.py` | Explicit ranking of measured layout/precision/setup choices; no parameter approval or online routing |
| `checked_switch_bgv.py` | One-use batched key-switch stage check with trusted input binding and fresh post-output weights |
| `checked_product_bgv.py`, `_verify/product.h` | Bound product/switch composition, c2-witness/local-c2 variants and matched native recomputation |
| `native_check_bgv.py`, `_verify/` | Optional homemade public C++/RNS/NTT check arithmetic; wrapper supplies required sampling/lifecycle |
| `NativeServer.product_switch_rns`, `_native/sanitize_product.cu` | Explicit bounded CUDA product stage with direct RNS export; independent standalone sanitizer oracle |
| `_native/digit_boundary.h`, `_native/digit_boundary.cu`, `_native/test_digit_boundary.cpp` | Public CRT/digit conversion, standalone CPU/GPU boundary benchmark and host sanitizer oracle |
| `native_bgv.py`, `_native/` | Isolated C++/RNS/CUDA evaluators with resident public keys/index |
| `_native/compact.h` | Exact terminal reduction in C++, before exporting the small result |
| `compact_bgv.py` | Congruence-preserving terminal modulus reduction and its correctness bound |
| `seeded_bgv.py` | Fresh owner-encrypted query; server regenerates the uniform component |
| `owner_bgv.py` | Bulk fresh sampling, identical public stream decoding, shifted-ternary multiplication and local owner |
| `native_owner_bgv.py`, `_owner/` | Separate optional private C++/GMP arithmetic; no SEAL/CUDA dependency |
| `results_bgv.py`, `_owner/finish.h` | Exact local distance lookup, stable heap top-k and fused native finishing |
| `_native/cuda_batch.cuh` | Distinct-query tensor/butterfly kernels; public keys and index shared within a batch |
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

The separate `_verify/` extension accelerates public stage checking. It loads
no HE secret and does not change the private backend. Low-level
`check_arithmetic` accepts weights for differential testing; caller-selected
weights do not establish sound verification. Use `context.begin(...,
native=NativeCheckArithmetic(context)).check_once(packet)` only for the bounded
stage statement described in the report, never as a full-search acceptance gate.
`ProductContext.prepare(...)` and its `begin(...).check_once(...)` wrapper also
bind multiplication to trusted index/query bytes. Registered inputs and global
coverage are obligations of the caller; its result is not an owner receipt.

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

Build the optional stage-check backend before its native tests or benchmark:

```bash
make -C experiments/bfv_search_lab/_verify PYTHON="$PWD/.venv/bin/python" CXX=g++-12
.venv/bin/python -m pytest experiments/bfv_search_lab/test_checked_switch_bgv.py \
  experiments/bfv_search_lab/test_native_checked_switch_bgv.py -q
.venv/bin/python benchmarks/bgv_checked_switch.py --ring-degree 16384 \
  --batches 1 8 32 --repeats 5 --native --json-out /tmp/bgv-checked-switch.json
.venv/bin/python benchmarks/bgv_checked_product.py --ring-degree 16384 \
  --batches 1 8 32 64 --repeats 10 --cuda --rns-cuda \
  --json-out /tmp/bgv-checked-product.json
.venv/bin/python benchmarks/bgv_layout_report.py \
  benchmarks/results/bgv_radix_all_precision_32768.json \
  --json-out /tmp/bgv-layout-planner.json
```

The stage benchmark measures trusted-input parsing, fresh sampling and the
complete check. Fixture byte packing, server-result construction and key setup
are recorded separately; transport and establishing the trusted tensor are
excluded. The layout report consumes measured data and needs no GPU. Reproduce
its inputs using the commands in the
[layout report](../../docs/research/bgv-layout-planning.md).
The product benchmark measures both verifier partitions, native recomputation
and actual checked CUDA subcircuits. Its direct-RNS path needs the rebuilt CUDA
extension and includes transient allocation and host-device copies. Padded=1
isolates multiplication/relinearization; these are ciphertext-tile timings,
not complete Hamming-search timings or measured enclave performance.

The `bfv_search_lab.py` benchmark reuses one index/key set across all CUDA/query variants,
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

## Result handling and distinct-query GPU batches

`OwnerClient.finish(response, count, dimension)` explicitly uses the native owner
to decrypt, decode and select top results without exporting intermediate plaintext
polynomials to Python. It returns `SearchResult(top, distances)`, where each top
entry is `(original_index, distance)`, ordered by distance then index. Set
`all_distances=False` to return only the top entries locally; **encrypted response
bytes stay unchanged**. The Python `sort`, `heap` and `lookup` methods remain
available as explicit ablations. Native finishing requires a native owner.

For the trace layout, residue `D*(dimension-2*distance) mod t` identifies a
distance exactly. The public table contains only valid distance residues;
invalid correlations still reject, even after enough top results have been
found. The native path uses modular arithmetic above the 65,536-entry table cap.
Top-k uses O(count log k) work with stable ties and a bounded k<=64. All distances
are checked whether or not the caller requests their return. These are local
plaintext optimizations, without a new privacy or authentication claim.

`NativeServer.search_many_compact(queries, index, batch_size=4, shared_index=True,
bits=25)` evaluates distinct queries against one immutable public context/index.
It requires CUDA level 4 and the joint circuit. The original `search_compact`
remains unchanged. `search_many` returns the full-Q results for arithmetic tests.
Each call accepts at most 32 queries, uses waves of 1..8, and refuses more than
4 GiB of coefficient scratch before device allocation. Call
`batch_workspace_bytes(index, wave_size)` to inspect that allocation count;
it excludes the index, keys, host buffers and CUDA runtime. The cap is per call,
so a deployment scheduler must separately account for concurrent calls.

The batch kernels transform queries together and keep each query's butterfly
separate. The optional tensor kernel broadcasts an index strip to query warps.
Existing tiled key products can share key reads across queries at smaller trace
stages. Scratch is private to each call and reused across its waves/result groups.
The batch returns once the entire call is complete; it does not stream early
responses or include a scheduler for waiting on arriving requests.

```bash
make -C experiments/bfv_search_lab/_owner PYTHON="$PWD/.venv/bin/python" CXX=g++-12
make -C experiments/bfv_search_lab/_native PYTHON="$PWD/.venv/bin/python" CXX=g++-12
make -C experiments/bfv_search_lab/_native cuda PYTHON="$PWD/.venv/bin/python" CUDA_CXX=g++-12 CUDA_ARCH=86
CUHEPY_REQUIRE_BGV_CUDA=1 .venv/bin/python -m pytest \
  experiments/bfv_search_lab/test_results_bgv.py experiments/bfv_search_lab/test_cuda_batch_bgv.py -q
.venv/bin/python benchmarks/bgv_finish_batch.py --num-vectors 8192 --repeats 10 \
  --json-out benchmarks/results/bgv_finish_batch_8192.json
.venv/bin/python benchmarks/bgv_finish_batch.py --num-vectors 32768 --repeats 10 \
  --json-out benchmarks/results/bgv_finish_batch_32768.json
```

Four fresh queries per round are shared across sequential calls, two/four host
workers, and native wave sizes one/two/four, with and without index broadcast.
Over-budget variants are recorded as skipped; the benchmark also checks the raw
native memory refusal on the real index when eight-query waves exceed the cap.
It shuffles variants, excludes one warmup, compares exact ciphertexts, and checks
all distances and stable top results. Batch throughput begins with expanded
queries ready and excludes batching wait, network, framing and authentication.
Completion times expose the latency cost of returning all batch results together.
Client finishing timings use the same response; their local phase sum adds the
first query's measured creation, expansion, serial evaluation and response packing.

## Persistent workspaces, private RNS and transport follow-up

The next experiments are described in
[`bgv-service-results.md`](../../docs/research/bgv-service-results.md). They
preserve the old arithmetic and interfaces as explicit baselines. No SEAL code
is imported by the new implementations.

```python
with server.prepare_workspace(prepared_index) as workspace:
    response = workspace.search_compact(encrypted_query, bits=25)
    # Further requests reuse this stream and scratch; each call returns alone.

client = owner_bgv.OwnerClient(pk, sk, native=True, rns=True)
```

One workspace serializes its own callers. Independent workspaces can overlap;
the application must budget their combined memory. The benchmark caps total
coefficient scratch at 4 GiB. Index/keys/runtime allocations are additional.
Workspace close waits for native use, and use after close/fork is refused.
Private RNS reuses our fixed-schedule NTT, but its GMP CRT and export remain
variable-time and its cache release does not promise secret erasure.

```bash
make -C experiments/bfv_search_lab/_native all cuda PYTHON="$PWD/.venv/bin/python" CXX=g++-12 CUDA_CXX=g++-12 CUDA_ARCH=86
make -C experiments/bfv_search_lab/_owner PYTHON="$PWD/.venv/bin/python" CXX=g++-12
.venv/bin/python benchmarks/bgv_service_pipeline.py --mode workspace --num-vectors 8192 --repeats 10 --json-out /tmp/workspace.json
.venv/bin/python benchmarks/bgv_service_pipeline.py --mode owner --num-vectors 8192 --repeats 20 --json-out /tmp/owner-rns.json
.venv/bin/python benchmarks/bgv_service_pipeline.py --mode transport --num-vectors 8192 --owner-rns --repeats 10 --json-out /tmp/transport.json
.venv/bin/python benchmarks/bgv_algorithm_portfolio.py --json-out /tmp/algorithms.json
.venv/bin/python benchmarks/bgv_scheme_comparison.py --num-vectors 8192 --repeats 5 --json-out /tmp/scheme-comparison.json
.venv/bin/python benchmarks/bgv_scheme_comparison.py --num-vectors 8192 --repeats 5 --variants paillier-lookup-hybrid --json-out /tmp/paillier-hybrid.json
```

The full comparison requires both Paillier CUDA extensions and the package BFV
extensions in addition to the research extensions. It uses the same corpus and
fresh query plaintexts across all eight variants, checks every distance and
stable top-3, and measures actual framing and both client phases. Its Paillier
CUDA variants use a GPU at the client too; the BFV/BGV clients run on the CPU.
Parameters and security assumptions differ across schemes. This is a trusted
local benchmark with setup and network transit excluded.
The optional hybrid uses the Paillier lookup GPU client with GMP server
multiplication. A separate invocation has the same corpus/distribution but
different later query plaintexts, because variant-order shuffling advances the
benchmark RNG; it is not part of the eight-way paired run.

The TCP harness binds only loopback, parses bounded frames against local context,
and compares each received ciphertext to its independently pinned local fixture
**before private decryption**. That excluded local evaluation is recorded as
setup; the equality gate is not a proof, TEE receipt or deployment protocol.
There is no decryption-dependent acknowledgement. The configured bandwidth and
RTT are application pacing, with no TCP loss/congestion/WAN emulation claim.

Profile separately from timing runs. Installed Nsight Systems 2022.4 captures
successfully but needs its importer invoked explicitly on this machine:

```bash
nsys profile --trace=cuda,nvtx --sample=none --cpuctxsw=none --capture-range=cudaProfilerApi --capture-range-end=stop --force-overwrite=true --output=/tmp/bgv-profile .venv/bin/python benchmarks/bgv_service_pipeline.py --mode profile --num-vectors 8192 --repeats 3 --json-out /tmp/profile-run.json
/usr/lib/nsight-systems/host-linux-x64/QdstrmImporter --input-file /tmp/bgv-profile.qdstrm --output-file /tmp/bgv-profile.nsys-rep
nsys stats --report gpukernsum,cudaapisum,nvtxsum --format csv /tmp/bgv-profile.nsys-rep
.venv/bin/python benchmarks/bgv_profile_summary.py --sqlite /tmp/bgv-profile.sqlite --json-out /tmp/profile-summary.json
```

Names above match the installed version; newer Nsight report names differ.
Nsight Compute counter access is currently refused (`ERR_NVGPUCTRPERM`); this
work did not alter the machine's system-wide counter policy. API waiting time
must not be interpreted as device-copy time or added to overlapping GPU work.

The narrow-limb study builds a standalone public arithmetic executable:

```bash
nvcc -O3 -std=c++17 -ccbin g++-12 -gencode arch=compute_86,code=sm_86 -Isrc/cuhepy/bfv/_cpu_ext experiments/bfv_search_lab/_native/narrow_ntt.cu -lgmpxx -lgmp -o /tmp/cuhepy-narrow-ntt
/tmp/cuhepy-narrow-ntt 16384 1024 20
/tmp/cuhepy-narrow-ntt 16384 1024 20 reverse
```

Each base has about 120 bits, but the products of its primes are different.
Both forward transforms and inverse round trips are checked against our CPU
oracle before timing. This measures NTTs only, without base conversion or a
full encryption parameter assessment; it is not a full narrow-limb BGV server.

## Rounded query communication experiment

[`compressed_query_bgv.py`](compressed_query_bgv.py) supplies a separate public
codec for existing fresh owner packets. It keeps the same ring, Q, secret and
public-seeded second component, but rounds c0 by bounded multiples of t. The
larger noise bound propagates through the existing evaluator and terminal
reduction. Precision must fit the whole circuit; query decryption alone is not
enough. See the [derivation and scope](../../docs/research/bgv-query-compression.md).

```python
from experiments.bfv_search_lab import compressed_query_bgv

fresh = client.encrypt(encoded_query)
packet = compressed_query_bgv.compress(fresh, pk, dropped_bits=56)
query = compressed_query_bgv.expand(packet, pk, dropped_bits=56)
response = workspace.search_compact(query, bits=25)  # Refuses excessive bounds.
```

The example is a trusted local fixture. It supplies no response authentication.
The optional benchmark index mode uses existing owner encryption with fresh
randomness per tile to obtain a smaller index noise bound; it requires owner
secret-key access during ingestion and a newly encrypted index.

The Python/GMP codec remains the default. Rebuild the lab `_native` extensions
and pass `backend="native"` to both `compress` and `expand` to use the homemade
C++/GMP public codec. Both implementations produce byte-identical packets and
ciphertexts. Add `--native-codec` below for a paired comparison that includes
both codecs and the original seeded-query baseline.

```bash
.venv/bin/python benchmarks/bgv_query_compression.py --num-vectors 8192 --repeats 10 --transport-repeats 5 --json-out /tmp/query-compression.json
```

## Compute and joint precision follow-up

The [compute and precision study](../../docs/research/bgv-compute-followup.md)
isolates NTT schedules, exact GPU terminal rounding, packed response handling,
and independent query/response coefficient compression. All are opt-in lab
paths with the previous kernels, CPU reduction and Python codecs retained.

```python
server = NativeServer(pk, keys, residue=True, device="cuda", cuda_level=4,
                      ntt_variant="indexed")
prepared = server.prepare_index(encrypted_index, count)
with server.prepare_workspace(prepared) as workspace:
    packet, bounds = workspace.search_packet(query, dimension, bits=25,
                                              gpu_terminal=True)
    # expected_packet must already be pinned by a trusted LOCAL fixture.
    result = client.finish_packed_fixture(packet, expected_packet, count,
                                          dimension, bits=25, bounds=bounds)
```

This preserves the compact-v1 bytes and private arithmetic. The fixture gate
requires a known complete expected response; it is not a remote verifier.
`compressed_response_bgv.py` adds a separate c0-only response codec, and
`joint_precision_bgv.py` enumerates admissible query/response precisions from
public bounds. The planner ranks transfer bytes; the benchmark includes codec
time and checks every distance before reporting performance.

```bash
.venv/bin/python benchmarks/bgv_pipeline_followup.py --num-vectors 8192 --repeats 10 --transport-repeats 5 --json-out /tmp/pipeline-8192.json
```

The native codec uses bounded unsigned-128-bit operations where both coefficient
widths are at most 120 bits and the retained GMP mapping otherwise. Explicit
`backend="native-gmp"` selects the prior mapping; Python remains the default.
Use `--mode joint --compare-codecs` in the benchmark to compare both native
arithmetic paths with identical packets and native response validation.

## BGV authentication and private terminal arithmetic

The separate [BGV authentication experiment](../../docs/research/bgv-authentication.md)
adds owner-authorized setup/queries and mandatory Nitro receipts before response
parsing or private work. Its [measured service](../bgv_nitro/README.md) computes
the complete CPU circuit once; it cannot sign an external GPU result. Existing
fixture/CUDA APIs retain their behavior and do not acquire authentication.

`private_bgv.py` and `_owner/bgv_private.h` supply a separate homemade fixed-work
terminal decoder with mandatory locked/wiped native buffers and packed input.
The optional `_owner` build now includes `_bgv_private` alongside `_bgv_owner`.
Key generation, query encryption and Python plaintext processing are outside the
new private-kernel scope; this is not a production or whole-client constant-time
claim. The report records the exact threat model, attack regression and checks.

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
BGV_SANITIZER=/tmp/cuhepy-sanitizer-12.9/cuda_sanitizer_api-linux-x86_64-12.9.79-archive/compute-sanitizer/compute-sanitizer
"$BGV_SANITIZER" --tool memcheck --error-exitcode 99 /tmp/cuhepy-bgv-cuda-sanitizer
"$BGV_SANITIZER" --tool racecheck --error-exitcode 99 /tmp/cuhepy-bgv-cuda-sanitizer
```

The older system Compute Sanitizer 2022.4.1 fails before the first instrumented
API. The follow-up installed the official **12.9.79** redistributable under
`/tmp/cuhepy-sanitizer-12.9`, after verifying SHA-256 against NVIDIA's
`redistrib_12.9.1.json` manifest. That version passes **memcheck and racecheck**
on the standalone oracle, including persistent workspaces and batch kernels.
See the follow-up report for the exact coverage and logs. No system CUDA or
driver installation was replaced. Run sanitizer jobs separately from benchmarks.
The variable above names that temporary installation; on another machine set it
to the path of a compatible Compute Sanitizer executable.
