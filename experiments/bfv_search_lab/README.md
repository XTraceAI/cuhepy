# BFV search research sandbox

The [experiment plan](../../docs/research/bfv-search-experiment-plan.md) proposes
12 directions from the accepted BFV CUDA baseline. The first implemented batch
now includes encrypted CPU/CUDA partial sums, owner query preprocessing,
seeded queries, a native SIMD encoder, and a depth-one BGV-style alternative.
The [results report](../../docs/research/search-lab-first-results.md) records
measurements, unsuccessful tradeoffs, and the next experiments.

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
| `planner.py` | Capability-filtered ranking under a modeled network connection |
| `test_*.py` | Differential, boundary, lifecycle and algebra tests |

The small C++ hooks live with the existing backends in
[`src/cuhepy/bfv/_cpu_ext`](../../src/cuhepy/bfv/_cpu_ext) and
[`src/cuhepy/bfv/_gpu_ext`](../../src/cuhepy/bfv/_gpu_ext). Rebuild **both** from
this checkout; old binaries do not have the experimental factories. The
accepted `create_server` path defaults to one complete sum as before.

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
