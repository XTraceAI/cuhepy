# BFV precomputation and the CUDA public server

This experiment adds `server_backend="cuda"` to the packed Hamming application.
The reference, GMP, native C++, persistent-RNS CPU and original SEAL experiment
remain available. It changes neither BFV parameters nor the ciphertext format.
It is an experimental evaluator, not a production security approval.

## What carries over from Paillier?

| Candidate optimization | BFV assessment | Decision here |
| --- | --- | --- |
| Lookup tables | Reuse NTT roots, modular multiplication constants, transformed public evaluation keys and plaintext masks. These depend on public parameters/keys, not a particular query. | Upload and retain these tables once per server plan. The CPU already caches related tables. |
| Lookup of encrypted distances | Fresh encryption randomizes coefficients. A small table indexed by plaintext bits does not replace encrypted polynomial multiplication and key switching. A table that exposed query bits would change the privacy model. | Keep the existing encrypted arithmetic circuit. |
| Smaller polynomial ring degree `N` | Changes lattice parameters, SIMD capacity, rotation layout and the number of ciphertexts needed for a fixed corpus. It is not equivalent to shortening a Paillier exponent. | Keep `N` fixed within each CPU/GPU comparison. |
| Smaller coefficient modulus `Q` | Fewer RNS primes can reduce work, but leave less room for BFV noise and scale-and-round. Requires a new correctness bound and parameter review for the entire circuit. | Preserve the three-prime, 180-bit modulus. |
| Smaller terminal response modulus | Already used: compact the response after evaluation. It reduces download bytes but does not accelerate earlier operations at the original modulus. | Retain the existing 50-bit terminal compaction. |
| CGBN | Useful for wide multiprecision arithmetic. Here each residue is below 2^60, even though `Q` is about 180 bits. | Use CUDA 64-bit words and high/low multiplication; no CGBN dependency. |

SEAL's [BFV evaluator](https://github.com/microsoft/SEAL/blob/main/native/src/seal/evaluator.cpp)
uses RNS bases and NTTs, and its [NTT implementation](https://github.com/microsoft/SEAL/blob/main/native/src/seal/util/ntt.cpp)
prepares reusable transform tables. These support the precomputation direction;
the implementation here ports this repository's existing exact arithmetic and
does not link or copy SEAL. NVIDIA documents the high-word operation in
[the CUDA integer API](https://docs.nvidia.com/cuda/libdevice-users-guide/__nv_umul64hi.html).
[CGBN](https://github.com/NVlabs/CGBN) targets cooperative multiprecision arithmetic;
it is unnecessary for our per-prime modular products. This does not imply that
all GPU 64-bit integer operations execute as one hardware instruction.

## Implementation

- `src/cuhepy/bfv/_gpu_ext/kernels.cuh`: canonical RNS arithmetic, batched
  negacyclic NTT, tensor square, exact scale-and-round, gadget decomposition,
  key switching, automorphisms and masks.
- `src/cuhepy/bfv/_gpu_ext/server.cuh`: immutable public tables and keys, bounded
  batches of 32 index tiles, CUDA buffer/stream ownership, and response packing.
- `src/cuhepy/bfv/_gpu_ext/bindings.cu`: builds the shared CPython validation
  boundary with the CUDA server factory. GPU and CPU server capsules have
  different names; unsupported parameters fail explicitly.
- `src/cuhepy/bfv/cuda.py`: the optional server wrapper and availability probe.
- `src/cuhepy/hamming/bfv.py`: public packed-search dispatch. Generic primitive
  helpers in `BFVEvaluator` still use CPU RNS arithmetic. Owner encryption and
  decryption remain CPU operations; `device="gpu"` is not supported for them.

Supported parameters are three 60-bit RNS primes, 30-bit gadget digits, plaintext
modulus below 2^30, and a padded vector dimension at most 512. Existing ring and
plaintext validation still applies. `N=8192` and `N=16384`, `t=65537`, `Q≈2^180`
are supported without changing keys or ciphertexts. Small rings in unit tests
are arithmetic fixtures and carry no security claim.

Tensor products use seven primes to preserve the exact signed integer
convolution. For `z=Q*k+r`, with `0<=r<Q`, the GPU recovers `r` in base Q and the
signed quotient `k` in an auxiliary four-prime base B. It then computes
`t*k + floor((t*r + floor(Q/2))/Q)` modulo Q. Mixed-radix reconstruction and
four-limb integer division avoid floating-point rounding. Public setup checks
the auxiliary-base bound. The key-switch and merge order matches the existing
CPU circuit, including incomplete response groups.

Per-prime arithmetic and the complete Hamming circuit run on the GPU. Wire
parsing, conversion to/from residues, and terminal response compaction still
run on CPU. Every search uploads the index; there is no mutable-object identity
cache or stale-index reuse. Immutable GPU keys/tables persist across queries.
Each call owns its scratch buffers and stream, and restores the caller's CUDA
device on exit. Errors propagate; requesting CUDA never silently selects CPU.

The largest group buffer holds at most `padded_dimension` tiles. Scratch uses
`86 * min(32, tile_count) * N` 64-bit words plus the group buffer, query, and
optional partial mask. Plan memory includes two words per transformed key
coefficient (value plus modular multiplication constant). There is no unbounded
per-index GPU cache. Concurrent callers each allocate their own scratch, so a
service must bound concurrency according to its VRAM budget.

## Build and use

Build both extensions with matching host C++ toolchains. CUDA 12.0 on the test
host supports GCC 12. `CUDA_ARCH=86` targets the RTX 3080; set the architecture
for the deployment GPU and use a toolkit-supported host compiler.

```bash
make -C src/cuhepy/bfv/_cpu_ext PYTHON="$PWD/.venv/bin/python" CXX=g++-12
make -C src/cuhepy/bfv/_gpu_ext PYTHON="$PWD/.venv/bin/python" CUDA_CXX=g++-12 CUDA_ARCH=86
```

Use an absolute `PYTHON` path when invoking `make -C` (for example,
`PYTHON="$PWD/.venv/bin/python"`). The extension is optional and built binaries
are ignored by git; a wheel containing it is tagged for the native platform.

```python
from cuhepy.hamming.bfv import BFVClient
from cuhepy.bfv.cuda import cuda_available

assert cuda_available()
server = BFVClient(
    embed_len=512,
    poly_modulus_degree=16384,
    rns_modulus=True,
    server_backend="cuda",
    skip_key_gen=True,
)
server.load_stringified_keys(
    owner_public_key_json, max_public_key_chars=authenticated_setup_key_size_limit
)
response = server.encode_hamming_server_packed(query, encrypted_index, vector_count)
```

This example is a public evaluator call, not an authenticated client/server
protocol. The N=16,384 JSON evaluation key is larger than the default import
limit; supply an explicit `max_public_key_chars` bound from your authenticated
setup policy (the benchmark uses the known length of its locally generated key). Import the owner's actual configuration when it differs from these
values. The server never needs the owner's secret key.

## Verification boundary

The malicious-server chosen-ciphertext problem still applies. An owner must not
expose private-key accept/reject behavior to unverified server responses. The
existing owner-controlled recomputation verifier remains a possible baseline.

`BFVAttestedServer` explicitly rejects `backend="cuda"` before setup processing.
The current enclave protocol establishes trust in its measured execution. Its
receipt cannot justify signing an arbitrary result returned by a host GPU.
AWS documents [Nitro's isolated CPU/memory environment](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html);
our conclusion is about this repository's measured service and protocol, not a
claim that every future AWS GPU attestation design is impossible. Integrating
GPU results requires a separately reviewed trust path, such as suitable GPU
attestation with a protected channel, cryptographic proofs, or trusted
recomputation. Private-key side channels and parameter assurance are unchanged.

## Validation and measurements

`tests/unit/test_bfv_cuda.py` compares exact ciphertexts against CPU residue and
GMP native evaluation, checks decrypted distances, tile/batch/response tails,
canonical coefficient extremes and randomized public inputs, concurrent reuse,
index replacement, malformed framing, unsupported parameters, and the explicit
Nitro rejection. These are regression checks, not a cryptographic review.

Final local validation: **356 BFV tests passed, 1 optional AWS test skipped**.
Ruff and mypy passed for the changed Python implementation. The standalone
`tests/unit/native/test_bfv_cuda.cu` test also passed exact CPU/GPU comparisons
at N=8, 16 and 256 with synthetic public keys and arbitrary canonical inputs.
The Python suite and benchmarks additionally exercise N=8192 and N=16384.

**Validation gap:** Compute Sanitizer 12.0 could not instrument either Python
or the standalone executable on this host. After supplying its installation
library paths, it still exited before the first instrumented API call with
`Target application terminated before first instrumented API call`. No GPU
memory-sanitizer success is claimed. Rerun memcheck (and racecheck for future
shared-memory kernels) on a working installation before deployment review.

The paired benchmark is the existing `benchmarks/bfv_server.py` with CUDA added:

```bash
PYTHONPATH=src .venv/bin/python benchmarks/bfv_server.py \
  --num-vectors 8192 --embed-len 512 --poly-modulus-degree 16384 \
  --rns-modulus --backends residue,cuda --repeats 4 \
  --json-out /tmp/bfv-cuda-8192-n16384.json
```

One cold and three warm searches per backend alternate execution order. Each
uses the same keys, index and encrypted query. Server timings include wire
conversion, arithmetic, compaction, allocations, transfers and synchronization;
they exclude owner encryption/decryption, outer MessagePack and network time.
Context creation and key import are reported separately. Cold search includes
lazy key preparation and GPU plan creation. The GPU reuploads the index even
for warm searches. Correctness checks run outside the timed interval.

### Recorded measurements

Hardware: AMD Ryzen 7 5800X and NVIDIA GeForce RTX 3080 (10 GiB), driver
580.173.02. CUDA 12.0, GCC 12.4.0, Python 3.12.3, GMP 6.3.0. Single CPU server
thread versus one GPU, without simultaneous benchmark/test/build jobs. Results
are local measurements, not cloud latency or a Paillier/SEAL comparison.

| Vectors × bits | Ring degree | CPU warm median | CUDA warm median | Server speedup | CPU first search | CUDA first search |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,024 × 512 | 16,384 | 2.526 s | 0.182 s | 13.9× | 3.192 s | 1.454 s |
| 8,192 × 512 | 16,384 | 20.191 s | 0.878 s | 23.0× | 20.812 s | 1.935 s |
| 8,192 × 512 | 8,192 | 19.299 s | 0.841 s | 23.0× | 19.806 s | 1.505 s |

For the 8,192-vector, N=16,384 run, both backends return the same 204,900-byte
response; the query is 737,394 bytes, giving 942,294 bytes combined in this
benchmark's MessagePack framing. This is raw evaluation without a TEE receipt.
The minimum measured terminal noise budget was 26 bits. Identical ciphertexts
mean this backend preserves the CPU result's noise and download size; it does
not provide an additional bandwidth reduction.

The N=16,384 GPU plan holds 174,328,768 bytes (166.25 MiB) of keys and tables,
in addition to host-side prepared keys and per-search scratch. For this batch
size and 8,192 vectors the scratch/group/query arrays account for about
537 MiB of device payload, excluding CUDA runtime overhead. Memory use is a
tradeoff for batching and constant-multiplier tables.

The separate `N=8192` engineering profile above is an arithmetic/performance
comparison, not a claim of equivalent security to `N=16384` or SEAL TC128.

The three raw runs are checked in under `benchmarks/results/bfv_cuda_*.json`,
including every sample, source/binary SHA-256 hashes, environment, setup costs,
packet sizes, exact prime values, and correctness outcomes. Across the runs,
24 searches checked 139,264 distances. All ciphertexts matched the CPU baseline.

### Next performance experiments

1. Profile kernel launches, GPU memory traffic and host wire-to-residue
   conversion separately, while retaining the complete-call timing above.
2. Fuse small NTT stages in shared memory and reuse scratch buffers with
   explicit synchronization/ownership; verify byte-for-byte compatibility.
3. Add an explicitly owned immutable GPU index snapshot if repeated-query
   workloads justify its VRAM footprint. Do not key a cache by Python object
   identity, because callers can mutate an index.
4. Evaluate smaller RNS primes or moduli only as separate parameter experiments
   with fresh keys, correctness bounds, security review and packing-aware IO
   measurements. Changing parameters is not needed for the gains reported here.
