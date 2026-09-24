# BGV coefficient search: joint packing, persistent RNS and CUDA

2026-09-24, branch `research/bfv-search-lab`. This continues the
[first search-lab measurements](search-lab-first-results.md). The default BFV,
Paillier and authenticated clients are unchanged. These implementations live
under [experiments/bfv_search_lab](../../experiments/bfv_search_lab).

The [next public-pipeline report](bgv-public-pipeline-results.md) measures kernel
ablations, native compaction, larger indexes, concurrent requests and reduced
terminal precision. The measurements below remain the preceding baseline.

## What was implemented

1. Joint trace and coefficient packing using an automorphism butterfly.
2. A native public evaluator with immutable, cached index/key NTTs and a
   Python/GMP reference for each circuit.
3. Persistent RNS evaluation with a product of two 60-bit ciphertext primes.
   BGV multiplication uses those two primes directly, without BFV's wide
   integer multiplication followed by scale-and-round.
4. A separate CUDA evaluator for both the per-tile and butterfly circuits.
   It reuses cuhepy's modular arithmetic and fused NTT kernels, retains the
   encrypted index on the GPU, and uses private per-request workspaces.
5. Terminal BGV modulus reduction with an explicit worst-case rounding bound.
6. An independent BGV circuit oracle linked against official SEAL 4.1.2,
   commit `119dc32e135cb89c1062076a69310d4413ebc824`.
7. Fresh seeded owner queries: transmit one polynomial and a public seed,
   expand the uniform component on the server, and keep error sampling separate.

This is an adaptation and engineering experiment, **not a claim of a new
packing primitive**. The butterfly identity is established prior art in
Chen, Dai, Kim and Song,
[Efficient Homomorphic Conversion Between (Ring) LWE Ciphertexts](https://eprint.iacr.org/2020/015),
Algorithm 2. The underlying scheme and modulus reduction follow the
[BGV approach](https://eprint.iacr.org/2011/277). Trace analysis also has recent
prior art in [Algebraic Analysis of Homomorphic Trace Evaluation and Its Applications](https://eprint.iacr.org/2026/1604).

## Why the butterfly saves work

Let D be the padded vector dimension, N the ring degree, and
`g = 1 + 2*N/D`. Shift each encrypted correlation product so its desired
coefficients lie at multiples of D. Call the resulting polynomials `f_i`.
The desired dense result is

```text
sum_i X^i Trace_D(f_i).
```

The old circuit applies every trace automorphism to each input separately,
then shifts and adds the projected results. In the new circuit, stage j uses
`h = D/2^(j+1)` and `sigma = sigma_g^(2^j)` and combines two inputs as

```text
A + X^h B + sigma(A - X^h B).
```

Since `sigma(X^h) = -X^h`, this equals
`(1+sigma)A + X^h(1+sigma)B`. Earlier shifts are multiples of `2h` and are fixed
by this automorphism. Repeating the stages projects and interleaves the
messages together. Missing tail inputs are public zeros; they require no
encryption. The implementation never restricts the secret to a subring.

For 8,192 vectors of 512 bits at N=16,384, there are 256 input ciphertexts:

| Circuit | Relinearizations | Automorphisms | Total key switches |
| --- | ---: | ---: | ---: |
| Independent trace | 256 | 2,304 | 2,560 |
| Joint butterfly | 256 | 511 | 767 |

The reduction is workload-dependent. At 65 vectors (three input tiles),
the count changes only from 27 to 24 automorphisms. Extra additions/copies can
outweigh that small saving.

Bounds follow the actual circuit. If A and B have phase bounds a and b and
a key switch contributes at most E, a merge has bound `2*(a+b)+E`. Missing
inputs have bound zero. The implementation computes this schedule before
evaluation and refuses any bound at or above Q/2. These are public conservative
correctness bounds, **not security estimates or evidence that a server ran the
approved circuit**.

## Measured CPU and GPU results

Hardware: Ryzen 7 5800X, RTX 3080 10 GB, CUDA 12.0, GCC 12.4, GMP 6.3.0.
The full workload is 8,192 vectors of 512 bits, N=16,384, t=1,031, error eta=21
and 30-bit gadget digits. Each artifact records one excluded warmup and five
shuffled paired trials. All variants within an artifact share keys, encrypted
index and each fresh query. Every distance and stable top-three result is
checked. Setup is excluded from recurring timings and recorded separately.

The initial single-prime Q96 native experiment, before persistent RNS:

| Q96 native CPU circuit | Median evaluation |
| --- | ---: |
| Per-tile trace | 26,606.9 ms |
| Joint butterfly | 10,913.3 ms |

That is a **2.44x** circuit improvement. The 65-vector pilot separately showed
4,332.9 ms for Python/GMP per-tile trace versus 320.6 ms in C++ (13.5x).
The native butterfly was slightly slower at that size, 327.6 ms.
Artifacts: [65-vector pilot](../../benchmarks/results/butterfly_bgv_65.json),
[8,192-vector Q96 run](../../benchmarks/results/butterfly_bgv_8192.json).
Their measured implementations are available at `a529883` / `8d92082`.

The next experiment uses **fresh keys for Q=p0*p1 (120 bits)**, persistent RNS,
and a 32-bit terminal response. This is a different parameter configuration
from Q96; the paired CPU/CUDA comparisons below use identical parameters:

| Backend and circuit | Evaluation | Terminal compaction | Local measured phases |
| --- | ---: | ---: | ---: |
| RNS CPU, per-tile trace | 7,138.8 ms | 17.6 ms | 7,310.9 ms |
| RNS CPU, joint butterfly | 2,615.1 ms | 17.4 ms | 2,787.1 ms |
| CUDA, per-tile trace | 97.4 ms | 17.4 ms | 272.1 ms |
| CUDA, joint butterfly | **46.8 ms** | 18.2 ms | **225.7 ms** |

Joint packing is **2.08x faster on this GPU** than the same BGV per-tile circuit.
The RNS CPU versus CUDA butterfly comparison is **55.9x for evaluation**.
Neither ratio includes index preparation. Phase medians do not necessarily
sum to the median total.

The local phase sum includes query creation/packing, the native query/result
boundary, synchronized GPU evaluation, terminal compaction, response packing,
client decryption, distance decoding and stable top-three selection. It excludes
wire parsing, network, attestation, content retrieval and concurrency load.
It is not a production end-to-end latency measurement. The earlier BFV table
includes wire parsing and was measured in a separate run; cross-scheme timing
comparisons remain indicative, not paired or security-equivalent.

Raw data: [full Q120 CPU/CUDA run](../../benchmarks/results/bgv_rns_cuda_8192.json),
[Q120 Python/native/RNS/CUDA pilot](../../benchmarks/results/bgv_rns_cuda_65.json).
The initial RNS/CUDA implementation is available at `faf223a`; the final
artifacts measure `49c40db`, after the stream-ordering correction described below.
The full run includes **12 exact cross-backend ciphertext comparisons**;
the pilot compares Python, auxiliary-prime native, persistent-RNS and CUDA
outputs for the joint circuit.

## Communication and setup

For the full public-key Q120 run:

| Measurement | Actual bytes / time |
| --- | ---: |
| Query upload | 491,616 bytes |
| Response download, 32-bit terminal modulus | **131,164 bytes** |
| Query + response | **622,780 bytes** |
| Encrypted index (generic fixture framing) | 125,832,025 bytes |
| GPU index storage | 134,217,728 bytes (128 MiB) |
| Evaluation-key raw coefficients | 19,660,800 bytes |
| Owner key generation | 0.099 s |
| Evaluation-key generation | 2.941 s |
| Index encryption | 32.824 s |
| CUDA plan construction | 0.586 s |
| CUDA index preparation/upload | 1.813 s |

The evaluation-key number is a raw coefficient count, not a serialized setup
bundle. The GPU index uses NTT uint64 residues, so it differs from the index's
wire size. Keys and index are one-time per context/index version; query and
response recur per search. Index preparation computes its NTTs on the CPU,
uploads once, then releases the temporary host NTT index in the CUDA wrapper.

### Fresh seeded owner queries

The owner can encrypt `c0 = m + t*e - a*s`, `c1 = a`, sending only c0 and a
fresh 256-bit seed for a. The server regenerates a from a domain-separated
SHAKE256 stream with rejection sampling. The public seed never samples secret
error, and every encryption uses fresh randomness. There is no preprocessing
pool or uncharged refill. This requires the owner to hold the secret key;
the public-key query interface remains available.

A separate five-trial run with the same workload/parameters and fresh keys
gave the following results for the CUDA butterfly:

| Measurement | Public-key queries | Seeded owner queries |
| --- | ---: | ---: |
| Query upload | 491,616 bytes | **245,866 bytes** |
| Response download | 131,164 bytes | **131,164 bytes** |
| Query + response | 622,780 bytes | **377,030 bytes** |
| Query encryption | 124.4 ms | 59.4 ms (includes framing) |
| Server seed expansion | — | 8.0 ms |
| GPU evaluation with native boundary | 46.8 ms | 43.3 ms |
| Server terminal compaction | 18.2 ms | 17.4 ms |
| Client decryption | 20.2 ms | 20.1 ms |
| Local measured phases | 225.7 ms | **157.0 ms** |

Raw [seeded-query artifact](../../benchmarks/results/bgv_seeded_cuda_8192.json),
measured at `49c40db`, includes six exact CPU/GPU ciphertext comparisons.
Public versus seeded timings are from separate runs, not a paired
significance test. The byte reduction is **39.5%** relative to this BGV
public-key-query configuration. Relative to the earlier BFV seeded/partial
experiment's 573,677 bytes, it is **34.3% smaller**; parameter and protocol
assurance differ. No network or authenticated execution is included.

For orientation, the earlier BFV CUDA baseline response was 204,900 bytes;
this experiment's response is **36.0% smaller**. Its public-key query remains
larger than the earlier seeded BFV query. These sizes describe different
experimental contexts and do not establish equivalent security.

Terminal reduction chooses a prime P satisfying `P = Q (mod t)` and rounds
each `(P/Q)*c` to the nearest integer congruent to c modulo t. The new phase
bound is

```text
ceil(P*old_bound/Q) + ceil((N+1)*t/2).
```

The second term accounts for rounding both ciphertext components under a
ternary secret. The client removes the trace factor D only after decryption.
The experiment refuses P when this bound reaches P/2, checks every recovered
coefficient in small fixtures, and tests the scalar rounding identity
exhaustively on several toy moduli. It does not simply truncate coefficients.

## Validation and limitations

The independent SEAL oracle uses BGV, TC128 parameter validation, two 48-bit
data primes and a separate 48-bit key-switch prime. It tests both circuits
against independently constructed plaintext coefficient expectations,
including a two-response 16,385-vector fixture. SEAL's different keys, modulus
basis and key switching make it a circuit oracle; **its parameter validation
does not certify our parameters or implementation**. SEAL is not linked into
the homemade evaluators. The pinned TenSEAL wrapper exposes no BGV enum, so
the BGV oracle is a standalone SEAL C++ program.

Tests also cover arbitrary signed-polynomial identities, every small tail,
canonical coefficient extremes, multi-pass CUDA NTTs, concurrent requests,
wrong contexts/capsules, malformed buffers and conservative-bound refusal.

The broader suite exposed an intermittent upload race in the first CUDA
implementation. A pageable host-to-device `cudaMemcpy` can finish host staging
before its device transfer completes; a nonblocking stream has no dependency
on that default-stream copy. Query uploads now execute on their consumer
stream, and setup uploads explicitly complete before the plan/index is exposed.
A 32-fresh-query regression exercises warm allocations at N=2,048.
This ordering follows [NVIDIA's documented synchronization semantics](https://docs.nvidia.com/cuda/cuda-runtime-api/api-sync-behavior.html).
The full timings are refreshed after the correction.

CPU AddressSanitizer/UndefinedBehaviorSanitizer passed 29 focused tests using
the instrumented extension. The standalone CUDA oracle matches the CPU, but
the local Compute Sanitizer 2022.4.1 exits 255 before its first instrumented
API call, even with the injection library and `--target-processes all`.
**GPU memory-sanitizer validation remains uncompleted.**

After the ordering correction, the complete repository/lab suite passes
**493 tests with 10 skips**. Both BFV and BGV CUDA and the independent SEAL
oracle are enabled. The skips are nine unavailable Paillier CUDA-extension
tests and the real AWS Nitro integration test. Ruff and mypy pass, including
the explicitly checked experimental modules.

Private encryption/decryption still use variable-time Python/GMP. There is no
reviewed BGV security profile, authenticated BGV response protocol, GPU
attestation integration, or chosen-ciphertext security guarantee. A correct
noise bound is not permission to decrypt an adversarial response. The existing
BFV acceptance-oracle threat model still applies to an unauthenticated BGV
deployment. These are synthetic, owner-controlled experiments only.

## Next experiments justified by these results

- Measure narrower, possibly 32-bit RNS limbs. Three approximately 31-bit
  primes could reduce residue storage and use cheaper GPU arithmetic. Prove
  bounds for the exact selected primes and obtain parameter review first;
  fewer modulus bits alone is not a security certification.
- Fuse butterfly sum/difference formation with digit decomposition and final
  accumulation. The current CUDA circuit is batched and uses fused NTTs,
  but still writes several intermediate buffers.
- Batch independent queries to improve occupancy near the root of the packing
  tree, measuring throughput separately from single-query latency.
- Optimize owner query encryption and compact-response decoding with an
  explicit private-arithmetic design. Their cost now exceeds GPU evaluation.
- Bind the new circuit, parameters, index version and response format to a
  reviewed attested execution protocol before enabling any real-data client.

The [lab README](../../experiments/bfv_search_lab/README.md) contains build,
oracle, test and benchmark commands. Raw artifacts contain public parameters,
timings, byte counts and source/binary hashes; no keys or ciphertext dumps.
