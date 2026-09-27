# E13: reference and native checks for batched BGV key switching

This follow-up moves beyond digit-conversion cost probes to one **complete
arithmetic subcircuit**: canonical relinearization of a batch of trusted input
tensors under a pinned public switching key. A homemade Python/GMP reference
and optional C++/RNS/NTT backend implement the same check. Neither authenticates
the complete search, runs in an enclave,
produce a receipt, or authorize private decryption.

The approach uses established randomized verification of batched linear maps.
[Slalom §3.2](https://arxiv.org/html/1806.03287v2#S3.SS2) discusses checking a
linear operation on a random combination of batch inputs. Our experiment
applies that identity **after trusted canonical BGV digit decomposition**.
It makes no novelty claim for randomized batching.

## Exact statement and why it covers the nonlinear part

Let `Q=p0*p1`, with the existing two 60-bit RNS primes, and
`R_p = F_p[X]/(X^N+1)`. Each already-trusted input tensor has components
`(c0_b,c1_b,c2_b)`. Let beta=2^30 and four public switching-key pairs be
`(K[j,0],K[j,1])`. The required output is:

```
C_b = canonical_CRT(c2_b mod p0, c2_b mod p1), 0 <= C_b < Q
d[b,j] = floor(C_b / beta^j) mod beta
y[b,k] = c[k]_b + sum_j d[b,j] * K[j,k]  (mod Q, X^N+1), k=0,1.
```

The verifier parses and validates **every** proposed output coefficient before
sampling weights. For each RNS prime, three independent repetitions sample a
uniform fresh vector alpha in `F_p^B`, then compute:

```
D[j] = sum_b alpha[b] * d[b,j]        (mod p)
Y[k] = sum_b alpha[b] * (y[b,k]-c[k]_b) (mod p)
check Y[k] == sum_j D[j] * K[j,k] in R_p, for BOTH whole polynomials.
```

Canonical CRT and decomposition happen inside the trusted reference, **before
folding the batch**. Decomposing a weighted sum of c2 instead is wrong: digit
carries make decomposition nonlinear. Digits from a GPU are never accepted as
evidence. The checker needs neither intermediate NTT traces nor GPU checksums;
it reads the complete input/output tensors and performs the combined products.

### Conditional statistical soundness

For a fixed incorrect canonical output in one prime, let E be the nonzero
`B × 2N` matrix of coefficient errors. The combined polynomial check misses
exactly when `alpha^T E=0`. If E has rank r≥1, the kernel has `p^(B-r)` elements,
so the miss probability is `p^-r <= p^-1`. Three independent repetitions give
at most `p^-3`. A forgery in just one RNS limb gets that limb's bound: do not
multiply the bounds of an honest limb and a corrupted limb.

Since the configured primes exceed 2^59, the conditional single-attempt bound
is below 2^-177. For J attempts a union bound is `J*min(p0,p1)^-3`; for example,
J≤2^40 gives less than 2^-137. These are **statistical checking bounds**, not HE
security estimates, deployment assurance or a complete protocol proof. They
assume trusted keys/input tensors, an immutable output fixed before sampling,
fresh uniform weights unpredictable until the output is fixed, and correct
checker execution. Context hashing
and the OS randomness source also have their usual computational assumptions.

No secret preprocessing pool is needed. All randomness and combined arithmetic
are performed online and charged. Unlike a reusable secret fingerprint, these
weights need not remain secret after the output is irrevocably fixed: learning
them then cannot change that attempt's immutable packet. Trusted memory, code
and fresh sampling remain essential. Post-output sampling simplifies the
protocol, but does not make its compute or trace-transfer costs small.

## Binding, parsing and lifecycle

[`checked_switch_bgv.py`](../../experiments/bfv_search_lab/checked_switch_bgv.py)
pins the registered key, ring/primes, batch size, exact input bytes, an opaque
32-byte parent-statement binding and a fresh nonce. Inputs and outputs use a
fixed-size little-endian RNS format; shapes, residue ranges and packet length
are checked. The public output header must match this request's statement
digest. The output packet and parsed tensors are immutable trusted-memory
copies, not a checksum supplied by the accelerator or a shared mutable buffer.

A request is consumed before any response validation. Rejected packets,
entropy failures and concurrent retries cannot reuse it. Copying and pickling
are refused; a process guard precedes acquiring the request lock after fork.
All arithmetic checks run even when an earlier mathematical check fails.
Neither weights nor secret seeds are returned or written to benchmark files.
Both implementations are variable-time and provide no memory-erasure or
side-channel assurance. They load no HE secret. This does not resolve the
separate assurance obligations of owner encryption, decryption or plaintext
processing.

The parent binding is an **input obligation**. This module does not establish
owner authorization, index coverage, an epoch, or the preceding tensor product.
A correct switch of a maliciously chosen tensor can pass. The same checker
also does not establish subsequent butterfly steps, terminal rounding or wire
compression. Only a complete, bound chain inside a trusted verifier could
eventually support the final pre-decryption receipt. Existing client gates and
Nitro execution policies are unchanged.

## Optional homemade native arithmetic

[`native_check_bgv.py`](../../experiments/bfv_search_lab/native_check_bgv.py)
adapts a separate
[`_verify/`](../../experiments/bfv_search_lab/_verify/) extension. It reuses our
existing public `PrimeNTT` arithmetic, not SEAL. The public switching key is
transformed once at setup. Exact unsigned-128-bit CRT reconstructs each c2,
followed by four 30-bit digits. Batched folds, NTTs and all coefficient
comparisons run in C++; the Python wrapper retains request binding, immutable
packets, post-output OS randomness and one-use lifecycle enforcement.

The native boundary independently validates sizes, canonical residues, prime
context and weight ranges. Batch size is at most 64 and `B*N <= 2^20`.
Accumulating 64 products of values below 2^60 stays below 2^126; the code uses
full unsigned-128-bit remainder for those sums. A word-quotient reduction would
be incorrect here. The four-product NTT accumulation has a smaller, separately
bounded quotient. Tests exercise maximum weights and canonical CRT boundaries.

`check_arithmetic` is deliberately a low-level arithmetic function accepting
weights. It is **not an authorization interface**: a regression demonstrates
that caller-supplied all-zero weights accept a corrupted result. Only the
one-use wrapper supplies the required fresh sampling order, and even its
result describes this stage alone.

## Tests and measurement scope

Independent schoolbook negacyclic arithmetic at small N supplies honest outputs
without relying on the checker's GMP product routine. Mutation tests change
every batch item, component and limb, as well as order, input, parent binding,
nonce, count, length and the last canonical residue. They check that malformed
packets are rejected before entropy is sampled and that every attempt is spent.
Concurrency, copying, serialization, entropy failure and fork-guard tests cover
lifecycle. Exhaustive 2×2 error matrices in fields 2, 3 and 5 confirm exactly
`p^-rank(E)` misses, and demonstrate why equal fixed weights permit cancellation.

The [CUDA regression](../../experiments/bfv_search_lab/test_cuda_checked_switch_bgv.py)
checks actual homemade GPU multiply/relinearize outputs at N=64, 2,048 and
16,384. It uses padded dimension one, so the native evaluator ends immediately
after relinearization. **CPU-computed trusted tensors are supplied to the
checker in this test**; this is not a claim that the checker independently
verifies a GPU-supplied tensor product. The decrypted outputs also agree with
the original three-component encrypted products.

[`bgv_checked_switch.py`](../../benchmarks/bgv_checked_switch.py) measures the
complete reference checker with fresh weights, full parse, canonical digits,
folding and combined products. It records key/context setup and input/result
framing separately. A full-Q Python/GMP recomputation is a separate arithmetic
control, **not the optimized native CPU server**. Check/control order is shuffled
after one excluded warmup; synthetic public tensors vary each round. The
original reference run has ten rounds; the paired native run has five.
All honest checks and deliberate corruptions must pass/fail as expected.
No expected-output equality gate is used inside the checker.

The fixture constructs an honest server result outside check timing and records
that cost. Inputs are assumed already trusted: establishing them, transport,
attestation, private decryption and the rest of search are excluded. These
measurements must not be advertised as verified-GPU end-to-end performance.

### Paired timings at N=16,384

Ryzen 5800X, GCC 12, Python 3.12.3, two 60-bit primes and four 30-bit digits.
The following medians use the **same tensors and output coefficients** in the
[paired native run](../../benchmarks/results/bgv_checked_switch_native_16384.json)
at source `99b55d1`; operation order is shuffled. Each checker uses independent
fresh challenges and its own request binding.

| Ciphertexts in batch | Full-Q GMP recomputation, arithmetic only | Reference checker + input binding | Native checker + input binding | Reference/native ratio |
|---:|---:|---:|---:|---:|
| 1 | 138.12 ms | 922.06 ms | **9.29 ms** | 99.3× |
| 8 | 1,109.23 ms | 1,426.67 ms | **23.15 ms** | 61.6× |
| 32 | 4,317.63 ms | 3,440.14 ms | **90.73 ms** | 37.9× |

The ratio compares two implementations of this checker, not checking versus
optimized native CPU recomputation. Native public-key preparation costs an
additional 8.80 ms once, following 36.78 ms to construct the reference context;
key generation and evaluation-key generation are also recorded separately.
All online native parsing, binding, fresh sampling, canonical digit conversion,
folding and products are included. Preparing the fixture's input/result byte
packets remains separate, as does construction of the honest server result.
For example, those Python packet adapters alone take 457.66/367.11 ms for the
32-ciphertext input/result. A native service would need to emit and consume
this format directly; the table does not silently count these adapters as free
end-to-end work.

| Batch | Already-trusted input bytes | Proposed output bytes, including stage header |
|---:|---:|---:|
| 1 | 786,432 | 524,347 |
| 8 | 6,291,456 | 4,194,363 |
| 32 | 25,165,824 | 16,777,275 |

This is internal stage traffic, not the small final owner response. Its size
is a substantial obstacle to a complete checked search. The earlier
[ten-round reference run](../../benchmarks/results/bgv_checked_switch_reference_16384.json)
is retained: complete reference checking cost 887.80/1,392.81/3,610.25 ms for
these batches. Those are separate-run observations, not a paired native ablation.
Five local rounds support an initial implementation comparison, not a latency
distribution or cloud-performance claim.

The native tests use independent schoolbook outputs, reference/native
differentials, B=64, large accumulators and malformed constructor/ABI inputs.
The CUDA tests check both implementations. The instrumented native extension
passes **53 ASan/UBSan tests**; see the
[log](../../benchmarks/results/bgv_checked_switch_asan.txt) and
[validation record](../../benchmarks/results/bgv_layout_checked_validation.md).
Python/GMP themselves are not instrumented; leak checking is disabled for the
CPython harness. The unmodified GPU kernels are exercised by regression tests.

```bash
make -C experiments/bfv_search_lab/_verify PYTHON="$PWD/.venv/bin/python" CXX=g++-12
CUHEPY_REQUIRE_BGV_CUDA=1 .venv/bin/python -m pytest \
  experiments/bfv_search_lab/test_checked_switch_bgv.py \
  experiments/bfv_search_lab/test_native_checked_switch_bgv.py \
  experiments/bfv_search_lab/test_cuda_checked_switch_bgv.py -q
.venv/bin/python benchmarks/bgv_checked_switch.py --ring-degree 16384 \
  --batches 1 8 32 --repeats 10 \
  --json-out benchmarks/results/bgv_checked_switch_reference_16384.json
.venv/bin/python benchmarks/bgv_checked_switch.py --ring-degree 16384 \
  --batches 1 8 32 --repeats 5 --native \
  --json-out benchmarks/results/bgv_checked_switch_native_16384.json
```

The next algebraic boundary is the **preceding fixed-index tensor product**.
Its three components are linear in the query for a pinned encrypted index;
a separate batch check could bind an untrusted tensor to that input. Complete
verification still needs all subsequent transitions and final exact bytes.
Before implementing the whole chain, compare this checker with **matched native
CPU recomputation**, test composing adjacent checked stages, and account for
every intermediate crossing the boundary. In particular, simply shipping all
of these tensors through Nitro/vsock may erase the raw GPU benefit. A viable
partition must be measured before extending receipts or private-client APIs.
