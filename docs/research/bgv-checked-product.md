# E13: bound product/relinearization and direct RNS GPU output

This checkpoint closes the trusted-tensor gap of the
[key-switch stage experiment](bgv-checked-switch.md). The verifier now starts
with a pinned query, ordered encrypted-index block and public switching key.
It checks both multiplication and canonical relinearization. An optional
homemade GPU entry point batches that exact subcircuit and exports RNS words
directly. The reference, native recomputation control and earlier GPU path are
retained.

This is a **locally checked arithmetic subcircuit**, not a deployed TEE service
or complete verified Hamming search. Butterfly reduction, terminal rounding,
compression, global index coverage and the final owner receipt remain outside
the statement. No private-client acceptance gate or existing Nitro policy is
changed.

## Eliminate unnecessary witnesses algebraically

Let `A_b=(a0_b,a1_b)` be registered encrypted index tile b, and `x=(x0,x1)` the
pinned query. All products below are in the negacyclic ring modulo Q. Before
relinearization, the required tensor is:

```
c0_b = a0_b*x0
c1_b = a0_b*x1 + a1_b*x0
c2_b = a1_b*x1.
```

The previous checker needed all three components as trusted inputs. Here the
verifier does not receive c0 or c1: their linear contributions can be combined
with the switch relation. There are two modes:

- **Witness:** the accelerator supplies c2 and the two output components.
  The verifier checks c2 as well as the final components.
- **Local c2:** the verifier computes c2 itself from the resident encrypted
  index and query, so the accelerator sends only the two output components.

For each coefficient, let `z_b` be canonical CRT reconstruction of the two c2
residues, in `[0,Q)`, and let `d[b,j]` be its four base-2^30 digits. This
conversion is trusted and happens separately for every tile before folding.
For each RNS prime p and each of three independent repetitions, sample
`alpha_b` uniformly in `F_p`, **after the entire output/witness is fixed**.
Form the following whole-polynomial combinations:

```
A0 = sum_b alpha_b*a0_b;       A1 = sum_b alpha_b*a1_b
D_j = sum_b alpha_b*d[b,j];    Y_k = sum_b alpha_b*y[b,k]
Z = sum_b alpha_b*z_b          (RNS projection of the canonical c2).

Witness mode: Z == A1*x1
Both modes:   Y0 == A0*x0 + sum_j D_j*K[j,0]
              Y1 == A0*x1 + A1*x0 + sum_j D_j*K[j,1].
```

Both output components and every coefficient are checked in both primes. Native
code folds the already-transformed resident index: NTT is linear, so this is
the same relation. No GPU-provided checksum, unchecked NTT trace or sampled
output coefficient is substituted for a whole-polynomial check.

This uses established randomized verification of batch linear maps, as in
[Slalom §3.2](https://arxiv.org/html/1806.03287v2#S3.SS2). The witness-elimination
equations here are a specialization to our exact BGV circuit; this report makes
no novelty claim for Freivalds-style batching or linear-map composition.

### Conditional checking bound

Once the complete proposed witness/output is fixed, each tile has a fixed
residual for each of the three equations. For a wrong canonical result or
witness, at least one limb has a nonzero `B × 3N` error matrix E. Otherwise c2
is the unique correct CRT value and both outputs are the correct switch.
For one check, `alpha^T E=0` with probability `p^-rank(E) <= 1/p`.
Three independent repetitions give at most `p^-3`. The local-c2 mode uses a
`B × 2N` error matrix and the same bound. Checking multiple equations with the
same alpha does not multiply their probabilities; they are columns of one
matrix. An honest limb does not strengthen the corrupted limb's bound.

For the configured primes, the per-attempt conditional miss bound is below
2^-177. A J-attempt union bound is `J*min(p0,p1)^-3`. This assumes trusted
registered inputs/keys, immutable complete outputs, uniform independent
post-output challenges and correct verifier execution. It is a statistical
checking bound, not an HE security level, reviewed protocol proof or production
assurance. Challenges need only remain unpredictable until the output is fixed;
there is no reusable secret preprocessing pool.

## Binding and implementation

[`checked_product_bgv.py`](../../experiments/bfv_search_lab/checked_product_bgv.py)
contains the Python/GMP reference and one-use wrapper. Its prepared context binds
the exact ordered index bytes, count, existing switch-key context and opaque
parent index/epoch binding. Each attempt additionally binds mode, exact query,
parent statement and a fresh nonce. A single fixed-length packet contains the
statement digest, optional c2 and complete output. Every residue and the full
packet grammar are validated before challenge generation.

Malformed responses, rejection and entropy failures consume the attempt. Copy,
pickle and reuse are refused; the process guard precedes the request lock.
All mathematical comparisons are completed even after one fails. The wrapper
never reads an HE secret or emits a receipt. The low-level native arithmetic
accepts caller-supplied weights for tests and is **not an authorization API**;
all-zero weights deliberately demonstrate why the wrapper is necessary.

[`_verify/product.h`](../../experiments/bfv_search_lab/_verify/product.h) and
[`native_check_bgv.py`](../../experiments/bfv_search_lab/native_check_bgv.py)
implement the optional homemade C++ backend. Public index/key NTTs are resident;
the query is transformed once per invocation. Canonical CRT uses exact 128-bit
arithmetic. Folds stream each tile into 128-bit sums rather than making long
strided reads. At B≤64, products of residues below 2^60 sum below 2^126;
full 128-bit remainder is used. Six-product NTT accumulations have a separately
bounded word-size quotient. No SEAL code is linked.

The native recomputation control uses the same prepared index and key, one
query transform, and computes the complete deterministic output. It combines
c0/c1 with switching-key contributions in the NTT domain before inverse
transforms. It returns canonical RNS bytes directly, with no Python coefficient
round trip. This is a stronger baseline than comparing against Python/GMP
recomputation alone; the existing native server is also measured independently.

The new `NativeServer.product_switch_rns` uses the existing tensor, digit,
key-product and merge kernels in one batch and returns canonical RNS bytes.
It accepts only padded=1, CUDA level 4, N≤16,384 and 1–64 tiles, with an exact
immutable canonical RNS query. Context, shape and process guards run before
device work. It creates per-invocation scratch and includes all allocation,
ordinary host copies, upload, download and synchronization. Existing search
and compact-response entry points remain separate.

## Internal traffic

All counts below exclude the short stage header and query; N=16,384. Tiles are
**ciphertexts**, not logical vectors. These uncompressed internal outputs
precede search packing and are much larger than the final owner response.

| Ciphertext tiles | Full tensor + output | c2 witness + output | Local c2, output only |
|---:|---:|---:|---:|
| 1 | 1.25 MiB | 0.75 MiB | 0.50 MiB |
| 8 | 10 MiB | 6 MiB | 4 MiB |
| 32 | 40 MiB | 24 MiB | 16 MiB |
| 64 | 80 MiB | 48 MiB | 32 MiB |

Witness mode removes 40% and local-c2 mode removes 60% of the coefficient bytes
relative to a hypothetical full-tensor-plus-output boundary. This comparison
does not assert that the earlier conditional checker established its tensors
over such a channel. The new modes actually bind multiplication to the inputs.
The common query is another 0.5 MiB. The trusted resident raw index and native
index NTT each cost the same coefficient bytes as the output column; Python
objects, cached keys/roots and workspace allocations are additional.

## Measurement contract and retained negative result

[`bgv_checked_product.py`](../../benchmarks/bgv_checked_product.py) runs paired,
shuffled trials at N=16,384, t=1031 and Q120 on the Ryzen 5800X / RTX 3080.
The registered index consists of actual fresh BGV encryptions, and each round
uses a freshly encrypted query shared across all variants. Ten rounds follow
one excluded warmup at each B=1/8/32/64. Both complete output components are
compared with the existing CPU/CUDA implementation. Within the new checker,
acceptance uses only pinned inputs and the randomized relation; there is no
known-answer equality gate.

The [initial run](../../benchmarks/results/bgv_checked_product_16384.json) at
`dec0fe2` retained the existing padded=1 GPU path, which processes tiles one by
one and exports through CRT/GMP/Python. Its negative result motivated the new
direct RNS path:

| Tiles | Optimized native recomputation | Witness verifier | Local-c2 verifier | Existing GPU checked stage |
|---:|---:|---:|---:|---:|
| 1 | 3.51 ms | 12.50 ms | 11.09 ms | 33.70 ms |
| 8 | 24.36 ms | 20.32 ms | 20.52 ms | 163.00 ms |
| 32 | 93.85 ms | 49.22 ms | 51.78 ms | 610.43 ms |
| 64 | 205.87 ms | 108.40 ms | 129.42 ms | 1,322.08 ms |

Verifier columns include input binding, complete output parsing/hash, fresh
weights, trusted c2/CRT/digits and the checks. The GPU column also includes GPU
execution, its original export/conversion, response framing and verification.
At 32 tiles the Python-to-RNS adapter alone costs 371.81 ms. Raw GPU arithmetic
speed therefore does not establish an efficient checked stage.

Key/index setup and encryption, query creation/adaptation and construction of
honest fixtures for verifier-only timing are separately recorded. The actual
GPU-stage measurement includes generation of its output. All stage timings
start from the same already-pinned query representation. They exclude the
rest of search, owner decryption, registration, attestation and real enclave
transport.

The artifacts separately project ideal serial query/result transfers at
1/10/25/100 Gbps. The remaining-accelerator budget subtracts verifier and ideal
transfer cost from measured native recomputation; negative values are retained.
This is a feasibility projection, not a measured Nitro/vsock link. An ordinary
host output snapshot is measured separately and is not called enclave or DMA
performance.

### Direct RNS + batched GPU follow-up

The [paired follow-up](../../benchmarks/results/bgv_checked_product_rns_16384.json)
at `5077d39` includes the new path alongside the old path, verifier-only modes,
optimized native recomputation and existing CPU server. These comparisons use
the same queries within the new run; they do not use differences between runs
as an isolated ablation.

| Tiles | Optimized native recomputation | Existing GPU checked stage | Direct-RNS GPU checked stage | Native / direct-RNS checked |
|---:|---:|---:|---:|---:|
| 1 | **3.45 ms** | 33.02 ms | 11.74 ms | 0.29× |
| 8 | 23.12 ms | 155.88 ms | **22.40 ms** | 1.03× |
| 32 | 91.58 ms | 590.16 ms | **61.27 ms** | 1.49× |
| 64 | 197.97 ms | 1,219.00 ms | **155.85 ms** | 1.27× |

The single-ciphertext case loses and the eight-ciphertext case is near parity;
do not describe these as universal GPU wins. For 32 tiles, the direct-RNS
checked stage is 9.63× faster than the retained GPU checked path and 33.1%
faster than the optimized native recomputation control. For 64 tiles, it is
7.82× faster than the old path and 21.3% faster than the native control. These
are ten-round machine-specific medians, not tail-latency or deployment claims.

| Tiles | Direct-RNS server, including allocation/copies | Local-c2 check after response | Response framing |
|---:|---:|---:|---:|
| 1 | 0.88 ms | 10.55 ms | 0.04 ms |
| 8 | 2.84 ms | 18.92 ms | 0.23 ms |
| 32 | 9.69 ms | 49.21 ms | 2.12 ms |
| 64 | 37.77 ms | 104.97 ms | 3.85 ms |

The complete-stage column above also includes request binding. Independent
phase medians need not sum to the median complete stage. The measured change
combines **batching and direct RNS export**; it does not isolate their individual
contributions. GPU host-device copies, transient scratch allocation and output
copies are included. No extra enclave channel or live attestation is present.
The checker now dominates the 32-tile result, so another kernel speedup alone
has limited room to improve the complete checked stage.

The separate verifier-only modes cost 12.11/19.19/50.87/97.86 ms with a c2
witness and 10.81/19.14/49.18/113.45 ms with local c2 at B=1/8/32/64. Local c2
trades trusted compute for lower traffic; at 64 tiles it costs more CPU time.
No GPU witness-export path is timed here, so adding a GPU time to that witness
column would be a projection. The existing CPU search/export wrapper costs
14.57/74.04/287.40/580.18 ms; we deliberately compare gains against the faster
direct native control in the main table.

Setup is also real. At B=32, adapting the registered index to raw RNS costs
370.95 ms, binding it costs 116.73 ms, preparing its trusted NTT costs 23.78 ms,
and preparing the existing GPU index costs 211.13 ms. The raw index and trusted
NTT each occupy 16 MiB of coefficient storage. These are resident costs,
separate from measured online requests and from key/index encryption. For all
64 tiles, initial public-key encryption of the index costs 7.99 seconds.

The ideal-transfer model illustrates a deployment limit: at B=32, local-c2
query/output traffic alone takes 138.41 ms over a 1 Gbps serial link, exceeding
the measured 91.58 ms native recomputation before any verifier or accelerator
work. At 10 Gbps it takes 13.84 ms. These are additional hypothetical channel
costs, not replacements for the host-device copies already measured in the
GPU path. Actual Nitro/vsock integration must establish its own budget.

## Tests and reproduction

Independent small-ring schoolbook arithmetic supplies complete tensor/switch
truth. Tests mutate every output tile/component/limb and every c2 witness limb,
and include a correctly relinearized **wrong tensor** that passes the old
conditional switch check but fails the new composed relation. Other tests
change index order/contents, query, epoch, parent binding, nonce, mode, packet
length and canonical residue ranges, plus one-use/concurrency/fork guards.
Exhaustive small-field three-equation error matrices confirm the rank bound.

Native tests cover maximum batch/weights and oversized/malformed ABI inputs.
Actual CUDA outputs agree with reference/native checking and deterministic
native recomputation. Direct RNS tests cover tile counts 1/7/8/9/64, N up to
16,384, both RNS limbs, larger radix plaintext moduli and concurrent calls.
The expanded checker passes 134 ASan/UBSan tests; the direct-RNS standalone
CUDA oracle passes Compute Sanitizer with zero errors. Full validation and
commands are recorded in the
[validation artifact](../../benchmarks/results/bgv_checked_product_validation.md).

```bash
make -C experiments/bfv_search_lab/_verify PYTHON="$PWD/.venv/bin/python" CXX=g++-12
make -C experiments/bfv_search_lab/_native all cuda PYTHON="$PWD/.venv/bin/python" \
  CXX=g++-12 CUDA_CXX=g++-12 CUDA_ARCH=86
.venv/bin/python benchmarks/bgv_checked_product.py --ring-degree 16384 \
  --batches 1 8 32 64 --repeats 10 --cuda --rns-cuda \
  --json-out benchmarks/results/bgv_checked_product_rns_16384.json
```

Before calling this a verified search, compose the remaining butterfly/key
switches and terminal conversions with exact coverage and final-byte binding.
A whole index exceeding 64 tiles requires a bound block schedule; checking one
block says nothing about omitted blocks. Benchmark against matched CPU thread
budgets and charge resident memory, full internal transfers and real enclave
execution before extending owner receipts. Existing parameter/private-side
channel assurance obligations also remain separate.
