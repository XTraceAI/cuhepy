# Fused NTT and exact RNS tensor scaling

The `residue` server now uses fused negacyclic transforms and exact RNS
scale-and-round. Existing product-Q keys and ciphertexts are compatible; the
arithmetic returns the same ciphertext coefficients as the previous kernels.
Rebuild the extension for **ABI 4**. The other backends and the Paillier and
SEAL examples remain available.

## Changes

`bfv_cpu_ext/rns_ntt.h` folds the negacyclic twist into stage roots and folds
inverse normalization into the last butterfly. It preserves the existing
bit-reversed spectrum, uses bounded lazy residues, and unrolls groups of four
butterflies. The implementation follows the transform organization discussed by
[Longa and Naehrig](https://eprint.iacr.org/2016/504.pdf) and inspected in
[SEAL 4.1.2's transform handler](https://github.com/microsoft/SEAL/blob/v4.1.2/native/src/seal/util/dwthandler.h).
No SEAL code is linked or called.

`bfv_cpu_ext/rns_scale.h` adds an independent exact RNS conversion plan. It
removes GMP reconstruction and division from the tensor scaling loop while
preserving our reference's signed rounding. This is related to the
[textbook's RNS BFV multiplication construction](https://fhetextbook.github.io/ApplyingRNSTechniquestoFHEOperations.html),
but retains our existing binary gadget and auxiliary-prime selection.

For each signed integer tensor coefficient z, write `z = Q*k + r`, with
`0 <= r < Q`. The desired result is exactly
`t*k + floor(t*r/Q + 1/2) mod Q`. The Q residues recover r. In an auxiliary
base B, compute `k = (z-r)/Q mod B`, then lift k with centered base conversion.
The constructor checks `B > 2*(floor(2*N*(Q-1)^2/Q)+1)`, so the quotient's sign
and value are unambiguous for every permitted tensor coefficient.

Base conversion uses `u_j = r_j*(M/p_j)^-1 mod p_j` and
`theta = sum(u_j/p_j)`. Integer fixed-point intervals certify the floor or
nearest-integer quotient. An interval that crosses a boundary invokes an exact
18-word integer comparison. Scaling splits each `t*u_j/p_j` into its integer
part and a bounded fraction before summing; increasing t does not amplify an
approximation error. There is no floating-point arithmetic. GMP is used for
public plan constants, incoming coefficients and final response conversion.

## Reproduce

```bash
make -C src/cuhepy/bfv/_cpu_ext PYTHON="$PWD/.venv/bin/python"
.venv/bin/python benchmarks/bfv_server.py --num-vectors 1024 \
  --rns-modulus --backends residue --residue-levels 0,1,2 --seal \
  --repeats 4 --native-profile --json-out /tmp/bfv-fused-1024.json
```

Level 0 retains the previous kernels, level 1 adds the fused transform, and
level 2 also adds RNS scaling. Level 2 is the `residue` default. The controls
are available through `BFVEvaluator(..., kernel_level=...)` for experiments;
they do not change serialized cryptographic parameters. All three receive the
same keys, encrypted query and index. Arithmetic context creation is now
reported separately under setup; cold search still includes lazy evaluation
key and mask preparation. This changes the cold measurement boundary relative
to older reports, but leaves the warm measurement boundary unchanged.

## Results

AMD Ryzen 7 5800X, GCC 13.3.0 `-O3`, Python 3.12.3, GMP 6.3.0,
TenSEAL 0.3.16. One CPU evaluation thread, N=8192, t=65537, 180-bit product Q,
30-bit gadget, eta=21, 50-bit response compaction. No simultaneous tests or
other benchmark jobs. Three warm samples follow one cold search; ordering
alternates. Profiles are separate additional searches.

| 1,024 vectors × 512 dimensions | First search (s) | Warm median (s) |
| --- | ---: | ---: |
| Previous residue kernels | 3.1222 | 2.7943 |
| Fused NTT only | 2.9633 | 2.6455 |
| Fused NTT + exact RNS scaling | 2.7570 | 2.4064 |
| Preserved SEAL prototype | 2.4590 | 2.4789 |

The complete change takes **13.9% less warm server time**, a **1.16x speedup**.
It is 2.9% faster than this SEAL prototype in this particular run; this small
gap is not a general claim of outperforming SEAL. SEAL uses different modulus
primes, key switching and a TC128 configuration. Our parameters have no
established equivalent security claim. The native timer excludes outer
MessagePack; SEAL includes its envelope and temporary-file binding I/O. Both
include ciphertext decoding, arithmetic, compaction and encoding, and exclude
key import, private encryption/decryption and network time.

For 32 vectors, warm medians are 0.08718 s (old), 0.08284 s (NTT only),
0.07628 s (both) and 0.07702 s (SEAL): 12.5% less time than the old kernels.
Cold times are 0.40162, 0.39037, 0.38269 and 0.08032 s respectively. Preparing
our public evaluation-key cache still dominates the small cold search.

All native output ciphertexts match exactly, and every backend returns all
1,024 correct distances. The response is 102,496 bytes; query plus response is
471,250 bytes. This optimization does not change the wire format or noise;
the observed minimum response noise budget is 26 bits, a correctness diagnostic
and not a cryptographic security level.

| Exclusive profile phase | Previous kernels (s) | Both optimizations (s) |
| --- | ---: | ---: |
| Forward + inverse NTT | 1.6556 | 1.5044 |
| Conversion to residues | 0.1385 | 0.0841 |
| GMP CRT reconstruction | 0.1828 (194 calls) | 0.0005 (2 calls) |
| GMP scale-and-round | 0.1678 (193 calls) | 0.0014 (1 call) |
| Exact RNS scale-and-round | 0 | 0.2152 (192 calls) |

The 192 tensor reconstructions disappear; only the two final response
components are reconstructed. Transform-table payload falls from 2,752,512
to 1,835,232 bytes. Key-cache payload stays 42,467,328 bytes, and the RNS scaling
constants add 1,824 bytes to the server plan. These are payload counts, not
peak process memory. NTTs still dominate the remaining cost.

Raw samples, complete phase profiles, exact parameters, environment and source/
binary hashes are in `benchmarks/results/native_bfv_fused_1024.json` and
`benchmarks/results/native_bfv_fused_32.json`. Fresh encryption changes key
JSON sizes slightly. Old benchmark artifacts are retained.

After the [security hardening](native-bfv-security.md), a fresh interleaved
1,024-vector run measured 2.7874 s (previous kernels), 2.4236 s (both
optimizations) and 2.4850 s (SEAL) as warm medians. The improvement remains
**13.1%**, with identical native ciphertexts and all distances correct.
`benchmarks/results/native_bfv_security_1024.json` records that final source
state and all samples. Public-key import, measured separately, took about
1.48 s with the stricter parser and the default ~86 MB bundle.

## Validation

The 118 BFV test cases pass, including exact ciphertext equality across the
three kernel levels for 60-, 180- and 480-bit Q. Standalone C++ oracles compare
the fused spectrum with the old transform through N=32768, and compare exact
scaling with GMP at all eight supported Q widths. Cases cover signed convolution
bounds, zero, maximal coefficients, half-integer rounding, large t and exact
CRT fallback decisions. The C++ suite and 33 native Python-binding tests also
pass AddressSanitizer and UndefinedBehaviorSanitizer. Lint and type checks pass.

These checks provide arithmetic and memory-safety evidence for the exercised
paths. They do not establish a security level, negligible decryption-failure
probability or production readiness.
