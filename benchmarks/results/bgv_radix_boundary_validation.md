# E16 radix / E13 digit-boundary validation

Implementation revisions:

- `2459649260a3dfd6a1c2cd17e2bea59dff01e268`: initial scalar radix experiments.
- `e77573bc4e99e890889f48f4444f029cac0ff2b7`: packed/vectorized client and first
  native/shared/tight-packing digit-boundary prototype.
- `1917f99e3c04ca3d96ffc3cb1a27c1d425e5bbd1`: aligned-word boundary variant.

All twelve new public JSON artifacts were checked for successful correctness
flags and the declared sample counts. Every tracked source digest in each
artifact matches its recorded commit. Ignored native binaries are identified
by their recorded SHA-256 rather than included in Git. Artifacts contain public
parameters, counts, timings and provenance, not secret keys or ciphertext dumps.

Benchmarks ran sequentially, separately from builds, tests and profilers. The
four full-size radix artifacts check every distance and stable top-three result.
The eight boundary artifacts check their complete native digit arrays and an
independent GMP reconstruction oracle. Initial boundary artifacts are retained
under `bgv_digit_boundary_v1_*.json`; follow-ups do not erase those results.

## Full regression suite

```bash
CUHEPY_REQUIRE_BGV_CUDA=1 CUHEPY_SEAL_BGV_ORACLE=/tmp/cuhepy-seal-bgv-oracle \
  .venv/bin/python -m pytest tests/ experiments/bfv/ experiments/bfv_search_lab/ -q
```

Exit 0: **955 passed, 1 skipped, 1 warning in 239.73 s** at `1917f99`.
The skip is the live AWS integration; the existing warning concerns the test
that checks refusal to use inherited private state after an actual fork.
[Full output](bgv_radix_boundary_full_tests.txt).

The focused radix suite passed 28 tests before the packed/vectorized timing
runs. The 19 verification-oracle tests passed after adding the aligned model.
The full run includes both. The SEAL executable is an independent test oracle;
the implementations and timings here use homemade arithmetic.

## Native boundary checks

The final standalone host harness was compiled with GCC 12, OpenMP,
`-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all`,
and exited 0 with all layouts/thread counts and the GMP oracle passing.
[Host output](bgv_digit_boundary_host_sanitizer.txt).

The final CUDA binary passed Compute Sanitizer **12.9** memcheck with
`--error-exitcode 1` at N=64, M=131, D=16, one timing round. All four layouts,
one/eight workers and full device output comparisons are exercised.
[Sanitizer output](bgv_digit_boundary_memcheck.txt) reports zero errors.

The system default sanitizer could not locate its injection library. The
successful run used:

```
/tmp/cuhepy-sanitizer-12.9/cuda_sanitizer_api-linux-x86_64-12.9.79-archive/compute-sanitizer/compute-sanitizer
```

Host sanitizer execution required running outside the sandbox's ptrace
restriction. No sanitizer diagnostics were suppressed. These checks cover the
new public transfer/conversion code; they are not a new private-side-channel
audit or evidence of real attested GPU execution.

## Static checks

All passed:

```bash
.venv/bin/ruff check src tests
.venv/bin/ruff check --config 'force-exclude=false' --config 'exclude=[]' \
  experiments/bfv_search_lab benchmarks/bgv_radix.py benchmarks/bgv_digit_boundary.py
.venv/bin/mypy src/cuhepy
git diff --check
```

Mypy checked 34 package source files; this is not a claim of strict typing for
the experimental modules. Real AWS deployment, independent parameter review
and a complete malicious-GPU verification protocol remain separate work.
