# E16 joint layout planning / E13 complete stage-check validation

Implementation revisions:

- `2d840654f04e0e24d044f5008ecaa9b191990187`: all-precision radix measurements
  and initial layout/precision/setup planner.
- `bfa88569b8520a8f619e4e67044e81221ed20d17`: complete reference key-switch
  checker, lifecycle/algebra/CUDA tests and benchmark/report commands.
- `99b55d1e7de22b1407feb2dce729d309e6095f46`: optional homemade native checker,
  native differential/ABI/sanitizer tests, paired timing and setup-cache fix.

The [layout report](../../docs/research/bgv-layout-planning.md) and
[stage-check report](../../docs/research/bgv-checked-switch.md) state methods,
results, limitations and next decisions. Main/staging and baseline PR #14 at
`3c0a547` remain separate from `experiment/bgv-verification-packing`.

## Artifact checks

All six new JSON artifacts were reviewed for successful correctness flags,
declared sample counts and public contents. Every tracked source SHA-256
matches the recorded commit; every recorded native binary hash matches the
local binary. Binaries are not added to Git. Planner reports additionally bind
their exact measurement artifact by SHA-256.

| Artifact | Source | SHA-256 |
|---|---|---|
| [All precision, 8,192](bgv_radix_all_precision_8192.json) | `2d84065` | `58433b3d36429bf18f5f0a74aa8d20b42f51960f55e03fce583882f164dc4f82` |
| [All precision, 32,768](bgv_radix_all_precision_32768.json) | `2d84065` | `e8d9b736b41a0fc12af38857cbb3dfcf868bbb574ace0b2cf8f269f0748dab0b` |
| [Layout planner, 8,192](bgv_layout_planner_8192.json) | `99b55d1` | `842bead2936da0c805496faac2de005fe34856a3907ef36939cc8d4936ac6513` |
| [Layout planner, 32,768](bgv_layout_planner_32768.json) | `99b55d1` | `3b857ccbdbf7705a6c6a177c022939bf51f181b27fd90bdd3d4c9038d9eac871` |
| [Reference stage checker](bgv_checked_switch_reference_16384.json) | `bfa8856` | `0a435d0c98f111826bc397aff93e4d10a658e33a6fa937436c12de1756737653` |
| [Paired native/reference checker](bgv_checked_switch_native_16384.json) | `99b55d1` | `97717449054ada780a3f750fe11c8236872087f75f446c0153dafca32f8161ed` |

Each radix artifact has 12 choices, ten local/five transport samples for each,
one excluded warmup and checks of all distances and stable top-three results.
Each analytical planner report has 63 scenarios and three separate paced-link
comparisons. Stage-check batches are 1/8/32, with ten reference-only or five
paired rounds following one warmup. The benchmark checks honest outputs and a
reference corruption; native mutations are also covered by the tests below.

Benchmarks ran sequentially, separately from builds, profilers and test suites.
Artifacts contain public parameters, counts, timing samples, public fixture
seeds and provenance. They contain no HE keys, ciphertext/tensor dumps or
verifier weights. Weight counts and sampling durations are public metadata.
The native-versus-reference ratios use the paired artifact, not the earlier
reference-only run. Setup projections are explicitly representation-specific
floors; no new attested GPU service timing is claimed.

## Full regression suite

```bash
CUHEPY_REQUIRE_BGV_CUDA=1 CUHEPY_SEAL_BGV_ORACLE=/tmp/cuhepy-seal-bgv-oracle \
  .venv/bin/python -m pytest tests/ experiments/bfv/ experiments/bfv_search_lab/ -q
```

At `99b55d1`, exit 0: **1,029 passed, 1 skipped, 1 warning in 232.28 s**.
[Full output](bgv_layout_checked_full_tests.txt). The skip is live AWS
integration; the existing warning concerns the actual-fork private-state guard
test. The SEAL executable is an independent oracle; the new implementation and
benchmarks use homemade arithmetic. The optional native checker was built and
loaded; none of its tests were skipped.

New tests cover all batch items/components/limbs, canonical boundary residues,
ordering/input/header/context mutations, output-before-entropy ordering,
one-use rejection/retry/concurrency, serialization and fork guards. Small-field
exhaustion checks the batch-error rank/miss identity. Independent schoolbook
outputs and complete native/reference differentials exercise the arithmetic.
Actual homemade CUDA outputs pass both checkers at N=64/2,048/16,384 and the
larger radix plaintext moduli, with independently established CPU tensors.

## Native sanitizer checks

The release extension builds without warnings using GCC 12. The instrumented
extension is built separately; it does not overwrite the release binary:

```bash
mkdir -p /tmp/cuhepy-check-sanitize
g++-12 -O1 -g -std=c++17 -fPIC -shared -fsanitize=address,undefined \
  -fno-omit-frame-pointer -fno-sanitize-recover=all \
  -I/usr/include/python3.12 -Isrc/cuhepy/bfv/_cpu_ext \
  experiments/bfv_search_lab/_verify/bindings.cpp -lgmpxx -lgmp \
  -o /tmp/cuhepy-check-sanitize/_bgv_checked.cpython-312-x86_64-linux-gnu.so
LD_PRELOAD=/usr/lib/gcc/x86_64-linux-gnu/12/libasan.so:/usr/lib/x86_64-linux-gnu/libstdc++.so.6 \
  ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
  .venv/bin/python experiments/bfv_search_lab/_verify/run_sanitizers.py \
  /tmp/cuhepy-check-sanitize/_bgv_checked.cpython-312-x86_64-linux-gnu.so
```

Exit 0: **53 passed in 0.97 s**. [Output](bgv_checked_switch_asan.txt).
The loader asserts that the exact requested binary is used, with no release
fallback. Address/undefined-behavior checking is active; leak checking is
disabled for the CPython harness. Python and GMP are not themselves rebuilt
with instrumentation. Execution required leaving the sandbox's ptrace
restriction. The tests include batch 64, weights at p-1, sums exceeding 64-bit
quotients, malformed/oversized constructors and ABI inputs. A dedicated
regression shows that the arithmetic API with attacker-selected zero weights
is not an authorization API.

No GPU kernels or HE private arithmetic changed in this checkpoint. The existing
GPU implementations are covered by the full suite and the new stage differential
tests. This is not a new GPU sanitizer or private-side-channel assurance claim.

## Static checks and remaining scope

All passed after the implementation changes:

```bash
.venv/bin/ruff check src tests
.venv/bin/ruff check --config 'force-exclude=false' --config 'exclude=[]' \
  experiments/bfv_search_lab benchmarks/bgv_radix.py \
  benchmarks/bgv_layout_report.py benchmarks/bgv_checked_switch.py
.venv/bin/mypy src/cuhepy
git diff --check
```

Mypy checks 34 package files, not strict typing of the experimental modules.
The stage check assumes trusted input tensors and pinned keys; it produces
neither a full-search proof nor a receipt. Complete chain verification,
matched native recomputation comparisons, real deployment transfers,
registration/epoch measurements and independent parameter review remain work.
