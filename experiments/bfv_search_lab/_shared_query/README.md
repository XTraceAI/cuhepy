# Q76 public native core

This is a work-in-progress public evaluator/checker for owner-canonical
shared-query BGV. It uses our PrimeNTT/RNS arithmetic and GMP. It imports or
links no SEAL implementation.

The context builds the graph internally and shares public preparation. It
exports evaluation, complete-body checking, length-bounded residual diagnostics
and a terminal coefficient codec. The ABI is 1202. The bounded Python adapter
is `experiments/bfv_search_lab/native_shared_query.py`.

**Q76.1 passed its retained N16/N32 public correctness gate:** 16 complete
fixtures, 208 source and 96 output faults, exact GMP tapes/frames and complete
schoolbook residuals in both actual primes. A 58-case boundary suite passes on
normal and UBSan builds. These are overlapping retained cases, not fresh keys.
See the [core return](../../../docs/research/native-shared-query-core-20261004.md).

The core alone supplies no owner authentication or release authority. The
combined local prototype now passes the owner-authenticated factory, durable
lifecycle and registered six-search source-scale correctness gates. Actual
private production release and attestation remain unfinished. Raw C ABI handles/buffers are trusted caller
interfaces, not an admission API for network peers.

Use the [current execution plan](../../../docs/research/system-contribution-execution-plan-20261004.md)
and [registration](../../../docs/research/native-shared-query-registration-20261004.json).
Q76.2 added owner-authenticated enrollment and signed original requests. The
initial unvalidated build/source and warning receipt remain preserved. Do not
benchmark or deploy before the later correctness/controller/lifecycle gates.

Build only an isolated target, from this directory:

```bash
make TARGET=/tmp/cuhepy-shared-query/libshared_query_native.so
```

Do not replace a delivered library. Keep the original build and future test
receipts in the outer `research-data/` tree. The producer and terminal codec
alone do not authorize a response; a controller must complete all
public checks and exact context/frame binding before any private operation.

The [matched prepared replay return](../../../docs/research/native-shared-query-replay-20261004.md)
records the later Q76.4a control and retained-input gates. Build it as a separate
isolated target with `SOURCE=shared_query_replay.cpp`. It preserves ABI1202 and
adds replay ABI1, sharing canonical expansion, paired products and the terminal
codec while omitting source-witness writes. Original normal and UBSan libraries
remain preserved; never overwrite them. This known-method control is not a
performance or security approval.
