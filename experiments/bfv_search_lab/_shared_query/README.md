# Unvalidated Q76 native draft

This is a work-in-progress public evaluator/checker for owner-canonical
shared-query BGV. It uses our PrimeNTT/RNS arithmetic and GMP. It imports or
links no SEAL implementation.

The context builds the graph internally and shares public preparation. The
draft exports evaluation, complete-body checking, residual diagnostics and a
terminal coefficient codec. **A successful build is the only current gate.**
No encrypted/native correctness cohort, authoritative owner-authenticated
factory, request controller, durable lifecycle, private release or attestation
has passed for this draft. Raw C ABI handles/buffers are trusted caller
interfaces, not an admission API for network peers.

Use the [current execution plan](../../../docs/research/system-contribution-execution-plan-20261004.md)
and [registration](../../../docs/research/native-shared-query-registration-20261004.json).
Q76.1 first adds the bounded Python adapter and retained-fixture gate. Fix the
compiler's misleading-indentation warnings during that review, and preserve
the initial build/source receipt. Do not benchmark or deploy this draft first.

Build only an isolated target, from this directory:

```bash
make TARGET=/tmp/cuhepy-shared-query/libshared_query_native.so
```

Do not replace a delivered library. Keep the original build and future test
receipts in the outer `research-data/` tree. The producer and terminal codec
alone do not authorize a response; the future controller must complete all
public checks and exact context/frame binding before any private operation.
