# Q76.1 public native core return

2026-10-04. Parent `719da6e7139eee3a46404a5ef14c4c63dbad3afb`, branch
`experiment/native-shared-query-service-20261004`.
Read the [receipt](native-shared-query-core-return-20261004.json),
[execution plan](system-contribution-execution-plan-20261004.md), and
[ledger](research-contribution-progress-20261004.json).

The homemade public C++ core now passes the registered **small retained gate**.
It does not authenticate owner origin, authorize private release or constitute
a completed service. Source-scale correctness, lifecycle and real attestation
remain later gates. No SEAL is linked or imported by this implementation.

| Evidence | Scope/result |
| --- | --- |
| Retained owner-canonical fixtures | 16 complete cases from the same two Q74 key contexts, N16/d3 and N32/d5, both queries and counts N−1/N/N+1/2N−1. Zero fresh keys. |
| Native public producer | Every source and both full terminal components match the GMP reference and retained tape exactly. The complete compact response frame matches. |
| Public checker | Every residual coefficient in each actual prime agrees with independent schoolbook whole-Q arithmetic, with common-Q digits used by both limbs. |
| Adversarial cohort | 208 source-coordinate and 96 output-coordinate faults rejected, including one-prime-preserving changes. The faults target the last physical coordinate, including unused record tails. |
| Boundary tests | One 58-case suite passes on both normal and UBSan builds; these are repeated tests, not 116 independent experiments. Includes malformed late inputs, full-frame changes, a scalar-vanishing polynomial, buffer lengths, ownership, shared preparation and fork. |
| Build/source | ABI1202, isolated `-Wall -Wextra -Werror` builds and exact dependency/source/library hashes. Production source and delivered libraries unchanged. |

Both suite runs emit the expected Python 3.12 warning from the intentional
fork-with-a-held-thread-lock test. The child rejects inherited ownership before
acquiring its mutex, exits successfully, and the parent handle remains valid.
UBSan reports no undefined behavior in this tested small scope; this is not
an exhaustive native memory or side-channel audit.

The adapter owns handles once, rejects copy/deepcopy/pickle, serializes access
to each query and keeps native shared preparation alive for existing queries
after the enrollment wrapper closes. The C ABI now bounds residual output
length before writing. It accepts no peer-supplied graph. Private HE work,
signing, entropy and callback authorization are absent from public checking.

Files:

- `experiments/bfv_search_lab/_shared_query/shared_query.cpp` and isolated Makefile.
- `experiments/bfv_search_lab/native_shared_query.py` and `test_native_shared_query.py`.
- `benchmarks/native_shared_query_lab.py`, the retained public gate runner.

Reproduce against the retained archive with an explicitly selected isolated
library; the runner refuses to overwrite an existing cohort directory:

```bash
make -C experiments/bfv_search_lab/_shared_query \
  TARGET=/tmp/cuhepy-q76/libshared_query_native.so CXXFLAGS=-Werror
.venv/bin/python benchmarks/native_shared_query_lab.py \
  --fixtures /home/pete/yavor-projects/xtrace-work/research-data/shared-query-admission-20261004/q74 \
  --library /tmp/cuhepy-q76/libshared_query_native.so \
  --out-dir /tmp/cuhepy-q76-new-cohort
```

Raw receipts, fault records, bodies/frames, normal/UBSan libraries, source
archive and preserved initial draft are outside Git at
`/home/pete/yavor-projects/xtrace-work/research-data/q76-native-core-20261004`.
The manual first-fixture smoke check and the unit tests overlap this cohort;
do not add them to the 16 independent retained-case count. No private key was
serialized, no private diagnostic was called, and no timing panel was run.

**Ledger return: Q76.1 is complete in its bounded public-core scope. Next is
Q76.2: owner-authenticated enrollment, signed original query and strict complete
packet grammar.** Q76 as a whole remains incomplete. Originality, source-scale
correctness, concrete parameters, private side channels and deployed TEE
security are not approved by this return.
