# Q76.3b independent GMP preflight

The bounded whole-Q GMP producer passed 59 tests before any source-scale HE
key was generated. All 16 retained owner-canonical N16/N32 source bodies and
complete frames match the preserved independent reference; schoolbook
residuals hold. Synthetic convolution extremes, signed permutations, terminal
rounding, immutable buffers/caps and malformed final coordinates are checked.
Tests forbid native production/checking and HE key generation/encryption/
decryption inside the public GMP producer. Two additional public fixture
tests check the large binary dataset's known exact ties and group boundaries.

This implements `experiments/bfv_search_lab/shared_query_gmp.py` independently
of the C++ NTT and graph interpreter. It reuses our own GMP Kronecker
convolution helper, uses four direct ciphertext products to supply the cross
terms, and packs expansion frontiers instead of retaining all coefficients as
Python objects. It accepts only the bounded owner-canonical Q120 profile,
two groups and immutable canonical whole-Q public buffers. It supplies neither
origin authentication nor private-release authority by itself.

The first executed producer/test bytes and 59-test log are preserved in
`/home/pete/yavor-projects/xtrace-work/research-data/q76-source-scale-20261004/`.
The preflight registration was written before implementation. Source capture
for that test invocation was taken immediately afterward without intervening
edits; the complete large-run source archive is frozen separately **before**
its single fresh-key attempt. No overlapping counts are added.

Next is the existing [registered source cohort](native-shared-query-registration-20261004.json):
one fresh HE key, N16384/d512, counts 8224/16384/32768 and two queries, six
searches maximum. `benchmarks/source_shared_query_lab.py` consumes the key
attempt before generation, preserves partial failures, and never silently
retries with another key. It compares all native/GMP bytes and full frames,
requires complete authenticated public admission plus a durable callback
claim, then runs owner-only variable-time phase/score/tail/tie diagnostics.
No HE secret is serialized or sent to a server. Process RSS is labeled as a
process high-water mark, not native peak accounting or timing.

These small preflight tests do not establish the large case, originality,
approved parameters, private side-channel safety or an attested service. The
[execution plan](system-contribution-execution-plan-20261004.md) still requires
the source gate, matched controls and certificate handoff before Q77 timing.
