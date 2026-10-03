# Q67: homemade isolated native public evaluator

Implemented in `experiments/bfv_search_lab/_gadget/propagated_server.h`, with
its own CPython bindings/Makefile and guarded
`native_propagated_gadget_bgv.py` interface. This is repository-owned C++/GMP/RNS
code, reusing existing repository arithmetic headers, without importing SEAL.
The company backends and historical binaries are unchanged. The isolated
173,792-byte extension is archived under
`../research-data/gadget-cut-research-20261003/native/`, SHA256
`1e617b91cacebfca26dd4cd1adbd4a72db71e08172693d752b8eec46a5eda8d3`.

The implementation canonically decomposes the first unary rotation source,
retains its common digit NTTs for one pair, then applies the next correction
through two public composite-key families. NTT automorphisms use exact
bit-reversed evaluation permutations. It never interprets independently chosen
limb values as small common integers. Pair-local execution releases digit state
after the second stage. Later stages and full groups use canonical switching.

Three tiny native whole-output tests cover N8/N16/N32 and half/full/tail groups,
both modes:18 complete full-Q/compact byte comparisons against the independent
public Python relation. Public context/index/byte/guard fault tests also pass.
These are diagnostic toy parameters. The final unified test receipt is separate
from the earlier overlapping development runs.

## Actual source geometry

One completed fresh Q120 context at8192×512, N16384/D512, t1031/eta21,
P=33,548,413, plus three held-out fixed query words:

- **24,576 unique query distances** and **49,152 unique query physical plaintext
  coordinates**, including unused coordinates, match independent truth.
- Same-module canonical full-Q bytes match the unchanged historical CPU RNS
  evaluator. Alternate full-Q/compact ciphertext bytes differ but every
  plaintext coefficient and stable top3 agree.
- Each framed client response remains **102,488 bytes**, with a102,400-byte
  packed body. The public propagated/terminal bounds are those modeled in Q65.
- Exact H word body2MiB; exact pair-digit word body2MiB. Monomial state and two
  permutation maps add0.5MiB shared word bodies; keys, index, object/allocator
  overhead and other scratch remain additional. Do not report4MiB as total RSS.

The first attempt aborted after query1 because the harness expected reversed
ranking tuples. Correct arithmetic/full-plaintext assertions precede that
failure in its preserved source. The separately registered single retry fixes
only `(ID,distance)` expectations and uses a fresh key because no secret was
retained. The failed context is not counted as another successful cohort.
Both public fixtures and executed-source archives are preserved. The completed
record is `../research-data/gadget-cut-research-20261003/Q67-source-retry/`.

This large cohort uses **locally trusted public computations** and outside-
controller synthetic-owner diagnostics. It does not claim a new efficient
native admission controller, remote response acceptance, protected execution,
parameter approval, private-side-channel assurance or a timing result.

## Stronger complete cost ledger

The refined two-family control adds1,024 key convolution equivalents at8k,
instead of the initial v1 per-sibling3,072 count. Cached-NTT execution also
charges33,554,432 sibling monomial word multiplications over both primes.
The added key work entails another33,554,432 word products. It avoids1,024
forward prime NTTs and128 canonical source reconstructions/decompositions at
the second stage; common output inverse transforms remain. These exact
instruction/body counts are **not** a measured speedup. Memory traffic,
allocation, full witness production, admission, setup and network must be paid.
Canonical controls may use the same pair-local schedule; cache scheduling alone
is not a novel contribution.

**Return to plan:** the bounded Q67 public evaluator component is complete.
Its full native malicious-server admission and complete matched timing pilot
remain unimplemented. Q68 advances only a provisional noise-aware verified-
evaluation candidate, with geometry-specific and known-method limitations.
