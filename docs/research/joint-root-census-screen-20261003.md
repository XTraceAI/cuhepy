# Q50/E123: complete fixed tiny joint-root census

2026-10-03. **Completed exact assurance census; return to R6 and a separate
theorem/closest-work decision.** The one externally supervised child exited 0
with empty stderr, no timeout, no termination signal and no retry. It reused
E122's 40 frozen counts and evaluated exactly the remaining 80 representatives.
All **120 signed-Galois orbits / 1,820 four-root subsets** now have exact masses.
The global maximum is **65/43,046,721**. The separately reviewed norm bridge
makes the exact probability of at least four vanishing roots
**1281/43,046,721**, including the zero polynomial once.

This is the unchanged formal `N16/q97/root19` context and raw IID uniform
ternary coefficient law. It is below the HE modulus floor. No source-prime
probability, new algorithm, performance win, cryptographic parameter approval
or original paper contribution follows.

## Complete finite results

Each root set is expressed as four odd exponents of E122's recorded root19,
in exponent order. No selector or orbit-inventory constructor was called by
this continuation. The table lists every orbit with a count greater than one:

| Orbit index | Canonical exponent tuple | Orbit size | Exact count | Origin |
|---|---|---:|---:|---|
| 40 | `(1,3,13,31)` | 16 | 33 | reused E122 |
| 101 | `(1,5,27,31)` | 8 | 33 | fresh E123 |
| 102 | `(1,7,9,15)` | 8 | **65** | fresh E123 |

All have denominator **43,046,721 = 3^16** and include the zero polynomial
once. Orbit102 is the only maximizing orbit: its eight member root sets have
count65. The complete histogram is:

| Exact count | Orbit size | Structured `X^4-a` packet | Representatives | Root subsets |
|---:|---:|---|---:|---:|
| 1 | 4 | no | 2 | 8 |
| 1 | 4 | yes | 1 | 4 |
| 1 | 8 | no | 6 | 48 |
| 1 | 16 | no | 108 | 1728 |
| 33 | 8 | no | 1 | 8 |
| 33 | 16 | no | 1 | 16 |
| 65 | 8 | no | 1 | 8 |

The four structured packets retain the strongest symbolic zero-only control
from E122, count1; their newly covered representatives were also checked
against it. E122's universal structured-extremality hypothesis remains false.
Completion supplies a global maximum for **this context**, rather than
reversing the earlier negative result or validating that surrogate elsewhere.

The fresh positive counts pay for the unchanged lexicographic nonzero witness
extraction, literal Horner validation and inverse signed-Galois transports
before durable completion. The new ledger retains each witness and count.
For the maximizing tuple the two half tables have 6,561 leaves each but only
**6,129 distinct projected keys each**: collisions are preserved, not discarded.
No full secret-to-root-set law or extra witness/full-zero-set search was run.

## Weighted moment versus the special exact union

Let `k(S)` count vanishing roots. In general the complete weighted sum is a
factorial moment, not a union:

```
E[binom(k(S),4)] = sum_orbits |orbit|*C_orbit / 3^16
                = 3100 / 43,046,721.
```

The [frozen norm refinement](joint-root-census-refinement-20261003.md) gives
the special conversion here. For every **nonzero integer** ternary S of
degree<16, irreducibility of `X^16+1` over the rationals gives a nonzero
negacyclic determinant. The known norm/Smith-factor controls imply

```
97^k divides det(S),
0 < |det(S)| <= 16^8 = 4,294,967,296
                       < 97^5 = 8,587,340,257.
```

Consequently nonzero S has `k<=4`. The main independently checks that public
integer inequality; it does not enumerate determinants or condition the
sampler. Every nonzero event counted by a quartet then has exactly four zeros
and contributes once to the complete weighted sum. The zero polynomial has
16 zeros and contributes1,820 to its numerator. The exact once-only correction
is therefore

```
Pr(k>=4) = (3100 - 1819) / 43,046,721
         = 1281 / 43,046,721.
```

There are **1,280 nonzero** vectors in that event, and one zero vector. The
optional conditional-on-nonzero diagnostic is `1280/43,046,720`; it is not a
changed or rejected-secret sampler. The census does not determine the
distribution of `k=0,1,2,3`, a general nonunit probability, or a once-per-owner
source setup/lifetime budget. This union equality needs both full coverage
and the fixed tiny nonzero-defect bound. It does not extend to a partial ledger
or to the actual source dimension/primes.

All counts satisfy the retained free signed-monomial constraint
`C=1 mod32`. The signed-Galois root-set partition and signed-monomial action
on secret coefficients are distinct controls; neither permits arbitrary root
translations or independent root-event assumptions.

## Reuse, work and interruption accounting

The [frozen census contract](joint-root-census-preregistration-20261003.md)
authenticates checkpoint `be7067836cb57fae798ed44650ed690b29f804b9`, its tag,
the recorded selected root, complete assignments, successful raw/receipts,
unchanged counting implementation and all 40 ordered JSONL records. Strict
parsing rejects duplicate JSON keys and numeric aliases **before** array-to-
tuple conversion. Every original line/count matches the old raw and ascending
representative. The source/input closure is checked before and after new work.
Recorded witness checks do not recompute their masses.

The new controller is separate from E122's first-counterexample controller.
It visits only the ascending suffix `[40:120]`, does not stop at positive
counts, and uses the frozen E122 `count_roots` unchanged. Each complete entry
is flushed/fsynced only after all checks pass, then accepted into the in-memory
completed ledger. The final ledger has exactly120 entries and aligned durable
coverage; no interruption occurred. Origins and original record hashes remain
explicit rather than treating the first40 as fresh work.

| Recorded logical work | Reused E122 records | Fresh E123 records |
|---|---:|---:|
| Representatives | 40 | 80 |
| Half leaves | 524,880 | 1,049,760 |
| Occupied left-bucket join visits | 262,440 | 524,340 |
| Half vector updates | 524,800 | 1,049,600 |
| Witness-extraction leaves | 21 | 330 |
| Witness-extraction vector updates | 26 | 340 |

The first column is historical recorded work, not repeated under the new
window. The raw labels counters `completed_mass_records_only`; histogram/
sample validation, coordinate tuple work, input validation, Horner/transports,
source hashing and output costs are excluded. An interrupted append/mass would
remain unknown and inconclusive, without a complete summary. These logical
counters are neither elapsed times nor full operation/memory costs.

The worker had 180-second CPU/wall and256-MiB address-space ceilings. Its new
supervisor charged input hashing and startup against the absolute wall window,
owned its child's process group, and permitted bounded TERM/KILL cleanup only
after the work deadline. No cleanup signal was needed. A separate CPU/wall/
max-RSS resource diagnostic is retained; it is **not a performance benchmark**.

## Known-control status and next decision

The equally informed generic receives the same recorded prefix, signed orbit
partition, collision-preserving incremental MITM, witnesses, packet proof and
norm/zero correction. Its logical method ratio is **1**. Our code is a homemade
public exact integer oracle using stdlib, with no SEAL, HE/native/GPU backend,
estimator or proof-system invocation. Known enumeration controls yielding the
same finite data do not establish an original algorithm or an original theorem.

The [closest-work card](joint-root-census-prior-comparison-20261003.md) retains
the existing scalar/binomial and norm controls and the newly read HPXv2
multiple-root near-uniformity theorem. That theorem already handles a general
prescribed-root question under its own order/range hypotheses. Its usable
constant, reported sign issues and applicability to source profiles are still
unresolved. These toy counts cannot settle them or supply a source-bound
extrapolation. Any proposed theorem must state a genuinely distinct precise
consequence and pay those hypotheses; generic near-uniformity itself is not
an unclaimed new target.

Retain the complete dataset as company/research assurance evidence, and return
to a **separate closest-work/theorem decision card**. No new N32 context, larger
grid, source secret rejection, enrollment probability, HE guard change, byte
saving, deployed side-channel assurance, timing claim, production approval or
accepted original paper main was produced by this census.

## Validation and immutable provenance

**16 new distinct synthetic/N2/N4 controller tests passed** under60-second/
256-MiB per-command caps; all three explicit nonempty Ruff paths passed. The
frozen **58 E122 tests are reused historical coverage and were not rerun or
added to that16**. The new cases cover strict aliases/duplicate-key parsing,
prefix completeness/hash/ordering, exact-once suffix execution, positive
synthetic records without early stop, callback/resource boundaries, false
completion, work separation and factorial-moment versus union semantics.
Synthetic positive records are trusted-controller diagnostics, not claims
about the actual tiny field law. No scientific N16 context/mass ran in tests.

The initial test attempt had9 passes/7 failures because its raw fixture retained
Python tuples instead of JSON arrays; the parser correctly rejected it. That
helper and three closure-lint bindings were corrected on the same16 cases.
Later static reviews added explicit checkpoint/cap guards and corrected the
old zero-accounting field's grammar: integer1, not booleanTrue. Alias regressions
fit inside an existing case. Supervisor startup/cleanup accounting was tightened
before main. All versions/logs/receipts are retained separately; repeats are
not summed. No scientific correction, resume or retry occurred.

The final closure pins **282 immutable inputs**: the old full238-source/input
closure, exact original census inputs/receipts, new sources/tests/supervisor/
interpreter, frozen contract/reviews/math cards and a copy of the **100-source
registry with all100 PDF/text pairs**. Mutable current governance and the active
registry are excluded. The complete cleaned environment includes assertions,
fixed Python hash seed and disabled user site packages. All scientific source
and raw bytes are frozen after this one main.

* [Controller/parsers](../../experiments/bfv_search_lab/joint_root_census.py),
  [tests](../../experiments/bfv_search_lab/test_joint_root_census.py),
  [runner](../../benchmarks/joint_root_census_lab.py).
* Selected [raw](../../benchmarks/results/publication-joint-root-census-20261003.json)
  SHA256 `98be666f98eb6c5c28532212c8a60cb8eee5ff9be2387aa029bcaa533503b49d`.
* Contract SHA256
  `0dff8993a9479624b4a563315a33b51f060b445be817e92b9194dffb23f51d55`;
  source/argv closure SHA256
  `4df46692560e3f0c169872fd592d9a679c201c5f500cec096211a34ae33c020c`.
* Unified ledger SHA256
  `3cf74de75451dd592e4ae1acc79c4eb545e0671b275ada7e8d210aa56638aa00`.
* External cache:
  `/home/pete/yavor-projects/xtrace-work/research-data/joint-root-census-20261003/`,
  including `main/authenticated-inputs.json`, `main/complete-or-partial-ledger.jsonl`,
  `main/completed-coverage.json`, `main/resource-diagnostic.json`, `main.stdout`,
  `main.stderr`, `supervisor-start.json`, `supervisor-receipt.json`, final16-case
  XML/IDs/receipt, `source-argv-freeze.json` and `execution-receipt.json`.

Root owns selected-raw/governance checkpointing. Complete ledger, preserved
validation failures and archived papers remain external. Stop scientific work
here and revisit the plan before activating another packet.
