# Q48/E122: structured four-root extremality is false in the fixed tiny case

2026-10-03. **Completed bounded counterexample gate; return to R6.** The one
externally supervised scientific child exited 0 with empty stderr and no
timeout or retry. It found a verified nonzero raw ternary witness and stopped
at the first counterexample, exactly as the
[frozen contract](joint-root-preregistration-20261003.md) requires. No further
root selection, context, mass, witness search or full zero-set calculation
was performed afterward. This refutes the specified N16/q97 hypothesis; it
does not establish a large-prime defect rate, security issue, performance win,
new theorem or original paper contribution.

## Exact finite result

The least integer z in [2,96] with z^16=-1 modulo97 is **19**. This selector
ran only inside the one main. Its primitive order32 and distinct powers were
validated. The 16 roots are indexed by odd exponents of z; root subsets use
exponent order, rather than numerical residue order.

Before evaluating any mass, the implementation constructed and audited the
entire **1,820 four-root-subset** inventory, partitioned into **120 signed
Galois orbits**. An independent bitmask action matches canonical tuple
assignments. Closure, inverses, signed basis evaluation/composition,
transporters, disjoint coverage, stabilizers and idempotent canonicalization
were checked. The action X -> X^g is a signed coefficient permutation for odd
g modulo32. Its evaluation identity sends a witness zero set T to g^-1*T;
it grants no arbitrary exponent translation or root-event independence.

The ascending mass prefix visited **40 canonical representatives** and left
**80 representatives unvisited**. The first 39 have zero-only count one. The
40th supplies this exact result:

| Quantity | Result |
|---|---|
| Canonical root exponent tuple | `(1,3,13,31)` |
| Raw annihilating vector count | **33** |
| Exact raw-law denominator | **43,046,721 = 3^16** |
| Strongest structured-packet count | **1**, by the retained symbolic control |
| Nonzero annihilating vectors at the selected tuple | **32** |
| Left/right half leaves for this count | 6,561 each |
| Distinct left/right projected keys for this count | 6,561 each |
| Left leaves rescanned for witness extraction | 21 |

The exported lexicographically smallest nonzero witness for this tuple is

```
(-1,-1,-1,-1,-1,1,-1,1,1,1,-1,0,-1,1,1,-1).
```

It has 15 nonzero coefficients. Independent literal Horner evaluation inside
the main verifies all four stated roots. The main also verifies inverse signed
Galois transports to the root sets in this orbit. This states at least those
four zeros; it does **not** assert its complete zero set or exact rank defect.
No secret was sampled or used as a deployed HE key: this is a public formal
witness from an exact finite raw-law census.

For the selected tuple, the exact mass is **33/43,046,721**, compared with
**1/43,046,721** for every structured X^4-a packet. The structured comparator
is the strongest retained *symbolic* zero-only argument, not a claim that all
packet masses were separately enumerated: reduction into four disjoint
length-four coefficient classes, followed by the integer determinant bound
16<97, excludes every nonzero class. Any nonzero arbitrary-quartet witness
therefore suffices to refute universal packet extremality here.

Complete structural orbit coverage is distinct from complete mass coverage.
The 80 unvisited classes could have other masses; no global maximum,
distribution across all classes or exact union probability was computed.
The first-counterexample order and the per-tuple witness order are fixed by
canonical representatives and lexicographic halves, not chosen after seeing
an outcome.

## Exact counting and known consistency controls

For each visited tuple, meet-in-the-middle enumerates two eight-coefficient
halves in lexicographic {-1,0,1} order. Four-coordinate projection dictionaries
retain multiplicities, and the full count is the exact sum
`sum_v L[v]*R[-v]`. The denominator is the raw uniform ternary **3^16**;
this is not CBD1's weighted law or an assumed uniform field distribution.
Every count includes the zero vector once. It is not an extra epoch failure,
and counts for overlapping root sets are not an exact union probability.

Right buckets retain their two lexicographically smallest assignments. A
lexicographic rescan of the left half recovers the smallest nonzero matching
full vector, excluding only the unique all-zero vector. Incremental vector
updates avoid a modular-power call per ternary leaf. The strongest generic
gets these same ordinary orbit, incremental, histogram, packet and witness
options; its logical method ratio is 1, not a measured speed ratio.

The completed records contain **524,880 half-enumeration leaves** and
**524,800 vector updates**, with another **21 leaves/26 vector updates** for
the single witness extraction. These counters describe the recorded mass
work; they exclude orbit/preparation/Horner/hash/output work and are not
elapsed times, memory measurements or a complete operation-cost comparison.
The raw explicitly declares `completed_mass_records_only` and handles an
interrupted mass computation as unknown extra work. Here no interruption
occurred. The internal CPU/wall and address-space ceilings and external
60-second supervisor are resource guards. The separate elapsed resource
diagnostic is not a performance benchmark.

The [signed-monomial card](signed-monomial-count-control-20261003.md) and its
independent symbolic review existed before the scientific main. They prove
the ordinary invariant `C_T=1+2N*k`: nonzero integer ternary vectors have
free signed-monomial orbits of size2N, and multiplication by X preserves each
fixed zero event. After the run, a metadata-only read of the **existing 40
counts** confirms all are 1 modulo32; count33 is consistent. This was not an
additional preregistered main assertion, root-set action, vector enumeration
or new scientific cohort. It supplies no standalone large-prime bound.

## What stops and what remains open

Stop **this universal structured-extremality recipe**. The counterexample
does not disprove a different uniform arbitrary-four-root upper bound, the
known scalar/binomial Fourier controls, or the useful cyclic-window law.
It does show why a packet surrogate cannot silently replace an arbitrary
root set. The targeted [primary-source comparison](joint-root-prior-comparison-20261003.md)
found deterministic norm/basis and scalar/binomial controls, not a theorem
establishing this extremality hypothesis. That is a bounded comparison, not
an exhaustive claim that no prior counterexample or relevant theorem exists.

The oracle is our homemade public exact integer implementation and uses
stdlib in its scientific child. It imports no SEAL, estimator, HE constructor,
native/GPU backend or proof system. q97 is below the existing HE modulus
floor. No sampler, key rejection, source-q60 profile, coefficient codec,
query precision, owner contract, parameter guard or production file changed.
The raw ternary law includes nonunits and zero; it was not conditioned on a
successful key or event. Shared-secret limb independence is still unavailable.
No large-prime setup probability, enrollment budget, lifetime/terminal noise
certificate, communication saving, protected-release assurance or originality
approval follows. A useful arbitrary-root theorem and its complete system
consequence remain separate work.

## Validation and provenance

**58 distinct bounded N2/N4 tests passed** under 60-second/256-MiB per-command
limits. They compare direct literal ternary counts with MITM, check complete
tiny orbit coverage and signed/inverse evaluation, preserve histogram
collisions, test lexicographic recovery, and reject malformed roots, fields,
counts, witnesses and orbit aliases/omissions. Predeclared synthetic cache
and controller cases test unique-zero exclusion and first-counterexample,
prefix, full-inventory and timeout statuses; they do not claim a genuine tiny
nonzero root witness. No N16/q97 context/mass was run in tests. Repeated same
fixture validation is preserved separately and not summed into the 58 IDs.

All three explicit nonempty Ruff paths passed. Three optional 256-MiB Ruff
attempts failed in the Rust allocator; they are retained as validation-tool
failures. Root clarified that the frozen memory cap governs scoped tests and
the scientific main, while lint is separately specified. Normal lint then
identified a style-only inequality rewrite, and final normal lint passed.
Strict orbit assignment/member/stabilizer grammar and completed-record
counter accounting were corrected before scientific closure, with source
versions/logs retained. No main correction or retry was made.

The final source closure pins **238 immutable inputs**, including the final
three sources, external supervisor, frozen contract, peer reviews/test
receipts, the unchanged E121 scientific closure, the pre-result monomial
card/review and a snapshot of all **99 archived PDF/text pairs**. Mutable
current governance/queues and future root finalizers are excluded. The
scientific child and source/argv attempt marker were created once.

* [Implementation](../../experiments/bfv_search_lab/joint_root.py),
  [tests](../../experiments/bfv_search_lab/test_joint_root.py),
  [runner](../../benchmarks/joint_root_lab.py).
* Selected [raw](../../benchmarks/results/publication-joint-root-20261003.json)
  SHA256 `9db6e36cbff3ddef95abd8ac5fca8efecd39d2e180f22713f123bf05fdd1cf3a`.
* Contract SHA256
  `8119b49f7c7a3cd6ea48c2f7a13af063a97df7bb19fb43920c8e91d6326904dc`;
  source/argv closure SHA256
  `f1b8f52227ac58b82fcbfdb2c81180077f4626a43d38775f5e9228bbce92cbc4`.
* Complete orbit inventory SHA256
  `f5a937d9b970b98fd22e05dbba465392e6c8f85e6df4aa8b971ed0948dd7a862`;
  completed mass-prefix SHA256
  `e68933d45e22112e9b2c017645a93ee6d1c045f005e0e77691009285ea813bb1`.
* External cache:
  `/home/pete/yavor-projects/xtrace-work/research-data/joint-root-20261003/`,
  including `main/selected-public-root.json`, `main/complete-orbit-inventory.json`,
  `main/mass-prefix.jsonl`, `main/counterexample.json`, `main/resource-diagnostic.json`,
  `main.stdout`, `main.stderr`, `supervisor-start.json`, `supervisor-receipt.json`,
  `final-tests.xml`, `final-test-case-ids.json`, `final-tests-receipt.json`,
  `source-argv-freeze.json` and `execution-receipt.json`.

Root owns any explicit selected-raw Git checkpoint; full finite inventories,
validation failures and archival papers stay external. Preserve this negative
control and return to the plan before activating another packet.
