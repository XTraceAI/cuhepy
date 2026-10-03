# Q48/E122: registered arbitrary four-root counterexample gate

2026-10-03. **Root contract, scientific execution not yet activated.** No root selection, orbit inventory,
projected sum, ternary mass, witness or MITM computation has been executed.
The E121 checkpoint is `d807503a7b31602be87cbf05fc2a27c51b9eac03`.
This packet is isolated on `experiment/joint-root-discriminator-20261003`.
Root must freeze this contract before implementation validation and the final
source/argv closure before separate scientific GO. This is one exact formal public oracle, not HE keygen,
parameter estimation, timing, security assurance or an originality claim.

## 1. Fixed hypothesis, comparator and stopping rule

Fix N16, prime q97, four distinct roots of X^16+1, and the unchanged raw law
S_j IID uniform on {-1,0,1}. The unproved hypothesis is that a structured
X^4-a root packet maximizes Pr(S annihilates the packet) among all four-root
subsets. This may be false; ALS2020 Section3 proves scalar Fourier bounds and
supports disjoint-class binomial packets, not arbitrary-root extremality.

The strongest structured control is already symbolic: each remainder class
has degree<4, and any nonzero class has nonzero negacyclic determinant with
absolute value <=4^2=16<97. It cannot vanish at a primitive eighth root mod97.
Thus every structured quartet annihilates S iff S=0, and its exact mass is
1/3^16. Any nonzero four-root witness falsifies universal extremality at these
fixed parameters. This does not certify or refute a source-q60 small-defect
bound. q97 is below the actual HE modulus floor; no HE constructor or guard
may be invoked/bypassed for this oracle.

**Fixed choice: stop at the first lexicographic counterexample**, searching
canonical orbit representatives in ascending order. Before any masses, build
and validate the COMPLETE four-root-subset orbit assignment. This full
combinatorial inventory is not a claim that every orbit mass was computed.
Limit mass evaluations to the first64 canonical representatives. If no
counterexample is found, report `full_fixed_inventory_no_counterexample` ONLY
if all representatives were actually evaluated; otherwise report
`bounded_prefix_inconclusive`. Even exhaustive tiny survival is not a theorem
at other dimensions/primes or an accepted research contribution.

## 2. Deterministic root and exact orbit proof

The public selector is the LEAST integer z in [2,96] with z^16 mod97=96.
Do not choose z from mass results. Stop if none exists. Validate q97 is prime,
z is nonzero, z^32=1, z^16=-1, and its32 successive powers are distinct.
For a power-of-two order, z^16=-1 implies exact order32. The16 roots are
z^e for odd e in {1,3,...,31}, ordered by exponent, not numerical residue.
No root has been selected by this draft.

All four-subsets T use sorted odd-exponent tuples. G consists of all odd
g modulo32; action gT sorts {ge mod32:e in T}. Its validity follows from
sigma_g(S)(X)=S(X^g) modulo X^16+1: coefficient j goes to position
(jg mod32) mod16, with sign minus precisely when jg mod32>=16. Odd g induces
a signed permutation, so symmetric IID raw ternary S has the same law.
Moreover sigma_g(S)(z^e)=S(z^{ge}); therefore event masses are invariant
along each orbit (using the inverse action for the zero-set direction).
No independent-root, unsigned-permutation or arbitrary additive-exponent
action is allowed.

Canonical representative is the lexicographic MINIMUM gT. Enumerate all
choose(16,4)=1820 tuples in lexicographic order; verify group closure/inverses,
idempotent canonicalization, every tuple assigned exactly once, disjoint orbit
members, orbit/stabilizer relation, and union equal to all1820 tuples. Record
the actual orbit count and complete assignment hash only AFTER activation.
Structured packets are those exponent tuples e,e+8,e+16,e+24 modulo32;
their algebraic label is checked without assuming all quartets are packets.
The canonical representative of any counterexample orbit is its smallest
tuple; searching representatives in order thus selects the globally first
counterexample root tuple within the visited complete orbit prefix.

## 3. Exact MITM count and independent witness verification

Split coefficients into j0..7 and j8..15. Enumerate each half in lexicographic
{-1,0,1}^8 order: exactly3^8=6561 assignments per half. For one quartet T,
project each half into F_97^4 using the frozen root powers; aggregate exact
integer multiplicities into dictionaries L and R. Then

    count_T = sum_v L[v] * R[-v],    probability_T = count_T / 3^16.

Keep the denominator exact and unreduced in the count ledger; a rational
display is optional and is not floating-point probability estimation.
Validate both multiplicity sums are6561, keys are strict four-tuples of
canonical residues0..96, count is an integer in [1,3^16], and count is odd
(the nonzero secrets pair as S,-S). Zero is included ONCE, not an additional
setup failure or a per-query charge.

If count_T>1, rescan the left half in lexicographic order and obtain the
lexicographically smallest nonzero matching full S. Right buckets retain
their two lexicographically smallest assignments, sufficient to exclude only
the unique all-zero full vector. Verify S is nonzero with all16 strict ternary
coefficients, and recompute its four evaluations by independent direct Horner
evaluation without the MITM/power-table helper. Compare all four with zero;
failure stops as an oracle error. Record the exact count, denominator, tuple,
witness, packet comparison and orbit coverage, then STOP. No root reroll,
larger field, alternate degree, second candidate or tuning run is permitted.

No separate low-weight branch is authorized: the degree16 determinant argument
requires a four-root nonzero ternary witness to have sufficiently large support
(support^2>=97), so a naive sparse search is not the promised fast route.
A new constructive theorem/witness search would need a separate freeze.

## 4. Resource and source closure

Hard limits for the ONE main process:60s wall AND60s CPU,256MiB address space,
at most64 canonical representative mass evaluations, and at most6561 live keys
per half dictionary. Delete a quartet's dictionaries before the next one.
Upper half-enumeration visits are64*2*6561, plus at most6561 for the single
counterexample extraction. Inventory work covers1820 tuples and16 group actions
per tuple; these are workload bounds, not computed orbit/mass outcomes.
No cache of every orbit's dictionaries, giant integer Fourier sums, source-q60
enumeration, GPU/native build or parallel worker is permitted.

The contract is frozen before implementation validation. Each validation
source version, command, failure and corrective edit is retained. Validation
may repeat only the same registered tiny fixture scope after a concrete
implementation issue; report final distinct case IDs rather than summing
repeats. The final source/argv/input closure must be frozen before the ONE
scientific main. A source correction after that requires a new separately
registered packet; this main is not retried. The runner uses
only public integer data and stdlib; environment sets PYTHONOPTIMIZE=0 and
rejects disabled assertions. Use one fresh output directory, never an old raw.
Preserve partial artifacts, stderr, elapsed RESOURCE diagnostic and timeout/
memory/failure receipt; do not retry a capped failure as a success. A cap stop
is `resource_bounded_inconclusive`, not a mass bound or a surviving conjecture.
Elapsed time is not a performance benchmark. After the one result, return R6
before any larger joint-Fourier certificate, source-prime probability, secret
sampling, owner contract, codec/candidate, security or service work.

## 5. Bounded tests and admissible conclusion

A bounded scoped test cohort, capped60s/256MiB per command and <=64 distinct
parametrized cases; recorded corrections/revalidation stay within the same
fixture scope. No N16/q97
mass computation in tests. Use fixed degree2/4 formal fixtures for direct
literal ternary enumeration versus MITM, exact denominator/zero/sign-pair
counts, independent Horner witness verification, and complete tiny orbit
coverage. Test basis-coefficient signed actions and inverse evaluation
directions; malformed/duplicate roots, wrong-order roots, bool/float aliases,
noncanonical residues, nonternary/zero witness, missing orbit members and
deliberate corrupted counts must reject. Use a synthetic predeclared fixture
to test first-counterexample, prefix-limit, timeout and output status handling.
Lint only the final owned new files, with nonempty checked-path accounting.
The actual N16 prime/root/orbit validation belongs to the ONE main and is
retained in its raw receipt; tests do not precompute scientific outcomes.

A verified nonzero witness refutes this universal structured-extremality
hypothesis and supplies a useful negative control for future joint-root claims.
It establishes neither a likely large-prime rank defect nor a security flaw,
original theorem, speed improvement or source-profile probability. Tiny full
survival leaves originality and source applicability unresolved. Shared-secret
limbs still cannot be treated independently; a later max-limb defect bound may
use a limb/root-set union and charge it once per honest enrollment epoch,
with unchanged sampler, unconditional failure accounting and all lifecycle
costs. Ordinary Fourier/packet controls and the useful known Holder path remain
available regardless of this conjecture's fate.


## 6. Owned files and exact outputs

Implementation: `experiments/bfv_search_lab/joint_root.py`,
`experiments/bfv_search_lab/test_joint_root.py`, and
`benchmarks/joint_root_lab.py`. Selected raw:
`benchmarks/results/publication-joint-root-20261003.json`. Full public finite
orbit/count/witness inventories, source snapshots, logs and review receipts
remain in `/home/pete/yavor-projects/xtrace-work/research-data/joint-root-20261003/`.
The runner freezes the deterministic selection rule, not a root computed early;
the scientific selector, N16 orbit inventory, masses and witness run only in
the ONE main. No implementation test invokes that main context.
