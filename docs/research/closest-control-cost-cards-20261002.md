# Q0: paid controls at the actual operator geometry

2026-10-02. Contract/count extraction, before E82/E83 implementation. Read the
[comparison](closest-work-comparison-20261002.md) and
[plan](contribution-plan-20261002.md). The homemade
[runner](../../benchmarks/fixed_function_control_cards.py) emits a new immutable
receipt, including source identities. Author timings are not local measurements.

## Objects and recipients

| Mode | Owner/client | Compute server | Binding and release |
|---|---|---|---|
| Existing token | Private M, fresh r, HE key and hidden check | Encrypted columns, fresh encrypted M r, public delta | Owner-approved token, full-Q check, then private decryption; trusted token work is paid |
| Maverick private-M control | Matrix-mask trapdoor and query-mask state | Masked matrix and public P/Q/codes | Actual Protocol 4 verification, then its mask correction; distinct assumption/field contract |
| Compressed EMVP control | Secret dual code, matrix-mask trapdoor, short query decryption vector | Masked encoded matrix, encrypted query and AHE correction | Paid AHE postprocessing; a matching malicious-feedback integrity adapter remains additional |
| E83 coded access control | Original encrypted query, owner-pinned coded operator root | Public ciphertext operator and coded rows | Entire answer fixed before fresh random row challenges, authenticated rows, check, then release |

For the two strongest private-matrix controls, use
[Maverick Protocol 4](https://arxiv.org/html/2609.10264v1#A3) and
[EMVP Figure 1 and download-rate extension](https://eprint.iacr.org/2025/858.pdf).
Their complete object formulas are in the receipt. Concrete code/security
parameters and implementations are still uninstantiated; counts do not fill that
gap. Full recursive trapdoor evaluation stays an explicit control obligation.

The pinned E76 plaintext profiles have widths **85** and **256**. Legacy
local row widths **32/23** coexist with larger concatenated query spaces.
For the ciphertext operator, width means the number of actual query-form
coefficients; output size includes every supported ciphertext component.
These objects must not be substituted for each other.

## Paid coded-row control

For an L-by-W prime-field operator, a rate-1/2 MDS code has length 2L and
distance L+1, provided its field supports enough distinct evaluation points.
Individual independent row checks need at most 128 samples for the fixed-error
2^-128 target. This is an elementary count target, not system security assurance.
Each query pays sample_count*W field values, authentication paths, code
evaluation and a round trip. Enrollment pays 2L*W field values or their complete
replacement representation. Owner-pinned V must actually equal E*D.

The retained eight D geometries plus the two strong global profiles are all
counted. The exact minimum sample count is calculated rather than fixed by
habit. Authentication costs and real transport remain explicit missing terms.
If a compact generator saves enrollment but needs its original coefficients
on every query, that download is charged in E83.

## E82 interfaces and first falsifiers

E82-T must implement the complete fresh-token contract. E82-D may implement
authenticated field outputs directly. Neither can use a shared low-dimensional
pad unless the **joint** repeated transcript is hidden. The first new tests are:

1. A secret reused code and a shared latent projection: exact finite transcript
   distributions and cross-block rank, including a fixed unknown affine offset.
2. A candidate multi-coordinate bit projection for VOLE: receiver recombines
   several line evaluations sharing one slope. Check recipient simulation and
   the source code's minimal-support count, since fewer coordinates need not
   mean fewer PRF keys.

The second candidate follows the general-projection question in
[secret-replication PCFs, §§3,6](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.ITC.2026.7).
Small-domain VOLE and its EMVP use are existing controls. No PRF/PCF, fresh
encrypted adapter or distributed MAC is implemented by these arithmetic tests.

**Q0 return:** the interfaces, dimensions and paid formulas are specified.
Next Q1/Q2 tests the two candidate steps. Unknown concrete baseline parameters
remain open and must be closed before a survivor claims a complete system win.


Final source-pinned repeat: [immutable result 02](../../benchmarks/results/publication-fixed-function-control-cards-20261002-02.json). Exact experiment/count fields agree with the initial run; Q0's archive cohort grows from 40 to 46 papers. The [execution receipt](fixed-function-execution-validation-20261002.json) records source closure, preservation and checks. The [latest return](construction-selection-20261002.md) governs current priorities.
