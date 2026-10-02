# E93/E94 targeted closest controls and next question

2026-10-02. Parent `a6993d1`. Three newly cached primary PDF/text pairs bring
the archive to **61**. Earlier 58 source entries stay byte-for-byte equivalent
as JSON records; deeper reading is appended separately. No author artifact
or reported runtime was reproduced. This bounded reading is not an exhaustive
priority, full reduction or parameter audit.

| Primary control | Targeted reading | Consequence for our experiments |
|---|---|---|
| [CHIMERA](https://eprint.iacr.org/2018/758) | §2.2/Theorem 2 functional-switch precision and variance control, revisited | Switching/rounding/fresh target keys are existing building blocks. A finite-family order restriction alone does not supply a new arithmetic mechanism. |
| [Drifting Towards Better Error Probabilities](https://eprint.iacr.org/2024/1718) | §3 Definitions3.2–3.3/Propositions3.4–3.5 and §5 quality rerandomization; full ACER page9 inspected | Public drift and rerandomization are strong controls. Correctness against chosen encryption coins differs from ordinary honest-coin correctness. Do not equate a fresh-key MGF with full sIND-CPAD security. |
| [Mean compensation](https://eprint.iacr.org/2025/809) | Existing §3/3.1 Equations4–8 reading retained | Secret-law centering is known; our uniform mean-zero ternary control has no binary mean term to remove. Fixed-weight/binary/prefix laws require their own analysis. |
| [Dependence-noise critique](https://eprint.iacr.org/2025/1036) | Existing §5/§6.2 derived-secret/product warnings retained | Reused/product errors and S^2 cannot be treated as fresh independent Gaussian noise. E94 instead conditions on the index and averages only honest new query CBD coins. |
| [Fast and Accurate full-domain bootstrap](https://eprint.iacr.org/2023/645) | §3.1 Algorithm1/Theorem 1, full page10 and §3 even-p premise | FDFB-Compress permits ordinary half-message input margin under its stated conditions, using two PBS and an intermediate bootstrap bound beta<q/(4p). Its even-p theorem is not an implemented odd-t adapter here. |
| [Spiral](https://eprint.iacr.org/2022/368) | §2 noise facts/Remark2.18; §3.4/Theorem 3.4, full page16 | Split-modulus compression and subgaussian noise control already exist. Its statistical switched-noise expression explicitly uses an independence heuristic. Its Regev-matrix/Recover relation is not our BGV-unit/odd-PBS relation. |
| [YPIR](https://eprint.iacr.org/2024/270) | §2 independence heuristic/ModReduce/Lemma2.4, full page8 | Strong amortized/shared packing and split-modulus controls must be priced fairly. Do not charge one fresh setup key per slot; its PIR query privacy does not automatically authenticate our owner-private score release. |
| [Accurate BGV Parameters Selection, v3](https://arxiv.org/abs/2504.18597v3) | §4 dependence setup, §5/§5.1 and §5.2; complete pages16/18 inspected | The shared secret/public-key dependencies and practical rescaling regime are already studied. Our seeded owner phases and unrescaled depth-one circuit differ; do not borrow their Gaussian/rescaling premises or infer finite negligible tails from a CLT/fit. |
| [Verifiable FHE](https://arxiv.org/abs/2301.07041) | Earlier malicious-input/noise/reaction model passages retained | A correct arithmetic proof is insufficient if accepted inputs can violate the noise/key provenance premises. The new budget objects are conditional public controls, not a complete verifier. |

Spiral and YPIR PDFs are mutable ePrint revisions pinned by retrieval hash on
2026-10-02. The new BGV source is explicitly arXiv **v3, 2026-03-05**, rather
than the older v1/v2 or a secondary site's excerpt. Acquisition records and
local paths are in [the registry](publication-literature-sources.json) and
[archive index](prior-work-archive.md).

## Mechanism decisions

E93's whole-family proof is a valid restricted control, but its packed-switch
outputs, key bodies, fresh generation and public recomputation costs are
identical to a strong standard precommitted shared-key epoch. **Stop generic
fresh-family composition as the proposed original mechanism.** The finite
probability oracle and explicit missing-order counterexample remain useful.
We do not claim that a cited paper states every detail of our application or
that a complete literature search proved non-novelty; the candidate lacks a
specified new construction step against its strongest control.

E94's fixed-index conditioning gives a useful, non-Gaussian lifetime source
bound without sampling/averaging a reused key or index. This is a known linear
MGF argument applied to the exact owner depth-one interface. It is worth keeping
and integrating only after provenance/lifetime/parameter review. The new
complete main protocol, binding proof and useful-cost result remain open.

The next discriminating question is [late owner rerandomization](late-owner-rerandomization-plan-20261002.md):
can one fresh true-uniform encrypted zero, generated after the original input
family is fixed, supply a valid **conditional-on-history, all-target-key**
rounding control across all replies/stages? This would avoid E93's new target
epoch for every adaptive query. Known rerandomization/ACER/quality controls
must get the same possible sharing. First prove the law for an unseeded mask;
a public SHAKE seed does not give an information-theoretically uniform mask.
Only a genuinely new complete provenance/binding/resource consequence can
be considered a contribution. Stop another generic composition if the strong
shared-rerandomization control supplies the whole step.
