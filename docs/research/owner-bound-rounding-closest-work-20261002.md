# E97/E98 targeted primary comparison and boundary

2026-10-02. Two new PDF/text pairs bring the archive to64. Earlier62 source
records/reading histories remain unchanged; this is an additional targeted
review, not an exhaustive novelty search, parameter audit or author reproduction.

| Primary control | Reviewed mechanism and premise | Consequence for this packet |
|---|---|---|
| [FHEW](https://eprint.iacr.org/2014/816.pdf), §3 Equation3/Lemma5, cached latest2015-03-02 | Independently randomized modulus switching; full lemma proof inspected. Deterministic-rounding/CLT qualifications are separate. | Unbiased randomized switching is known. Our independent fixed-input integer law/order checks are controls, not a new HE primitive. |
| [FINALLY](https://eprint.iacr.org/2024/1505.pdf), §3.5 Definition3.9/Lemma3.5, cached latest2025-05-26 | Bernoulli rounding and modulus/secret/noise terms; full relevant definition/proof pages inspected; attribution to FHEW. | Do not copy its whole Gaussian/independence/variance statement into a transcript with reused related keys. E97 proves only its registered conditional law and pays old error separately. |
| [Ciphertext drift](https://eprint.iacr.org/2024/1718.pdf), §4.1, §5.1–5.3, previously cached | Quality tests, probabilistic rounding and transformations have distinct premises. Its full fresh-encryption rerandomization condition is stronger than our shared-zero or coin construction. | A fixed-T fresh-coin law neither proves fresh ciphertext distribution nor supplies ACER/statistical rerandomization. Public coins still require an honest post-binding schedule. |
| [Mean compensation](https://eprint.iacr.org/2025/809.pdf), §3 Equations4–8, previously cached | Reduced drift through secret-mean compensation under the stated secret model. | Do not infer a smaller all-fixed-T error from a binary-secret averaged calculation. The registered universal card uses independent coefficient coins and a support cap. |
| [HE security guidelines](https://eprint.iacr.org/2024/463.pdf), §2.1–2.3, previously cached | Actual LWE/RLWE dimensions, error/secret laws and sparsity matter; key transcripts need appropriate security treatment. | Public zero suffixes and auxiliary key rows need their own exact sample accounting. E96's fresh-zero transcript and E98's setup-only transcript are different. |
| Pinned [lattice-estimator source](../../../research-data/reference-artifacts-20260930/lattice-estimator/estimator/lwe_dual.py), revision53da598 | Default `LWE.dual_hybrid` aliases MATZOV; its default original m=n exceeds E98's available setup samples. The distinct finite-sample DH routine clamps original m. | Keep raw results, audit applicability, and run a separately preregistered finite-sample control. Neither routine models the exact gapped noise law by a theorem or approves parameters. |
| VFHE/HELIOPOLIS/HasteBoots, earlier cached comparison | Complete ciphertext computation, auxiliary transformations/PBS and accepted-secret-release order require binding relations, not just correct output arithmetic. | E97's full local recomputation and volatile ledger are a diagnostic gate. A compact original-score/rounding/PBS/ID proof remains missing. No new artifact execution in this packet. |

Full PDF pages5/6 of FHEW and16/17 of FINALLY were rendered/inspected. Their
PDF and extracted-text hashes, retrieval scripts/receipts and reading scopes
are recorded in [the registry](publication-literature-sources.json). The
earlier uncached FINALLY lead is retained as history and is now resolved by the
new cached revision. No Microsoft/author HE implementation is imported for
E97/E98. Sage plus the external estimator is a disclosed cost-model control.

## Strongest standard control receives the same resources

Standard shared stochastic rounding gets the same fixed originals, full
canonical switch keys, independent coefficient coins, sign-complement map,
signed/permuted views, fresh lifetime schedule, whole-family union, public
subrelation, packet framing and owner/server locality as the candidate.
It has identical arithmetic outputs and all720 first passing degrees/resources.
**Stop generic stochastic-rounding originality.** Keep it as a useful company
adapter: it removes the owner-zero secret multiplication/CBD draws in that
part of the protocol. There is no measured elapsed win or complete deployment.

The setup-row cancellation used by E98 is also generic linear algebra. A
candidate research contribution would need a new dependency-aware transcript
or joint correctness/security resource consequence that survives equally
strong general linear/matrix controls and closest primary work. The
[next proposal](key-transcript-precision-plan-20261002.md) defines that bounded
discriminator without claiming this novelty has been established.
