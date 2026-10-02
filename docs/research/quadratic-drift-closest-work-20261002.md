# Q17/E91: dependence and norm controls

2026-10-02. Targeted primary-source reading, not a complete proof/parameter
audit or reproduced author artifact. The [archive](prior-work-archive.md)
retains versioned PDF/text hashes; older source entries remain unchanged.

| Primary source | Closest established control | Consequence for our claim |
|---|---|---|
| [Drifting Towards Better Error Probabilities in Fully Homomorphic Encryption Schemes](https://eprint.iacr.org/2024/1718) | Ciphertext-specific exact drift, public quality tests and rerandomization; targeted §3 definitions/propositions, §5 tests and §6 premises | Public input-dependent rounding certification is prior work. Our upward half convention differs from its stated convention. A drift check does not imply its security theorem applies to our malicious response protocol. |
| [A Critique on Average-Case Noise Analysis in RLWE-Based Homomorphic Encryption](https://eprint.iacr.org/2025/1036) | Dependence-aware analysis; §6.2 explicitly treats degree-k BGV rounding terms containing a derived secret power; §2 canonical norm and §5 dependent products | Recognizing the S/S-squared dependence is prior work. Our deterministic all-secret control avoids an independence premise; it does not replace a reviewed probability/parameter analysis. |
| [Fully Homomorphic Encryption for Cyclotomic Prime Moduli](https://eprint.iacr.org/2024/1587) | §2.1 canonical embedding, multiplicative norms and coefficient/canonical comparison | Canonical norm control is established mathematics. Our signed power-of-two matrix proof is restricted to its actual ring; prime-cyclotomic conditioning and the author's scheme/implementation are not transplanted. |
| [New Secret Keys for Enhanced Performance in (T)FHE](https://eprint.iacr.org/2023/979) | Partial-key and FFT switching controls already recorded in E87 | A public prefix must describe the actual approved secret. A tighter quadratic estimate does not create a smaller independent key or free auxiliary material. |
| [Meta-PBS](https://eprint.iacr.org/2025/2284) | Targeted §3 and §5 compact/high-precision packing, Appendix D/E premises | Shared precision or a low-dimensional output must be compared with this paid control, including compact key, decomposition, noise, and subsequent complete authentication. |

The E91 trace-power certificate is a sound homemade application of known
norm mathematics. A restricted all-k identity has survived the finite proof
checks; priority and a useful new full authenticated consequence remain open.
The [next screen](partial-packed-switch-plan-20261002.md) asks whether it can
make an actual precision-limited partial-switch release admissible beyond
ordinary approximate/truncated switching. Targeted review of that closest
family precedes implementation or a new claim.
