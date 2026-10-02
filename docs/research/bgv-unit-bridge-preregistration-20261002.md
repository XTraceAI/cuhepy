# Q12/E86: the modular-unit BGV conversion control

2026-10-02, after E85 and before new source/results. A further closest-control
search located Figure 11, BGV/BFV conversion, in the primary threshold-FHE
reference (ePrint 2025/699). This motivates a separate bounded return, rather
than inferring that E85's two failed rescalings exhaust cheap conversion.
Section 5.6.2/Lemma 7 covers its Q=1 mod t case; the arbitrary-coprime unit
case below is derived independently as a baseline adapter, not claimed novel.

Proposed public arithmetic: for gcd(t,Q)=1, multiply every BGV component by
lambda = t^{-1} mod Q. Write lambda*t=1+kQ. With a centered original phase
phi=h+t*e, scaled decoding should yield k*h mod t when |phi|<Q/2. Undo that
known permutation by k^{-1} mod t. Compare independently with centered BGV
decoding over whole toy phase domains and actual homemade BGV ciphertexts.

1. Exhaust full centered phases for several coprime Q,t, including composite
   CRT Q. Check every mask/key decomposition in a bounded small case.
2. Check all two/three-component degree-two ring ciphertexts and keys over a
   small field. Preserve C2, signs and original ring binding.
3. Test public B/Q switching *after* modular-unit multiplication. Derive a
   rational margin from the actual BGV phase bound and full extracted secret
   norm. Retain failing tight-margin cases; no free PBS padding is inferred.
4. Differentially check one depth-one product from our homemade shallow BGV.
   This is local trusted test decryption, not a new remote release interface.
5. Count public modular products, unchanged input/key/index sizes, optional
   Q=+/-1 mod t parameter contexts and their required NTT-prime search. A
   permutation can be absorbed into a LUT only subject to its full-domain and
   negacyclic/padding restrictions. Keep generic programmable conversion and
   RevoLUT as strong controls.

The public unit map is invertible and adds no secret key material. Its
standalone IND-CPA claim is conditional on the original scheme: a simulator
applies the same public map. It does not establish malicious-response release,
valid TFHE auxiliary keys/noise, private side channels or parameter assurance.
Do not claim this known conversion as original. Use it to update the next
joint conversion/verification candidate and avoid an artificially weak control.
