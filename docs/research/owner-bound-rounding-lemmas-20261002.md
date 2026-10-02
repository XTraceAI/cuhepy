# E97 restricted conditional rounding laws

2026-10-02. These are arithmetic/noise-budget arguments for the registered
diagnostic control. They are not a full HE, transcript/privacy or security
reduction. [Prerequisites and finite scopes](owner-bound-rounding-preregistration-20261002.md)
remain binding; all source/proof/PBS/parameter/private assumptions are separate.

## Scalar law and exact signed coupling

Write Bx=Qk+r, 0<=r<Q. For U uniform0..Q-1 independent of fixed x,
`R(x,U)=k+1[U<r]`, so `d=Q*R-Bx=Q*1[U<r]-r`. Its mean is zero,
variance r(Q-r), and nonzero support has width Q. At r0 it is identically zero.
This is standard randomized rounding, valid even without gcd(B,Q)=1.

For x'=(-x) mod Q, set U'=Q-1-U. At r0 both errors vanish. Otherwise
r'=Q-r and `1[U'<r']=1[U>=r]`; hence d(x',U')=-d(x,U) and
R(x',U')=-R(x,U) mod B. An arbitrary signed permutation of coefficients
preserves the law if coins are permuted and complemented at negative positions.
Identical coins on both signs do not supply that pointwise identity. Sharing
the one packet across distinct fixed inputs/stages preserves each view's
independent coefficient marginals but not independence between views.

## Fixed-target phase and conditional bounds

Fix any T in {-1,0,1} with a supported prefix p. After the old canonical switch,
`C0+C1*T = original_phase + old_key_error - residual*S^2 (mod Q)`.
Rounding both components gives

`Q*rounded_phase-B*original_phase
 = d0+d1*T+B*old_key_error-B*residual*S^2 (mod Q*B)`.

For one coefficient, d0 and the p signed convolution terms are independent
conditional on the entire fixed input/key history and T. Their exact means
are zero regardless of the posterior distribution of T. Apply Hoeffding to
at most p+1 intervals of width Q, giving twice-proxy Q^2*(p+1)/2. Actual zero
remainders eliminate terms. Unknown zero secret coefficients only reduce the
variance/proxy; using the supported cap is valid for every fixed T.

Let v=sum r_i(Q-r_i) over these public positions and c be the maximum possible
absolute error. Bernstein gives the standard two-sided upper tail
`2*exp(-a^2/(2*(v+c*a/3)))`. Taking
`a=ceil_sqrt(2*v*L)+ceil(2*c*L/3)` is sufficient, since for a0=sqrt(2vL)
and b=2cL/3, `(a0+b)^2-b*(a0+b)>=2vL`. Use
`L=kappa+ceil_log2(2*K)`, conservatively above the required natural logarithm.
The exact source remainders and these thresholds precede the coins. Selecting
the smaller of the valid Hoeffding/Bernstein thresholds is therefore safe for
this one fixed conditional distribution. A pointwise public support bound
after coins is valid simultaneously for all T and can also cap the result.
No ciphertext-dependent Gaussian substitution or IID reused-key assumption.

Cover K prescribed events by union, then all M generated/discarded families
by conditional tower/union with kappa129+ceil_log2(M). E94's separate source
event at kappa129 makes only those two arithmetic terms sum to at most2^-128.
Original-score authenticity, honest old key errors, HE/key graphs, sampling,
proof/PBS, public seeds and private/durable assurance are not implicitly zero.

## Feedback and provenance boundary

Under a complete pre-secret verifier binding original inputs/canonical keys,
fresh honest coins/order, every arithmetic/precision event and output/ID
coverage, accepted releases couple to the correct function outside genuine
noise/verifier failures. This conditional correctness/feedback statement is
not confidentiality or a production secret-release gate. Full diagnostic
recomputation and a volatile one-use ledger supply only the tested subrelation.

Post-coin input choice, server-selected/grinded coins, shared coefficients or
new adaptive inputs reusing old coins invalidate the conditional law. Owner
labels/hashes authenticate identities only under an external trusted-channel
premise; they do not prove honest sampling or chronological order. A publicly
seeded deterministic expansion is not paired independent uniform coins.

Randomized switching and these concentration controls are known mathematics.
The strongest standard adapter receives the identical sign coupling, packet,
fixed-input/public proof subrelation and lifetime resources. Retaining a cheaper
owner control does not select an original conference mechanism.
