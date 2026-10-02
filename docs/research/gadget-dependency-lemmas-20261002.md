# E99 restricted exact lemmas

These are known algebra/distribution controls specialized to our diagnostic
keys, not new security reductions. Trusted generation fixes distinct source
labels, independent uniform mask atoms and independent CBD_eta error atoms.
Actual S and its negacyclic square remain different symbolic sources; no
independence between them is assumed. Observing key bodies does not preserve
a claimed IID posterior error distribution.

**Source annihilation.** For rows b_j=g_j V-a_j T+e_j and any integer row c,
let A=sum c_j a_j and B=sum c_j b_j. If sum c_j g_j=0 modQ, then
B+A*T=sum c_j e_j modQ. For multiple distinct source labels, each multiplier
sum must vanish separately. Retain the integer source form: a multiple Q*V
vanishes in R_Q but is not the integer zero polynomial.

**Adjacent masks and noise.** F has rows(-r,1) at consecutive positions.
Its columns1 through l-1 form a triangular unit-pivot matrix, so the map from
l independent uniform masks to l-1 adjacent masks is surjective over any Q.
Uniform inputs have equal-size fibers; hence the resulting masks are jointly
uniform. Independent CBD_eta atoms have mean0 and variance eta/2, so exact
covariance is(eta/2)*F*F^t: diagonal eta*(r²+1)/2, adjacent entries -eta*r/2,
others0. Masks being independent does not make those overlapping errors IID.

**Primitive-map criterion.** A rectangular integer matrix F with m<=l is
surjective from Z_Q^l to Z_Q^m iff gcd(Q, all m-by-m minors)=1. Integer Smith
normal form gives invariant factors d_1,...,d_m; surjectivity requires each
d_i to be a unit moduloQ, equivalently their product (the gcd of maximal
minors) is coprime toQ. At compositeQ, nonzero entries/field rank are
insufficient. No individual unit minor is necessary: row(2,3) is surjective
mod6. The adapter bounds enumeration and declines unsupported sizes.

**Complete modular kernel.** Let g=(1,r,...,r^(l-1)) and d represent the
integer Q in base r, with a final carry allowed. Adjacent rows generate the
integer kernel g*c=0 by back substitution. For any c with g*c=kQ, c-k*d is
in that integer kernel. Thus adjacent rows plus d generate the full modular
kernel, of determinantQ because g_0=1. Balanced digits change its basis,
not its lattice. A full l-row basis is not a surjective mask map modQ.
Unimodular LLL changes preserve this fact and preserve the original adjacent
relations as public linear combinations. They cannot remove E98's existing
independent sample subset.

**Conservative IID subset.** After aggregating repeated atom identities,
disjoint error-atom supports make the transformed errors independent under
honest generation. A joint-surjective mask map gives independent uniform
masks. Identical sorted absolute coefficients produce identical marginal CBD
laws by symmetry. These are sufficient conditions, not a complete classifier.
Zero covariance alone is insufficient: E1+E2 and E1-E2 for CBD1 share parity
constraints despite covariance0. The displayed-basis subset inventory is
not a bound on all possible public linear-combination samples.

**Fixed-target hidden-support rounding.** Fix T, every input and old key
history before independent uniform owner coins. For a component remainder
r in[0,Q), rounding drift is D=Q*1[U<r]-r. Its exact mean is0, variance
r*(Q-r) and interval widthQ. For coefficient k of D_body+D_mask*T, the
active mask variables are distinct and have signs T_i times the negacyclic
wrap sign. Thus the conditional variance is body variance plus
sum_i T_i²*r_mask[(k-i) modN]*(Q-r_mask[(k-i) modN]). For ternary T of
weight<=h, a public bound without its positions adds the h largest mask
variances. The Hoeffding twice-proxy is at most ceil(Q²*(h+1)/2). The known
MGF/union argument uses the whole declared family/lifetime; outputs/views
need not be independent. Old errors/residuals retain their paid deterministic
bounds. This proves neither ciphertext privacy nor a fresh old-error law.

**Hidden sampler.** Uniformly choose h distinct positions, then choose p
positive positions among them; remaining nonzero entries are negative. Each
signed secret has probability1/[binomial(N,h)*binomial(h,p)]. Public(N,h,p)
does not disclose positions through this policy object. The actual key
transcript and private implementation still require assurance. Entropy does
not equal concrete security, and this distribution is not an IID ternary
prefix of dimension h. The correct unknown dimension remains N.

The [preregistered oracle](gadget-dependency-preregistration-20261002.md)
checks the declared finite laws and actual homemade key fixtures. It is not
a formal mechanized proof, circular/auxiliary-key reduction, correlated-noise
attack model, full parameter review or release authorization.
