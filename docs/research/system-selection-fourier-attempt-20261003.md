# SB01: one complete weighted Fourier bound, supporting control only

2026-10-03. **Static symbolic attempt completed; original-build selection
STOP.** The preselected bound below is proved, but its mechanism is ordinary
regular-cover Hölder plus the existing cyclotomic determinant gap. The equally
informed generic receives the identical formula: symbolic bound ratio **1**,
not a measured performance ratio. No stronger original certificate, actual
source probability, source usefulness, security approval or application GO
is established. No scientific program, field/root/energy enumeration, source
numeric evaluation, constant selection, test, key or HE operation ran.

The [target freeze](../../../research-data/system-selection-20261003/fourier-attempt/freeze-target.md)
and [pre-derivation receipt](../../../research-data/system-selection-20261003/fourier-attempt/freeze-receipt.json)
precede this derivation. They fix **one approach**, the temperature split
`2+2`, and the stop rule. This does not modify the
[earlier Fourier target](cyclotomic-fourier-certificate-plan-20261003.md), its
unproved stronger spectrum/count target, or any current guard.

## Exact domain, weights and proved lemma

Let N be a power of two, N>=4, and p an odd prime with p=1 modulo 2N.
Let T=(alpha_1,...,alpha_h) consist of h distinct primitive 2N-th roots,
where h=1,...,4. For u in F_p^h define

    a_j(u) = sum_i u_i*alpha_i^j in F_p,  0<=j<N,
    z_j(u) = dist(a_j(u)/p,Z)^2,
    E_T(u) = sum_j z_j(u),
    Theta_p(x) = p^-1 * sum_{a in F_p} exp(-x*dist(a/p,Z)^2),
    F_T(t) = p^-h * sum_{u in F_p^h} exp(-t*E_T(u)),
    Z_T(t) = F_T(t)-p^-h,
    L_h = p^(-2*h/N).

The distance uses the canonical centered modular representative. All weights
are the actual uniform dual weights p^-h. The only removed term is u=0,
whose exponential is exactly 1. No secret law is conditioned or changed.

For every t>0,

    F_T(t) <= Theta_p(t*N/h)^h.

The frozen, complete nonzero-character bound is

    Z_T(4) <= exp(-2*L_h) * [Theta_p(2*N/h)^h-p^-h].       (SB01)

This holds for all tuples in the declared domain, including every original
zero-coordinate support. The dependence on p remains symbolic; no prime,
amplitude or value of Theta was selected or computed.

### Proof: exact windows, ordinary cover, then the nonzero gap

**1. Exact window law.** Extend the dual sequence by a_(j+N)=-a_j,
since every alpha_i^N=-1. For U uniform in F_p^h, every consecutive h-term
sequence window is uniform in F_p^h: its matrix is a Vandermonde matrix on
the distinct alpha_i, multiplied by an invertible diagonal matrix. A window
of the actual cyclic coordinates has additional invertible row signs where
it wraps. Therefore its h coordinate residues are jointly independent and
uniform. This proves neither arbitrary-subset independence nor independence
between windows. The squared distances ignore those wrap signs.

**2. Complete cover.** Take the N cyclic length-h windows W_j. Each actual
coordinate occurs exactly h times. Ordinary Hölder with N equal exponents
gives

    F_T(t)
      = E_U product_j exp[-(t/h)*sum_{i in W_j} z_i(U)]
      <= product_j {E_U exp[-(t*N/h)*sum_{i in W_j}z_i(U)]}^(1/N)
      = Theta_p(t*N/h)^h.

The factorization is used only inside each uniform window, never for the
full sequence. In particular the full vector need not be IID.

**3. Existing determinant gap.** For u!=0 let d<=h be its active support.
Let r_j be the centered integer representative of a_j, and put
R(X)=sum_j r_j X^j. Modular evaluation of R vanishes at every root of
X^N+1 except the inverses of the d active alpha_i. At an active inverse it
is N*u_i, which is nonzero. Thus multiplication by R has modular nullity
N-d. The integer multiplication determinant Delta_R is nonzero because
X^N+1 is irreducible over Q and R is a nonzero polynomial of degree below N.
Smith divisibility and Hadamard give

    p^(N-d) divides Delta_R,
    p^(N-d) <= |Delta_R| <= ||r||_2^N,
    E_T(u) >= p^(-2*d/N) >= L_h.

These are the determinant ingredients already retained in the earlier card.

**4. Fixed 2+2 split, with the zero term paid first.** For u!=0,
exp(-4E_T(u))<=exp(-2L_h)*exp(-2E_T(u)). Hence

    Z_T(4) <= exp(-2L_h)*Z_T(2)
             <= exp(-2L_h)*[Theta_p(2N/h)^h-p^-h].

The gap is never applied to u=0. Subtracting p^-h after incorrectly charging
the zero character would not prove this statement.

### Original-support accounting

The exact support decomposition, before any inequality, is

    Z_T(4) = p^-h * sum_{empty!=S subset of T}
                         sum_{u in (F_p^*)^S} exp(-4*E_S(u)).

There are choose(h,d)*(p-1)^d characters at original support size d, each
still with weight p^-h. SB01 covers this entire disjoint union through the
uniform full amplitude vector. It does not assert a conditional window law
after forcing all active amplitudes nonzero, replace the weights by p^-d,
or assign a subspace dimension to an unproved energy stratum.

## Strongest matched controls and prior separation

The equally informed generic receives every proved ingredient above, without
recomputing a source experiment. Its additional ordinary bounds include

| Complete control for the same h-root tuple | Bound on Z_T(4) |
| --- | --- |
| Unsplit window Hölder | Theta_p(4N/h)^h-p^-h |
| Determinant minimum | (1-p^-h)*exp(-4L_h) |
| Consecutive-window nonzero minimum | (1-p^-h)*exp[-4*floor(N/h)/p^2] |
| Frozen gap/window combination | SB01 exactly |

Taking the minimum of valid upper bounds is a known comparison operation.
No winner, strict improvement over these controls, source application or
finite evaluation cost is measured here.

**Scalar and packet control remains stronger than a claimed new mechanism.**
For a complete k=2 or k=4 packet alpha*omega^ell, the field DFT maps the
amplitudes bijectively to k independent scalar amplitudes. With n=N/k,
beta=alpha^k, and F_scalar the corresponding full scalar Laplace sum,

    F_packet(t) = F_scalar(n,beta,t)^k,
    Z_packet(t) = F_scalar(n,beta,t)^k-p^-k.

The rescaling alpha^r of each scalar amplitude permutes its complete sum.
The exact signed root probability likewise factors into the k-th power of
the shorter scalar root probability, by independence of the polynomial's
residue-class coefficient blocks. These are different quantities: a positive
Laplace envelope is not an exact signed root probability. The generic gets
both controls and the two-opposite-pair reduction in the frozen target.
Applying the scalar cover bound to each factor already gives the unsplit
packet cover formula. No packet product or transformed-stratum mechanism is
new here, and a one-active transformed amplitude can have full original
support. SB01 supplies no improved scalar high-order theorem.

The direct known cover mechanism is [Pelekis–Ramon–Wang v1](https://arxiv.org/abs/1511.07204v1),
§3's equal-multiplicity proof and §5's independence-system extension. The
present h-window uniformity supplies precisely those premises. The exact
retained text was reread; this is direct containment, not a dependency-graph
or arbitrary-subset heuristic.

[HPXv2](https://arxiv.org/abs/2201.06156v2), Theorem4.1 and Proposition6.2(2),
already gives prescribed multiple-root Fourier control with degree/order
premises, including reduced supports. Its final quantitative C remains
unprovided by the inspected proof; the retained sign issues are unchanged.
[Breuillard–Varju v2](https://arxiv.org/html/1909.09053v2), §2 Lemma6/Theorem5,
provides scalar high-order energy/mixing controls and a low-order alternative.
Typical-multiplier conclusions do not certify a fixed cyclotomic subgroup.
SB01 does not remove those quantitative losses or prove a sharper finite
cyclotomic high-order certificate. This bounded comparison is not an
exhaustive novelty search.

## Build/stop decision and unpaid consequence

**Retain the lemma as a known supporting bound; stop this attempt as an
original build candidate.** The fixed route closes its mathematical output
contract, but produces no prior-separating lemma. The generic formula ratio
is 1 by shared derivation, with no implementation or timing claim. There is
no second approach, parameter tuning, source calculation or automatic scan
in this packet.

The Fourier consequence for raw IID ternary coefficients is only the ordinary
inequality `|P[all h roots vanish]-p^-h|<=Z_T(4)`, using the already reviewed
characteristic envelope. No value of either probability was evaluated.
Literal evaluation of Theta contains p scalar terms; a fast rigorous
evaluation method, precision, time and state have not been supplied. Complete
root-subset/all-limb/epoch adaptation remains a separate paid step.

Honest enrollment and same-domain input totals, allocated complete-system
failure budget, parameter assurance, actual owner enrollment and source
guard admission remain unresolved in the [eligibility card](source-certificate-eligibility-screen-20261003.md).
No budget or missing cost is assigned zero. A mathematical allowance cannot
verify complete server execution or authorize private release. Context
binding, setup/updates, proof/certificate checking, protected residency,
attestation/transport, private side channels and the permitted plaintext
cache/full protected replay/ring-proof competitors remain paid unknowns.
No owner API, sampler, key law, guard, production scheme or security claim
changes. The [attempt receipt](../../../research-data/system-selection-20261003/fourier-attempt/attempt-receipt.json)
pins the freeze, report and bounded exact-primary/source readings. No new
paper pair or registry entry was acquired.
