# E108: stronger shared bit-expanded control amendment

2026-10-03 UTC. Freeze before evaluating either new constraint model. This
adds a stronger comparison to the unchanged [original registration](native-proof-interface-preregistration.md).
It does not rewrite the baseline or retroactively claim a candidate-only gain.

Both the native adapter and the generic scalar R1CS control may eliminate the32
preterminal C variables, using C=-t*P^-1*r modulo BOTH Q limbs and unique
canonical CRT reconstruction. Source and centered remainder variables remain
canonical in[0,Q). Their single shared scalar bit strings determine all digits.
For u=r+H, H=(Q-1)/2, substitute the integer bit powers into every affine row,
reduce the resulting coefficients modulo each named prime and move the original
query contribution to a locally owner-computed canonical public RHS. All query
expansion/RHS work is paid and never trusted from the server. Static index/key
constants and sparse circuit shape are reusable; public RHS depends on the query.

A limb row has form sum(a_j*b_j)+p-rhs=p*k, with 0<=a_j<p, shared scalar bits
and 0<=rhs<p. At most13,440 shared bits imply 0<=k<=13,441; a14-bit quotient
is sufficient, and a tighter bound may be compiled from the actual row. The
reduced terminal row uses a_j=(t*2^j) modP, h=(Q*y+t*H) modP, and
sum(a_j*u_j)+P-h=P*v, with0<=v<=121 and a7-bit quotient. Exact range slack
for each quotient must still be charged if enforcing the tighter interval.
All rows must have a proved integer residual bound below the scalar field.
No Boolean identity over a CRT product or independent limb bits is substituted.

Base bit strings with exact Q range slack: (80 sources+32 remainders)*2*120
=26,880 Boolean gates, before quotient bits. Removing C saves7,680 baseline
Boolean gates. Bit-coefficient folding shortens quotients but can substantially
increase coefficient nonzeros and preprocessing/online RHS work; price all of
these. Generic compilation receives identical elimination/folding, so the
candidate-to-strongest-generic ratio remains1 unless a distinct mechanism is
independently demonstrated. Neither counts nor sparse R1CS satisfaction are a
cryptographic proof, proof byte estimate, security assurance or runtime panel.

Execute the baseline and stronger control on the same eight frozen original
queries. Compare their accepted complete response bytes and rejection cases.
If constrained implementation time prevents the stronger model, report it as
unimplemented and do not present the baseline as best generic verification.
The bounded cap and return-to-R6 rules are unchanged.
