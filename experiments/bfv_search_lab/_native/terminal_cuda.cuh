// Exact PUBLIC terminal reduction directly from the two CUDA RNS limbs.
// Q<=120 bits, P<2^60 and t<2^30 keep every intermediate below 192 bits.
// No floating point, secret key, approximate CRT, or changed rounding rule.
#pragma once
#include "compact.h"
#include "../_gpu_ext/server.cuh"

namespace cuhepy_bgv_lab::terminal_gpu {
using namespace xtrace_bfv::gpu;
struct Plan {
    U p, t, radix_t, q[3], qt[3], denominators[60][3];
    int bits;
};

inline void copy_words(const mpz_class& value, U* output) {
    if (value<0 || mpz_sizeinbase(value.get_mpz_t(),2)>192)
        throw std::invalid_argument("Terminal word bound exceeded");
    for (int i=0;i<3;++i) output[i]=mpz_getlimbn(value.get_mpz_t(),i);
}
inline Plan make_plan(const mpz_class& q, const TerminalReduction& reduction) {
    if (mpz_sizeinbase(q.get_mpz_t(),2)>120)
        throw std::invalid_argument("GPU terminal reduction requires Q<=120 bits");
    Plan plan{};
    plan.p=reduction.modulus.get_ui(); plan.t=reduction.t;
    mpz_class radix=mpz_class(1)<<64;
    plan.radix_t=mpz_fdiv_ui(radix.get_mpz_t(),plan.t);
    copy_words(q,plan.q); copy_words(q*reduction.t,plan.qt);
    U maximum=plan.p/plan.t+1;
    for (U value=maximum;value;value>>=1) ++plan.bits;
    for (int i=0;i<plan.bits;++i) copy_words((2*q*reduction.t)<<i,plan.denominators[i]);
    return plan;
}

__device__ inline bool greater_equal(const U* a,const U* b) {
    for (int i=2;i>=0;--i) if (a[i]!=b[i]) return a[i]>b[i];
    return true;
}
__device__ inline void subtract(U* a,const U* b) {
    U borrow=0;
    for (int i=0;i<3;++i) {
        U difference=a[i]-b[i], next=difference-borrow;
        borrow=(a[i]<b[i])|(difference<borrow); a[i]=next;
    }
}
__device__ inline void multiply_word(const U* a,U b,U* out) {
    U carry=0;
    for (int i=0;i<3;++i) {
        U low=a[i]*b,high=__umul64hi(a[i],b);
        out[i]=low+carry; carry=high+(out[i]<low);
    }
}
__device__ inline void add_words(U* a,const U* b) {
    U carry=0;
    for (int i=0;i<3;++i) {
        U sum=a[i]+b[i],next=sum+carry;
        carry=(sum<a[i])|(next<sum); a[i]=next;
    }
}
__device__ inline U reduce(const U* c,const Plan& plan) {
    U residue=(c[0]%plan.t+(c[1]%plan.t)*plan.radix_t)%plan.t;
    U numerator[3], removed[3];
    multiply_word(c,2*plan.p,numerator);
    add_words(numerator,plan.qt);
    multiply_word(plan.q,2*residue,removed);
    // floor((2*P*c - 2*Q*(c mod t) + Q*t)/(2*Q*t)).
    // A negative numerator is greater than -Q*t, hence its quotient is -1.
    if (!greater_equal(numerator,removed)) return plan.p-plan.t+residue;
    subtract(numerator,removed);
    U quotient=0;
    for (int bit=plan.bits-1;bit>=0;--bit) {
        if (greater_equal(numerator,plan.denominators[bit])) {
            subtract(numerator,plan.denominators[bit]); quotient|=U(1)<<bit;
        }
    }
    U result=quotient*plan.t+residue;
    return result>=plan.p ? result-plan.p : result;
}

__global__ void compact(const U* input,U* output,const Parameters* rns,const Plan* terminal) {
    int at=blockIdx.x*blockDim.x+threadIdx.x,n=rns->n;
    if (at>=2*n) return;
    int component=at/n,i=at%n;
    U digits[2]={input[(component*2)*n+i],input[(component*2+1)*n+i]},c[4];
    garner(digits,0,2,*rns); words(digits,0,2,c,*rns);
    output[at]=reduce(c,*terminal);
}
} // namespace cuhepy_bgv_lab::terminal_gpu
