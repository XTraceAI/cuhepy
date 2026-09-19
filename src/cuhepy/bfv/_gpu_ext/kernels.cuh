// Public BFV evaluation only. No secret key, encryption, or decryption runs here.
// Layout: [tile][component (or gadget digit)][prime][coefficient]. All kernel
// boundaries hold canonical residues. Q has three 60-bit primes; B has four.
#pragma once
#include <cuda_runtime.h>

namespace xtrace_bfv::gpu {
using U = unsigned long long;
struct Mul { U value, quotient; };
struct Prime { U p, reciprocal_low, reciprocal_high; };
struct Parameters {
    int n, t, t_bits;
    Prime primes[7];
    Mul inverse[7][7], prime_mod[7][7], inverse_q[4];
    U b_mod_q[3], half_b[4], shifted_q[31][4], half_q[4];
    U q_words[4];
    Mul radix64[3];
};

__device__ inline U add(U a, U b, U p) { U s = a + b; return s >= p ? s - p : s; }
__device__ inline U sub(U a, U b, U p) { return a >= b ? a - b : a + p - b; }
__device__ inline U mul(U a, Mul b, U p) {
    U r = a * b.value - __umul64hi(a, b.quotient) * p;
    return r >= p ? r - p : r;
}
__device__ inline U product(U a, U b, Prime p) {
    // Barrett reduction of a 128-bit product using four 64x64 products. Every
    // modulus is below 2^60, so the quotient estimate needs one correction.
    U lo = a * b, hi = __umul64hi(a, b);
    U a0 = __umul64hi(lo, p.reciprocal_low);
    U a1 = lo * p.reciprocal_high, a2 = hi * p.reciprocal_low;
    U middle = a0 + a1, carry = middle < a0;
    U next = middle + a2; carry += next < middle;
    U q = hi * p.reciprocal_high + __umul64hi(lo, p.reciprocal_high)
        + __umul64hi(hi, p.reciprocal_low) + carry;
    U r = lo - q * p.p;
    return r >= p.p ? r - p.p : r;
}

// Exact mixed-radix CRT. The primes are all in (2^59,2^60), allowing a single
// subtraction to reduce a mixed-radix digit into any other prime in the base.
__device__ inline void garner(U* digits, int start, int count, const Parameters& p) {
    for (int j = 0; j < count; ++j) {
        U mod = p.primes[start + j].p;
        for (int k = 0; k < j; ++k) {
            U d = digits[k]; if (d >= mod) d -= mod;
            digits[j] = mul(sub(digits[j], d, mod), p.inverse[start+j][start+k], mod);
        }
    }
}
__device__ inline U extend(const U* digits, int start, int count, int to, const Parameters& p) {
    U mod = p.primes[to].p, r = digits[count-1];
    if (r >= mod) r -= mod;
    for (int k = count-2; k >= 0; --k) {
        U d = digits[k]; if (d >= mod) d -= mod;
        r = add(mul(r, p.prime_mod[to][start+k], mod), d, mod);
    }
    return r;
}
__device__ inline void words(const U* digits, int start, int count, U* out, const Parameters& p) {
    out[0] = digits[count-1]; out[1] = out[2] = out[3] = 0;
    for (int k = count-2; k >= 0; --k) {
        U carry = digits[k], prime = p.primes[start+k].p;
        for (int w = 0; w < 4; ++w) {
            U lo = out[w] * prime, hi = __umul64hi(out[w], prime);
            out[w] = lo + carry; carry = hi + (out[w] < lo);
        }
    }
}
__device__ inline bool at_least(const U* a, const U* b) {
    for (int w = 3; w >= 0; --w) if (a[w] != b[w]) return a[w] > b[w];
    return true;
}
__device__ inline void subtract_words(U* a, const U* b) {
    U borrow = 0;
    for (int w = 0; w < 4; ++w) {
        U old = a[w], d = old - b[w], next = d - borrow;
        borrow = (old < b[w]) | (d < borrow); a[w] = next;
    }
}

// Decode the unchanged 180-bit packed wire directly on the device. Each
// component is padded with one zero word by the uploader for the final shifted
// read. Reject >=Q before evaluating, including coefficients in unused slots.
__global__ void unpack_residues(const U* packed, U* out, unsigned* invalid,
                                 const Parameters* plan, int batch, int stride) {
    int at = blockIdx.x*blockDim.x+threadIdx.x, n = plan->n;
    if (at >= batch*2*n) return;
    int poly = at/n, i = at%n, offset = (i*180)/64, shift = (i*180)%64;
    const U* source = packed+poly*stride+offset;
    U value[4]{};
    for (int w = 0; w < 3; ++w) {
        value[w] = source[w]>>shift;
        if (shift) value[w] |= source[w+1]<<(64-shift);
    }
    value[2] &= (U(1)<<52)-1;
    if (at_least(value,plan->q_words)) { atomicExch(invalid,1U); return; }
    for (int j = 0; j < 3; ++j) {
        Prime prime = plan->primes[j];
        U result = value[2]; // Fewer than 60 bits.
        result = add(mul(result,plan->radix64[j],prime.p),product(value[1],1,prime),prime.p);
        result = add(mul(result,plan->radix64[j],prime.p),product(value[0],1,prime),prime.p);
        out[(poly*3+j)*n+i] = result;
    }
}

__global__ void difference(const U* query, const U* index, U* out, const Parameters* plan, int batch) {
    const auto& p = *plan;
    int at = blockIdx.x * blockDim.x + threadIdx.x;
    if (at >= batch * 2 * p.n) return;
    int i = at % p.n, c = (at / p.n) % 2, b = at / (2*p.n);
    U d[3];
    for (int j = 0; j < 3; ++j) {
        int pos = (c*3+j)*p.n+i;
        d[j] = sub(query[pos], index[b*6*p.n+pos], p.primes[j].p);
        out[((b*2+c)*7+j)*p.n+i] = d[j];
    }
    // BFV tensor multiplication uses the canonical integer lift in [0,Q).
    garner(d, 0, 3, p);
    for (int j = 3; j < 7; ++j) out[((b*2+c)*7+j)*p.n+i] = extend(d, 0, 3, j, p);
}

__global__ void ntt_stage(U* data, const Mul* roots, const Parameters* plan,
                          int primes, int polys, int groups, bool inverse) {
    const auto& p = *plan;
    int at = blockIdx.x * blockDim.x + threadIdx.x;
    if (at >= polys * primes * (p.n/2)) return;
    int butterfly = at % (p.n/2), poly = at / (p.n/2), j = poly % primes;
    int gap = p.n / (2*groups), group = butterfly / gap, offset = butterfly % gap;
    int pos = poly*p.n + 2*group*gap + offset;
    U mod = p.primes[j].p, a = data[pos], b = data[pos+gap];
    Mul root = roots[j*p.n+groups+group];
    if (inverse) {
        data[pos] = add(a, b, mod);
        data[pos+gap] = mul(sub(a, b, mod), root, mod);
    } else {
        b = mul(b, root, mod);
        data[pos] = add(a, b, mod); data[pos+gap] = sub(a, b, mod);
    }
}
__global__ void normalize(U* data, const Mul* inverse_n, const Parameters* plan, int primes, int size) {
    int at = blockIdx.x * blockDim.x + threadIdx.x;
    if (at < size) { int j = (at / plan->n) % primes; data[at] = mul(data[at], inverse_n[j], plan->primes[j].p); }
}

// Split an NTT into two shared-memory passes, retaining the baseline's exact
// butterfly order. The outer pass owns every row for a strip of columns; the
// inner pass owns one contiguous row. No butterfly crosses a block boundary
// within either pass. For N<=1024, one block owns the whole polynomial.
// N<=32768 leaves at least 32 adjacent columns in each outer strip, so global
// loads/stores remain coalesced. All threads reach every block barrier.
template<int Primes, bool Inverse, bool Outer>
__global__ void ntt_fused(U* data, const Mul* roots, const Mul* inverse_n,
                          const Parameters* plan) {
    constexpr int tile = 1024;
    __shared__ U values[tile];
    int n = plan->n, row_size = n < tile ? n : tile;
    int rows = n/row_size, columns = tile/rows;
    int poly = blockIdx.y, chunk = blockIdx.x, j = poly % Primes;
    int size = Outer ? tile : row_size;
    U mod = plan->primes[j].p;
    for (int i = threadIdx.x; i < size; i += blockDim.x) {
        int position = Outer ? (i/columns)*row_size + chunk*columns + i%columns : chunk*row_size+i;
        values[i] = data[poly*n+position];
    }
    __syncthreads();
    int last = Outer ? rows/2 : row_size/2;
    for (int groups = Inverse ? last : 1;
         Inverse ? groups >= 1 : groups <= last;
         groups = Inverse ? groups/2 : groups*2) {
        int gap = size/(2*groups);
        for (int at = threadIdx.x; at < size/2; at += blockDim.x) {
            int group = at/gap, position = 2*group*gap + at%gap;
            int root_index = Outer ? groups+group : rows*groups+chunk*groups+group;
            U a = values[position], b = values[position+gap];
            Mul root = roots[j*n+root_index];
            if constexpr (Inverse) {
                values[position] = add(a,b,mod);
                values[position+gap] = mul(sub(a,b,mod),root,mod);
            } else {
                b = mul(b,root,mod);
                values[position] = add(a,b,mod);
                values[position+gap] = sub(a,b,mod);
            }
        }
        __syncthreads();
    }
    for (int i = threadIdx.x; i < size; i += blockDim.x) {
        int position = Outer ? (i/columns)*row_size + chunk*columns + i%columns : chunk*row_size+i;
        U value = values[i];
        if constexpr (Inverse) if (Outer || n<=tile) value = mul(value,inverse_n[j],mod);
        data[poly*n+position] = value;
    }
}
__global__ void square(const U* a, U* out, const Parameters* plan, int batch) {
    int at = blockIdx.x * blockDim.x + threadIdx.x;
    int n = plan->n;
    if (at >= batch*7*n) return;
    int b = at/(7*n), pos = at%(7*n), j = pos/n;
    Prime p = plan->primes[j];
    U x = a[b*14*n+pos], y = a[b*14*n+7*n+pos];
    out[b*21*n+pos] = product(x, x, p);
    U xy = product(x, y, p);
    out[b*21*n+7*n+pos] = add(xy, xy, p.p);
    out[b*21*n+14*n+pos] = product(y, y, p);
}
__global__ void scale_round(const U* tensor, U* out, const Parameters* plan, int batch) {
    const auto& p = *plan;
    int at = blockIdx.x * blockDim.x + threadIdx.x;
    if (at >= batch*3*p.n) return;
    int poly = at/p.n, i = at%p.n;
    U r[3], k[4], rw[4], kw[4];
    for (int j = 0; j < 3; ++j) r[j] = tensor[(poly*7+j)*p.n+i];
    garner(r, 0, 3, p);
    for (int j = 0; j < 4; ++j) {
        U z = tensor[(poly*7+j+3)*p.n+i], mod = p.primes[j+3].p;
        k[j] = mul(sub(z, extend(r, 0, 3, j+3, p), mod), p.inverse_q[j], mod);
    }
    garner(k, 3, 4, p); words(k, 3, 4, kw, p); words(r, 0, 3, rw, p);
    bool negative = at_least(kw, p.half_b); // half_b = ceil(B/2), B odd.
    // floor((t*r + floor(Q/2))/Q), using only exact integer operations.
    U carry = 0;
    for (int w = 0; w < 4; ++w) {
        U lo = rw[w]*p.t, hi = __umul64hi(rw[w], U(p.t));
        rw[w] = lo+carry; carry = hi+(rw[w]<lo);
    }
    carry = 0;
    for (int w = 0; w < 4; ++w) {
        U a = rw[w]+p.half_q[w], c = a<rw[w], b = a+carry;
        carry = c | (b<a); rw[w] = b;
    }
    U rounded = 0;
    for (int bit = p.t_bits-1; bit >= 0; --bit)
        if (at_least(rw, p.shifted_q[bit])) { subtract_words(rw, p.shifted_q[bit]); rounded |= U(1)<<bit; }
    for (int j = 0; j < 3; ++j) {
        U mod = p.primes[j].p, value = extend(k, 3, 4, j, p);
        if (negative) value = sub(value, p.b_mod_q[j], mod);
        out[(poly*3+j)*p.n+i] = add(product(value, p.t, p.primes[j]), rounded, mod);
    }
}
__global__ void decompose(const U* src, U* dst, const Parameters* plan, int batch, int components, int component) {
    const auto& p = *plan;
    int at = blockIdx.x * blockDim.x + threadIdx.x;
    if (at >= batch*p.n) return;
    int b = at/p.n, i = at%p.n;
    U digits[3], limbs[4];
    for (int j = 0; j < 3; ++j) digits[j] = src[((b*components+component)*3+j)*p.n+i];
    garner(digits, 0, 3, p); words(digits, 0, 3, limbs, p);
    for (int d = 0; d < 6; ++d) {
        int start = d*30, word = start/64, shift = start%64;
        U value = limbs[word]>>shift;
        if (shift) value |= limbs[word+1]<<(64-shift);
        value &= (U(1)<<30)-1;
        for (int j = 0; j < 3; ++j) dst[((b*6+d)*3+j)*p.n+i] = value;
    }
}
__global__ void key_product(const U* digits, const Mul* key, U* dst, const Parameters* plan, int batch) {
    const auto& p = *plan;
    int at = blockIdx.x * blockDim.x + threadIdx.x;
    if (at >= batch*6*p.n) return;
    int b = at/(6*p.n), pos = at%(6*p.n), c = pos/(3*p.n), j = (pos/p.n)%3, i = pos%p.n;
    U total = 0, mod = p.primes[j].p;
    for (int d = 0; d < 6; ++d)
        total = add(total, mul(digits[((b*6+d)*3+j)*p.n+i], key[((d*2+c)*3+j)*p.n+i], mod), mod);
    dst[at] = total;
}

// Eight ciphertexts share a coefficient strip of the same public key. Load the
// key once per block, reuse each gadget digit for both output components, and
// keep adjacent lanes on adjacent coefficients. Separate shared arrays avoid
// the extra bank conflicts of a 16-byte array-of-structures layout.
__global__ void key_product_tiled(const U* __restrict__ digits, const Mul* __restrict__ key,
                                  U* __restrict__ dst, const Parameters* plan, int batch) {
    constexpr int lanes = 32, tiles = 8;
    __shared__ U values[6][2][lanes], quotients[6][2][lanes];
    int n = plan->n, j = blockIdx.z, start = blockIdx.x*lanes;
    for (int at = threadIdx.x; at < 6*2*lanes; at += blockDim.x) {
        int d = at/(2*lanes), c = (at/lanes)%2, lane = at%lanes;
        Mul value = key[((d*2+c)*3+j)*n+start+lane];
        values[d][c][lane] = value.value; quotients[d][c][lane] = value.quotient;
    }
    __syncthreads();
    int lane = threadIdx.x%lanes, b = blockIdx.y*tiles+threadIdx.x/lanes;
    if (b >= batch) return;
    U mod = plan->primes[j].p, sum0 = 0, sum1 = 0;
    #pragma unroll
    for (int d = 0; d < 6; ++d) {
        U digit = digits[((b*6+d)*3+j)*n+start+lane];
        sum0 = add(sum0,mul(digit,{values[d][0][lane],quotients[d][0][lane]},mod),mod);
        sum1 = add(sum1,mul(digit,{values[d][1][lane],quotients[d][1][lane]},mod),mod);
    }
    dst[(b*6+j)*n+start+lane] = sum0;
    dst[(b*6+3+j)*n+start+lane] = sum1;
}
__global__ void add_linear(U* out, const U* scaled, const Parameters* plan, int batch) {
    int at = blockIdx.x * blockDim.x + threadIdx.x, n = plan->n;
    if (at < batch*6*n) {
        int b = at/(6*n), pos = at%(6*n), j = (pos/n)%3;
        out[at] = add(out[at], scaled[b*9*n+pos], plan->primes[j].p);
    }
}
__global__ void permute(const U* src, U* dst, const Parameters* plan, int batch, U exponent, int first, int step) {
    int at = blockIdx.x * blockDim.x + threadIdx.x, n = plan->n;
    if (at >= batch*6*n) return;
    int b = at/(6*n), pos = at%(6*n), i = pos%n, j = (pos/n)%3;
    U value = src[(first+b*step)*6*n+pos], target = (i*exponent)&(2*n-1);
    if (target >= U(n) && value) value = plan->primes[j].p-value;
    dst[b*6*n+(pos/n)*n+(target&(n-1))] = value;
}
__global__ void add_rotation(U* out, const U* rotated, const U* permuted,
                             const Parameters* plan, int batch, int first, int step) {
    int at = blockIdx.x * blockDim.x + threadIdx.x, n = plan->n;
    if (at >= batch*6*n) return;
    int b = at/(6*n), pos = at%(6*n), c = pos/(3*n), j = (pos/n)%3;
    U mod = plan->primes[j].p, value = rotated[at];
    if (!c) value = add(value, permuted[at], mod);
    int target = (first+b*step)*6*n+pos;
    out[target] = add(out[target], value, mod);
}
__global__ void mask_product(U* data, const Mul* full, const Mul* partial,
                             const Parameters* plan, int batch, bool last_partial) {
    int at = blockIdx.x * blockDim.x + threadIdx.x, n = plan->n;
    if (at < batch*6*n) {
        int b = at/(6*n), pos = at%(3*n), j = pos/n;
        data[at] = mul(data[at], (last_partial && b==batch-1 ? partial : full)[pos], plan->primes[j].p);
    }
}
} // namespace xtrace_bfv::gpu
