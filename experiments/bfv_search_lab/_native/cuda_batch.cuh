// Included inside cuhepy_bgv_lab after the single-query kernel helpers.
// Distinct queries share public keys/index only; no cross-query arithmetic.
#pragma once
namespace cuda_detail {

__global__ void tensor_many(const U* queries, const U* index, U* out, const Parameters* p,
                            int batch, int requests) {
    int at = blockIdx.x*blockDim.x+threadIdx.x, n = p->n;
    if (at >= requests*batch*2*n) return;
    int i = at%n, j = (at/n)%2, b = at/(2*n), request = b/batch, tile = b%batch;
    auto prime = p->primes[j];
    U a = queries[(request*4+j)*n+i], c = queries[(request*4+2+j)*n+i];
    U x = index[(tile*4+j)*n+i], y = index[(tile*4+2+j)*n+i];
    out[(b*6+j)*n+i] = product(a,x,prime);
    out[(b*6+2+j)*n+i] = add(product(a,y,prime),product(c,x,prime),prime.p);
    out[(b*6+4+j)*n+i] = product(c,y,prime);
}

// One warp per query; each block loads an index strip once for all requests.
// Both component stores remain coalesced within each warp. No thread exits
// before the barrier; launch exactly 32*requests threads and N/32 blocks in x.
__global__ void tensor_many_shared(const U* queries, const U* index, U* out, const Parameters* p,
                                   int batch) {
    __shared__ U first[32], second[32];
    int lane = threadIdx.x%32, request = threadIdx.x/32;
    int n = p->n, i = blockIdx.x*32+lane, tile = blockIdx.y, j = blockIdx.z;
    if (threadIdx.x < 32) {
        first[lane] = index[(tile*4+j)*n+i];
        second[lane] = index[(tile*4+2+j)*n+i];
    }
    __syncthreads();
    auto prime = p->primes[j];
    U a = queries[(request*4+j)*n+i], c = queries[(request*4+2+j)*n+i];
    U x = first[lane], y = second[lane];
    int b = request*batch+tile;
    out[(b*6+j)*n+i] = product(a,x,prime);
    out[(b*6+2+j)*n+i] = add(product(a,y,prime),product(c,x,prime),prime.p);
    out[(b*6+4+j)*n+i] = product(c,y,prime);
}

// Each stage compacts active -> count tiles WITHIN each request. The next
// key switch can then treat all request*count ciphertexts as one batch.
__global__ void gather_digits_many(const U* work, U* digits, const Parameters* p,
                                    int active, int count, int shift, U inverse, int requests) {
    int at = blockIdx.x*blockDim.x+threadIdx.x, n = p->n;
    if (at >= requests*count*n) return;
    int i = at%n, output = at/n, request = output/count, tile = output%count;
    int b = request*active+tile, source = (i*inverse)%(2*n);
    U difference[2];
    #pragma unroll
    for (int j = 0; j < 2; ++j) {
        U prime = p->primes[j].p, rhs = 0;
        if (tile+shift < active) rhs = shifted_coefficient(work,b+shift,2+j,source%n,shift,n,prime);
        U v = sub(work[(b*4+2+j)*n+source%n],rhs,prime);
        difference[j] = source >= n && v ? prime-v : v;
    }
    write_digits(difference[0],difference[1],digits,*p,output,i);
}

__global__ void gather_merge_many(const U* work, const U* switched, U* output, const Parameters* p,
                                   int active, int count, int shift, U inverse, int requests) {
    int at = blockIdx.x*blockDim.x+threadIdx.x, n = p->n;
    if (at >= requests*count*4*n) return;
    int i = at%n, j = (at/n)%2, c = (at/(2*n))%2, out = at/(4*n), poly = c*2+j;
    int request = out/count, tile = out%count, b = request*active+tile;
    U prime = p->primes[j].p, rhs = 0;
    if (tile+shift < active) rhs = shifted_coefficient(work,b+shift,poly,i,shift,n,prime);
    U value = add(add(work[(b*4+poly)*n+i],rhs,prime),switched[at],prime);
    if (!c) {
        int source = (i*inverse)%(2*n);
        U right = 0;
        if (tile+shift < active) right = shifted_coefficient(work,b+shift,j,source%n,shift,n,prime);
        U v = sub(work[(b*4+j)*n+source%n],right,prime);
        if (source >= n && v) v = prime-v;
        value = add(value,v,prime);
    }
    output[at] = value;
}
} // namespace cuda_detail
