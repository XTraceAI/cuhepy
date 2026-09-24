// Experimental BGV public evaluator: two ciphertext primes, four gadget digits.
// Reuse cuhepy's validated modular primitives, fused NTTs, and CUDA RAII owners.
// Secret keys and private operations never enter this module.
#pragma once
#include "trace_server.h"
#include "../_gpu_ext/server.cuh"

namespace cuhepy_bgv_lab {
namespace cuda_detail {
using namespace xtrace_bfv::gpu;

__global__ void tensor(const U* query, const U* index, U* out, const Parameters* p, int batch) {
    int at = blockIdx.x * blockDim.x + threadIdx.x, n = p->n;
    if (at >= batch * 2 * n) return;
    int i = at % n, j = (at / n) % 2, b = at / (2 * n);
    auto prime = p->primes[j];
    U a = query[j*n+i], c = query[(2+j)*n+i];
    U x = index[(b*4+j)*n+i], y = index[(b*4+2+j)*n+i];
    out[(b*6+j)*n+i] = product(a,x,prime);
    out[(b*6+2+j)*n+i] = add(product(a,y,prime),product(c,x,prime),prime.p);
    out[(b*6+4+j)*n+i] = product(c,y,prime);
}

__device__ inline void write_digits(U first, U second, U* out, const Parameters& p, int b, int i) {
    U values[2] = {first, second};
    garner(values,0,2,p);
    U value[4];
    words(values,0,2,value,p);
    for (int digit = 0; digit < 4; ++digit) {
        int bit = 30*digit, limb = bit/64, offset = bit%64;
        U v = value[limb] >> offset;
        if (offset) v |= value[limb+1] << (64-offset);
        v &= (U(1)<<30)-1;
        out[((b*4+digit)*2)*p.n+i] = v;
        out[((b*4+digit)*2+1)*p.n+i] = v;
    }
}

__global__ void digits(const U* source, U* out, const Parameters* p, int batch, int components, int component) {
    int at = blockIdx.x * blockDim.x + threadIdx.x, n = p->n;
    if (at >= batch * n) return;
    int b = at/n, i = at%n;
    write_digits(source[(b*components*2+component*2)*n+i],
                 source[(b*components*2+component*2+1)*n+i],out,*p,b,i);
}

__global__ void key_product(const U* input, const Mul* key, U* output, const Parameters* p, int batch) {
    int at = blockIdx.x*blockDim.x+threadIdx.x, n = p->n;
    if (at >= batch*4*n) return;
    int i = at%n, j = (at/n)%2, c = (at/(2*n))%2, b = at/(4*n);
    U value = 0, prime = p->primes[j].p;
    for (int digit = 0; digit < 4; ++digit)
        value = add(value,mul(input[((b*4+digit)*2+j)*n+i],key[((digit*2+c)*2+j)*n+i],prime),prime);
    output[at] = value;
}

// Reuse each key coefficient across eight ciphertexts and each input digit for
// both output components. The baseline remains available for paired ablations.
__global__ void key_product_tiled(const U* __restrict__ input, const Mul* __restrict__ key,
                                   U* __restrict__ output, const Parameters* p, int batch) {
    constexpr int lanes = 32, tiles = 8;
    __shared__ U values[4][2][lanes], quotients[4][2][lanes];
    int n = p->n, j = blockIdx.z, start = blockIdx.x*lanes;
    for (int at = threadIdx.x; at < 4*2*lanes; at += blockDim.x) {
        int d = at/(2*lanes), c = (at/lanes)%2, lane = at%lanes;
        Mul value = key[((d*2+c)*2+j)*n+start+lane];
        values[d][c][lane] = value.value;
        quotients[d][c][lane] = value.quotient;
    }
    __syncthreads();
    int lane = threadIdx.x%lanes, b = blockIdx.y*tiles+threadIdx.x/lanes;
    if (b >= batch) return;
    U prime = p->primes[j].p, sum0 = 0, sum1 = 0;
    #pragma unroll
    for (int d = 0; d < 4; ++d) {
        U digit = input[((b*4+d)*2+j)*n+start+lane];
        sum0 = add(sum0,mul(digit,{values[d][0][lane],quotients[d][0][lane]},prime),prime);
        sum1 = add(sum1,mul(digit,{values[d][1][lane],quotients[d][1][lane]},prime),prime);
    }
    output[(b*4+j)*n+start+lane] = sum0;
    output[(b*4+2+j)*n+start+lane] = sum1;
}

__global__ void initial_shift(const U* tensor, const U* switched, U* work, const Parameters* p, int batch, int shift) {
    int at = blockIdx.x*blockDim.x+threadIdx.x, n = p->n;
    if (at >= batch*4*n) return;
    int i = at%n, j = (at/n)%2, c = (at/(2*n))%2, b = at/(4*n);
    int target = (i+shift)%(2*n);
    U prime = p->primes[j].p, v = add(tensor[(b*6+c*2+j)*n+i],switched[at],prime);
    work[(b*4+c*2+j)*n+target%n] = target >= n && v ? prime-v : v;
}

// Build the sum and the automorphism of the difference in one pass. Each output
// address has exactly one writer because the Galois exponent is odd.
__global__ void butterfly_inputs(const U* work, U* plus, U* permuted, const Parameters* p,
                                 int active, int count, int shift, U exponent) {
    int at = blockIdx.x*blockDim.x+threadIdx.x, n = p->n;
    if (at >= count*4*n) return;
    int i = at%n, j = (at/n)%2, c = (at/(2*n))%2, b = at/(4*n);
    U prime = p->primes[j].p, a = work[at], rhs = 0;
    if (b+shift < active) {
        int source = (i+2*n-shift)%(2*n);
        rhs = work[((b+shift)*4+c*2+j)*n+source%n];
        if (source >= n && rhs) rhs = prime-rhs;
    }
    plus[at] = add(a,rhs,prime);
    U v = sub(a,rhs,prime);
    int target = (i*exponent)%(2*n);
    permuted[(b*4+c*2+j)*n+target%n] = target >= n && v ? prime-v : v;
}

// Form the next stage's sum, permuted c0, and gadget digits of permuted c1
// together. Exact CRT happens AFTER the negacyclic sign, since gadget digits
// require the canonical representative in [0,Q). No permuted c1 buffer exists.
__global__ void butterfly_digits(const U* work, U* plus, U* permuted0, U* digits,
                                  const Parameters* p, int active, int count, int shift, U exponent) {
    int at = blockIdx.x*blockDim.x+threadIdx.x, n = p->n;
    if (at >= count*n) return;
    int i = at%n, b = at/n, target = (i*exponent)%(2*n);
    U difference1[2];
    #pragma unroll
    for (int c = 0; c < 2; ++c) {
        #pragma unroll
        for (int j = 0; j < 2; ++j) {
            U prime = p->primes[j].p, a = work[(b*4+c*2+j)*n+i], rhs = 0;
            if (b+shift < active) {
                int source = (i+2*n-shift)%(2*n);
                rhs = work[((b+shift)*4+c*2+j)*n+source%n];
                if (source >= n && rhs) rhs = prime-rhs;
            }
            plus[(b*4+c*2+j)*n+i] = add(a,rhs,prime);
            U v = sub(a,rhs,prime);
            if (target >= n && v) v = prime-v;
            if (c) difference1[j] = v;
            else permuted0[(b*2+j)*n+target%n] = v;
        }
    }
    write_digits(difference1[0],difference1[1],digits,*p,b,target%n);
}

__device__ inline U shifted_coefficient(const U* work, int b, int poly, int i,
                                        int shift, int n, U prime) {
    int source = (i+2*n-shift)%(2*n);
    U value = work[(b*4+poly)*n+source%n];
    return source >= n && value ? prime-value : value;
}

// Gather using sigma^-1 so the eight gadget-polynomial stores are coalesced.
// The first fused experiment scattered all eight; fewer launches alone did not
// compensate for that traffic. No sum or permuted-component buffer is written.
__global__ void gather_digits(const U* work, U* digits, const Parameters* p,
                               int active, int count, int shift, U inverse_exponent) {
    int at = blockIdx.x*blockDim.x+threadIdx.x, n = p->n;
    if (at >= count*n) return;
    int i = at%n, b = at/n, source = (i*inverse_exponent)%(2*n);
    U difference[2];
    #pragma unroll
    for (int j = 0; j < 2; ++j) {
        U prime = p->primes[j].p, rhs = 0;
        if (b+shift < active) rhs = shifted_coefficient(work,b+shift,2+j,source%n,shift,n,prime);
        U v = sub(work[(b*4+2+j)*n+source%n],rhs,prime);
        difference[j] = source >= n && v ? prime-v : v;
    }
    write_digits(difference[0],difference[1],digits,*p,b,i);
}

// Ping-pong output is necessary: sigma's reads span other threads' input
// coefficients. In-place writes would introduce a cross-block data race.
__global__ void gather_merge(const U* work, const U* switched, U* output, const Parameters* p,
                              int active, int count, int shift, U inverse_exponent) {
    int at = blockIdx.x*blockDim.x+threadIdx.x, n = p->n;
    if (at >= count*4*n) return;
    int i = at%n, j = (at/n)%2, c = (at/(2*n))%2, b = at/(4*n), poly = c*2+j;
    U prime = p->primes[j].p, rhs = 0;
    if (b+shift < active) rhs = shifted_coefficient(work,b+shift,poly,i,shift,n,prime);
    U value = add(add(work[at],rhs,prime),switched[at],prime);
    if (!c) {
        int source = (i*inverse_exponent)%(2*n);
        U right = 0;
        if (b+shift < active) right = shifted_coefficient(work,b+shift,j,source%n,shift,n,prime);
        U v = sub(work[(b*4+j)*n+source%n],right,prime);
        if (source >= n && v) v = prime-v;
        value = add(value,v,prime);
    }
    output[at] = value;
}

__global__ void finish_merge(U* work, const U* plus, const U* permuted, const U* switched,
                             const Parameters* p, int count, bool compact_permuted = false) {
    int at = blockIdx.x*blockDim.x+threadIdx.x, n = p->n;
    if (at >= count*4*n) return;
    int j = (at/n)%2, c = (at/(2*n))%2, b = at/(4*n), i = at%n;
    U prime = p->primes[j].p, v = add(plus[at],switched[at],prime);
    work[at] = c ? v : add(v,permuted[compact_permuted ? (b*2+j)*n+i : at],prime);
}

__global__ void pack_tiles(const U* work, U* output, const Parameters* p, int count) {
    int at = blockIdx.x*blockDim.x+threadIdx.x, n = p->n;
    if (at >= 4*n) return;
    int i = at%n, poly = at/n, j = poly%2;
    U prime = p->primes[j].p, sum = 0;
    for (int b = 0; b < count; ++b) {
        int source = (i+2*n-b)%(2*n);
        U v = work[(b*4+poly)*n+source%n];
        if (source >= n && v) v = prime-v;
        sum = add(sum,v,prime);
    }
    output[at] = sum;
}
} // namespace cuda_detail

#include "cuda_batch.cuh"

class CudaTraceServer final : public Server {
    using U = xtrace_bfv::gpu::U;
    using Mul = xtrace_bfv::gpu::Mul;
    using Parameters = xtrace_bfv::gpu::Parameters;
    template<class T> using Buffer = xtrace_bfv::gpu::Buffer<T>;
    int device_;
    Parameters host_{};
    Buffer<Parameters> parameters_;
    Buffer<Mul> roots_, inverse_roots_, inverse_n_;
    std::vector<Buffer<Mul>> keys_ntt_;
    const unsigned kernel_level_;
    std::vector<Word> inverse_exponents_;

    template<bool Inverse> void transform(U* data, std::size_t polys, cudaStream_t stream) const {
        using namespace xtrace_bfv::gpu;
        dim3 grid(std::max<std::size_t>(1,ring->n/1024),polys*2);
        const auto* roots = Inverse ? inverse_roots_.data() : roots_.data();
        if constexpr (Inverse) {
            ntt_fused<2,true,false><<<grid,256,0,stream>>>(data,roots,inverse_n_.data(),parameters_.data());
            if (ring->n > 1024) ntt_fused<2,true,true><<<grid,256,0,stream>>>(data,roots,inverse_n_.data(),parameters_.data());
        } else {
            if (ring->n > 1024) ntt_fused<2,false,true><<<grid,256,0,stream>>>(data,roots,inverse_n_.data(),parameters_.data());
            ntt_fused<2,false,false><<<grid,256,0,stream>>>(data,roots,inverse_n_.data(),parameters_.data());
        }
        check(cudaGetLastError());
    }
    void switch_digits(U* digits, U* output, int batch, std::size_t key, cudaStream_t stream) const {
        using namespace xtrace_bfv::gpu;
        transform<false>(digits,batch*4,stream);
        if (kernel_level_ >= 3 && batch >= 8 && ring->n >= 32) {
            dim3 grid(ring->n/32,(batch+7)/8,2);
            cuda_detail::key_product_tiled<<<grid,256,0,stream>>>(digits,keys_ntt_[key].data(),output,parameters_.data(),batch);
        } else {
            cuda_detail::key_product<<<blocks(batch*4*ring->n),256,0,stream>>>(digits,keys_ntt_[key].data(),output,parameters_.data(),batch);
        }
        transform<true>(output,batch*2,stream);
    }
    void switch_key(const U* source, U* digits, U* output, int batch, int components,
                    int component, std::size_t key, cudaStream_t stream) const {
        using namespace xtrace_bfv::gpu;
        cuda_detail::digits<<<blocks(batch*ring->n),256,0,stream>>>(source,digits,parameters_.data(),batch,components,component);
        switch_digits(digits,output,batch,key,stream);
    }
public:
    struct DeviceIndex {
        Buffer<U> values;
        std::size_t count;
        DeviceIndex(const std::vector<U>& data, std::size_t count) : values(data), count(count) {}
    };
    CudaTraceServer(std::shared_ptr<const Ring> r, std::size_t d,
                    std::vector<std::shared_ptr<const SwitchKey>> keys, unsigned kernel_level = 0)
        : Server(std::move(r), d, std::move(keys)), kernel_level_(kernel_level) {
        using namespace xtrace_bfv::gpu;
        if (ring->residue_prime_count != 2 || ring->digit_bits != 30 || ring->digits != 4 || padded > 512)
            throw std::invalid_argument("BGV CUDA requires Q=two 60-bit primes, four 30-bit digits, D<=512");
        if (kernel_level > 4) throw std::invalid_argument("Unknown BGV CUDA kernel level");
        for (auto exponent : exponents) {
            auto inverse = power_mod(exponent,padded-1,2*ring->n);
            if (exponent*inverse%(2*ring->n) != 1) throw std::logic_error("Incorrect inverse automorphism");
            inverse_exponents_.push_back(inverse);
        }
        check(cudaGetDevice(&device_));
        host_.n = ring->n;
        std::vector<Mul> roots, inverse_roots, inverse_n;
        for (int j = 0; j < 2; ++j) {
            auto p = ring->transforms[j].modulus;
            mpz_class reciprocal = (mpz_class(1)<<128)/p;
            host_.primes[j] = {p,mpz_getlimbn(reciprocal.get_mpz_t(),0),mpz_getlimbn(reciprocal.get_mpz_t(),1)};
            Word psi = 0;
            for (Word candidate = 2; !psi; ++candidate) {
                auto w = power_mod(candidate,(p-1)/(2*ring->n),p);
                if (power_mod(w,ring->n,p) == p-1) psi = w;
            }
            auto inverse = power_mod(psi,p-2,p);
            for (std::size_t i = 0; i < ring->n; ++i) {
                std::size_t reversed = 0, v = i;
                for (auto size = ring->n; size > 1; size /= 2) { reversed = 2*reversed+(v&1); v >>= 1; }
                roots.push_back(multiplier(power_mod(psi,reversed,p),p));
                inverse_roots.push_back(multiplier(power_mod(inverse,reversed,p),p));
            }
            inverse_n.push_back(multiplier(power_mod(ring->n,p-2,p),p));
            for (int k = 0; k < 2; ++k)
                if (j != k) host_.inverse[j][k] = multiplier(power_mod(ring->transforms[k].modulus%p,p-2,p),p);
        }
        parameters_ = Buffer<Parameters>(std::vector<Parameters>{host_});
        roots_ = Buffer<Mul>(roots); inverse_roots_ = Buffer<Mul>(inverse_roots); inverse_n_ = Buffer<Mul>(inverse_n);
        for (const auto& key : this->keys) {
            std::vector<Mul> data;
            for (const auto& column : key->transformed())
                for (const auto& poly : column)
                    for (int j = 0; j < 2; ++j)
                        for (Word v : poly[j]) data.push_back(multiplier(v,host_.primes[j].p));
            keys_ntt_.emplace_back(data);
        }
        // Pageable host cudaMemcpy may return after staging, before device DMA
        // completes. Future nonblocking query streams do not wait on stream 0.
        check(cudaStreamSynchronize(nullptr));
    }
    std::shared_ptr<const DeviceIndex> prepare_device(const std::vector<PreparedCiphertext>& index) const {
        using namespace xtrace_bfv::gpu;
        DeviceScope scope(device_);
        std::vector<U> data;
        data.reserve(index.size()*4*ring->n);
        for (const auto& tile : index)
            for (const auto& poly : tile)
                for (const auto& prime : poly) data.insert(data.end(),prime.begin(),prime.end());
        auto result = std::make_shared<DeviceIndex>(data,index.size());
        check(cudaStreamSynchronize(nullptr));
        return result;
    }
    std::vector<Ciphertext> search_device(const Ciphertext& query, const DeviceIndex& index, bool joint) const {
        using namespace xtrace_bfv::gpu;
        DeviceScope scope(device_);
        auto n = ring->n, maximum = std::min(padded,index.count);
        if (!maximum) return {};
        ResidueArithmetic arithmetic(*ring);
        auto query_residues = kernel_level_ ? PreparedCiphertext{arithmetic.split(query[0]),arithmetic.split(query[1])} : prepare(query);
        std::vector<U> input;
        for (const auto& poly : query_residues) for (const auto& prime : poly)
            input.insert(input.end(),prime.begin(),prime.end());
        Buffer<U> query_ntt(input.size()), tensor(maximum*6*n), digits(maximum*8*n), switched(maximum*4*n),
                  work(maximum*4*n), plus(maximum*4*n),
                  permuted(maximum*(kernel_level_ >= 4 ? 0 : kernel_level_ >= 2 ? 2 : 4)*n);
        // Declare the stream last so it synchronizes before workspace destruction
        // on both success and exception paths. Every invocation has private scratch.
        Stream stream;
        // Order the upload and its consumers on this invocation's stream.
        check(cudaMemcpyAsync(query_ntt.data(),input.data(),input.size()*sizeof(U),cudaMemcpyHostToDevice,stream.value));
        if (kernel_level_) transform<false>(query_ntt.data(),2,stream.value);
        std::vector<Ciphertext> output;
        for (std::size_t start = 0; start < index.count; start += padded) {
            auto batch = std::min(padded,index.count-start);
            cuda_detail::tensor<<<blocks(batch*2*n),256,0,stream.value>>>(query_ntt.data(),index.values.data()+start*4*n,tensor.data(),parameters_.data(),batch);
            transform<true>(tensor.data(),batch*3,stream.value);
            switch_key(tensor.data(),digits.data(),switched.data(),batch,3,2,0,stream.value);
            cuda_detail::initial_shift<<<blocks(batch*4*n),256,0,stream.value>>>(tensor.data(),switched.data(),work.data(),parameters_.data(),batch,2*n+1-padded);
            auto active = batch, shift = padded/2;
            for (std::size_t j = 0; j < exponents.size(); ++j, shift /= 2) {
                auto count = joint ? std::min(shift,active) : active;
                if (kernel_level_ >= 4) {
                    cuda_detail::gather_digits<<<blocks(count*n),256,0,stream.value>>>(work.data(),digits.data(),parameters_.data(),active,count,joint ? shift : active,inverse_exponents_[j]);
                    switch_digits(digits.data(),switched.data(),count,j+1,stream.value);
                    cuda_detail::gather_merge<<<blocks(count*4*n),256,0,stream.value>>>(work.data(),switched.data(),plus.data(),parameters_.data(),active,count,joint ? shift : active,inverse_exponents_[j]);
                    work.swap(plus);
                } else if (kernel_level_ >= 2) {
                    cuda_detail::butterfly_digits<<<blocks(count*n),256,0,stream.value>>>(work.data(),plus.data(),permuted.data(),digits.data(),parameters_.data(),active,count,joint ? shift : active,exponents[j]);
                    switch_digits(digits.data(),switched.data(),count,j+1,stream.value);
                } else {
                    cuda_detail::butterfly_inputs<<<blocks(count*4*n),256,0,stream.value>>>(work.data(),plus.data(),permuted.data(),parameters_.data(),active,count,joint ? shift : active,exponents[j]);
                    switch_key(permuted.data(),digits.data(),switched.data(),count,2,1,j+1,stream.value);
                }
                if (kernel_level_ < 4)
                    cuda_detail::finish_merge<<<blocks(count*4*n),256,0,stream.value>>>(work.data(),plus.data(),permuted.data(),switched.data(),parameters_.data(),count,kernel_level_ >= 2);
                active = count;
            }
            const U* result = work.data();
            if (!joint) {
                cuda_detail::pack_tiles<<<blocks(4*n),256,0,stream.value>>>(work.data(),plus.data(),parameters_.data(),batch);
                result = plus.data();
            }
            check(cudaGetLastError());
            std::vector<U> data(4*n);
            check(cudaMemcpyAsync(data.data(),result,data.size()*sizeof(U),cudaMemcpyDeviceToHost,stream.value));
            check(cudaStreamSynchronize(stream.value));
            Ciphertext ciphertext;
            for (std::size_t k = 0; k < 2; ++k) {
                Residues residues;
                for (std::size_t j = 0; j < 2; ++j)
                    residues.emplace_back(data.begin()+(k*2+j)*n,data.begin()+(k*2+j+1)*n);
                ciphertext[k] = arithmetic.compose(residues);
            }
            output.push_back(std::move(ciphertext));
        }
        return output;
    }
    std::vector<std::vector<Ciphertext>> search_many_device(const std::vector<Ciphertext>& queries,
            const DeviceIndex& index, std::size_t batch_size, bool shared_index) const {
        using namespace xtrace_bfv::gpu;
        if (kernel_level_ != 4 || !batch_size || batch_size > 8 || queries.size() > 32)
            throw std::invalid_argument("BGV batches require level 4, 1..8 concurrent queries and at most 32 requests");
        std::vector<std::vector<Ciphertext>> output(queries.size());
        auto n = ring->n, maximum = std::min(padded,index.count), wave = std::min(batch_size,queries.size());
        if (!wave || !maximum) return output;
        auto workspace = wave*(4+26*maximum)*n*sizeof(U);
        if (workspace > (std::size_t(4)<<30))
            throw std::invalid_argument("Batched BGV coefficient workspace exceeds 4 GiB; select a smaller batch size");
        DeviceScope scope(device_);
        ResidueArithmetic arithmetic(*ring);
        std::vector<U> input, data(wave*4*n);
        input.reserve(wave*4*n);
        Buffer<U> query_ntt(wave*4*n), tensor(wave*maximum*6*n), digits(wave*maximum*8*n),
                  switched(wave*maximum*4*n), work(wave*maximum*4*n), plus(wave*maximum*4*n);
        // All host/device transfer buffers outlive the stream, including on error.
        // Scratch is allocated once per call and reused across chunks/groups.
        Stream stream;
        for (std::size_t first = 0; first < queries.size(); first += wave) {
            auto requests = std::min(wave,queries.size()-first);
            input.clear();
            for (std::size_t request = first; request < first+requests; ++request)
                for (const auto& poly : queries[request])
                    for (const auto& prime : arithmetic.split(poly)) input.insert(input.end(),prime.begin(),prime.end());
            check(cudaMemcpyAsync(query_ntt.data(),input.data(),input.size()*sizeof(U),cudaMemcpyHostToDevice,stream.value));
            transform<false>(query_ntt.data(),requests*2,stream.value);
            for (std::size_t start = 0; start < index.count; start += padded) {
                auto batch = std::min(padded,index.count-start), total = requests*batch;
                if (shared_index && requests > 1 && n >= 32) {
                    dim3 grid(n/32,batch,2);
                    cuda_detail::tensor_many_shared<<<grid,32*requests,0,stream.value>>>(
                        query_ntt.data(),index.values.data()+start*4*n,tensor.data(),parameters_.data(),batch);
                } else {
                    cuda_detail::tensor_many<<<blocks(total*2*n),256,0,stream.value>>>(
                        query_ntt.data(),index.values.data()+start*4*n,tensor.data(),parameters_.data(),batch,requests);
                }
                transform<true>(tensor.data(),total*3,stream.value);
                switch_key(tensor.data(),digits.data(),switched.data(),total,3,2,0,stream.value);
                cuda_detail::initial_shift<<<blocks(total*4*n),256,0,stream.value>>>(
                    tensor.data(),switched.data(),work.data(),parameters_.data(),total,2*n+1-padded);
                auto active = batch, shift = padded/2;
                for (std::size_t j = 0; j < exponents.size(); ++j, shift /= 2) {
                    auto count = std::min(shift,active);
                    cuda_detail::gather_digits_many<<<blocks(requests*count*n),256,0,stream.value>>>(
                        work.data(),digits.data(),parameters_.data(),active,count,shift,inverse_exponents_[j],requests);
                    switch_digits(digits.data(),switched.data(),requests*count,j+1,stream.value);
                    cuda_detail::gather_merge_many<<<blocks(requests*count*4*n),256,0,stream.value>>>(
                        work.data(),switched.data(),plus.data(),parameters_.data(),active,count,shift,inverse_exponents_[j],requests);
                    work.swap(plus); active = count;
                }
                check(cudaGetLastError());
                check(cudaMemcpyAsync(data.data(),work.data(),requests*4*n*sizeof(U),cudaMemcpyDeviceToHost,stream.value));
                check(cudaStreamSynchronize(stream.value));
                for (std::size_t request = 0; request < requests; ++request) {
                    Ciphertext cipher;
                    for (std::size_t c = 0; c < 2; ++c) {
                        Residues residues;
                        for (std::size_t j = 0; j < 2; ++j) {
                            auto begin = data.begin()+(request*4+c*2+j)*n;
                            residues.emplace_back(begin,begin+n);
                        }
                        cipher[c] = arithmetic.compose(residues);
                    }
                    output[first+request].push_back(std::move(cipher));
                }
            }
        }
        return output;
    }
};
} // namespace cuhepy_bgv_lab
