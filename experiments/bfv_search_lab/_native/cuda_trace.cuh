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

__global__ void digits(const U* source, U* out, const Parameters* p, int batch, int components, int component) {
    int at = blockIdx.x * blockDim.x + threadIdx.x, n = p->n;
    if (at >= batch * n) return;
    int b = at/n, i = at%n;
    U values[2] = {source[(b*components*2+component*2)*n+i], source[(b*components*2+component*2+1)*n+i]};
    garner(values,0,2,*p);
    U value[4];
    words(values,0,2,value,*p);
    for (int digit = 0; digit < 4; ++digit) {
        int bit = 30*digit, limb = bit/64, offset = bit%64;
        U v = value[limb] >> offset;
        if (offset) v |= value[limb+1] << (64-offset);
        v &= (U(1)<<30)-1;
        out[((b*4+digit)*2)*n+i] = v;
        out[((b*4+digit)*2+1)*n+i] = v;
    }
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

__global__ void finish_merge(U* work, const U* plus, const U* permuted, const U* switched,
                             const Parameters* p, int count) {
    int at = blockIdx.x*blockDim.x+threadIdx.x, n = p->n;
    if (at >= count*4*n) return;
    int j = (at/n)%2, c = (at/(2*n))%2;
    U prime = p->primes[j].p, v = add(plus[at],switched[at],prime);
    work[at] = c ? v : add(v,permuted[at],prime);
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
    void switch_key(const U* source, U* digits, U* output, int batch, int components,
                    int component, std::size_t key, cudaStream_t stream) const {
        using namespace xtrace_bfv::gpu;
        cuda_detail::digits<<<blocks(batch*ring->n),256,0,stream>>>(source,digits,parameters_.data(),batch,components,component);
        transform<false>(digits,batch*4,stream);
        cuda_detail::key_product<<<blocks(batch*4*ring->n),256,0,stream>>>(digits,keys_ntt_[key].data(),output,parameters_.data(),batch);
        transform<true>(output,batch*2,stream);
    }
public:
    struct DeviceIndex {
        Buffer<U> values;
        std::size_t count;
        DeviceIndex(const std::vector<U>& data, std::size_t count) : values(data), count(count) {}
    };
    CudaTraceServer(std::shared_ptr<const Ring> r, std::size_t d,
                    std::vector<std::shared_ptr<const SwitchKey>> keys)
        : Server(std::move(r), d, std::move(keys)) {
        using namespace xtrace_bfv::gpu;
        if (ring->residue_prime_count != 2 || ring->digit_bits != 30 || ring->digits != 4 || padded > 512)
            throw std::invalid_argument("BGV CUDA requires Q=two 60-bit primes, four 30-bit digits, D<=512");
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
        std::vector<U> input;
        for (const auto& poly : prepare(query)) for (const auto& prime : poly)
            input.insert(input.end(),prime.begin(),prime.end());
        Buffer<U> query_ntt(input.size()), tensor(maximum*6*n), digits(maximum*8*n), switched(maximum*4*n),
                  work(maximum*4*n), plus(maximum*4*n), permuted(maximum*4*n);
        // Declare the stream last so it synchronizes before workspace destruction
        // on both success and exception paths. Every invocation has private scratch.
        Stream stream;
        // Order the upload and its consumers on this invocation's stream.
        check(cudaMemcpyAsync(query_ntt.data(),input.data(),input.size()*sizeof(U),cudaMemcpyHostToDevice,stream.value));
        ResidueArithmetic arithmetic(*ring);
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
                cuda_detail::butterfly_inputs<<<blocks(count*4*n),256,0,stream.value>>>(work.data(),plus.data(),permuted.data(),parameters_.data(),active,count,joint ? shift : active,exponents[j]);
                switch_key(permuted.data(),digits.data(),switched.data(),count,2,1,j+1,stream.value);
                cuda_detail::finish_merge<<<blocks(count*4*n),256,0,stream.value>>>(work.data(),plus.data(),permuted.data(),switched.data(),parameters_.data(),count);
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
};
} // namespace cuhepy_bgv_lab
