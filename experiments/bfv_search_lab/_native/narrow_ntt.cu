// Standalone arithmetic experiment, not a new encryption parameter set.
// Compare 4x30-bit with 2x60-bit transforms (~120-bit bases, different Q).
// No CRT/gadget conversion, key switching, owner work or wire cost is timed.
#include "../_gpu_ext/server.cuh"
#include <chrono>
#include <iostream>
#include <random>

namespace narrow {
using W = unsigned;
struct Mul { W value, quotient; };
struct Plan { int n; W primes[4]; };
__device__ W add(W a, W b, W p) { W s = a+b; return s >= p ? s-p : s; }
__device__ W sub(W a, W b, W p) { return a >= b ? a-b : a+p-b; }
__device__ W mul(W a, Mul b, W p) {
    W r = a*b.value-__umulhi(a,b.quotient)*p;
    return r >= p ? r-p : r;
}
// Same public butterfly schedule as our 64-bit kernel; 32-bit shared storage
// and Shoup quotients. Canonical boundaries; p<2^30 keeps additions in range.
template<bool Inverse, bool Outer>
__global__ void transform(W* data, const Mul* roots, const Mul* inverse_n, const Plan* plan) {
    __shared__ W values[1024];
    int n = plan->n, row_size = n < 1024 ? n : 1024, rows = n/row_size, columns = 1024/rows;
    int poly = blockIdx.y, chunk = blockIdx.x, prime = poly%4, size = Outer ? 1024 : row_size;
    W p = plan->primes[prime];
    for (int i = threadIdx.x; i < size; i += blockDim.x) {
        int at = Outer ? (i/columns)*row_size+chunk*columns+i%columns : chunk*row_size+i;
        values[i] = data[poly*n+at];
    }
    __syncthreads();
    int last = Outer ? rows/2 : row_size/2;
    for (int groups = Inverse ? last : 1; Inverse ? groups >= 1 : groups <= last;
         groups = Inverse ? groups/2 : groups*2) {
        int gap = size/(2*groups);
        for (int at = threadIdx.x; at < size/2; at += blockDim.x) {
            int group = at/gap, position = 2*group*gap+at%gap;
            int root = Outer ? groups+group : rows*groups+chunk*groups+group;
            W a = values[position], b = values[position+gap];
            if constexpr (Inverse) {
                values[position] = add(a,b,p);
                values[position+gap] = mul(sub(a,b,p),roots[prime*n+root],p);
            } else {
                b = mul(b,roots[prime*n+root],p);
                values[position] = add(a,b,p); values[position+gap] = sub(a,b,p);
            }
        }
        __syncthreads();
    }
    for (int i = threadIdx.x; i < size; i += blockDim.x) {
        int at = Outer ? (i/columns)*row_size+chunk*columns+i%columns : chunk*row_size+i;
        W value = values[i];
        if constexpr (Inverse) if (Outer || n<=1024) value = mul(value,inverse_n[prime],p);
        data[poly*n+at] = value;
    }
}
} // namespace narrow

using namespace xtrace_bfv;
using namespace xtrace_bfv::gpu;

template<bool Small> void experiment(std::size_t n, std::size_t polys, int repeats) {
    using W = std::conditional_t<Small,unsigned,U>;
    using M = std::conditional_t<Small,narrow::Mul,Mul>;
    using P = std::conditional_t<Small,narrow::Plan,Parameters>;
    constexpr int count = Small ? 4 : 2, bits = Small ? 30 : 60;
    P plan{}; plan.n = n;
    std::vector<M> roots, inverse_roots, inverse_n;
    std::vector<W> input(polys*count*n), expected(input.size());
    std::mt19937_64 random(20260925);
    mpz_class product = 1;
    Word p = (Word(1)<<bits)-2*n+1;
    for (int j = 0; j < count; ++j) {
        mpz_class candidate(p);
        while (!mpz_probab_prime_p(candidate.get_mpz_t(),32)) { p -= 2*n; candidate = p; }
        product *= p;
        if constexpr (Small) plan.primes[j] = p;
        else plan.primes[j].p = p;
        Word psi = 0;
        for (Word v = 2; !psi; ++v) {
            Word root = power_mod(v,(p-1)/(2*n),p);
            if (power_mod(root,n,p) == p-1) psi = root;
        }
        Word inverse = power_mod(psi,p-2,p);
        auto make = [p](Word v) { return M{W(v),W((Wide(v)<<(8*sizeof(W)))/p)}; };
        for (std::size_t i = 0; i < n; ++i) {
            std::size_t rev = 0, value = i;
            for (auto degree = n; degree > 1; degree /= 2) { rev = 2*rev+(value&1); value >>= 1; }
            roots.push_back(make(power_mod(psi,rev,p)));
            inverse_roots.push_back(make(power_mod(inverse,rev,p)));
        }
        inverse_n.push_back(make(power_mod(n,p-2,p)));
        PrimeNTT oracle(n,p,true,true);
        for (std::size_t b = 0; b < polys; ++b) {
            std::vector<Word> coefficients(n);
            for (auto& c : coefficients) c = random()%p;
            coefficients[0] = p-1; coefficients[1] = 0;
            std::copy(coefficients.begin(),coefficients.end(),input.begin()+(b*count+j)*n);
            oracle.forward(coefficients);
            std::copy(coefficients.begin(),coefficients.end(),expected.begin()+(b*count+j)*n);
        }
        p -= 2*n;
    }
    Buffer<P> parameters(std::vector<P>{plan});
    Buffer<M> forward(roots), inverse(inverse_roots), scale(inverse_n);
    Buffer<W> data(input);
    check(cudaDeviceSynchronize());
    Stream stream;
    auto run = [&](bool backwards) {
        dim3 grid(std::max<std::size_t>(1,n/1024),polys*count);
        if constexpr (Small) {
            if (backwards) {
                narrow::transform<true,false><<<grid,256,0,stream.value>>>(data.data(),inverse.data(),scale.data(),parameters.data());
                if (n>1024) narrow::transform<true,true><<<grid,256,0,stream.value>>>(data.data(),inverse.data(),scale.data(),parameters.data());
            } else {
                if (n>1024) narrow::transform<false,true><<<grid,256,0,stream.value>>>(data.data(),forward.data(),scale.data(),parameters.data());
                narrow::transform<false,false><<<grid,256,0,stream.value>>>(data.data(),forward.data(),scale.data(),parameters.data());
            }
        } else {
            if (backwards) {
                ntt_fused<2,true,false><<<grid,256,0,stream.value>>>(data.data(),inverse.data(),scale.data(),parameters.data());
                if (n>1024) ntt_fused<2,true,true><<<grid,256,0,stream.value>>>(data.data(),inverse.data(),scale.data(),parameters.data());
            } else {
                if (n>1024) ntt_fused<2,false,true><<<grid,256,0,stream.value>>>(data.data(),forward.data(),scale.data(),parameters.data());
                ntt_fused<2,false,false><<<grid,256,0,stream.value>>>(data.data(),forward.data(),scale.data(),parameters.data());
            }
        }
        check(cudaGetLastError());
    };
    std::vector<W> downloaded(input.size());
    run(false);
    check(cudaMemcpyAsync(downloaded.data(),data.data(),data.bytes(),cudaMemcpyDeviceToHost,stream.value));
    check(cudaStreamSynchronize(stream.value));
    if (downloaded != expected) throw std::runtime_error("Forward NTT differs from independent CPU oracle");
    run(true);
    check(cudaMemcpyAsync(downloaded.data(),data.data(),data.bytes(),cudaMemcpyDeviceToHost,stream.value));
    check(cudaStreamSynchronize(stream.value));
    if (downloaded != input) throw std::runtime_error("Inverse NTT differs from input");
    cudaEvent_t start, end;
    check(cudaEventCreate(&start)); check(cudaEventCreate(&end));
    std::cout << "{\"limb_bits\":" << bits << ",\"primes\":" << count << ",\"q_hex\":\"" << product.get_str(16)
              << "\",\"buffer_bytes\":" << data.bytes() << ",\"roundtrip_gpu_ms\":[";
    for (int i = 0; i <= repeats; ++i) {
        check(cudaEventRecord(start,stream.value)); run(false); run(true);
        check(cudaEventRecord(end,stream.value)); check(cudaEventSynchronize(end));
        float elapsed; check(cudaEventElapsedTime(&elapsed,start,end));
        if (i) std::cout << (i>1 ? "," : "") << elapsed;
    }
    check(cudaEventDestroy(start)); check(cudaEventDestroy(end));
    std::cout << "],\"forward_and_inverse_exact\":true}";
}
int main(int argc, char** argv) {
    try {
        std::size_t n = argc>1 ? std::stoul(argv[1]) : 16384, polys = argc>2 ? std::stoul(argv[2]) : 1024;
        int repeats = argc>3 ? std::stoi(argv[3]) : 20;
        if (n<8 || n>32768 || (n&(n-1)) || polys<1 || polys>2048 || repeats<1 || repeats>1000)
            throw std::invalid_argument("Invalid narrow NTT workload");
        std::cout << "{\"kind\":\"ntt_limb_microbenchmark\",\"n\":" << n << ",\"polynomials\":" << polys << ",\"variants\":[";
        if (argc>4 && std::string(argv[4]) == "reverse") {
            experiment<true>(n,polys,repeats); std::cout << ','; experiment<false>(n,polys,repeats);
        } else {
            experiment<false>(n,polys,repeats); std::cout << ','; experiment<true>(n,polys,repeats);
        }
        std::cout << "]}\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
