// Public arithmetic oracle and shuffled NTT-only timing; no encryption secrets.
#include "ntt_variants.cuh"
#include <iostream>
#include <random>

using namespace xtrace_bfv;
using namespace xtrace_bfv::gpu;
namespace experiment = cuhepy_bgv_lab::ntt_experiment;

int main(int argc, char** argv) {
    try {
        std::size_t n = argc>1 ? std::stoul(argv[1]) : 16384;
        std::size_t polys = argc>2 ? std::stoul(argv[2]) : 256;
        int repeats = argc>3 ? std::stoi(argv[3]) : 20;
        if (n<8 || n>32768 || (n&(n-1)) || !polys || polys>2048 || repeats<1 || repeats>1000)
            throw std::invalid_argument("Invalid bounded NTT workload");
        Parameters plan{}; plan.n = n;
        std::vector<Mul> roots, inverse_roots, inverse_n;
        std::vector<U> input(polys*2*n), expected(input.size()), received(input.size());
        std::mt19937_64 rng(20260925);
        Word prime = (Word(1)<<60)-2*n+1;
        mpz_class q = 1;
        for (int j=0;j<2;++j) {
            mpz_class candidate(prime);
            while (!mpz_probab_prime_p(candidate.get_mpz_t(),32)) { prime-=2*n; candidate=prime; }
            q *= prime; plan.primes[j].p=prime;
            Word psi=0;
            for (Word v=2;!psi;++v) {
                auto w=power_mod(v,(prime-1)/(2*n),prime);
                if (power_mod(w,n,prime)==prime-1) psi=w;
            }
            auto inverse=power_mod(psi,prime-2,prime);
            for (std::size_t i=0;i<n;++i) {
                std::size_t rev=0,value=i;
                for (auto degree=n;degree>1;degree/=2) { rev=2*rev+(value&1); value>>=1; }
                roots.push_back(multiplier(power_mod(psi,rev,prime),prime));
                inverse_roots.push_back(multiplier(power_mod(inverse,rev,prime),prime));
            }
            inverse_n.push_back(multiplier(power_mod(n,prime-2,prime),prime));
            PrimeNTT oracle(n,prime,true,true);
            for (std::size_t b=0;b<polys;++b) {
                std::vector<Word> values(n);
                for (auto& v:values) v=rng()%prime;
                values[0]=prime-1; values[1]=0;
                std::copy(values.begin(),values.end(),input.begin()+(b*2+j)*n);
                oracle.forward(values);
                std::copy(values.begin(),values.end(),expected.begin()+(b*2+j)*n);
            }
            prime-=2*n;
        }
        Buffer<Parameters> parameters(std::vector<Parameters>{plan});
        Buffer<Mul> forward(roots), inverse(inverse_roots), scale(inverse_n);
        Buffer<U> data(input);
        check(cudaDeviceSynchronize());
        Stream stream;
        auto run=[&](unsigned v,bool backwards) {
            if (backwards) experiment::run<true>(v,data.data(),inverse.data(),scale.data(),parameters.data(),n,polys,stream.value);
            else experiment::run<false>(v,data.data(),forward.data(),scale.data(),parameters.data(),n,polys,stream.value);
        };
        for (unsigned v=0;v<5;++v) {
            run(v,false);
            check(cudaMemcpyAsync(received.data(),data.data(),received.size()*sizeof(U),cudaMemcpyDeviceToHost,stream.value));
            check(cudaStreamSynchronize(stream.value));
            if (received!=expected) throw std::runtime_error("NTT forward mismatch for variant "+std::to_string(v));
            run(v,true);
            check(cudaMemcpyAsync(received.data(),data.data(),received.size()*sizeof(U),cudaMemcpyDeviceToHost,stream.value));
            check(cudaStreamSynchronize(stream.value));
            if (received!=input) throw std::runtime_error("NTT inverse mismatch for variant "+std::to_string(v));
        }
        cudaEvent_t begin,end;
        check(cudaEventCreate(&begin)); check(cudaEventCreate(&end));
        std::array<std::vector<float>,5> samples;
        for (int r=0;r<=repeats;++r) {
            std::array<unsigned,5> order{0,1,2,3,4};
            std::shuffle(order.begin(),order.end(),rng);
            for (unsigned v:order) {
                check(cudaEventRecord(begin,stream.value)); run(v,false); run(v,true);
                check(cudaEventRecord(end,stream.value)); check(cudaEventSynchronize(end));
                float ms; check(cudaEventElapsedTime(&ms,begin,end));
                if (r) samples[v].push_back(ms);
            }
        }
        check(cudaEventDestroy(begin)); check(cudaEventDestroy(end));
        const char* names[]={"baseline","indexed","warp1024","warp512","warp2048"};
        std::cout<<"{\"n\":"<<n<<",\"polynomials\":"<<polys<<",\"q_hex\":\""<<q.get_str(16)
                 <<"\",\"forward_and_inverse_exact\":true,\"roundtrip_gpu_ms\":{";
        for (unsigned v=0;v<5;++v) {
            if (v) std::cout<<',';
            std::cout<<'"'<<names[v]<<"\":[";
            for (std::size_t i=0;i<samples[v].size();++i) { if(i) std::cout<<','; std::cout<<samples[v][i]; }
            std::cout<<']';
        }
        std::cout<<"}}\n";
    } catch(const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
