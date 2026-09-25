// Public boundary oracle for exact GPU terminal rounding, including quotients
// near half-integer transitions and reconstruction at Q-1. No private inputs.
#include "terminal_cuda.cuh"
#include <iostream>
#include <random>

using namespace cuhepy_bgv_lab;
using namespace xtrace_bfv::gpu;
int main() {
    try {
        std::mt19937_64 rng(20260925);
        for (std::size_t n:{16,2048,16384}) {
            auto aux=std::make_shared<Ring>(n,(mpz_class(1)<<120)-119,30,true);
            mpz_class q=mpz_class(aux->transforms[0].modulus)*aux->transforms[1].modulus;
            Parameters rns{}; rns.n=n;
            for (int j=0;j<2;++j) rns.primes[j].p=aux->transforms[j].modulus;
            auto p0=rns.primes[0].p,p1=rns.primes[1].p;
            rns.inverse[1][0]=multiplier(power_mod(p0%p1,p1-2,p1),p1);
            Buffer<Parameters> device_rns(std::vector<Parameters>{rns});
            for (Word t:{3,1031,65537}) for (int bits:{16,25,32,59,60}) {
                if ((Word(1)<<bits)<=8*t) continue;
                mpz_class p=(mpz_class(1)<<bits)-1;
                p-=(mpz_fdiv_ui(p.get_mpz_t(),t)+t-mpz_fdiv_ui(q.get_mpz_t(),t))%t;
                if (mpz_even_p(p.get_mpz_t())) p-=t;
                while (!mpz_probab_prime_p(p.get_mpz_t(),32)) p-=2*t;
                TerminalReduction oracle(q,t,p);
                auto plan=terminal_gpu::make_plan(q,oracle);
                std::vector<mpz_class> edges{0,1,mpz_class(t-1),mpz_class(t),q/2,q/2+1,q-2,q-1};
                for (Word residue:{Word(0),t/2,t-1}) for (Word k:{Word(0),Word(1),Word(p.get_ui()/t/2),Word(p.get_ui()/t)}) {
                    mpz_class center=q*(2*mpz_class(k)*t+2*residue-t)/(2*p);
                    mpz_class offset=center-residue;
                    center-=mpz_fdiv_ui(offset.get_mpz_t(),t);
                    for (int delta=-2;delta<=2;++delta) {
                        mpz_class value=center+mpz_class(delta)*t;
                        if (value>=0 && value<q) edges.push_back(value);
                    }
                }
                Ciphertext cipher;
                for (auto& poly:cipher) {
                    poly.resize(n);
                    for (std::size_t i=0;i<n;++i)
                        poly[i]=i<edges.size() ? edges[i] : ((mpz_class(rng())<<64)+rng())%q;
                }
                std::vector<U> input(4*n),received(2*n);
                for (int c=0;c<2;++c) for (int j=0;j<2;++j) for (std::size_t i=0;i<n;++i)
                    input[(c*2+j)*n+i]=mpz_fdiv_ui(cipher[c][i].get_mpz_t(),rns.primes[j].p);
                oracle.apply(cipher);
                Buffer<U> data(input),out(2*n);
                Buffer<terminal_gpu::Plan> device_plan(std::vector<terminal_gpu::Plan>{plan});
                check(cudaDeviceSynchronize());
                Stream stream;
                terminal_gpu::compact<<<blocks(2*n),256,0,stream.value>>>(data.data(),out.data(),device_rns.data(),device_plan.data());
                check(cudaGetLastError());
                check(cudaMemcpyAsync(received.data(),out.data(),received.size()*sizeof(U),cudaMemcpyDeviceToHost,stream.value));
                check(cudaStreamSynchronize(stream.value));
                for (int c=0;c<2;++c) for (std::size_t i=0;i<n;++i)
                    if (received[c*n+i]!=cipher[c][i].get_ui()) throw std::runtime_error("GPU terminal rounding mismatch");
            }
        }
        std::cout<<"Exact GPU terminal rounding agrees with GMP at boundaries and N=16/2048/16384\n";
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
