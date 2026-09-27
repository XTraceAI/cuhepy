// E13 synthetic public GPU/CPU digit-boundary microbenchmark, not a verifier.
#include "cuda_trace.cuh"
#include "digit_boundary.h"
#include <chrono>
#include <iomanip>
#include <iostream>
#include <numeric>

using namespace xtrace_bfv;
using namespace xtrace_bfv::gpu;
namespace boundary=cuhepy_bgv_lab::digit_boundary;
namespace kernels=cuhepy_bgv_lab::cuda_detail;
using Clock=std::chrono::steady_clock;
inline double seconds(Clock::time_point start) { return std::chrono::duration<double>(Clock::now()-start).count(); }

class Pinned {
    void* pointer_=nullptr;
public:
    explicit Pinned(std::size_t bytes) { check(cudaHostAlloc(&pointer_,bytes,cudaHostAllocDefault)); }
    ~Pinned() { if(pointer_) cudaFreeHost(pointer_); }
    Pinned(const Pinned&)=delete;
    void* data() { return pointer_; }
};

__global__ void pack_residues120(const U* source,unsigned char* out,int n,int batch) {
    int at=blockIdx.x*blockDim.x+threadIdx.x;
    if(at>=n*batch) return;
    int b=at>>(__ffs(n)-1),i=at&(n-1);
    U a=source[(b*2)*n+i],c=source[(b*2+1)*n+i],low=a|(c<<60),high=c>>4;
    #pragma unroll
    for(int j=0;j<8;++j) out[15*std::size_t(at)+j]=low>>(8*j);
    #pragma unroll
    for(int j=0;j<7;++j) out[15*std::size_t(at)+8+j]=high>>(8*j);
}

__global__ void expand_digits(const unsigned char* packed,const U* shared,U* out,int n,int batch,int layout) {
    int at=blockIdx.x*blockDim.x+threadIdx.x;
    if(at>=n*batch) return;
    int b=at>>(__ffs(n)-1),i=at&(n-1);
    U digits[4];
    if(layout==2 || layout==3) {
        U low=0,high=0;
        if(layout==3) { low=shared[2*at];high=shared[2*at+1]; }
        else {
            #pragma unroll
            for(int j=0;j<8;++j) low|=U(packed[15*std::size_t(at)+j])<<(8*j);
            #pragma unroll
            for(int j=0;j<7;++j) high|=U(packed[15*std::size_t(at)+8+j])<<(8*j);
        }
        U mask=(U(1)<<30)-1;
        digits[0]=low&mask;digits[1]=(low>>30)&mask;digits[2]=((low>>60)|(high<<4))&mask;digits[3]=high>>26;
    } else {
        #pragma unroll
        for(int d=0;d<4;++d) digits[d]=shared[(b*4+d)*n+i];
    }
    #pragma unroll
    for(int d=0;d<4;++d) { out[((b*4+d)*2)*n+i]=digits[d];out[((b*4+d)*2+1)*n+i]=digits[d]; }
}

struct Sample { double down=0,cpu=0,up=0,total=0; };
struct Variant { const char* name; bool gpu; boundary::Layout layout; int threads; };

int main(int argc,char** argv) {
    try {
        int n=argc>1?std::stoi(argv[1]):16384;
        int count=argc>2?std::stoi(argv[2]):8192;
        int padded=argc>3?std::stoi(argv[3]):512;
        int repeats=argc>4?std::stoi(argv[4]):10;
        if(n<8||n>32768||(n&(n-1))||padded<1||padded>std::min(512,n/2)||(padded&(padded-1))
           ||count<1||count>65536||repeats<1||repeats>100)
            throw std::invalid_argument("Invalid bounded digit benchmark workload");
        std::vector<int> batches;
        int tiles=(count+n/padded-1)/(n/padded);
        for(int start=0;start<tiles;start+=padded) {
            int active=std::min(padded,tiles-start);batches.push_back(active);
            for(int shift=padded/2;shift;shift/=2) { active=std::min(active,shift);batches.push_back(active); }
        }
        int maximum=*std::max_element(batches.begin(),batches.end());
        std::size_t coefficients=std::size_t(n)*std::accumulate(batches.begin(),batches.end(),0);
        auto aux=std::make_shared<Ring>(n,(mpz_class(1)<<120)-119,30,true);
        Word p0=aux->transforms[0].modulus,p1=aux->transforms[1].modulus;
        boundary::CRT crt(p0,p1);
        boundary::self_test(crt);
        Parameters plan{};plan.n=n;plan.primes[0].p=p0;plan.primes[1].p=p1;
        plan.inverse[1][0]=multiplier(power_mod(p0%p1,p1-2,p1),p1);
        Buffer<Parameters> parameters(std::vector<Parameters>{plan});
        std::size_t slots=std::size_t(n)*maximum;
        std::vector<U> input(2*slots),expected(8*slots),received(8*slots);
        std::mt19937_64 rng(20260927);
        for(int b=0;b<maximum;++b) for(int i=0;i<n;++i) {
            input[(b*2)*n+i]=i<2?(i?p0-1:0):rng()%p0;
            input[(b*2+1)*n+i]=i<2?(i?p1-1:0):rng()%p1;
        }
        Buffer<U> source(input),output(8*slots);
        Buffer<unsigned char> packed_input(15*slots),uploaded(4*slots*sizeof(U));
        Pinned host_input(2*slots*sizeof(U)),host_output(8*slots*sizeof(U));
        Stream stream;
        check(cudaDeviceSynchronize());
        using L=boundary::Layout;
        std::vector<Variant> variants{{"gpu",true,L::native,1},
            {"cpu-native-1",false,L::native,1},{"cpu-shared-1",false,L::shared,1},{"cpu-packed-1",false,L::packed,1},
            {"cpu-words-1",false,L::words,1},
            {"cpu-native-8",false,L::native,8},{"cpu-shared-8",false,L::shared,8},{"cpu-packed-8",false,L::packed,8},
            {"cpu-words-8",false,L::words,8}};
        auto run=[&](const Variant& v,const std::vector<int>& schedule) {
            Sample sample;auto whole=Clock::now();
            for(int batch:schedule) {
                std::size_t size=std::size_t(batch)*n;
                if(v.gpu) {
                    kernels::digits<<<blocks(size),256,0,stream.value>>>(source.data(),output.data(),parameters.data(),batch,1,0);
                    continue;
                }
                auto phase=Clock::now();
                std::size_t down_bytes=size*(v.layout==L::packed?15:2*sizeof(U));
                const void* down=source.data();
                if(v.layout==L::packed) {
                    pack_residues120<<<blocks(size),256,0,stream.value>>>(source.data(),packed_input.data(),n,batch);
                    down=packed_input.data();
                }
                check(cudaMemcpyAsync(host_input.data(),down,down_bytes,cudaMemcpyDeviceToHost,stream.value));
                check(cudaStreamSynchronize(stream.value));sample.down+=seconds(phase);
                phase=Clock::now();
                boundary::convert(crt,host_input.data(),host_output.data(),n,batch,v.layout,v.threads);
                sample.cpu+=seconds(phase);phase=Clock::now();
                std::size_t up_bytes=size*(v.layout==L::packed?15:(v.layout==L::words?2:v.layout==L::shared?4:8)*sizeof(U));
                void* up=v.layout==L::native?static_cast<void*>(output.data()):uploaded.data();
                check(cudaMemcpyAsync(up,host_output.data(),up_bytes,cudaMemcpyHostToDevice,stream.value));
                if(v.layout!=L::native) expand_digits<<<blocks(size),256,0,stream.value>>>(uploaded.data(),
                    reinterpret_cast<const U*>(uploaded.data()),output.data(),n,batch,int(v.layout));
                check(cudaStreamSynchronize(stream.value));sample.up+=seconds(phase);
            }
            check(cudaGetLastError());check(cudaStreamSynchronize(stream.value));
            sample.total=seconds(whole);return sample;
        };
        run(variants[0],{maximum});
        check(cudaMemcpy(expected.data(),output.data(),expected.size()*sizeof(U),cudaMemcpyDeviceToHost));
        for(const auto& v:variants) {
            run(v,{maximum});
            check(cudaMemcpy(received.data(),output.data(),received.size()*sizeof(U),cudaMemcpyDeviceToHost));
            if(received!=expected) throw std::runtime_error(std::string("CPU/GPU digit mismatch: ")+v.name);
        }
        std::vector<std::vector<Sample>> samples(variants.size()),warmup(variants.size());
        std::vector<int> order(variants.size());std::iota(order.begin(),order.end(),0);
        for(int r=0;r<=repeats;++r) {
            std::shuffle(order.begin(),order.end(),rng);
            for(int v:order) (r?samples:warmup)[v].push_back(run(variants[v],batches));
        }
        auto print_samples=[&](const auto& groups) {
            std::cout<<'{';
            for(std::size_t v=0;v<variants.size();++v) {
                if(v)std::cout<<',';std::cout<<'"'<<variants[v].name<<"\":[";
                for(std::size_t j=0;j<groups[v].size();++j) {
                    if(j)std::cout<<',';const auto& s=groups[v][j];
                    std::cout<<"{\"down_and_pack_s\":"<<s.down<<",\"cpu_crt_digits_s\":"<<s.cpu
                             <<",\"up_and_expand_s\":"<<s.up<<",\"total_s\":"<<s.total<<'}';
                } std::cout<<']';
            }std::cout<<'}';
        };
        std::cout<<std::setprecision(12)<<"{\"n\":"<<n<<",\"count\":"<<count<<",\"padded\":"<<padded
                 <<",\"rns_primes\":["<<p0<<','<<p1<<"],\"switch_coefficients\":"<<coefficients
                 <<",\"native_roundtrip_bytes\":"<<80*coefficients<<",\"shared_roundtrip_bytes\":"<<48*coefficients
                 <<",\"packed_roundtrip_bytes\":"<<30*coefficients<<",\"host_pinned_bytes\":"<<80*slots
                 <<",\"word_packed_roundtrip_bytes\":"<<32*coefficients
                 <<",\"complete_cpu_gpu_digits_equal\":true,\"gmp_oracle_and_rejections_passed\":true,\"samples\":";
        print_samples(samples);std::cout<<",\"warmup\":";print_samples(warmup);std::cout<<"}\n";
    } catch(const std::exception& error) {std::cerr<<error.what()<<'\n';return 1;}
}
