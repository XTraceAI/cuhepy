// Standalone direct-RNS stage oracle for Compute Sanitizer. Public random
// coefficients/keys; compare EVERY output word to the existing native server.
#include "cuda_trace.cuh"
#include "residue_trace.h"
#include <iostream>
#include <random>

using namespace cuhepy_bgv_lab;
int main() {
    try {
        std::mt19937_64 rng(20261002);
        for(const auto entry : std::vector<std::pair<std::size_t,std::size_t>>{
            {64,1},{64,7},{64,8},{64,9},{64,64},{2048,8},{16384,9}}) {
            const auto n=entry.first,batch=entry.second;
            auto auxiliary=std::make_shared<Ring>(n,(mpz_class(1)<<120)-119,30,true);
            mpz_class q=mpz_class(auxiliary->transforms[0].modulus)*auxiliary->transforms[1].modulus;
            auto ring=std::make_shared<Ring>(n,q,30,true,true,2);
            auto polynomial=[&]() {
                Polynomial result(n);
                for(auto& c:result) c=((mpz_class(rng())<<64)+rng())%q;
                result[0]=q-1;result[1]=0;result[2]=mpz_class(1)<<90;
                return result;
            };
            std::vector<Ciphertext> columns;
            for(std::size_t j=0;j<4;++j) columns.push_back({polynomial(),polynomial()});
            std::vector<std::shared_ptr<const SwitchKey>> keys{std::make_shared<SwitchKey>(ring,columns)};
            ResidueTraceServer cpu(ring,1,keys);
            ResidueArithmetic arithmetic(*ring);
            Ciphertext query{polynomial(),polynomial()};
            std::vector<PreparedCiphertext> index;
            for(std::size_t b=0;b<batch;++b) index.push_back(cpu.prepare({polynomial(),polynomial()}));
            auto encode=[&](const std::vector<Ciphertext>& values) {
                std::string bytes(values.size()*4*n*sizeof(Word),'\0');std::size_t at=0;
                for(const auto& ct:values) for(const auto& poly:ct)
                    for(const auto& limb:arithmetic.split(poly)) for(Word word:limb) {
                        std::memcpy(bytes.data()+at,&word,sizeof(word));at+=sizeof(word);
                    }
                return bytes;
            };
            const auto raw=encode({query}),expected=encode(cpu.search(query,index,true));
            for(unsigned variant: {0U,1U}) {
                CudaTraceServer gpu(ring,1,keys,4,variant);auto device=gpu.prepare_device(index);
                if(gpu.product_switch_rns(raw,*device)!=expected) throw std::runtime_error("RNS stage mismatch");
                bool refused=false;
                try { gpu.product_switch_rns(raw.substr(1),*device); }
                catch(const std::invalid_argument&) {refused=true;}
                if(!refused) throw std::runtime_error("Truncated stage query accepted");
                auto bad=raw;const Word p=ring->transforms[1].modulus;
                std::memcpy(bad.data()+bad.size()-8,&p,8);refused=false;
                try {gpu.product_switch_rns(bad,*device);}
                catch(const std::invalid_argument&) {refused=true;}
                if(!refused) throw std::runtime_error("Noncanonical stage query accepted");
            }
            std::cout << "RNS stage N=" << n << " batch=" << batch << " passed\n";
        }
    } catch(const std::exception& error) {std::cerr << error.what() << '\n';return 1;}
}
