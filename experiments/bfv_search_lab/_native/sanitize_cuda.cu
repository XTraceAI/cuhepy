// Standalone public-arithmetic oracle for NVIDIA Compute Sanitizer. Avoids the
// Python process attachment limitation observed with the local toolchain.
#include "cuda_trace.cuh"
#include "residue_trace.h"
#include <iostream>
#include <random>

using namespace cuhepy_bgv_lab;
int main() {
    try {
        std::mt19937_64 random(20260924);
        for (std::size_t n : {16, 2048}) {
            auto auxiliary = std::make_shared<Ring>(n,(mpz_class(1)<<120)-119,30,true);
            mpz_class q = mpz_class(auxiliary->transforms[0].modulus) * auxiliary->transforms[1].modulus;
            auto ring = std::make_shared<Ring>(n,q,30,true,true,2);
            const std::size_t padded = 8;
            auto polynomial = [&]() {
                Polynomial result(n);
                for (auto& c : result) c = ((mpz_class(random())<<64)+random())%q;
                result[0] = q-1; result[1] = mpz_class(1)<<64;
                return result;
            };
            std::vector<std::shared_ptr<const SwitchKey>> keys;
            for (int i = 0; i < 4; ++i) {
                std::vector<Ciphertext> columns;
                for (std::size_t j = 0; j < ring->digits; ++j) columns.push_back({polynomial(),polynomial()});
                keys.push_back(std::make_shared<SwitchKey>(ring,columns));
            }
            ResidueTraceServer cpu(ring,padded,keys);
            Ciphertext query{polynomial(),polynomial()};
            std::vector<PreparedCiphertext> index;
            for (int i = 0; i < 11; ++i) index.push_back(cpu.prepare({polynomial(),polynomial()}));
            std::array<std::vector<Ciphertext>, 2> expected{cpu.search(query,index,false),cpu.search(query,index,true)};
            for (unsigned level = 0; level <= 4; ++level) {
                CudaTraceServer gpu(ring,padded,keys,level);
                auto device = gpu.prepare_device(index);
                for (bool joint : {false,true})
                    if (expected[joint] != gpu.search_device(query,*device,joint))
                        throw std::runtime_error("Standalone CUDA ciphertext mismatch");
                if (level == 4) {
                    std::vector<Ciphertext> queries{query,{polynomial(),polynomial()},query,
                                                    {polynomial(),polynomial()},query};
                    std::vector<std::vector<Ciphertext>> batch_expected;
                    for (const auto& q : queries) batch_expected.push_back(cpu.search(q,index,true));
                    for (std::size_t size : {1,2,3,4,8}) for (bool shared : {false,true})
                        if (gpu.search_many_device(queries,*device,size,shared) != batch_expected)
                            throw std::runtime_error("Standalone CUDA multi-query mismatch");
                }
            }
        }
        std::cout << "BGV CUDA canonical arithmetic, both circuits and multi-query batches passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
