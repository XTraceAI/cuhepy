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
              for (unsigned variant = 0; variant < (level == 4 ? 5U : 1U); ++variant) {
                CudaTraceServer gpu(ring,padded,keys,level,variant);
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
                    auto workspace = gpu.prepare_workspace(*device);
                    for (std::size_t i = 0; i < queries.size(); ++i)
                        if (gpu.search_device(queries[i],*device,true,workspace.get()) != batch_expected[i])
                            throw std::runtime_error("Standalone CUDA workspace mismatch");
                    // Exercise lazy terminal scratch, plan changes and reuse on
                    // the complete pipeline, not just the standalone kernel.
                    for (int bits : {25,32,59,60,25}) {
                        const Word t = 1031;
                        mpz_class p = (mpz_class(1)<<bits)-1;
                        p -= (mpz_fdiv_ui(p.get_mpz_t(),t)+t-mpz_fdiv_ui(q.get_mpz_t(),t))%t;
                        if (mpz_even_p(p.get_mpz_t())) p -= t;
                        while (!mpz_probab_prime_p(p.get_mpz_t(),32)) p -= 2*t;
                        TerminalReduction reduction(q,t,p);
                        auto compact_expected = expected[1];
                        for (auto& ct : compact_expected) reduction.apply(ct);
                        if (gpu.search_device(query,*device,true,workspace.get(),&reduction) != compact_expected)
                            throw std::runtime_error("Standalone CUDA terminal workspace mismatch");
                    }
                    workspace->close();
                    bool refused = false;
                    try { gpu.search_device(query,*device,true,workspace.get()); }
                    catch (const std::runtime_error&) { refused = true; }
                    if (!refused) throw std::runtime_error("Closed workspace was accepted");
                }
              }
            }
        }
        std::cout << "BGV CUDA canonical arithmetic, all NTT variants, terminal workspace and multi-query batches passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
