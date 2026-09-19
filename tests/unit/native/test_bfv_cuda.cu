// Standalone exact-oracle test, also usable under Compute Sanitizer without
// embedding Python. Synthetic public evaluation keys are arithmetic fixtures.
// Build from the repository root:
// nvcc -O2 -std=c++17 -ccbin g++-12 -arch=sm_86 \
//   tests/unit/native/test_bfv_cuda.cu -lgmpxx -lgmp -o /tmp/test_bfv_cuda
#include "../../../src/cuhepy/bfv/_gpu_ext/server.cuh"
#include <iostream>

using namespace xtrace_bfv;

int main() {
    try {
        gmp_randclass random(gmp_randinit_mt);
        random.seed(179);
        for (std::size_t n : {8, 16, 256, 1024, 2048, 8192, 16384, 32768}) {
            Ring auxiliary(n, (mpz_class(1)<<180)-1, 30, true);
            mpz_class q = 1;
            for (int j = 0; j < 3; ++j) q *= auxiliary.transforms[j].modulus;
            auto ring = std::make_shared<Ring>(n, q, 30, true, true, 2);
            auto polynomial = [&]() {
                Polynomial result(n);
                for (std::size_t i = 0; i < n; ++i) {
                    result[i] = random.get_z_range(q);
                    if (i%7 == 0) result[i] = 0;
                    if (i%7 == 1) result[i] = q-1;
                    if (i%7 == 2) result[i] = q/2;
                }
                return result;
            };
            std::vector<std::array<Polynomial,2>> key;
            for (int d = 0; d < 6; ++d) key.push_back({polynomial(),polynomial()});
            auto relin = std::make_shared<SwitchKey>(ring,key);
            std::map<Word,KeyHandle> keys;
            const std::size_t padded = std::min<std::size_t>(512,n/2), lanes = n/(2*padded);
            for (std::size_t size = 1; size < padded; size *= 2) {
                keys.emplace(power_mod(3,lanes*size,2*n),relin);
                keys.emplace(power_mod(3,n/2-lanes*size,2*n),relin);
            }
            ResidueServer cpu(relin,keys,padded,65537,(mpz_class(1)<<50)-27);
            gpu::CudaServer cuda(relin,keys,padded,65537,cpu.target);
            Ciphertext query{polynomial(),polynomial()};
            std::vector<Ciphertext> index;
            for (std::size_t i = 0; i < (n <= 256 ? n+1 : 2); ++i) index.push_back({polynomial(),polynomial()});
            const std::vector<std::size_t> counts = n <= 256 ? std::vector<std::size_t>{1,n-1,n+1,2*n+1} : std::vector<std::size_t>{1,2*lanes+1};
            for (std::size_t count : counts) {
                auto read = [&](std::size_t at) { return index.at(at); };
                std::vector<Ciphertext> expected, actual;
                cpu.search(query,count,read,[&](const Ciphertext& v) { expected.push_back(v); },false);
                cuda.search(query,count,read,[&](const Ciphertext& v) { actual.push_back(v); },false);
                if (actual != expected) throw std::runtime_error("CUDA/CPU ciphertext mismatch");
            }
            std::cout << "N=" << n << ": exact ciphertexts match\n";
        }
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
