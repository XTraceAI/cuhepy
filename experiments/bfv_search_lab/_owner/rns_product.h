// Private research arithmetic using OUR fixed-schedule NTT butterflies.
// CRT/export still use variable-time GMP; this is not a constant-time backend.
#pragma once
#include "private_decoder.h"
#include <map>

namespace cuhepy_bgv_owner {
class RNSProduct {
    using Word = xtrace_bfv::Word;
    using Polynomial = xtrace_bfv::Polynomial;
    using Transform = xtrace_bfv_private::FixedNTT;
    struct Context {
        std::vector<std::unique_ptr<Transform>> transforms;
        std::vector<std::vector<Word>> secret;
        std::vector<mpz_class> weights;
        mpz_class product = 1;
        bool direct = false;
    };
    const std::size_t n_;
    std::map<mpz_class,Context> contexts_;
public:
    explicit RNSProduct(std::size_t n) : n_(n) {}
    void prepare(const mpz_class& modulus, const std::vector<unsigned char>& shifted) {
        if (contexts_.count(modulus)) return;
        if (modulus < 3 || mpz_sizeinbase(modulus.get_mpz_t(),2) > 240 || shifted.size() != n_)
            throw std::invalid_argument("Invalid private RNS context");
        if (contexts_.size() >= 16) throw std::invalid_argument("Private RNS context cache is full");
        Context context;
        std::vector<Word> primes;
        Word prime = (Word(1)<<60)-2*n_+1;
        // Reconstruct the signed integer product using M > 2*N*(q-1).
        // If M == q earlier, direct RNS modulo q suffices instead.
        const mpz_class bound = 2*n_*(modulus-1);
        while (context.product <= bound) {
            mpz_class candidate(prime);
            while (!mpz_probab_prime_p(candidate.get_mpz_t(),32)) {
                prime -= 2*n_;
                if (prime <= (Word(1)<<59)) throw std::invalid_argument("No private auxiliary prime");
                candidate = prime;
            }
            primes.push_back(prime);
            context.product *= prime;
            auto transform = std::make_unique<Transform>(n_,prime);
            std::vector<Word> values(n_);
            for (std::size_t i = 0; i < n_; ++i)
                values[i] = Word(shifted[i] == 2) + (prime-1)*Word(shifted[i] == 0);
            transform->forward(values.data());
            context.secret.push_back(std::move(values));
            context.transforms.push_back(std::move(transform));
            if (context.product == modulus) { context.direct = true; break; }
            prime -= 2*n_;
        }
        for (Word p : primes) {
            mpz_class partial = context.product/p;
            Word inverse = xtrace_bfv::power_mod(mpz_fdiv_ui(partial.get_mpz_t(),p),p-2,p);
            context.weights.push_back(partial*inverse);
        }
        contexts_.emplace(modulus,std::move(context));
    }
    Polynomial multiply(const Polynomial& input, const mpz_class& modulus,
                        const std::vector<unsigned char>& shifted) {
        prepare(modulus,shifted);
        const auto& context = contexts_.at(modulus);
        std::vector<std::vector<Word>> residues;
        for (std::size_t j = 0; j < context.transforms.size(); ++j) {
            const auto& transform = *context.transforms[j];
            std::vector<Word> values(n_);
            for (std::size_t i = 0; i < n_; ++i) values[i] = mpz_fdiv_ui(input[i].get_mpz_t(),transform.p);
            transform.forward(values.data()); // Input spectrum is public.
            for (std::size_t i = 0; i < n_; ++i)
                values[i] = xtrace_bfv_private::PublicMultiplier(values[i],transform.p).multiply(context.secret[j][i],transform.p);
            transform.inverse(values.data());
            residues.push_back(std::move(values));
        }
        Polynomial output(n_);
        mpz_class half = context.product/2;
        for (std::size_t i = 0; i < n_; ++i) {
            for (std::size_t j = 0; j < residues.size(); ++j) output[i] += context.weights[j]*residues[j][i];
            mpz_mod(output[i].get_mpz_t(),output[i].get_mpz_t(),context.product.get_mpz_t());
            if (!context.direct && output[i] > half) output[i] -= context.product;
            mpz_mod(output[i].get_mpz_t(),output[i].get_mpz_t(),modulus.get_mpz_t());
        }
        return output;
    }
    void clear() { contexts_.clear(); } // Reference release, not secret erasure.
};
} // namespace cuhepy_bgv_owner
