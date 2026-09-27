// Research-only private GMP arithmetic. Independently implemented, not SEAL.
// Variable-time, without secure-erasure assurance. Never link this into the
// public server or treat it as a remotely callable decryption service.
#pragma once
#include "packed_wire.h"
#include "finish.h"
#include "rns_product.h"
#include <map>
#include <mutex>
#include <unistd.h>

namespace cuhepy_bgv_owner {
using namespace xtrace_bfv;

inline void extract(mpz_class& out, std::string_view data, std::size_t index, std::size_t bits) {
    auto offset = (index*bits/64)*8, shift = index*bits%64, count = (bits+63)/64;
    std::array<Word,4> limbs{};
    if (bits > 256) throw std::invalid_argument("Oversized owner coefficient");
    for (std::size_t j = 0; j < count; ++j) {
        limbs[j] = load_word(data,offset+8*j)>>shift;
        if (shift) limbs[j] |= load_word(data,offset+8*j+8)<<(64-shift);
    }
    if (bits%64) limbs[count-1] &= (Word(1)<<(bits%64))-1;
    mpz_import(out.get_mpz_t(),count,-1,sizeof(Word),0,0,limbs.data());
}

inline Polynomial read_poly(std::string_view data, std::size_t n, const mpz_class& modulus) {
    auto bits = mpz_sizeinbase(modulus.get_mpz_t(),2);
    if (modulus < 3 || bits > 240 || data.size() != (n*bits+7)/8)
        throw std::invalid_argument("Invalid packed owner polynomial size/modulus");
    Polynomial result(n);
    for (std::size_t i = 0; i < n; ++i) {
        extract(result[i],data,i,bits);
        if (result[i] >= modulus) throw std::invalid_argument("Noncanonical owner coefficient");
    }
    return result;
}

class Product {
    const pid_t pid_ = getpid();
    std::mutex mutex_;
    bool closed_ = false;
    std::vector<unsigned char> shifted_;
    std::map<std::size_t,mpz_class> packed_;
    std::unique_ptr<RNSProduct> rns_;

    void check_process() const {
        // Must precede the lock: another thread may have held it at fork.
        if (getpid() != pid_) throw std::runtime_error("Create a new native owner after fork");
    }
    void check_open() const {
        if (closed_) throw std::runtime_error("Native owner is closed");
    }
    std::size_t width(const mpz_class& modulus) const {
        if (modulus < 3 || mpz_sizeinbase(modulus.get_mpz_t(),2) > 240)
            throw std::invalid_argument("Invalid native owner modulus");
        mpz_class bound = 2*n*(modulus-1);
        return mpz_sizeinbase(bound.get_mpz_t(),2);
    }
    const mpz_class& prepare_locked(std::size_t bits) {
        auto found = packed_.find(bits);
        if (found != packed_.end()) return found->second;
        Polynomial shifted(n);
        for (std::size_t i = 0; i < n; ++i) shifted[i] = shifted_[i];
        auto bytes = export_packed(shifted,(mpz_class(1)<<bits)-1);
        mpz_class value;
        mpz_import(value.get_mpz_t(),bytes.size(),-1,1,0,0,bytes.data());
        return packed_.emplace(bits,std::move(value)).first->second;
    }
    Polynomial multiply_locked(const Polynomial& input, const mpz_class& modulus) {
        if (rns_) return rns_->multiply(input,modulus,shifted_);
        auto bits = width(modulus);
        const auto& secret = prepare_locked(bits);
        auto bytes = export_packed(input,(mpz_class(1)<<bits)-1);
        mpz_class encoded, product;
        mpz_import(encoded.get_mpz_t(),bytes.size(),-1,1,0,0,bytes.data());
        product = encoded*secret;
        if (mpz_sizeinbase(product.get_mpz_t(),2) > 2*n*bits)
            throw std::logic_error("Ternary coefficient packing bound exceeded");
        std::string coefficients((2*n*bits+7)/8,'\0');
        mpz_export(coefficients.data(),nullptr,-1,1,0,0,product.get_mpz_t());
        mpz_class total = 0, prefix = 0, low, high;
        for (const auto& c : input) total += c;
        Polynomial output(n);
        for (std::size_t i = 0; i < n; ++i) {
            prefix += input[i];
            extract(low,coefficients,i,bits);
            extract(high,coefficients,i+n,bits);
            output[i] = low-high-2*prefix+total;
            mpz_mod(output[i].get_mpz_t(),output[i].get_mpz_t(),modulus.get_mpz_t());
        }
        return output;
    }
    std::vector<Word> decrypt_values_locked(const Polynomial& c0, const Polynomial& c1,
                                            const mpz_class& modulus, Word t) {
        auto product = multiply_locked(c1,modulus);
        mpz_class half = modulus/2, phase;
        std::vector<Word> output(n);
        for (std::size_t i = 0; i < n; ++i) {
            phase = c0[i]+product[i];
            mpz_mod(phase.get_mpz_t(),phase.get_mpz_t(),modulus.get_mpz_t());
            if (phase > half) phase -= modulus;
            output[i] = mpz_fdiv_ui(phase.get_mpz_t(),t);
        }
        return output;
    }
public:
    const std::size_t n;
    Product(std::size_t degree, std::string_view shifted, bool rns = false) : n(degree) {
        if (n < 8 || n > 32768 || (n&(n-1)) || shifted.size() != n)
            throw std::invalid_argument("Invalid native ternary owner shape");
        for (unsigned char c : shifted)
            if (c > 2) throw std::invalid_argument("Invalid shifted ternary secret");
        shifted_.assign(shifted.begin(),shifted.end());
        if (rns) rns_ = std::make_unique<RNSProduct>(n);
    }
    void prepare(const mpz_class& modulus) {
        check_process(); std::lock_guard<std::mutex> lock(mutex_); check_open();
        if (rns_) rns_->prepare(modulus,shifted_);
        else prepare_locked(width(modulus));
    }
    std::string multiply(std::string_view poly, const mpz_class& modulus) {
        check_process(); std::lock_guard<std::mutex> lock(mutex_); check_open();
        auto input = read_poly(poly,n,modulus);
        return export_packed(multiply_locked(input,modulus),modulus);
    }
    std::string encrypt(std::string_view a_bytes, std::string_view message, std::string_view entropy,
                        const mpz_class& modulus, Word t, unsigned eta) {
        check_process(); std::lock_guard<std::mutex> lock(mutex_); check_open();
        if (t < 3 || t >= (Word(1)<<30) || !(t&1) || modulus <= t || eta < 1 || eta > 64 ||
            message.size() != n*4 || entropy.size() != n*((2*eta+7)/8))
            throw std::invalid_argument("Invalid native encryption fields");
        // Validate all caller-controlled fields before starting private arithmetic.
        auto a = read_poly(a_bytes,n,modulus);
        for (std::size_t i = 0; i < n; ++i)
            if ((load_word(message,4*i)&0xffffffffU) >= t)
                throw std::invalid_argument("Noncanonical owner plaintext");
        auto product = multiply_locked(a,modulus);
        const auto stride = (2*eta+7)/8;
        const Word mask = ~Word(0)>>(64-eta);
        for (std::size_t i = 0; i < n; ++i) {
            Wide sample = 0;
            for (unsigned j = 0; j < stride; ++j)
                sample |= Wide(static_cast<unsigned char>(entropy[i*stride+j]))<<(8*j);
            long error = __builtin_popcountll(Word(sample)&mask)-__builtin_popcountll(Word(sample>>eta)&mask);
            long m = load_word(message,4*i)&0xffffffffU;
            if (Word(m) > t/2) m -= static_cast<long>(t);
            product[i] = m+mpz_class(t)*error-product[i];
            mpz_mod(product[i].get_mpz_t(),product[i].get_mpz_t(),modulus.get_mpz_t());
        }
        return export_packed(product,modulus);
    }
    std::string decrypt(std::string_view c0_bytes, std::string_view c1_bytes,
                        const mpz_class& modulus, Word t) {
        check_process(); std::lock_guard<std::mutex> lock(mutex_); check_open();
        if (t < 3 || t >= (Word(1)<<30) || !(t&1) || modulus <= t)
            throw std::invalid_argument("Invalid native decryption modulus");
        auto c0 = read_poly(c0_bytes,n,modulus), c1 = read_poly(c1_bytes,n,modulus);
        auto plain = decrypt_values_locked(c0,c1,modulus,t);
        std::string output(n*4,'\0');
        for (std::size_t i = 0; i < n; ++i) put32(output,4*i,plain[i]);
        return output;
    }
    std::pair<std::string,std::string> finish(const std::vector<std::array<std::string_view,2>>& pairs,
            const mpz_class& modulus, Word t, std::size_t count, std::size_t dimension, std::size_t k, bool all) {
        check_process(); std::lock_guard<std::mutex> lock(mutex_); check_open();
        Finisher result(n,t,count,dimension,k,all);
        if (modulus <= t || pairs.size() != result.groups()) throw std::invalid_argument("Invalid native response shape/modulus");
        // Validate EVERY packed ciphertext before the first private product.
        std::vector<std::array<Polynomial,2>> vetted;
        for (const auto& pair : pairs) vetted.push_back({read_poly(pair[0],n,modulus),read_poly(pair[1],n,modulus)});
        for (const auto& pair : vetted) result.consume(decrypt_values_locked(pair[0],pair[1],modulus,t));
        return result.result();
    }
    void close() {
        check_process(); std::lock_guard<std::mutex> lock(mutex_);
        closed_ = true;
        packed_.clear(); std::vector<unsigned char>().swap(shifted_);
        if (rns_) rns_->clear();
        // Frees references/storage, not a secure-erasure guarantee for GMP copies.
    }
};
} // namespace cuhepy_bgv_owner
