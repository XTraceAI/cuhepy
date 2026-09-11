// Private BFV terminal decryption. No secret-dependent division or table index.
// This is a narrow, independently testable kernel, not an end-to-end CT claim.
#pragma once
#include "rns_ntt.h" // Public parameter setup only; private transforms below are separate.
#include <mutex>
#include <sys/mman.h>
#include <unistd.h>

namespace xtrace_bfv_private {
using Word = std::uint64_t;
using Wide = unsigned __int128;
using SignedWide = __int128;

inline Word select_mask(Word condition) {
    Word mask = Word(0) - condition;
    // GCC/Clang register value barrier: prevent optimizing a masked operation
    // back into a secret-dependent branch. The Clang -O3 taint regression
    // detects those branches if this barrier is removed. Recheck each toolchain.
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile("" : "+r"(mask));
#else
#error "Private BFV requires a reviewed GCC/Clang value barrier"
#endif
    return mask;
}
inline Word normalize(Word value, Word p) { return value - (p & select_mask(value >= p)); }

// Public multipliers (NTT roots or the PUBLIC c1 spectrum). Only multiply()
// receives secret data. Its inputs are <p<2^60, so one masked correction suffices.
struct PublicMultiplier {
    Word value, quotient;
    PublicMultiplier(Word v, Word p) : value(v), quotient((Wide(v) << 64) / p) {}
    Word multiply(Word input, Word p) const {
        Word estimate = (Wide(input) * quotient) >> 64;
        return normalize(input * value - estimate * p, p);
    }
};

// Binary long division has PUBLIC loop count, no hardware divide, and remainder
// <p. It supports an at-most-120-bit numerator and p<2^61. The quotient is used
// only where the final quotient fits in a Word; its prefixes then fit as well.
inline std::pair<Word, Word> fixed_divide(Wide input, Word p, unsigned bits) {
    Word remainder = 0, quotient = 0;
    for (unsigned i = bits; i-- > 0;) {
        remainder = (remainder << 1) | Word((input >> i) & 1);
        Word subtract = remainder >= p;
        remainder -= p & select_mask(subtract);
        quotient = (quotient << 1) | subtract;
    }
    return {quotient, remainder};
}

class SecureWords {
    Word* data_ = nullptr;
    std::size_t bytes_;
public:
    explicit SecureWords(std::size_t count) {
        if (!count || count > 3 * 32768) throw std::invalid_argument("Invalid private buffer size");
        const auto page_value = sysconf(_SC_PAGESIZE);
        if (page_value < 1) throw std::runtime_error("Cannot obtain private buffer page size");
        const auto page = static_cast<std::size_t>(page_value);
        bytes_ = ((count * sizeof(Word) + page - 1) / page) * page;
        auto memory = mmap(nullptr, bytes_, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (memory == MAP_FAILED) throw std::bad_alloc();
        data_ = static_cast<Word*>(memory);
        if (mlock(data_, bytes_) != 0) {
            munmap(data_, bytes_); data_ = nullptr;
            throw std::runtime_error("Private BFV buffer locking failed; no unlocked fallback");
        }
#ifdef MADV_DONTDUMP
        if (madvise(data_, bytes_, MADV_DONTDUMP) != 0) {
            munlock(data_, bytes_); munmap(data_, bytes_); data_ = nullptr;
            throw std::runtime_error("Private BFV dump exclusion failed");
        }
#endif
    }
    SecureWords(const SecureWords&) = delete;
    SecureWords& operator=(const SecureWords&) = delete;
    Word* data() { return data_; }
    const Word* data() const { return data_; }
    void clear() noexcept {
        // Volatile writes prevent dead-store removal; wipe the full mapped region.
        auto output = reinterpret_cast<volatile unsigned char*>(data_);
        if (output) for (std::size_t i = 0; i < bytes_; ++i) output[i] = 0;
    }
    ~SecureWords() {
        if (data_) { clear(); munlock(data_, bytes_); munmap(data_, bytes_); }
    }
};

class FixedNTT {
    std::size_t n_;
    std::vector<std::size_t> reversal_;
    std::vector<PublicMultiplier> twist_, untwist_, forward_, inverse_;

    void transform(Word* data, const std::vector<PublicMultiplier>& roots) const {
        for (std::size_t i = 0; i < n_; ++i)
            if (i < reversal_[i]) std::swap(data[i], data[reversal_[i]]); // Public permutation.
        std::size_t base = 0;
        for (std::size_t length = 2; length <= n_; length *= 2) {
            for (std::size_t start = 0; start < n_; start += length) {
                for (std::size_t j = 0; j < length / 2; ++j) {
                    Word u = data[start + j];
                    Word v = roots[base + j].multiply(data[start + j + length / 2], p);
                    data[start + j] = normalize(u + v, p);
                    data[start + j + length / 2] = normalize(u + p - v, p);
                }
            }
            base += length / 2;
        }
    }
public:
    const Word p;
    FixedNTT(std::size_t n, Word modulus) : n_(n), p(modulus) {
        if (n < 8 || n > 32768 || (n & (n - 1)) || p < 3 || p >= (Word(1) << 60) || p % (2 * n) != 1)
            throw std::invalid_argument("Invalid private transform parameters");
        mpz_class prime(p);
        if (!mpz_probab_prime_p(prime.get_mpz_t(), 32)) throw std::invalid_argument("Nonprime private transform modulus");
        Word psi = 0;
        for (Word candidate = 2; ; ++candidate) {
            psi = xtrace_bfv::power_mod(candidate, (p - 1) / (2 * n), p);
            if (xtrace_bfv::power_mod(psi, n, p) == p - 1) break;
        }
        const Word inv_psi = xtrace_bfv::power_mod(psi, p - 2, p);
        const Word inv_n = xtrace_bfv::power_mod(n, p - 2, p);
        Word power = 1, inverse_power = 1;
        for (std::size_t i = 0; i < n; ++i) {
            twist_.emplace_back(power, p);
            untwist_.emplace_back(Word(Wide(inverse_power) * inv_n % p), p);
            power = Wide(power) * psi % p;
            inverse_power = Wide(inverse_power) * inv_psi % p;
            std::size_t reversed = 0;
            for (std::size_t at = i, bits = n; bits > 1; bits >>= 1, at >>= 1) reversed = (reversed << 1) | (at & 1);
            reversal_.push_back(reversed);
        }
        const Word root = Wide(psi) * psi % p, inverse_root = Wide(inv_psi) * inv_psi % p;
        for (std::size_t length = 2; length <= n; length *= 2) {
            Word step = xtrace_bfv::power_mod(root, n / length, p);
            Word inverse_step = xtrace_bfv::power_mod(inverse_root, n / length, p);
            Word w = 1, iw = 1;
            for (std::size_t j = 0; j < length / 2; ++j) {
                forward_.emplace_back(w, p); inverse_.emplace_back(iw, p);
                w = Wide(w) * step % p; iw = Wide(iw) * inverse_step % p;
            }
        }
    }
    void forward(Word* data) const {
        for (std::size_t i = 0; i < n_; ++i) data[i] = twist_[i].multiply(data[i], p);
        transform(data, forward_);
    }
    void inverse(Word* data) const {
        transform(data, inverse_);
        for (std::size_t i = 0; i < n_; ++i) data[i] = untwist_[i].multiply(data[i], p);
    }
};

class PrivateDecoder {
    const std::size_t n_;
    const Word q_, t_;
    const FixedNTT first_, second_, plain_;
    const PublicMultiplier inverse_first_;
    SecureWords spectra_;
    std::mutex mutex_;
    bool closed_ = false;

    static std::size_t checked_n(std::size_t n, Word q, Word t, Word p0, Word p1) {
        if (n < 8 || n > 32768 || (n & (n - 1)) || q <= t || q >= (Word(1) << 50) ||
            t < 3 || t >= (Word(1) << 30) || p0 <= p1 || p1 <= (Word(1) << 59) || p0 >= (Word(1) << 60))
            throw std::invalid_argument("Private BFV requires N<=32768, t<2^30, q<2^50 and two descending 60-bit primes");
        return n;
    }
public:
    PrivateDecoder(std::size_t n, Word q, Word t, Word p0, Word p1, const unsigned char* secret)
        : n_(checked_n(n, q, t, p0, p1)), q_(q), t_(t), first_(n, p0), second_(n, p1), plain_(n, t),
          inverse_first_(xtrace_bfv::power_mod(p0 % p1, p1 - 2, p1), p1), spectra_(2 * n) {
        unsigned invalid = 0;
        for (std::size_t i = 0; i < n_; ++i) {
            unsigned value = secret[i];
            invalid |= 1U ^ unsigned((value == 0) | (value == 1) | (value == 255));
            Word plus = value == 1, minus = value == 255;
            spectra_.data()[i] = plus + (p0 - 1) * minus;
            spectra_.data()[n_ + i] = plus + (p1 - 1) * minus;
        }
        if (invalid) throw std::invalid_argument("Private BFV key must be ternary");
        first_.forward(spectra_.data()); second_.forward(spectra_.data() + n_);
    }
    std::size_t degree() const { return n_; }
    Word modulus() const { return q_; }
    void close() {
        std::lock_guard<std::mutex> guard(mutex_);
        spectra_.clear(); closed_ = true;
    }
    void decode(const Word* c0, const Word* c1, unsigned char* output) {
        std::lock_guard<std::mutex> guard(mutex_);
        if (closed_) throw std::runtime_error("Private BFV decoder is closed");
        std::vector<Word> public_spectrum(c1, c1 + n_);
        SecureWords work(3 * n_);
        for (unsigned prime = 0; prime < 2; ++prime) {
            const FixedNTT& transform = prime ? second_ : first_;
            if (prime) std::copy(c1, c1 + n_, public_spectrum.begin());
            transform.forward(public_spectrum.data());
            Word* product = work.data() + prime * n_;
            const Word* secret = spectra_.data() + prime * n_;
            for (std::size_t i = 0; i < n_; ++i)
                product[i] = PublicMultiplier(public_spectrum[i], transform.p).multiply(secret[i], transform.p);
            transform.inverse(product);
        }
        const Word p0 = first_.p, p1 = second_.p;
        const Wide product = Wide(p0) * p1, half = product / 2;
        Word* plaintext = work.data() + 2 * n_;
        for (std::size_t i = 0; i < n_; ++i) {
            Word a = work.data()[i], b = work.data()[n_ + i];
            Word difference = normalize(b + p1 - normalize(a, p1), p1);
            Word k = inverse_first_.multiply(difference, p1);
            Wide value = a + Wide(p0) * k;
            // Both operands are <2^120. The high bit of unsigned half-value
            // distinguishes the negative CRT representative without a 128-bit
            // relational operator that could compile to a secret branch.
            Wide negative_mask = Wide(0) - ((half - value) >> 127);
            SignedWide signed_value = SignedWide(value) - SignedWide(product & negative_mask);
            // |c1*s| < N*q < 2^65, so adding N*q yields a nonnegative value
            // below 2^67, congruent to c0+c1*s modulo q.
            Wide shifted = Wide(signed_value + SignedWide(Wide(n_) * q_) + c0[i]);
            Word phase = fixed_divide(shifted, q_, 67).second;
            Word message = fixed_divide(2 * Wide(t_) * phase + q_, 2 * q_, 82).first;
            plaintext[i] = normalize(message, t_);
        }
        plain_.forward(plaintext);
        Word exponent = 1;
        for (std::size_t i = 0; i < n_ / 2; ++i) {
            const std::size_t positions[2] = {(exponent - 1) / 2, (2 * n_ - exponent - 1) / 2};
            for (unsigned row = 0; row < 2; ++row) {
                Word value = plaintext[positions[row]];
                for (unsigned byte = 0; byte < 4; ++byte)
                    output[4 * (row * n_ / 2 + i) + byte] = static_cast<unsigned char>(value >> (8 * byte));
            }
            exponent = exponent * 3 % (2 * n_); // Public slot order.
        }
    }
#ifdef XTRACE_BFV_CT_TEST
    // Test-only access for dynamic secret-taint checks; absent from the extension.
    Word* test_secret_spectra() { return spectra_.data(); }
#endif
};
} // namespace xtrace_bfv_private
