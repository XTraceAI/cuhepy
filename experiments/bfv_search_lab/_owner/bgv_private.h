// Fixed-work BGV terminal decryption. Public setup/key import is outside scope.
// The shared primitives are homemade BFV code; this is BGV centered reduction,
// with neither BFV rescaling nor a plaintext slot transform.
#pragma once
#include "private_decoder.h"

namespace cuhepy_bgv_private {
using namespace xtrace_bfv_private;

// For public p<2^60 and arbitrary 64-bit x, reciprocal=floor(2^64/p).
// floor(x*reciprocal/2^64) underestimates floor(x/p) by at most one.
// Thus the remainder is <2*p, and one masked subtraction is sufficient.
// Only construction divides; its operands are public.
struct PublicReducer {
    Word p, reciprocal;
    explicit PublicReducer(Word modulus) : p(modulus), reciprocal((Wide(1) << 64) / modulus) {}
    Word reduce(Word input) const {
        Word estimate = (Wide(input) * reciprocal) >> 64;
        return normalize(input - estimate * p, p);
    }
};

class Decoder {
    std::size_t n_;
    Word p_, center_offset_;
    FixedNTT first_, second_;
    PublicMultiplier inverse_first_;
    PublicReducer phase_reducer_, plain_reducer_;
    const bool narrow_;
    SecureWords spectra_;
    const pid_t pid_ = getpid();
    std::mutex mutex_;
    bool closed_ = false;

    static std::size_t parameters(std::size_t n, Word p, Word t, Word p0, Word p1) {
        if (n < 8 || n > 32768 || (n & (n - 1)) || p <= t || p >= (Word(1) << 60)
            || t < 3 || t >= (Word(1) << 30) || !(t & 1) || !(p & 1)
            || p0 <= p1 || p1 <= (Word(1) << 59) || p0 >= (Word(1) << 60))
            throw std::invalid_argument("Invalid fixed-work BGV parameters");
        return n;
    }
    void process() const {
        // Check BEFORE touching a mutex potentially held by a vanished thread.
        if (getpid() != pid_) throw std::runtime_error("Create a new BGV decoder after fork");
    }
public:
    Decoder(std::size_t n, Word p, Word t, Word p0, Word p1, const unsigned char* secret)
        : n_(parameters(n, p, t, p0, p1)), p_(p),
          center_offset_((p / t + (p % t != 0)) * t),
          first_(n, p0), second_(n, p1),
          inverse_first_(xtrace_bfv::power_mod(p0 % p1, p1 - 2, p1), p1),
          phase_reducer_(p), plain_reducer_(t), narrow_(Wide(2) * n * p < p0), spectra_(2 * n) {
        unsigned invalid = 0;
        for (std::size_t i = 0; i < n_; ++i) {
            unsigned char c = secret[i];
            invalid |= (c != 0 && c != 1 && c != 255);
            spectra_.data()[i] = Word(c == 1) + Word(c == 255) * (p0 - 1);
            spectra_.data()[n_ + i] = Word(c == 1) + Word(c == 255) * (p1 - 1);
        }
        if (invalid) throw std::invalid_argument("Nonternary BGV secret");
        first_.forward(spectra_.data());
        second_.forward(spectra_.data() + n_);
    }
    std::size_t degree() const { process(); return n_; }
    Word modulus() const { process(); return p_; }
    void close() {
        process();
        std::lock_guard<std::mutex> lock(mutex_);
        spectra_.clear();
        closed_ = true;
    }
    void decode(const Word* c0, const Word* c1, unsigned char* output) {
        process();
        std::lock_guard<std::mutex> lock(mutex_);
        if (closed_) throw std::runtime_error("BGV decoder is closed");
        std::vector<Word> public_spectrum(n_);
        SecureWords work((narrow_ ? 1 : 2) * n_);
        const FixedNTT* transforms[] = {&first_, &second_};
        for (unsigned j = 0; j < (narrow_ ? 1U : 2U); ++j) {
            const auto& transform = *transforms[j];
            // c1 is authenticated PUBLIC ciphertext. This division is public.
            for (std::size_t i = 0; i < n_; ++i) public_spectrum[i] = c1[i] % transform.p;
            transform.forward(public_spectrum.data());
            Word* product = work.data() + j * n_;
            for (std::size_t i = 0; i < n_; ++i)
                product[i] = PublicMultiplier(public_spectrum[i], transform.p).multiply(
                    spectra_.data()[j * n_ + i], transform.p);
            transform.inverse(product);
        }
        const Word p0 = first_.p, p1 = second_.p;
        const Wide product = Wide(p0) * p1, half = product / 2;
        for (std::size_t i = 0; i < n_; ++i) {
            Word a = work.data()[i], phase;
            if (narrow_) { // PUBLIC decision: 2*N*P < p0, independent of the key/ciphertext.
                SignedWide value = SignedWide(a) - SignedWide(p0 & select_mask(a > p0 / 2));
                Word shifted = Word(value + SignedWide(Wide(n_) * p_) + c0[i]);
                phase = phase_reducer_.reduce(shifted); // Shifted < (2*N+1)*P < 2^61.
            } else {
                Word b = work.data()[n_ + i];
                Word difference = normalize(b + p1 - normalize(a, p1), p1);
                Wide value = a + Wide(p0) * inverse_first_.multiply(difference, p1);
                // Exact signed CRT: |c1*s| < N*P < 2^75, far below p0*p1/2.
                Wide negative = Wide(0) - ((half - value) >> 127);
                SignedWide signed_value = SignedWide(value) - SignedWide(product & negative);
                // N*P makes the numerator nonnegative without changing phase.
                Wide shifted = Wide(signed_value + SignedWide(Wide(n_) * p_) + c0[i]);
                phase = fixed_divide(shifted, p_, 77).second;
            }
            // BGV plaintext = centered(phase mod P) mod t. Add a PUBLIC multiple
            // of t to avoid signed remainder, then use fixed-work reduction.
            Word centered = phase + center_offset_ - (p_ & select_mask(phase > p_ / 2));
            Word message = plain_reducer_.reduce(centered);
            for (unsigned j = 0; j < 4; ++j) output[4 * i + j] = message >> (8 * j);
        }
    }
#ifdef CUHEPY_BGV_CT_TEST
    Word* test_secret_spectra() { return spectra_.data(); }
#endif
};
} // namespace cuhepy_bgv_private
