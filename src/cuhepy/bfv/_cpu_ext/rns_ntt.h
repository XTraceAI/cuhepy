// Native XTrace BFV arithmetic. Independently implemented; no SEAL code is linked.
// Auxiliary RNS primes accelerate exact integer products without changing BFV's q.
#pragma once

#include <gmpxx.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <vector>
#include "profile.h"

namespace xtrace_bfv {
static_assert(sizeof(unsigned long) == 8 && sizeof(std::size_t) == 8,
              "BFV RNS kernels require a 64-bit platform with 64-bit unsigned long");
using Word = std::uint64_t;
using Wide = unsigned __int128;
using Polynomial = std::vector<mpz_class>;
using Residues = std::vector<std::vector<Word>>;
using Ciphertext = std::array<Polynomial, 2>;

inline Word power_mod(Word value, Word exponent, Word modulus) {
    Word result = 1;
    while (exponent) {
        if (exponent & 1) result = Wide(result) * value % modulus;
        value = Wide(value) * value % modulus;
        exponent >>= 1;
    }
    return result;
}

struct Multiplier {
    Word value, quotient;
    Multiplier(Word value, Word modulus)
        : value(value), quotient((Wide(value) << 64) / modulus) {}

    // Shoup reduction for a fixed multiplier: the quotient estimate is at
    // most one below floor(input*value/p). The remainder is in [0,2p), even
    // though both low-word products wrap modulo 2^64. Here p < 2^60.
    Word multiply(Word input, Word modulus) const {
        Word remainder = multiply_lazy(input, modulus);
        return remainder >= modulus ? remainder - modulus : remainder;
    }

    Word multiply_lazy(Word input, Word modulus) const {
        Word estimate = (Wide(input) * quotient) >> 64;
        return input * value - estimate * modulus;
    }
};

class PrimeNTT {
    std::size_t n_;
    bool lazy_;
    bool fused_;
    Word reciprocal_low_, reciprocal_high_;
    std::vector<Multiplier> roots_, inverse_roots_, twists_, inverse_scales_;
    std::vector<Multiplier> stage_roots_, stage_inverse_;
    std::unique_ptr<Multiplier> inverse_n_, last_inverse_;

    void forward_fused(std::vector<Word>& values) const {
        const Word twice = 2 * modulus;
        // Evaluate at odd powers of psi directly. One root per contiguous
        // butterfly group incorporates the negacyclic twist into the transform.
        // Stage inputs/outputs are in [0,4p); the fixed multiplier sees <4p.
        for (std::size_t groups = 1, gap = n_ / 2; groups < n_; groups *= 2, gap /= 2) {
            for (std::size_t group = 0; group < groups; ++group) {
                const auto root = stage_roots_[groups + group];
                Word* a = values.data() + 2 * group * gap;
                Word* b = a + gap;
                auto butterfly = [&](std::size_t j) {
                    Word u = a[j];
                    if (u >= twice) u -= twice;
                    Word v = root.multiply_lazy(b[j], modulus);
                    a[j] = u + v;
                    b[j] = u + twice - v;
                };
                std::size_t j = 0;
                for (; j + 4 <= gap; j += 4) {
                    butterfly(j); butterfly(j + 1); butterfly(j + 2); butterfly(j + 3);
                }
                for (; j < gap; ++j) butterfly(j);
            }
        }
        for (auto& value : values) {
            if (value >= twice) value -= twice;
            if (value >= modulus) value -= modulus;
        }
    }

    void inverse_fused(std::vector<Word>& values) const {
        const Word twice = 2 * modulus;
        for (std::size_t groups = n_ / 2, gap = 1; groups > 1; groups /= 2, gap *= 2) {
            for (std::size_t group = 0; group < groups; ++group) {
                const auto root = stage_inverse_[groups + group];
                Word* a = values.data() + 2 * group * gap;
                Word* b = a + gap;
                auto butterfly = [&](std::size_t j) {
                    Word u = a[j], v = b[j], sum = u + v;
                    a[j] = sum >= twice ? sum - twice : sum;
                    b[j] = root.multiply_lazy(u + twice - v, modulus);
                };
                std::size_t j = 0;
                for (; j + 4 <= gap; j += 4) {
                    butterfly(j); butterfly(j + 1); butterfly(j + 2); butterfly(j + 3);
                }
                for (; j < gap; ++j) butterfly(j);
            }
        }
        // Inverse stages keep [0,2p). Fuse 1/N into the final butterfly, saving
        // N/2 multiplications and the separate inverse-twist/scaling pass.
        for (std::size_t j = 0; j < n_ / 2; ++j) {
            Word u = values[j], v = values[j + n_ / 2];
            values[j] = inverse_n_->multiply(u + v, modulus);
            values[j + n_ / 2] = last_inverse_->multiply(u + twice - v, modulus);
        }
    }

public:
    const Word modulus;
    PrimeNTT(std::size_t n, Word prime, bool lazy = false, bool fused = false)
        : n_(n), lazy_(lazy), fused_(fused), modulus(prime) {
        // For an odd prime, floor((2^128-1)/p) == floor(2^128/p).
        Wide reciprocal = ~Wide(0) / prime;
        reciprocal_low_ = Word(reciprocal);
        reciprocal_high_ = Word(reciprocal >> 64);
        Word psi = 0;
        for (Word candidate = 2; !psi; ++candidate) {
            Word root = power_mod(candidate, (prime - 1) / (2 * n), prime);
            if (power_mod(root, n, prime) == prime - 1) psi = root;
        }
        Word omega = Wide(psi) * psi % prime;
        Word inverse_omega = power_mod(omega, prime - 2, prime);
        Word inverse_psi = power_mod(psi, prime - 2, prime);
        if (fused_) {
            unsigned log_n = 0;
            for (auto v = n; v > 1; v /= 2) ++log_n;
            std::vector<Word> powers(n, 1), inverse_powers(n, 1);
            for (std::size_t i = 1; i < n; ++i) {
                powers[i] = Wide(powers[i - 1]) * psi % prime;
                inverse_powers[i] = Wide(inverse_powers[i - 1]) * inverse_psi % prime;
            }
            stage_roots_.reserve(n); stage_inverse_.reserve(n);
            for (std::size_t i = 0; i < n; ++i) {
                Word reversed = 0, index = i;
                for (unsigned bit = 0; bit < log_n; ++bit) { reversed = 2 * reversed + (index & 1); index >>= 1; }
                stage_roots_.emplace_back(powers[reversed], prime);
                stage_inverse_.emplace_back(inverse_powers[reversed], prime);
            }
            Word inverse_n = power_mod(n, prime - 2, prime);
            inverse_n_ = std::make_unique<Multiplier>(inverse_n, prime);
            last_inverse_ = std::make_unique<Multiplier>(Wide(stage_inverse_[1].value) * inverse_n % prime, prime);
            return;
        }
        Word root = 1, inverse_root = 1, twist = 1;
        Word scale = power_mod(n, prime - 2, prime);
        roots_.reserve(n / 2);
        inverse_roots_.reserve(n / 2);
        twists_.reserve(n);
        inverse_scales_.reserve(n);
        for (std::size_t i = 0; i < n; ++i) {
            if (i < n / 2) {
                roots_.emplace_back(root, prime);
                inverse_roots_.emplace_back(inverse_root, prime);
                root = Wide(root) * omega % prime;
                inverse_root = Wide(inverse_root) * inverse_omega % prime;
            }
            twists_.emplace_back(twist, prime);
            inverse_scales_.emplace_back(scale, prime);
            twist = Wide(twist) * psi % prime;
            scale = Wide(scale) * inverse_psi % prime;
        }
    }

    // Negacyclic twist followed by a decimation-in-frequency transform. Output
    // is bit-reversed; keys and query digits use the same order, so no explicit
    // bit-reversal permutation is needed between forward and inverse NTTs.
    void forward(std::vector<Word>& values) const {
        ProfileScope timing(Phase::forward_ntt);
        if (fused_) { forward_fused(values); return; }
        if (lazy_) {
            // Internal values stay below 2p. One correction per butterfly;
            // canonicalize only at the boundary so gadget accumulation keeps
            // its original <2^120 product and 256-term overflow bounds.
            const Word twice = 2 * modulus;
            for (std::size_t i = 0; i < n_; ++i)
                values[i] = twists_[i].multiply_lazy(values[i], modulus);
            for (std::size_t length = n_; length > 1; length >>= 1) {
                std::size_t half = length / 2, stride = n_ / length;
                for (std::size_t start = 0; start < n_; start += length)
                    for (std::size_t j = 0; j < half; ++j) {
                        Word a = values[start + j], b = values[start + j + half];
                        Word sum = a + b;
                        values[start + j] = sum >= twice ? sum - twice : sum;
                        values[start + j + half] = roots_[j * stride].multiply_lazy(a + twice - b, modulus);
                    }
            }
            for (auto& value : values) if (value >= modulus) value -= modulus;
            return;
        }
        for (std::size_t i = 0; i < n_; ++i)
            values[i] = twists_[i].multiply(values[i], modulus);
        for (std::size_t length = n_; length > 1; length >>= 1) {
            std::size_t half = length / 2, stride = n_ / length;
            for (std::size_t start = 0; start < n_; start += length) {
                for (std::size_t j = 0; j < half; ++j) {
                    Word a = values[start + j], b = values[start + j + half];
                    Word sum = a + b;
                    values[start + j] = sum >= modulus ? sum - modulus : sum;
                    values[start + j + half] = roots_[j * stride].multiply(a + modulus - b, modulus);
                }
            }
        }
    }

    // Complementary decimation-in-time inverse, fusing 1/N and the inverse
    // negacyclic twist in the final coefficient pass.
    void inverse(std::vector<Word>& values) const {
        ProfileScope timing(Phase::inverse_ntt);
        if (fused_) { inverse_fused(values); return; }
        if (lazy_) {
            // Inputs to each butterfly are below 4p. Reduce a into [0,2p),
            // obtain b*w in [0,2p), then both outputs fit [0,4p). With p<2^60
            // these operations and Shoup's low-word arithmetic cannot overflow.
            const Word twice = 2 * modulus;
            for (std::size_t length = 2; length <= n_; length <<= 1) {
                std::size_t half = length / 2, stride = n_ / length;
                for (std::size_t start = 0; start < n_; start += length)
                    for (std::size_t j = 0; j < half; ++j) {
                        Word a = values[start + j];
                        if (a >= twice) a -= twice;
                        Word b = inverse_roots_[j * stride].multiply_lazy(values[start + j + half], modulus);
                        values[start + j] = a + b;
                        values[start + j + half] = a + twice - b;
                    }
            }
            for (std::size_t i = 0; i < n_; ++i)
                values[i] = inverse_scales_[i].multiply(values[i], modulus);
            return;
        }
        for (std::size_t length = 2; length <= n_; length <<= 1) {
            std::size_t half = length / 2, stride = n_ / length;
            for (std::size_t start = 0; start < n_; start += length) {
                for (std::size_t j = 0; j < half; ++j) {
                    Word a = values[start + j];
                    Word b = inverse_roots_[j * stride].multiply(values[start + j + half], modulus);
                    Word sum = a + b, difference = a + modulus - b;
                    values[start + j] = sum >= modulus ? sum - modulus : sum;
                    values[start + j + half] = difference >= modulus ? difference - modulus : difference;
                }
            }
        }
        for (std::size_t i = 0; i < n_; ++i)
            values[i] = inverse_scales_[i].multiply(values[i], modulus);
    }

    std::size_t bytes() const { return (fused_ ? 2 * n_ + 2 : 3 * n_) * sizeof(Multiplier); }

    // Barrett reduction for any unsigned 128-bit input. Only the low word of
    // floor(x*floor(2^128/p)/2^128) is needed: subtraction wraps mod 2^64,
    // while the actual residual lies in [0,2p). The estimate is at most one low.
    Word reduce(Wide value) const {
        Word low = Word(value), high = Word(value >> 64);
        Wide p00 = Wide(low) * reciprocal_low_;
        Wide p01 = Wide(low) * reciprocal_high_, p10 = Wide(high) * reciprocal_low_;
        Wide middle = (p00 >> 64) + Word(p01) + Word(p10);
        Word quotient = high * reciprocal_high_ + Word(p01 >> 64) + Word(p10 >> 64) + Word(middle >> 64);
        Word remainder = low - quotient * modulus;
        return remainder >= modulus ? remainder - modulus : remainder;
    }

    // Quotient and remainder when floor(value/p) fits one word. Tensor scaling
    // uses value=t*y with t,y<2^60, so the quotient is below 2^61.
    std::pair<Word, Word> divide(Wide value) const {
        Word low = Word(value), high = Word(value >> 64);
        Wide p00 = Wide(low) * reciprocal_low_;
        Wide p01 = Wide(low) * reciprocal_high_, p10 = Wide(high) * reciprocal_low_;
        Wide middle = (p00 >> 64) + Word(p01) + Word(p10);
        Word quotient = high * reciprocal_high_ + Word(p01 >> 64) + Word(p10 >> 64) + Word(middle >> 64);
        Word remainder = low - quotient * modulus;
        if (remainder >= modulus) { remainder -= modulus; ++quotient; }
        return {quotient, remainder};
    }

    Word remainder(Wide value) const { return lazy_ ? reduce(value) : value % modulus; }

    // Exact floor(y*2^64/p) for y<p, used by certified CRT. The low input word
    // is zero, so the reciprocal quotient simplifies to two word products.
    Word fraction(Word y) const {
        Word quotient = y * reciprocal_high_ + Word((Wide(y) * reciprocal_low_) >> 64);
        if (Word(0) - quotient * modulus >= modulus) ++quotient;
        return quotient;
    }
};

struct CRTBase {
    mpz_class product, half;
    std::vector<mpz_class> weights;
    mpz_class product_mod_q;
    std::vector<mpz_class> partial_mod_q;
    std::vector<Multiplier> inverses;
};

class Ring {
    std::vector<CRTBase> bases_;

public:
    const std::size_t n, coefficient_bytes, digits;
    const unsigned digit_bits;
    const mpz_class q;
    const bool fast;
    const unsigned kernel_level;
    std::vector<PrimeNTT> transforms;
    std::size_t switch_prime_count;
    std::size_t residue_prime_count = 0;

    Ring(std::size_t n, const mpz_class& q, unsigned bits, bool fast = false, bool residue = false,
         unsigned kernel_level = 0)
        : n(n), coefficient_bytes((mpz_sizeinbase(q.get_mpz_t(), 2) + 7) / 8),
          digits(bits ? (mpz_sizeinbase(q.get_mpz_t(), 2) + bits - 1) / bits : 0),
          digit_bits(bits), q(q), fast(fast), kernel_level(kernel_level) {
        if (n < 8 || n > 32768 || (n & (n - 1)) || q < 3 ||
            mpz_sizeinbase(q.get_mpz_t(), 2) > 512 || bits < 1 || bits > mpz_sizeinbase(q.get_mpz_t(), 2))
            throw std::invalid_argument("Invalid native BFV ring parameters");
        if (kernel_level > 2 || (kernel_level && !residue))
            throw std::invalid_argument("Kernel level must be 0..2, with nonzero levels requiring the residue backend");
        // A coefficient of a gadget dot product has |c| <= N*L*(2^b-1)*(q-1).
        // A BFV cross component is a sum of two products, bounded by 2N(q-1)^2.
        // Auxiliary modulus M must exceed twice the bound for exact signed CRT.
        mpz_class switch_bound = n * digits * ((mpz_class(1) << bits) - 1) * (q - 1);
        mpz_class tensor_bound = 2 * n * (q - 1) * (q - 1);
        mpz_class needed = 2 * std::max(switch_bound, tensor_bound);
        mpz_class product = 1;
        Word prime = (Word(1) << 60) - 2 * n + 1;
        while (product <= needed) {
            mpz_class candidate(prime);
            while (!mpz_probab_prime_p(candidate.get_mpz_t(), 32)) {
                if (prime <= (Word(1) << 59)) throw std::invalid_argument("No suitable 60-bit auxiliary prime");
                prime -= 2 * n;
                candidate = prime;
            }
            transforms.emplace_back(n, prime, fast, kernel_level >= 1);
            product *= prime;
            prime -= 2 * n;
        }
        product = 1;
        for (std::size_t count = 1; count <= transforms.size(); ++count) {
            product *= transforms[count - 1].modulus;
            CRTBase base{product, product / 2, {}, product % q, {}, {}};
            for (std::size_t j = 0; j < count; ++j) {
                Word p = transforms[j].modulus;
                mpz_class partial = product / p;
                Word residue = mpz_fdiv_ui(partial.get_mpz_t(), p);
                Word inverse = power_mod(residue, p - 2, p);
                base.weights.push_back(partial * inverse);
                if (fast) {
                    base.partial_mod_q.push_back(partial % q);
                    base.inverses.emplace_back(inverse, p);
                }
            }
            bases_.push_back(std::move(base));
        }
        switch_prime_count = prime_count(switch_bound);
        if (residue) {
            // The residue backend uses the first L primes as the actual BFV
            // modulus Q. Products modulo Q then need only those L transforms;
            // the larger auxiliary base is still needed for BFV scale/round.
            for (std::size_t count = 1; count <= bases_.size(); ++count)
                if (bases_[count - 1].product == q) residue_prime_count = count;
            if (!residue_prime_count || residue_prime_count > 8)
                throw std::invalid_argument("Residue backend requires Q to be a product of the first 60-bit NTT primes");
            switch_prime_count = residue_prime_count;
        }
    }

    std::size_t prime_count(const mpz_class& bound) const {
        for (std::size_t count = 1; count <= bases_.size(); ++count)
            if (bases_[count - 1].product > 2 * bound) return count;
        throw std::invalid_argument("Insufficient auxiliary CRT modulus for exact reconstruction");
    }

    Residues encode(const Polynomial& poly, std::size_t count) const {
        ProfileScope timing(Phase::to_residues);
        Residues result;
        { ProfileScope allocation(Phase::buffers); result.assign(count, std::vector<Word>(n)); }
        for (std::size_t j = 0; j < count; ++j) {
            for (std::size_t i = 0; i < n; ++i)
                result[j][i] = mpz_fdiv_ui(poly[i].get_mpz_t(), transforms[j].modulus);
            transforms[j].forward(result[j]);
        }
        return result;
    }

    Polynomial decode(Residues values) const {
        ProfileScope timing(Phase::crt_reconstruct);
        std::size_t count = values.size();
        const auto& base = bases_.at(count - 1);
        for (std::size_t j = 0; j < count; ++j) transforms[j].inverse(values[j]);
        Polynomial result(n);
        for (std::size_t i = 0; i < n; ++i) {
            auto& value = result[i];
            for (std::size_t j = 0; j < count; ++j)
                mpz_addmul_ui(value.get_mpz_t(), base.weights[j].get_mpz_t(), values[j][i]);
            value %= base.product;
            if (value > base.half) value -= base.product;
        }
        return result;
    }

    Polynomial product(const Polynomial& lhs, const Polynomial& rhs) const {
        mpz_class bound = n * *std::max_element(lhs.begin(), lhs.end()) * *std::max_element(rhs.begin(), rhs.end());
        std::size_t count = prime_count(bound);
        auto a = encode(lhs, count), b = encode(rhs, count);
        { ProfileScope timing(Phase::pointwise);
        for (std::size_t j = 0; j < count; ++j)
            for (std::size_t i = 0; i < n; ++i)
                a[j][i] = transforms[j].remainder(Wide(a[j][i]) * b[j][i]);
        }
        return decode(std::move(a));
    }

    Polynomial decode_mod_q(Residues values) const {
        if (!fast) {
            auto result = decode(std::move(values));
            ProfileScope timing(Phase::mod_q);
            for (auto& value : result) mpz_mod(value.get_mpz_t(), value.get_mpz_t(), q.get_mpz_t());
            return result;
        }
        const auto count = values.size();
        const auto& base = bases_.at(count - 1);
        for (std::size_t j = 0; j < count; ++j) transforms[j].inverse(values[j]);
        Polynomial result(n);
        {
            ProfileScope timing(Phase::crt_reconstruct);
            std::vector<Word> terms(count);
            for (std::size_t i = 0; i < n; ++i) {
                // y_j = residue_j / M_j mod p_j; theta = sum(y_j / p_j).
                // The centered integer is sum(y_j*M_j) - round(theta)*M.
                // We only need that result modulo q, so use M_j mod q.
                // Integer fixed-point bounds certify round(theta); no floats
                // or unproved approximate CRT are used.
                Wide fraction = 0;
                for (std::size_t j = 0; j < count; ++j) {
                    Word p = transforms[j].modulus;
                    terms[j] = base.inverses[j].multiply(values[j][i], p);
                    fraction += transforms[j].fraction(terms[j]);
                }
                // fraction/2^64 <= theta < (fraction+count)/2^64.
                // A rounding boundary inside that interval needs exact CRT.
                const Wide half = Wide(1) << 63;
                Word nearest = (fraction + half) >> 64;
                auto& value = result[i];
                if (nearest != ((fraction + count + half) >> 64)) {
                    ProfileScope fallback(Phase::crt_exact_fallback);
                    for (std::size_t j = 0; j < count; ++j)
                        mpz_addmul_ui(value.get_mpz_t(), base.weights[j].get_mpz_t(), values[j][i]);
                    value %= base.product;
                    if (value > base.half) value -= base.product;
                } else {
                    for (std::size_t j = 0; j < count; ++j)
                        mpz_addmul_ui(value.get_mpz_t(), base.partial_mod_q[j].get_mpz_t(), terms[j]);
                    mpz_submul_ui(value.get_mpz_t(), base.product_mod_q.get_mpz_t(), nearest);
                }
            }
        }
        { ProfileScope timing(Phase::mod_q);
          for (auto& value : result) mpz_mod(value.get_mpz_t(), value.get_mpz_t(), q.get_mpz_t()); }
        return result;
    }

    std::array<Residues, 3> tensor(
        const std::array<Polynomial, 2>& lhs, const std::array<Polynomial, 2>& rhs,
        bool square) const {
        std::size_t count = prime_count(2 * n * (q - 1) * (q - 1));
        auto a0 = encode(lhs[0], count), a1 = encode(lhs[1], count);
        Residues b0, b1;
        if (!square) { b0 = encode(rhs[0], count); b1 = encode(rhs[1], count); }
        std::array<Residues, 3> output;
        { ProfileScope allocation(Phase::buffers);
          for (auto& component : output) component.assign(count, std::vector<Word>(n)); }
        { ProfileScope timing(Phase::pointwise);
        for (std::size_t j = 0; j < count; ++j) {
            for (std::size_t i = 0; i < n; ++i) {
                Word x0 = a0[j][i], x1 = a1[j][i];
                Word y0 = square ? x0 : b0[j][i], y1 = square ? x1 : b1[j][i];
                output[0][j][i] = transforms[j].remainder(Wide(x0) * y0);
                output[1][j][i] = transforms[j].remainder(Wide(x0) * y1 + Wide(x1) * y0);
                output[2][j][i] = transforms[j].remainder(Wide(x1) * y1);
            }
        }
        }
        return output;
    }

    std::array<Polynomial, 3> multiply(
        const std::array<Polynomial, 2>& lhs, const std::array<Polynomial, 2>& rhs,
        Word t, bool square) const {
        auto output = tensor(lhs, rhs, square);
        std::array<Polynomial, 3> result;
        mpz_class denominator = 2 * q;
        for (std::size_t k = 0; k < 3; ++k) {
            result[k] = decode(std::move(output[k]));
            ProfileScope timing(Phase::scale_round);
            for (auto& value : result[k]) {
                // Preserve the reference's exact signed scale-and-round BEFORE
                // reducing mod q: floor((2*t*integer_product + q) / (2*q)).
                value = 2 * t * value + q;
                mpz_fdiv_q(value.get_mpz_t(), value.get_mpz_t(), denominator.get_mpz_t());
                mpz_mod(value.get_mpz_t(), value.get_mpz_t(), q.get_mpz_t());
            }
        }
        return result;
    }

    std::size_t bytes() const {
        std::size_t result = 0;
        for (const auto& plan : transforms) result += plan.bytes();
        return result;
    }
};

class SwitchKey {
    // digit -> component -> auxiliary prime -> bit-reversed NTT coefficient.
    std::vector<std::array<Residues, 2>> key_;

public:
    const std::shared_ptr<const Ring> ring;
    // Read-only transformed public keys for optional accelerator plans. The
    // owning SwitchKey keeps the coefficients alive; callers must not mutate them.
    const std::vector<std::array<Residues, 2>>& transformed() const { return key_; }
    SwitchKey(std::shared_ptr<const Ring> ring, const std::vector<std::array<Polynomial, 2>>& key)
        : ring(std::move(ring)) {
        if (key.size() != this->ring->digits) throw std::invalid_argument("Incorrect gadget digit count");
        for (const auto& pair : key)
            key_.push_back({this->ring->encode(pair[0], this->ring->switch_prime_count),
                            this->ring->encode(pair[1], this->ring->switch_prime_count)});
    }

    std::array<Polynomial, 2> apply(const Polynomial& poly) const {
        const auto& r = *ring;
        // Decompose once, then reuse each integer digit across auxiliary primes.
        std::vector<Polynomial> decomposition;
        std::vector<std::vector<Word>> small_digits;
        { ProfileScope timing(Phase::gadget_decompose);
#if GMP_NUMB_BITS == 64
        if (r.digit_bits <= 60) {
            small_digits.assign(r.digits, std::vector<Word>(r.n));
            Word mask = (Word(1) << r.digit_bits) - 1;
            for (std::size_t digit = 0; digit < r.digits; ++digit) {
                std::size_t bit = digit * r.digit_bits, limb = bit / 64, offset = bit % 64;
                for (std::size_t i = 0; i < r.n; ++i) {
                    Word value = mpz_getlimbn(poly[i].get_mpz_t(), limb) >> offset;
                    if (offset) value |= mpz_getlimbn(poly[i].get_mpz_t(), limb + 1) << (64 - offset);
                    small_digits[digit][i] = value & mask;
                }
            }
        } else
#endif
        {
            decomposition.assign(r.digits, Polynomial(r.n));
            for (std::size_t digit = 0; digit < r.digits; ++digit)
                for (std::size_t i = 0; i < r.n; ++i) {
                    auto& value = decomposition[digit][i];
                    mpz_fdiv_q_2exp(value.get_mpz_t(), poly[i].get_mpz_t(), digit * r.digit_bits);
                    mpz_fdiv_r_2exp(value.get_mpz_t(), value.get_mpz_t(), r.digit_bits);
                }
        }
        }
        auto output_ntt = apply_digits([&](std::size_t j, std::size_t digit, std::vector<Word>& digit_values) {
            Word p = r.transforms[j].modulus;
            for (std::size_t i = 0; i < r.n; ++i) {
                if (small_digits.empty())
                    digit_values[i] = mpz_fdiv_ui(decomposition[digit][i].get_mpz_t(), p);
                else {
                    Word value = small_digits[digit][i];
                    digit_values[i] = value >= p ? value - p : value;
                }
            }
        });
        std::array<Polynomial, 2> result;
        for (std::size_t k = 0; k < 2; ++k)
            result[k] = r.decode_mod_q(std::move(output_ntt[k]));
        return result;
    }

    // Share the cached key dot product with the persistent-residue evaluator.
    // Its digit reader uses fixed-size limbs, without constructing GMP objects.
    // Both readers must supply canonical residues in [0,p).
    template <class ReadDigit>
    std::array<Residues, 2> apply_digits(ReadDigit read_digit) const {
        const auto& r = *ring;
        std::array<Residues, 2> output;
        { ProfileScope allocation(Phase::buffers);
          for (auto& component : output) component.assign(r.switch_prime_count, std::vector<Word>(r.n)); }
        { ProfileScope timing(Phase::pointwise);
        for (std::size_t j = 0; j < r.switch_prime_count; ++j) {
            std::array<std::vector<Wide>, 2> accum{std::vector<Wide>(r.n), std::vector<Wide>(r.n)};
            std::vector<Word> digit_values(r.n);
            for (std::size_t digit = 0; digit < r.digits; ++digit) {
                read_digit(j, digit, digit_values);
                r.transforms[j].forward(digit_values);
                for (std::size_t k = 0; k < 2; ++k)
                    for (std::size_t i = 0; i < r.n; ++i)
                        accum[k][i] += Wide(digit_values[i]) * key_[digit][k][j][i];
                // Products are < 2^120; a batch of 256 fits in 128 bits.
                // Longer gadgets (e.g. 512 one-bit digits) need intermediate reduction.
                if ((digit + 1) % 256 == 0)
                    for (auto& component : accum)
                        for (auto& value : component) value = r.transforms[j].remainder(value);
            }
            for (std::size_t k = 0; k < 2; ++k)
                for (std::size_t i = 0; i < r.n; ++i) output[k][j][i] = r.transforms[j].remainder(accum[k][i]);
        }
        }
        return output;
    }

    std::size_t bytes() const { return ring->digits * 2 * ring->switch_prime_count * ring->n * sizeof(Word); }
};

inline void add_inplace(Ciphertext& lhs, const Ciphertext& rhs, const Ring& ring) {
    ProfileScope timing(Phase::add_sub);
    for (std::size_t k = 0; k < 2; ++k)
        for (std::size_t i = 0; i < ring.n; ++i) {
            lhs[k][i] += rhs[k][i];
            if (lhs[k][i] >= ring.q) lhs[k][i] -= ring.q;
        }
}

inline Ciphertext rotate(const Ciphertext& ciphertext, Word exponent, const SwitchKey& key) {
    const auto& r = *key.ring;
    Ciphertext permuted{Polynomial(r.n), Polynomial(r.n)};
    { ProfileScope timing(Phase::automorphism);
    for (std::size_t k = 0; k < 2; ++k)
        for (std::size_t i = 0; i < r.n; ++i) {
            std::size_t index = (i * exponent) % (2 * r.n);
            auto& value = permuted[k][index % r.n];
            value = ciphertext[k][i];
            if (index >= r.n && value != 0) value = r.q - value;
        }
    }
    auto switched = key.apply(permuted[1]);
    for (std::size_t i = 0; i < r.n; ++i) {
        switched[0][i] += permuted[0][i];
        if (switched[0][i] >= r.q) switched[0][i] -= r.q;
    }
    return switched;
}

// Keep a complete Hamming tile inside the native module. This performs exactly
// the Python client's subtract/square/relinearize/rotate/add/mask circuit, while
// avoiding conversion back to Python mpz tuples after every intermediate step.
inline Ciphertext distance_tile(
    Ciphertext query, const Ciphertext& tile, const SwitchKey& relin,
    const std::vector<std::pair<Word, std::shared_ptr<const SwitchKey>>>& rotations,
    const Polynomial& mask, Word t) {
    const auto& r = *relin.ring;
    { ProfileScope timing(Phase::add_sub);
    for (std::size_t k = 0; k < 2; ++k)
        for (std::size_t i = 0; i < r.n; ++i) {
            query[k][i] -= tile[k][i];
            if (query[k][i] < 0) query[k][i] += r.q;
        }
    }
    auto quadratic = r.multiply(query, query, t, true);
    auto distance = relin.apply(quadratic[2]);
    Ciphertext linear{std::move(quadratic[0]), std::move(quadratic[1])};
    add_inplace(distance, linear, r);
    for (const auto& entry : rotations) {
        auto shifted = entry.first == 1 ? distance : rotate(distance, entry.first, *entry.second);
        add_inplace(distance, shifted, r);
    }
    for (auto& component : distance) {
        component = r.product(component, mask);
        ProfileScope timing(Phase::mod_q);
        for (auto& value : component) mpz_mod(value.get_mpz_t(), value.get_mpz_t(), r.q.get_mpz_t());
    }
    return distance;
}
} // namespace xtrace_bfv
