// Exact BFV tensor scale-and-round in RNS. Public plan construction uses GMP;
// evaluation uses small residues and fixed-word corrections at CRT boundaries.
#pragma once
#include "rns_ntt.h"

namespace xtrace_bfv {
// Even the complete auxiliary product is <= 17*60 bits for 480-bit Q. These
// extra limbs also cover the largest scaled CRT sum used by a correction.
using CRTWords = std::array<Word, 18>;
using CRTTerms = std::array<Word, 18>;

inline CRTWords crt_words(const mpz_class& value) {
    CRTWords result{};
    if (value < 0 || mpz_sizeinbase(value.get_mpz_t(), 2) > 64 * result.size())
        throw std::invalid_argument("CRT constant exceeds the fixed-word bound");
    mpz_export(result.data(), nullptr, -1, sizeof(Word), 0, 0, value.get_mpz_t());
    return result;
}

inline void words_addmul(CRTWords& value, const CRTWords& source, Word multiplier) {
    Word carry = 0;
    for (std::size_t i = 0; i < value.size(); ++i) {
        Wide product = Wide(source[i]) * multiplier + value[i] + carry;
        value[i] = Word(product); carry = Word(product >> 64);
    }
    if (carry) throw std::overflow_error("Fixed-word CRT correction overflow");
}

inline CRTWords words_mul(const CRTWords& value, Word multiplier) {
    CRTWords result{};
    words_addmul(result, value, multiplier);
    return result;
}

inline bool words_ge(const CRTWords& lhs, const CRTWords& rhs) {
    for (std::size_t i = lhs.size(); i-- > 0;)
        if (lhs[i] != rhs[i]) return lhs[i] > rhs[i];
    return true;
}

class ExactRNSBase {
    const Ring& ring_;
    std::vector<Multiplier> inverses_, product_mod_target_;
    std::vector<CRTWords> partial_words_;
    std::vector<std::vector<Word>> partial_mod_target_;
    CRTWords product_words_;

    CRTWords sum_words(const CRTTerms& terms) const {
        CRTWords result{};
        for (std::size_t j = 0; j < count; ++j) words_addmul(result, partial_words_[j], terms[j]);
        return result;
    }

public:
    const std::size_t start, count, target_start, target_count;
    mpz_class product = 1;
    struct Normalized { CRTTerms terms{}; Word alpha = 0; };

    ExactRNSBase(const Ring& ring, std::size_t start, std::size_t count,
                 std::size_t target_start, std::size_t target_count)
        : ring_(ring), start(start), count(count), target_start(target_start), target_count(target_count) {
        if (!count || count > 17 || !target_count || target_count > 17 ||
            start > ring.transforms.size() || count > ring.transforms.size() - start ||
            target_start > ring.transforms.size() || target_count > ring.transforms.size() - target_start)
            throw std::invalid_argument("Invalid exact RNS conversion bases");
        for (std::size_t j = 0; j < count; ++j) product *= ring.transforms[start + j].modulus;
        product_words_ = crt_words(product);
        partial_mod_target_.assign(target_count, std::vector<Word>(count));
        for (std::size_t j = 0; j < count; ++j) {
            Word p = ring.transforms[start + j].modulus;
            mpz_class partial = product / p;
            partial_words_.push_back(crt_words(partial));
            inverses_.emplace_back(power_mod(mpz_fdiv_ui(partial.get_mpz_t(), p), p - 2, p), p);
            for (std::size_t k = 0; k < target_count; ++k)
                partial_mod_target_[k][j] = mpz_fdiv_ui(partial.get_mpz_t(), ring.transforms[target_start + k].modulus);
        }
        for (std::size_t k = 0; k < target_count; ++k) {
            Word p = ring.transforms[target_start + k].modulus;
            product_mod_target_.emplace_back(mpz_fdiv_ui(product.get_mpz_t(), p), p);
        }
    }

    // A=sum(u_j*M_j), theta=A/M. floor(theta) selects [0,M), while
    // round(theta) selects (-M/2,M/2). Fixed-point bounds certify the quotient;
    // an ambiguous interval is resolved by an exact fixed-word comparison.
    Normalized normalize(const CRTTerms& residues, bool centered) const {
        Normalized result;
        Wide fraction = 0;
        for (std::size_t j = 0; j < count; ++j) {
            const auto& transform = ring_.transforms[start + j];
            result.terms[j] = inverses_[j].multiply(residues[j], transform.modulus);
            fraction += transform.fraction(result.terms[j]);
        }
        Wide bias = centered ? Wide(1) << 63 : 0;
        result.alpha = Word((fraction + bias) >> 64);
        if (result.alpha != ((fraction + count + bias) >> 64)) {
            ProfileScope fallback(Phase::crt_exact_fallback);
            auto sum = sum_words(result.terms);
            if (centered) {
                if (words_ge(words_mul(sum, 2), words_mul(product_words_, 2 * result.alpha + 1))) ++result.alpha;
            } else if (words_ge(sum, words_mul(product_words_, result.alpha + 1))) ++result.alpha;
        }
        return result;
    }

    CRTTerms convert(const Normalized& value) const {
        CRTTerms output{};
        for (std::size_t k = 0; k < target_count; ++k) {
            const auto& transform = ring_.transforms[target_start + k];
            Wide sum = 0;
            // At most 17 products below 2^120 fit in the 128-bit accumulator.
            for (std::size_t j = 0; j < count; ++j) sum += Wide(value.terms[j]) * partial_mod_target_[k][j];
            Word residue = transform.reduce(sum);
            Word correction = product_mod_target_[k].multiply(value.alpha, transform.modulus);
            Word result = residue + transform.modulus - correction;
            output[k] = result >= transform.modulus ? result - transform.modulus : result;
        }
        return output;
    }

    // For the canonical lift r=A-alpha*M, round(t*r/M) is
    // round(t*theta)-t*alpha. Split each t*u_j/p_j into its integer part and a
    // rigorously bounded 64-bit fraction. No precision is lost as t increases.
    Word round_fraction(const Normalized& value, Word t) const {
        Word whole = 0;
        Wide fraction = 0;
        for (std::size_t j = 0; j < count; ++j) {
            const auto& transform = ring_.transforms[start + j];
            auto divided = transform.divide(Wide(t) * value.terms[j]);
            whole += divided.first;
            fraction += transform.fraction(divided.second);
        }
        const Wide half = Wide(1) << 63;
        Word rounded = whole + Word((fraction + half) >> 64);
        if (((fraction + half) >> 64) != ((fraction + count + half) >> 64)) {
            ProfileScope fallback(Phase::crt_exact_fallback);
            if (words_ge(words_mul(sum_words(value.terms), 2 * t), words_mul(product_words_, 2 * rounded + 1))) ++rounded;
        }
        return rounded - t * value.alpha;
    }

    std::size_t bytes() const {
        return (count + target_count) * sizeof(Multiplier) + (count + 1) * sizeof(CRTWords)
            + target_count * count * sizeof(Word);
    }
};

class RNSScale {
    const Ring& ring_;
    const Word t_;
    const std::size_t tensor_count_;
    ExactRNSBase q_to_b_, b_to_q_;
    std::vector<Multiplier> inverse_q_, plaintext_;

public:
    RNSScale(const Ring& ring, Word t)
        : ring_(ring), t_(t), tensor_count_(ring.prime_count(2 * ring.n * (ring.q - 1) * (ring.q - 1))),
          q_to_b_(ring, 0, ring.residue_prime_count, ring.residue_prime_count, tensor_count_ - ring.residue_prime_count),
          b_to_q_(ring, ring.residue_prime_count, tensor_count_ - ring.residue_prime_count, 0, ring.residue_prime_count) {
        if (t < 2 || t >= (Word(1) << 60) || t >= ring.q || q_to_b_.product != ring.q || q_to_b_.count > 8)
            throw std::invalid_argument("Invalid RNS scale parameters");
        mpz_class quotient_bound = 2 * ring.n * (ring.q - 1) * (ring.q - 1) / ring.q + 1;
        if (b_to_q_.product <= 2 * quotient_bound)
            throw std::invalid_argument("RNS quotient basis is too small for exact signed scaling");
        for (std::size_t j = 0; j < b_to_q_.count; ++j) {
            Word p = ring.transforms[b_to_q_.start + j].modulus;
            inverse_q_.emplace_back(power_mod(mpz_fdiv_ui(ring.q.get_mpz_t(), p), p - 2, p), p);
        }
        for (std::size_t j = 0; j < q_to_b_.count; ++j) {
            Word p = ring.transforms[j].modulus;
            plaintext_.emplace_back(t % p, p);
        }
    }

    Residues scale(Residues tensor) const {
        ProfileScope timing(Phase::rns_scale);
        if (tensor.size() != tensor_count_ ||
            std::any_of(tensor.begin(), tensor.end(), [&](const auto& p) { return p.size() != ring_.n; }))
            throw std::invalid_argument("Incorrect RNS tensor dimensions");
        for (std::size_t j = 0; j < tensor_count_; ++j) ring_.transforms[j].inverse(tensor[j]);
        Residues result(q_to_b_.count, std::vector<Word>(ring_.n));
        for (std::size_t i = 0; i < ring_.n; ++i) {
            CRTTerms remainder{}, quotient{};
            for (std::size_t j = 0; j < q_to_b_.count; ++j) remainder[j] = tensor[j][i];
            auto normalized = q_to_b_.normalize(remainder, false);
            auto remainder_b = q_to_b_.convert(normalized);
            Word rounded_remainder = q_to_b_.round_fraction(normalized, t_);
            for (std::size_t j = 0; j < b_to_q_.count; ++j) {
                Word p = ring_.transforms[b_to_q_.start + j].modulus;
                Word residue = tensor[b_to_q_.start + j][i] + p - remainder_b[j];
                quotient[j] = inverse_q_[j].multiply(residue, p);
            }
            // z=Q*k+r with 0<=r<Q. B is large enough to recover signed k,
            // hence round(t*z/Q) mod Q = t*k + round(t*r/Q) mod Q exactly.
            auto quotient_q = b_to_q_.convert(b_to_q_.normalize(quotient, true));
            for (std::size_t j = 0; j < q_to_b_.count; ++j) {
                Word p = ring_.transforms[j].modulus;
                Word r = rounded_remainder >= p ? rounded_remainder - p : rounded_remainder;
                Word c = plaintext_[j].multiply(quotient_q[j], p) + r;
                result[j][i] = c >= p ? c - p : c;
            }
        }
        return result;
    }

    std::array<Residues, 3> multiply(const Ciphertext& lhs, const Ciphertext& rhs, bool square) const {
        auto output = ring_.tensor(lhs, rhs, square);
        for (auto& component : output) component = scale(std::move(component));
        return output;
    }

    std::size_t bytes() const { return q_to_b_.bytes() + b_to_q_.bytes() + (inverse_q_.size() + plaintext_.size()) * sizeof(Multiplier); }
};
} // namespace xtrace_bfv
