// Exact public terminal BGV reduction. This is the same congruence-preserving
// rounding as compact_bgv.py, with reused GMP temporaries and no Python loop.
// Correctness bounds belong to the caller; this does not authenticate a result.
#pragma once
#include "trace_server.h"

namespace cuhepy_bgv_lab {
class TerminalReduction {
    const mpz_class q_, qt_, denominator_;
public:
    const mpz_class modulus;
    const Word t;
    const std::size_t coefficient_bytes;

    TerminalReduction(const mpz_class& q, Word plaintext, mpz_class p)
        : q_(q), qt_(q * plaintext), denominator_(2 * qt_),
          modulus(std::move(p)), t(plaintext),
          coefficient_bytes((mpz_sizeinbase(modulus.get_mpz_t(), 2) + 7) / 8) {
        if (t < 3 || !(t & 1) || t >= (Word(1) << 30) || modulus < (mpz_class(1) << 15) ||
            modulus >= (mpz_class(1) << 60) || modulus >= q_ || 4 * mpz_class(t) >= modulus ||
            mpz_even_p(modulus.get_mpz_t()) || (q_ - modulus) % t != 0 ||
            mpz_probab_prime_p(modulus.get_mpz_t(), 32) == 0)
            throw std::invalid_argument("Invalid native terminal BGV modulus");
    }

    void apply(Ciphertext& cipher) const {
        mpz_class numerator, rounded;
        for (auto& poly : cipher)
            for (auto& c : poly) {
                // floor((2*(P*c - Q*(c mod t)) + Q*t)/(2*Q*t))*t + (c mod t).
                // Floor division matters near zero, where the numerator is negative.
                Word residue = mpz_fdiv_ui(c.get_mpz_t(), t);
                numerator = modulus * c - q_ * residue;
                numerator = 2 * numerator + qt_;
                mpz_fdiv_q(rounded.get_mpz_t(), numerator.get_mpz_t(), denominator_.get_mpz_t());
                rounded = rounded * t + residue;
                mpz_mod(c.get_mpz_t(), rounded.get_mpz_t(), modulus.get_mpz_t());
            }
    }
};
} // namespace cuhepy_bgv_lab
