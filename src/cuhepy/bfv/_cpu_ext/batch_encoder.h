// Experimental owner-side SIMD encoder. The transform matches scheme.py's
// two-row order exactly. This reuses variable-time public arithmetic; it is not
// part of the separately hardened private decoder or a side-channel claim.
#pragma once
#include "rns_ntt.h"

namespace xtrace_bfv {
class BatchEncoder {
    PrimeNTT transform_;
    std::vector<std::size_t> order_;
public:
    const std::size_t n;
    const Word t;

    // The binding must validate N, primality and t == 1 (mod 2N) before this
    // constructor invokes the primitive-root search in PrimeNTT.
    BatchEncoder(std::size_t degree, Word modulus)
        : transform_(degree, modulus, true, true), n(degree), t(modulus) {
        unsigned log_n = 0;
        for (auto v = n; v > 1; v >>= 1) ++log_n;
        order_.resize(n);
        Word g = 1;
        for (std::size_t lane = 0; lane < n / 2; ++lane) {
            for (std::size_t row = 0; row < 2; ++row) {
                std::size_t at = ((row ? 2 * n - g : g) - 1) / 2, reversed = 0;
                for (unsigned bit = 0; bit < log_n; ++bit) {
                    reversed = 2 * reversed + (at & 1); at >>= 1;
                }
                order_[row * n / 2 + lane] = reversed;
            }
            g = g * 3 % (2 * n);
        }
    }

    std::vector<Word> encode(const std::vector<Word>& slots) const {
        if (slots.size() != n) throw std::invalid_argument("Expected N batch slots");
        std::vector<Word> values(n);
        for (std::size_t i = 0; i < n; ++i) {
            if (slots[i] >= t) throw std::invalid_argument("Noncanonical batch slot");
            values[order_[i]] = slots[i];
        }
        transform_.inverse(values);
        return values;
    }
};
} // namespace xtrace_bfv
