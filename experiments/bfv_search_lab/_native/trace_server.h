// Experimental, public-only depth-one BGV evaluator. No BFV scale-and-round.
// Reuse the project's generic exact RNS/NTT and gadget-switch arithmetic.
#pragma once
#include "rns_ntt.h"

namespace cuhepy_bgv_lab {
using namespace xtrace_bfv;
using PreparedCiphertext = std::array<Residues, 2>;

inline Ciphertext monomial(const Ciphertext& input, std::size_t shift, const Ring& r) {
    Ciphertext output{Polynomial(r.n), Polynomial(r.n)};
    for (std::size_t k = 0; k < 2; ++k)
        for (std::size_t i = 0; i < r.n; ++i) {
            auto at = (i + shift) % (2 * r.n);
            const auto& value = input[k][i];
            output[k][at % r.n] = at >= r.n && value != 0 ? r.q - value : value;
        }
    return output;
}

class Server {
public:
    const std::shared_ptr<const Ring> ring;
    const std::size_t padded, primes;
    std::vector<std::shared_ptr<const SwitchKey>> keys;
    std::vector<Word> exponents;

    Server(std::shared_ptr<const Ring> r, std::size_t d,
           std::vector<std::shared_ptr<const SwitchKey>> k)
        : ring(std::move(r)), padded(d),
          primes(ring->prime_count(2 * ring->n * (ring->q - 1) * (ring->q - 1))), keys(std::move(k)) {
        if (!d || (d & (d - 1)) || d > ring->n / 2)
            throw std::invalid_argument("Invalid native trace layout");
        Word exponent = 1 + 2 * ring->n / d;
        for (auto shift = d / 2; shift; shift /= 2) {
            exponents.push_back(exponent);
            exponent = exponent * exponent % (2 * ring->n);
        }
        if (keys.size() != exponents.size() + 1)
            throw std::invalid_argument("Incorrect trace evaluation key count");
        for (const auto& key : keys)
            if (key->ring != ring) throw std::invalid_argument("Mismatched native key context");
    }

    PreparedCiphertext prepare(const Ciphertext& cipher) const {
        return {ring->encode(cipher[0], primes), ring->encode(cipher[1], primes)};
    }

    Ciphertext product(const PreparedCiphertext& query, const PreparedCiphertext& tile) const {
        // Four coefficient products share two forward NTTs per input and three
        // inverse transforms. Query/index transforms are cached outside this loop.
        std::array<Residues, 3> tensor;
        for (auto& c : tensor) c.assign(primes, std::vector<Word>(ring->n));
        for (std::size_t j = 0; j < primes; ++j)
            for (std::size_t i = 0; i < ring->n; ++i) {
                auto a = query[0][j][i], b = query[1][j][i];
                auto c = tile[0][j][i], d = tile[1][j][i];
                const auto& transform = ring->transforms[j];
                tensor[0][j][i] = transform.remainder(Wide(a) * c);
                tensor[1][j][i] = transform.remainder(Wide(a) * d + Wide(b) * c);
                tensor[2][j][i] = transform.remainder(Wide(b) * d);
            }
        // Generic exact centered CRT, then reduction mod Q. BGV needs no
        // plaintext scaling here; applying Ring::multiply would be incorrect.
        auto c0 = ring->decode_mod_q(std::move(tensor[0]));
        auto c1 = ring->decode_mod_q(std::move(tensor[1]));
        auto c2 = ring->decode_mod_q(std::move(tensor[2]));
        auto output = keys[0]->apply(c2);
        add_inplace(output, Ciphertext{std::move(c0), std::move(c1)}, *ring);
        return monomial(output, 2 * ring->n + 1 - padded, *ring);
    }

    std::vector<Ciphertext> search(const Ciphertext& query,
                                  const std::vector<PreparedCiphertext>& index, bool butterfly) const {
        const auto& r = *ring;
        auto prepared = prepare(query);
        std::vector<Ciphertext> output;
        for (std::size_t start = 0; start < index.size(); start += padded) {
            auto count = std::min(padded, index.size() - start);
            if (!butterfly) {
                Ciphertext combined{Polynomial(r.n), Polynomial(r.n)};
                for (std::size_t i = 0; i < count; ++i) {
                    auto tile = product(prepared, index[start + i]);
                    for (std::size_t j = 0; j < exponents.size(); ++j) {
                        auto rotated = rotate(tile, exponents[j], *keys[j + 1]);
                        add_inplace(tile, rotated, r);
                    }
                    add_inplace(combined, monomial(tile, i, r), r);
                }
                output.push_back(std::move(combined));
                continue;
            }
            std::vector<Ciphertext> work;
            for (std::size_t i = 0; i < count; ++i) work.push_back(product(prepared, index[start + i]));
            auto shift = padded / 2;
            for (std::size_t j = 0; j < exponents.size(); ++j, shift /= 2) {
                std::vector<Ciphertext> merged;
                for (std::size_t i = 0; i < std::min(shift, work.size()); ++i) {
                    auto plus = work[i], minus = work[i];
                    if (i + shift < work.size()) {
                        auto right = monomial(work[i + shift], shift, r);
                        add_inplace(plus, right, r);
                        for (std::size_t k = 0; k < 2; ++k)
                            for (std::size_t a = 0; a < r.n; ++a) {
                                minus[k][a] -= right[k][a];
                                if (minus[k][a] < 0) minus[k][a] += r.q;
                            }
                    }
                    add_inplace(plus, rotate(minus, exponents[j], *keys[j + 1]), r);
                    merged.push_back(std::move(plus));
                }
                work = std::move(merged);
            }
            output.push_back(std::move(work[0]));
        }
        return output;
    }
};
} // namespace cuhepy_bgv_lab
