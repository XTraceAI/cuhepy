// Same BGV circuit with persistent RNS intermediates. Requires fresh keys for
// Q equal to the product of the actual NTT primes; no integer-lift tensor base.
#pragma once
#include "trace_server.h"
#include "bfv_residue.h"

namespace cuhepy_bgv_lab {
class ResidueTraceServer final : public Server {
    const ResidueArithmetic arithmetic_;

    ResidueCiphertext monomial(const ResidueCiphertext& input, std::size_t shift) const {
        ResidueCiphertext output;
        for (std::size_t k = 0; k < 2; ++k) {
            output[k].assign(primes, std::vector<Word>(ring->n));
            for (std::size_t j = 0; j < primes; ++j)
                for (std::size_t i = 0; i < ring->n; ++i) {
                    auto at = (i + shift) % (2 * ring->n);
                    auto value = input[k][j][i];
                    output[k][j][at % ring->n] = at >= ring->n && value ? ring->transforms[j].modulus - value : value;
                }
        }
        return output;
    }

    ResidueCiphertext product(const PreparedCiphertext& query, const PreparedCiphertext& tile) const {
        std::array<Residues, 3> tensor;
        for (auto& c : tensor) c.assign(primes, std::vector<Word>(ring->n));
        for (std::size_t j = 0; j < primes; ++j) {
            const auto& transform = ring->transforms[j];
            for (std::size_t i = 0; i < ring->n; ++i) {
                auto a = query[0][j][i], b = query[1][j][i];
                auto c = tile[0][j][i], d = tile[1][j][i];
                tensor[0][j][i] = transform.remainder(Wide(a) * c);
                tensor[1][j][i] = transform.remainder(Wide(a) * d + Wide(b) * c);
                tensor[2][j][i] = transform.remainder(Wide(b) * d);
            }
            for (auto& c : tensor) transform.inverse(c[j]);
        }
        auto result = arithmetic_.apply(tensor[2], *keys[0]);
        arithmetic_.add(result, ResidueCiphertext{std::move(tensor[0]), std::move(tensor[1])});
        return monomial(result, 2 * ring->n + 1 - padded);
    }

public:
    ResidueTraceServer(std::shared_ptr<const Ring> r, std::size_t d,
                       std::vector<std::shared_ptr<const SwitchKey>> keys)
        : Server(std::move(r), d, std::move(keys)), arithmetic_(*ring) {}

    std::vector<Ciphertext> search(const Ciphertext& query,
                                  const std::vector<PreparedCiphertext>& index, bool butterfly) const override {
        auto prepared = prepare(query);
        std::vector<Ciphertext> output;
        for (std::size_t start = 0; start < index.size(); start += padded) {
            std::vector<ResidueCiphertext> work;
            for (std::size_t i = 0; i < std::min(padded, index.size() - start); ++i)
                work.push_back(product(prepared, index[start + i]));
            ResidueCiphertext result;
            if (butterfly) {
                auto shift = padded / 2;
                for (std::size_t j = 0; j < exponents.size(); ++j, shift /= 2) {
                    std::vector<ResidueCiphertext> merged;
                    for (std::size_t i = 0; i < std::min(shift, work.size()); ++i) {
                        auto plus = work[i], minus = work[i];
                        if (i + shift < work.size()) {
                            auto right = monomial(work[i + shift], shift);
                            arithmetic_.add(plus, right);
                            for (std::size_t k = 0; k < 2; ++k)
                                for (std::size_t p = 0; p < primes; ++p)
                                    for (std::size_t a = 0; a < ring->n; ++a) {
                                        auto x = minus[k][p][a], y = right[k][p][a];
                                        minus[k][p][a] = x >= y ? x - y : x + ring->transforms[p].modulus - y;
                                    }
                        }
                        arithmetic_.add(plus, arithmetic_.rotate(minus, exponents[j], *keys[j + 1]));
                        merged.push_back(std::move(plus));
                    }
                    work = std::move(merged);
                }
                result = std::move(work[0]);
            } else {
                for (std::size_t i = 0; i < work.size(); ++i) {
                    for (std::size_t j = 0; j < exponents.size(); ++j)
                        arithmetic_.add(work[i], arithmetic_.rotate(work[i], exponents[j], *keys[j + 1]));
                    auto shifted = monomial(work[i], i);
                    if (!i) result = std::move(shifted);
                    else arithmetic_.add(result, shifted);
                }
            }
            output.push_back({arithmetic_.compose(result[0]), arithmetic_.compose(result[1])});
        }
        return output;
    }
};
} // namespace cuhepy_bgv_lab
