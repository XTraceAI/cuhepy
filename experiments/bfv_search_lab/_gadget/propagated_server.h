// Q67 public evaluator prototype. Known gadget algebra; no admission or secret.
// All supplied ciphertext/key coefficients are canonical full-Q values. Derived
// RNS states are deterministic images of a COMMON bounded integer digit tuple;
// independently chosen limb digits never enter this interface.
#pragma once
#include "residue_trace.h"

namespace cuhepy_bgv_lab {
class PropagatedGadgetServer final : public Server {
    using DigitNTT = std::vector<Residues>;
    struct Anchored { ResidueCiphertext value; DigitNTT digits; };
    const ResidueArithmetic arithmetic_;
    std::vector<std::array<Residues, 2>> h_;
    std::vector<std::size_t> old_map_, new_map_;
    Residues right_move_;
    const bool enabled_;

    static std::size_t reverse(std::size_t x, unsigned bits) {
        std::size_t result = 0;
        for (unsigned j = 0; j < bits; ++j, x >>= 1) result = 2 * result + (x & 1);
        return result;
    }
    std::vector<std::size_t> ntt_map(Word exponent) const {
        unsigned bits = 0;
        for (auto n = ring->n; n > 1; n >>= 1) ++bits;
        std::vector<std::size_t> map(ring->n);
        for (std::size_t i = 0; i < ring->n; ++i) {
            auto odd = ((2 * reverse(i, bits) + 1) * exponent) % (2 * ring->n);
            map[i] = reverse((odd - 1) / 2, bits);
        }
        return map;
    }
    Residues permute(const Residues& input, Word exponent, std::size_t shift = 0) const {
        Residues output(primes, std::vector<Word>(ring->n));
        for (std::size_t p = 0; p < primes; ++p)
            for (std::size_t i = 0; i < ring->n; ++i) {
                auto at = (i * exponent + shift) % (2 * ring->n);
                auto x = input[p][i];
                output[p][at % ring->n] = at >= ring->n && x ? ring->transforms[p].modulus - x : x;
            }
        return output;
    }
    ResidueCiphertext moved(const ResidueCiphertext& input, std::size_t shift) const {
        return {permute(input[0], 1, shift), permute(input[1], 1, shift)};
    }
    void subtract(ResidueCiphertext& a, const ResidueCiphertext& b) const {
        for (std::size_t k = 0; k < 2; ++k)
            for (std::size_t p = 0; p < primes; ++p)
                for (std::size_t i = 0; i < ring->n; ++i) {
                    auto x = a[k][p][i], y = b[k][p][i];
                    a[k][p][i] = x >= y ? x - y : x + ring->transforms[p].modulus - y;
                }
    }
    DigitNTT decompose(const Residues& source) const {
        auto words = arithmetic_.compose_words(source);
        DigitNTT digits(ring->digits, Residues(primes, std::vector<Word>(ring->n)));
        for (std::size_t a = 0; a < ring->digits; ++a)
            for (std::size_t p = 0; p < primes; ++p) {
                for (std::size_t i = 0; i < ring->n; ++i)
                    digits[a][p][i] = ResidueArithmetic::extract(words[i], a * 30, 30);
                ring->transforms[p].forward(digits[a][p]);
            }
        return digits;
    }
    ResidueCiphertext apply_ntt(const DigitNTT& digits, const SwitchKey& key) const {
        ResidueCiphertext out;
        for (auto& c : out) c.assign(primes, std::vector<Word>(ring->n));
        for (std::size_t p = 0; p < primes; ++p)
            for (std::size_t k = 0; k < 2; ++k) {
                const auto& transform = ring->transforms[p];
                for (std::size_t i = 0; i < ring->n; ++i) {
                    Wide sum = 0;
                    for (std::size_t a = 0; a < ring->digits; ++a)
                        sum += Wide(digits[a][p][i]) * key.transformed()[a][k][p][i];
                    out[k][p][i] = transform.remainder(sum);
                }
                transform.inverse(out[k][p]);
            }
        return out;
    }
    ResidueCiphertext product_rns(const PreparedCiphertext& query, const PreparedCiphertext& tile) const {
        // Same persistent-RNS tensor/relinearization as the canonical control.
        std::array<Residues, 3> tensor;
        for (auto& c : tensor) c.assign(primes, std::vector<Word>(ring->n));
        for (std::size_t p = 0; p < primes; ++p) {
            const auto& transform = ring->transforms[p];
            for (std::size_t i = 0; i < ring->n; ++i) {
                auto a = query[0][p][i], b = query[1][p][i];
                auto c = tile[0][p][i], d = tile[1][p][i];
                tensor[0][p][i] = transform.remainder(Wide(a) * c);
                tensor[1][p][i] = transform.remainder(Wide(a) * d + Wide(b) * c);
                tensor[2][p][i] = transform.remainder(Wide(b) * d);
            }
            for (auto& c : tensor) transform.inverse(c[p]);
        }
        auto result = arithmetic_.apply(tensor[2], *keys[0]);
        arithmetic_.add(result, {std::move(tensor[0]), std::move(tensor[1])});
        return moved(result, 2 * ring->n + 1 - padded);
    }
    Anchored anchor(ResidueCiphertext input) const {
        auto source = permute(input[1], exponents[0]);
        auto digits = decompose(source);
        auto correction = apply_ntt(digits, *keys[1]);
        auto c0 = permute(input[0], exponents[0]);
        arithmetic_.add(input, {std::move(c0), Residues(primes, std::vector<Word>(ring->n))});
        arithmetic_.add(input, correction);
        return {std::move(input), std::move(digits)};
    }
    ResidueCiphertext merge_anchored(const Anchored& left, const Anchored* right) const {
        auto plus = left.value, minus = left.value;
        if (right) {
            auto shifted = moved(right->value, padded / 4);
            arithmetic_.add(plus, shifted);
            subtract(minus, shifted);
        }
        ResidueCiphertext correction;
        for (auto& c : correction) c.assign(primes, std::vector<Word>(ring->n));
        const auto& next = keys[2]->transformed();
        for (std::size_t p = 0; p < primes; ++p) {
            const auto& transform = ring->transforms[p];
            auto modulus = transform.modulus;
            for (std::size_t i = 0; i < ring->n; ++i) {
                std::array<Wide, 2> sum{}; // Eight <2^120 products fit in 128 bits.
                for (std::size_t a = 0; a < ring->digits; ++a) {
                    auto old = left.digits[a][p][old_map_[i]];
                    auto fresh = left.digits[a][p][new_map_[i]];
                    if (right) {
                        auto rold = transform.remainder(Wide(right_move_[p][i]) * right->digits[a][p][old_map_[i]]);
                        auto rnew = transform.remainder(Wide(right_move_[p][i]) * right->digits[a][p][new_map_[i]]);
                        old = old >= rold ? old - rold : old + modulus - rold;
                        fresh = fresh >= rnew ? fresh - rnew : fresh + modulus - rnew;
                    }
                    for (std::size_t k = 0; k < 2; ++k)
                        sum[k] += Wide(old) * next[a][k][p][i] + Wide(fresh) * h_[a][k][p][i];
                }
                for (std::size_t k = 0; k < 2; ++k) correction[k][p][i] = transform.remainder(sum[k]);
            }
            for (auto& c : correction) transform.inverse(c[p]);
        }
        auto c0 = permute(minus[0], exponents[1]);
        arithmetic_.add(plus, {std::move(c0), Residues(primes, std::vector<Word>(ring->n))});
        arithmetic_.add(plus, correction);
        return plus;
    }
    ResidueCiphertext finish(std::vector<ResidueCiphertext> work, std::size_t first) const {
        auto shift = padded >> (first + 1);
        for (std::size_t level = first; level < exponents.size(); ++level, shift /= 2) {
            std::vector<ResidueCiphertext> merged;
            for (std::size_t i = 0; i < std::min(shift, work.size()); ++i) {
                auto plus = work[i], minus = work[i];
                if (i + shift < work.size()) {
                    auto right = moved(work[i + shift], shift);
                    arithmetic_.add(plus, right);
                    subtract(minus, right);
                }
                arithmetic_.add(plus, arithmetic_.rotate(minus, exponents[level], *keys[level + 1]));
                merged.push_back(std::move(plus));
            }
            work = std::move(merged);
        }
        return std::move(work.at(0));
    }

public:
    PropagatedGadgetServer(std::shared_ptr<const Ring> r, std::size_t d,
                          std::vector<std::shared_ptr<const SwitchKey>> keys, bool enabled)
        : Server(std::move(r), d, std::move(keys)), arithmetic_(*ring), enabled_(enabled) {
        if (ring->digits != 4 || ring->digit_bits != 30 || primes != 2)
            throw std::invalid_argument("Gadget prototype requires Q120/four30-bit digits");
        if (!enabled || d < 4) return;
        const auto& first = this->keys[1]->transformed();
        const auto& next = this->keys[2]->transformed();
        // Both exponents are odd modulo2N; exact inverse uses the small group.
        Word inverse = 1;
        while (inverse * exponents[0] % (2 * ring->n) != 1) inverse += 2;
        old_map_ = ntt_map(exponents[1] * inverse % (2 * ring->n));
        new_map_ = ntt_map(exponents[1]);
        Polynomial move(ring->n);
        auto at = (exponents[1] * (padded / 4)) % (2 * ring->n);
        move[at % ring->n] = at >= ring->n ? ring->q - 1 : mpz_class(1);
        right_move_ = ring->encode(move, primes);
        h_.resize(ring->digits);
        for (std::size_t a = 0; a < ring->digits; ++a) {
            Residues coefficients = first[a][1];
            for (std::size_t p = 0; p < primes; ++p) ring->transforms[p].inverse(coefficients[p]);
            auto digits = decompose(coefficients);
            for (auto& c : h_[a]) c.assign(primes, std::vector<Word>(ring->n));
            for (std::size_t p = 0; p < primes; ++p)
                for (std::size_t i = 0; i < ring->n; ++i)
                    for (std::size_t k = 0; k < 2; ++k) {
                        Wide sum = 0;
                        for (std::size_t j = 0; j < ring->digits; ++j)
                            sum += Wide(digits[j][p][new_map_[i]]) * next[j][k][p][i];
                        h_[a][k][p][i] = ring->transforms[p].remainder(sum);
                    }
        }
    }
    std::vector<Ciphertext> search(const Ciphertext& query,
                                  const std::vector<PreparedCiphertext>& index, bool joint) const override {
        if (!joint) throw std::invalid_argument("Only the joint butterfly is registered");
        auto prepared = prepare(query);
        std::vector<Ciphertext> output;
        for (std::size_t start = 0; start < index.size(); start += padded) {
            auto count = std::min(padded, index.size() - start);
            std::vector<ResidueCiphertext> work;
            bool propagate = enabled_ && padded >= 4 && count <= padded / 2;
            if (propagate) {
                // Pair-local NTT digits die here; no whole-stage digit cache.
                for (std::size_t i = 0; i < std::min(padded / 4, count); ++i) {
                    auto left = anchor(product_rns(prepared, index[start + i]));
                    if (i + padded / 4 < count) {
                        auto right = anchor(product_rns(prepared, index[start + i + padded / 4]));
                        work.push_back(merge_anchored(left, &right));
                    } else work.push_back(merge_anchored(left, nullptr));
                }
            } else {
                for (std::size_t i = 0; i < count; ++i) work.push_back(product_rns(prepared, index[start + i]));
            }
            auto result = finish(std::move(work), propagate ? 2 : 0);
            output.push_back({arithmetic_.compose(result[0]), arithmetic_.compose(result[1])});
        }
        return output;
    }
    std::size_t shared_h_bytes() const { return h_.size() * 2 * primes * ring->n * sizeof(Word); }
    std::size_t pair_digit_bytes() const { return enabled_ && padded >= 4 ? 2 * ring->digits * primes * ring->n * sizeof(Word) : 0; }
};
} // namespace cuhepy_bgv_lab
