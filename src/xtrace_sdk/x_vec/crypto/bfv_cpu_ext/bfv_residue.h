// Persistent RNS ciphertext arithmetic for Q = p_0 * ... * p_{L-1}.
// Independently implemented. Binary gadget keys and exact BFV rounding are
// unchanged, so the GMP evaluator is a coefficient-for-coefficient oracle.
#pragma once
#include "bfv_server.h"

namespace xtrace_bfv {
using ResidueCiphertext = std::array<Residues, 2>;
using CoefficientWords = std::array<Word, 8>; // Q has at most 480 bits here.

class ResidueArithmetic {
    const Ring& ring_;
    // Inverses p_k^-1 mod p_j for Garner's mixed-radix reconstruction, k < j.
    std::vector<std::vector<Multiplier>> inverses_;

public:
    const std::size_t count;
    explicit ResidueArithmetic(const Ring& ring) : ring_(ring), count(ring.residue_prime_count) {
        if (!count || count > 8) throw std::invalid_argument("Missing persistent RNS modulus");
        for (std::size_t j = 0; j < count; ++j) {
            inverses_.emplace_back();
            Word p = ring.transforms[j].modulus;
            for (std::size_t k = 0; k < j; ++k)
                inverses_.back().emplace_back(power_mod(ring.transforms[k].modulus % p, p - 2, p), p);
        }
    }

    Residues split(const Polynomial& poly) const {
        ProfileScope timing(Phase::to_residues);
        Residues result(count, std::vector<Word>(ring_.n));
        for (std::size_t j = 0; j < count; ++j)
            for (std::size_t i = 0; i < ring_.n; ++i)
                result[j][i] = mpz_fdiv_ui(poly[i].get_mpz_t(), ring_.transforms[j].modulus);
        return result;
    }

    // Recover the UNIQUE representative in [0,Q), not a centered or approximate
    // CRT lift. Gadget digits depend on that choice. All arithmetic below uses
    // 64/128-bit words, with no floating point, big-integer division or GMP.
    std::vector<CoefficientWords> compose_words(const Residues& poly) const {
        ProfileScope timing(Phase::rns_compose);
        std::vector<CoefficientWords> result(ring_.n);
        for (std::size_t i = 0; i < ring_.n; ++i) {
            std::array<Word, 8> digits{};
            for (std::size_t j = 0; j < count; ++j) {
                Word p = ring_.transforms[j].modulus, value = poly[j][i];
                for (std::size_t k = 0; k < j; ++k) {
                    // Every p is in (2^59,2^60): a mixed-radix digit from an
                    // earlier prime needs at most one subtraction modulo p.
                    Word d = digits[k] >= p ? digits[k] - p : digits[k];
                    value = inverses_[j][k].multiply(value + p - d, p);
                }
                digits[j] = value;
            }
            auto& words = result[i];
            words[0] = digits[count - 1];
            std::size_t used = 1;
            for (std::size_t j = count - 1; j > 0; --j) {
                Word carry = digits[j - 1], p = ring_.transforms[j - 1].modulus;
                for (std::size_t limb = 0; limb < used; ++limb) {
                    Wide product = Wide(words[limb]) * p + carry;
                    words[limb] = Word(product);
                    carry = Word(product >> 64);
                }
                if (carry) words[used++] = carry;
            }
        }
        return result;
    }

    Polynomial compose(const Residues& poly) const {
        auto words = compose_words(poly);
        ProfileScope timing(Phase::crt_reconstruct);
        Polynomial result(ring_.n);
        for (std::size_t i = 0; i < ring_.n; ++i)
            mpz_import(result[i].get_mpz_t(), 8, -1, sizeof(Word), 0, 0, words[i].data());
        return result;
    }

    static Word extract(const CoefficientWords& value, unsigned bit, unsigned width) {
        // width <= 60, and the caller never asks for a bit above Q's bit length.
        auto limb = bit / 64, offset = bit % 64;
        Word result = value[limb] >> offset;
        if (offset && limb + 1 < value.size()) result |= value[limb + 1] << (64 - offset);
        return result & ((Word(1) << width) - 1);
    }

    // Also support wider binary gadgets. Reduction consumes at most 60 bits
    // per step, so each intermediate fits 120 bits even for a 480-bit digit.
    Word digit_mod(const CoefficientWords& value, unsigned start, unsigned bits, std::size_t j) const {
        auto q_bits = unsigned(60 * count);
        unsigned width = std::min(bits, q_bits - start);
        const auto& transform = ring_.transforms[j];
        if (width <= 60) {
            Word result = extract(value, start, width);
            return result >= transform.modulus ? result - transform.modulus : result;
        }
        Word result = 0;
        while (width) {
            unsigned take = std::min(width, 60U);
            result = transform.reduce((Wide(result) << take) | extract(value, start + width - take, take));
            width -= take;
        }
        return result;
    }

    ResidueCiphertext apply(const Residues& poly, const SwitchKey& key) const {
        auto words = compose_words(poly);
        std::vector<std::vector<Word>> small_digits;
        if (ring_.digit_bits <= 60) {
            ProfileScope timing(Phase::gadget_decompose);
            small_digits.assign(ring_.digits, std::vector<Word>(ring_.n));
            for (std::size_t digit = 0; digit < ring_.digits; ++digit)
                for (std::size_t i = 0; i < ring_.n; ++i)
                    small_digits[digit][i] = extract(words[i], digit * ring_.digit_bits, ring_.digit_bits);
        }
        auto result = key.apply_digits([&](std::size_t j, std::size_t digit, std::vector<Word>& values) {
            ProfileScope timing(Phase::gadget_decompose);
            if (small_digits.empty()) {
                for (std::size_t i = 0; i < ring_.n; ++i)
                    values[i] = digit_mod(words[i], digit * ring_.digit_bits, ring_.digit_bits, j);
            } else {
                Word p = ring_.transforms[j].modulus;
                for (std::size_t i = 0; i < ring_.n; ++i) {
                    Word value = small_digits[digit][i];
                    values[i] = value >= p ? value - p : value;
                }
            }
        });
        for (auto& component : result)
            for (std::size_t j = 0; j < count; ++j) ring_.transforms[j].inverse(component[j]);
        return result;
    }

    void add(ResidueCiphertext& lhs, const ResidueCiphertext& rhs) const {
        ProfileScope timing(Phase::add_sub);
        for (std::size_t k = 0; k < 2; ++k)
            for (std::size_t j = 0; j < count; ++j) {
                Word p = ring_.transforms[j].modulus;
                for (std::size_t i = 0; i < ring_.n; ++i) {
                    Word value = lhs[k][j][i] + rhs[k][j][i];
                    lhs[k][j][i] = value >= p ? value - p : value;
                }
            }
    }

    ResidueCiphertext rotate(const ResidueCiphertext& value, Word exponent, const SwitchKey& key) const {
        ResidueCiphertext permuted;
        { ProfileScope timing(Phase::automorphism);
          for (std::size_t k = 0; k < 2; ++k) {
              permuted[k].assign(count, std::vector<Word>(ring_.n));
              for (std::size_t j = 0; j < count; ++j) {
                  Word p = ring_.transforms[j].modulus;
                  for (std::size_t i = 0; i < ring_.n; ++i) {
                      std::size_t at = (i * exponent) & (2 * ring_.n - 1);
                      Word c = value[k][j][i];
                      permuted[k][j][at & (ring_.n - 1)] = at >= ring_.n && c ? p - c : c;
                  }
              }
          } }
        auto switched = apply(permuted[1], key);
        { ProfileScope timing(Phase::add_sub);
          for (std::size_t j = 0; j < count; ++j) {
              Word p = ring_.transforms[j].modulus;
              for (std::size_t i = 0; i < ring_.n; ++i) {
                  Word c = switched[0][j][i] + permuted[0][j][i];
                  switched[0][j][i] = c >= p ? c - p : c;
              }
          } }
        return switched;
    }

    void multiply_plain(ResidueCiphertext& value, const Residues& mask_ntt) const {
        for (auto& component : value)
            for (std::size_t j = 0; j < count; ++j) {
                const auto& transform = ring_.transforms[j];
                transform.forward(component[j]);
                { ProfileScope timing(Phase::pointwise);
                  for (std::size_t i = 0; i < ring_.n; ++i)
                      component[j][i] = transform.remainder(Wide(component[j][i]) * mask_ntt[j][i]); }
                transform.inverse(component[j]);
            }
    }
};

class ResidueServer : public HammingServer {
    ResidueArithmetic arithmetic_;
    Residues full_mask_ntt_;

    ResidueCiphertext tile(const Ciphertext& query, const Ciphertext& indexed, const Residues& selected) const {
        Ciphertext difference = query;
        { ProfileScope timing(Phase::add_sub);
          for (std::size_t k = 0; k < 2; ++k)
              for (std::size_t i = 0; i < ring->n; ++i) {
                  difference[k][i] -= indexed[k][i];
                  if (difference[k][i] < 0) difference[k][i] += ring->q;
              } }
        // One exact tensor and scale/round per tile still uses the original
        // auxiliary base and GMP. After this boundary, ciphertexts remain RNS
        // through relinearization, all rotations, masks and the merge tree.
        auto product = ring->multiply(difference, difference, t, true);
        auto distance = arithmetic_.apply(arithmetic_.split(product[2]), *relin_);
        arithmetic_.add(distance, {arithmetic_.split(product[0]), arithmetic_.split(product[1])});
        for (auto g : left_) {
            auto rotated = arithmetic_.rotate(distance, g, key(g));
            arithmetic_.add(distance, rotated);
        }
        arithmetic_.multiply_plain(distance, selected);
        return distance;
    }

public:
    ResidueServer(KeyHandle relin, std::map<Word, KeyHandle> keys,
                  std::size_t padded, Word t, const mpz_class& target)
        : HammingServer(std::move(relin), std::move(keys), padded, t, target, false),
          arithmetic_(*ring), full_mask_ntt_(ring->encode(mask(capacity), arithmetic_.count)) {}

    void search(const Ciphertext& query, std::size_t count, ReadTile read_tile, Emit emit, bool compact_result) const override {
        const auto tiles = (count + capacity - 1) / capacity;
        Residues partial;
        if (count % capacity) partial = ring->encode(mask(count % capacity), arithmetic_.count);
        merge_hamming_tiles<ResidueCiphertext>(tiles, padded, [&](std::size_t at) {
            const auto& selected = at + 1 == tiles && !partial.empty() ? partial : full_mask_ntt_;
            return tile(query, read_tile(at), selected);
        }, [&](const ResidueCiphertext& result, std::size_t level) {
            return arithmetic_.rotate(result, right_.at(level), key(right_.at(level)));
        }, [&](ResidueCiphertext& lhs, const ResidueCiphertext& rhs) {
            arithmetic_.add(lhs, rhs);
        }, [&](ResidueCiphertext result) {
            Ciphertext output{arithmetic_.compose(result[0]), arithmetic_.compose(result[1])};
            if (compact_result) compact(output);
            emit(output);
        });
    }

    std::size_t bytes() const override { return HammingServer::bytes() + arithmetic_.count * ring->n * sizeof(Word); }
};
} // namespace xtrace_bfv
