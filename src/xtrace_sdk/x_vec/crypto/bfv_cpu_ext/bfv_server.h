// Complete public-key BFV Hamming evaluation, independent of Python objects.
// Ciphertexts cross the binding once, retain native coefficients through the
// circuit and merge tree, and are serialized only after terminal compaction.
#pragma once
#include "rns_ntt.h"
#include <map>
#include <string>

namespace xtrace_bfv {
using KeyHandle = std::shared_ptr<const SwitchKey>;

class PreparedPlain {
    const Ring& ring_;
    Residues value_;
public:
    PreparedPlain(const Ring& ring, const Polynomial& value) : ring_(ring) {
        mpz_class bound = ring.n * (ring.q - 1) * *std::max_element(value.begin(), value.end());
        value_ = ring.encode(value, ring.prime_count(bound));
    }
    Polynomial apply(const Polynomial& value) const {
        auto transformed = ring_.encode(value, value_.size());
        { ProfileScope timing(Phase::pointwise);
          for (std::size_t j = 0; j < value_.size(); ++j)
              for (std::size_t i = 0; i < ring_.n; ++i)
                  transformed[j][i] = ring_.transforms[j].remainder(Wide(transformed[j][i]) * value_[j][i]); }
        return ring_.decode_mod_q(std::move(transformed));
    }
    std::size_t bytes() const { return value_.size() * ring_.n * sizeof(Word); }
};

class HammingServer {
    KeyHandle relin_;
    std::map<Word, KeyHandle> keys_;
    PrimeNTT plaintext_;
    std::vector<Word> left_, right_;
    std::unique_ptr<PreparedPlain> full_mask_;

    Word exponent(std::size_t step) const { return power_mod(3, step % (ring->n / 2), 2 * ring->n); }
    const SwitchKey& key(Word g) const {
        auto found = keys_.find(g);
        if (found == keys_.end()) throw std::invalid_argument("Missing native server rotation key");
        return *found->second;
    }
    Polynomial mask(std::size_t count) const {
        std::vector<Word> evaluations(ring->n);
        unsigned log_n = 0;
        for (std::size_t v = ring->n; v > 1; v >>= 1) ++log_n;
        Word g = 1;
        for (std::size_t lane = 0; lane < lanes; ++lane) {
            for (std::size_t row = 0; row < 2; ++row) {
                if (row * lanes + lane >= count) continue;
                std::size_t position = ((row ? 2 * ring->n - g : g) - 1) / 2;
                std::size_t reversed = 0;
                for (unsigned bit = 0; bit < log_n; ++bit) { reversed = 2 * reversed + (position & 1); position >>= 1; }
                evaluations[reversed] = 1;
            }
            g = g * 3 % (2 * ring->n);
        }
        plaintext_.inverse(evaluations);
        Polynomial result(ring->n);
        for (std::size_t i = 0; i < ring->n; ++i) result[i] = evaluations[i];
        return result;
    }

public:
    const std::shared_ptr<const Ring> ring;
    const std::size_t padded, lanes, capacity;
    const Word t;
    const mpz_class target;

    HammingServer(KeyHandle relin, std::map<Word, KeyHandle> keys,
                  std::size_t padded, Word t, const mpz_class& target)
        : relin_(std::move(relin)), keys_(std::move(keys)), plaintext_(relin_->ring->n, t, relin_->ring->fast),
          ring(relin_->ring), padded(padded), lanes(ring->n / (2 * padded)),
          capacity(2 * lanes), t(t), target(target) {
        // The binding checks algebraic parameters before constructing the NTT.
        for (std::size_t size = 1; size < padded; size *= 2) {
            left_.push_back(exponent(lanes * size));
            right_.push_back(exponent(ring->n / 2 - lanes * size));
            key(left_.back()); key(right_.back());
        }
        full_mask_ = std::make_unique<PreparedPlain>(*ring, mask(capacity));
    }

    Ciphertext tile(const Ciphertext& query, const Ciphertext& indexed, const PreparedPlain& selected) const {
        Ciphertext difference = query;
        { ProfileScope timing(Phase::add_sub);
          for (std::size_t k = 0; k < 2; ++k)
              for (std::size_t i = 0; i < ring->n; ++i) {
                  difference[k][i] -= indexed[k][i];
                  if (difference[k][i] < 0) difference[k][i] += ring->q;
              } }
        auto product = ring->multiply(difference, difference, t, true);
        auto distance = relin_->apply(product[2]);
        add_inplace(distance, {std::move(product[0]), std::move(product[1])}, *ring);
        for (auto g : left_) {
            auto rotated = rotate(distance, g, key(g));
            add_inplace(distance, rotated, *ring);
        }
        for (auto& component : distance) component = selected.apply(component);
        return distance;
    }

    void compact(Ciphertext& value) const {
        ProfileScope timing(Phase::scale_round);
        mpz_class denominator = 2 * ring->q;
        for (auto& component : value)
            for (auto& c : component) {
                c = 2 * target * c + ring->q;
                mpz_fdiv_q(c.get_mpz_t(), c.get_mpz_t(), denominator.get_mpz_t());
                mpz_mod(c.get_mpz_t(), c.get_mpz_t(), target.get_mpz_t());
            }
    }

    // read_tile/emit allow the binding to stream packed bytes with the GIL
    // released. At most O(log(padded)) intermediate ciphertexts are retained.
    template <class ReadTile, class Emit>
    void search(const Ciphertext& query, std::size_t count, ReadTile read_tile, Emit emit, bool compact_result) const {
        const auto tiles = (count + capacity - 1) / capacity;
        std::unique_ptr<PreparedPlain> partial;
        if (count % capacity) partial = std::make_unique<PreparedPlain>(*ring, mask(count % capacity));
        for (std::size_t start = 0; start < tiles; start += padded) {
            std::vector<std::pair<Ciphertext, std::size_t>> stack;
            for (std::size_t at = start; at < std::min(start + padded, tiles); ++at) {
                const auto& selected = at + 1 == tiles && partial ? *partial : *full_mask_;
                auto result = tile(query, read_tile(at), selected);
                std::size_t size = 1, level = 0;
                while (!stack.empty() && stack.back().second == size) {
                    auto rotated = rotate(result, right_.at(level), key(right_[level]));
                    result = std::move(stack.back().first);
                    stack.pop_back();
                    add_inplace(result, rotated, *ring);
                    size *= 2; ++level;
                }
                stack.emplace_back(std::move(result), size);
            }
            auto result = std::move(stack.back().first);
            stack.pop_back();
            while (!stack.empty()) {
                auto size = stack.back().second;
                std::size_t level = 0;
                while ((std::size_t(1) << level) < size) ++level;
                auto rotated = rotate(result, right_.at(level), key(right_[level]));
                result = std::move(stack.back().first);
                stack.pop_back();
                add_inplace(result, rotated, *ring);
            }
            if (compact_result) compact(result);
            emit(result);
        }
    }
    std::size_t bytes() const { return plaintext_.bytes() + full_mask_->bytes(); }
};
} // namespace xtrace_bfv
