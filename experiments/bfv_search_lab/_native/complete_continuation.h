// Complete public BGV arithmetic for the secretless verification controls.
// The caller must authenticate/check the unshifted product tiles first. These
// helpers do not sample challenges, authorize release, or hold an HE secret.
#pragma once
#include "residue_trace.h"
#include "compact.h"

namespace cuhepy_bgv_lab {
class CompleteContinuation {
    const Server& server_;
    const Ring& ring_;
    const ResidueArithmetic arithmetic_;

    ResidueCiphertext monomial(const ResidueCiphertext& input, std::size_t shift) const {
        ResidueCiphertext output;
        for (std::size_t component = 0; component < 2; ++component) {
            output[component].assign(arithmetic_.count, std::vector<Word>(ring_.n));
            for (std::size_t limb = 0; limb < arithmetic_.count; ++limb) {
                const auto modulus = ring_.transforms[limb].modulus;
                for (std::size_t i = 0; i < ring_.n; ++i) {
                    const auto at = (i + shift) % (2 * ring_.n);
                    const auto value = input[component][limb][i];
                    output[component][limb][at % ring_.n] =
                        at >= ring_.n && value ? modulus - value : value;
                }
            }
        }
        return output;
    }

    void subtract(ResidueCiphertext& left, const ResidueCiphertext& right) const {
        for (std::size_t component = 0; component < 2; ++component)
            for (std::size_t limb = 0; limb < arithmetic_.count; ++limb) {
                const auto modulus = ring_.transforms[limb].modulus;
                for (std::size_t i = 0; i < ring_.n; ++i) {
                    const auto a = left[component][limb][i], b = right[component][limb][i];
                    left[component][limb][i] = a >= b ? a - b : a + modulus - b;
                }
            }
    }

    static Word read_word(const unsigned char* source) {
        // Do not cast the unaligned Python byte buffer to a native word pointer.
        Word value = 0;
        for (unsigned byte = 0; byte < 8; ++byte) value |= Word(source[byte]) << (8 * byte);
        return value;
    }

public:
    // Match the existing E13 product-check protocol. Other native profiles are
    // deliberately rejected until they have a matching admitted stage checker.
    explicit CompleteContinuation(const Server& server)
        : server_(server), ring_(*server.ring), arithmetic_(ring_) {
        if (ring_.n > 16384 || arithmetic_.count != 2 || ring_.digit_bits != 30 || ring_.digits != 4)
            throw std::invalid_argument("Complete control requires N<=16384, Q120, and four common 30-bit digits");
    }

    std::size_t product_bytes(std::size_t tiles) const {
        if (!tiles || tiles > 4096 || tiles > (std::size_t(1) << 31) / (4 * ring_.n * sizeof(Word)))
            throw std::invalid_argument("Complete product coverage exceeds the native allocation limit");
        return tiles * 4 * ring_.n * sizeof(Word);
    }

    void validate_products(const unsigned char* data, std::size_t size, std::size_t tiles) const {
        if (size != product_bytes(tiles))
            throw std::invalid_argument("Incomplete exact product-body coverage");
        // Grammar is [tile][component][limb][coefficient], little-endian uint64.
        // Scan EVERY coefficient before a controller samples any challenge.
        std::size_t offset = 0;
        for (std::size_t tile = 0; tile < tiles; ++tile)
            for (std::size_t component = 0; component < 2; ++component)
                for (std::size_t limb = 0; limb < arithmetic_.count; ++limb)
                    for (std::size_t i = 0; i < ring_.n; ++i, offset += sizeof(Word))
                        if (read_word(data + offset) >= ring_.transforms[limb].modulus)
                            throw std::invalid_argument("Noncanonical product RNS residue");
    }

    std::vector<ResidueCiphertext> read_products(const unsigned char* data, std::size_t size,
                                               std::size_t tiles) const {
        validate_products(data, size, tiles);
        std::vector<ResidueCiphertext> result(tiles);
        std::size_t offset = 0;
        for (auto& tile : result)
            for (auto& component : tile) {
                component.assign(arithmetic_.count, std::vector<Word>(ring_.n));
                for (auto& limb : component)
                    for (auto& value : limb) {
                        value = read_word(data + offset);
                        offset += sizeof(Word);
                    }
            }
        return result;
    }

    std::vector<ResidueCiphertext> split_products(const std::vector<Ciphertext>& products,
                                                std::size_t expected_tiles) const {
        product_bytes(expected_tiles);
        if (products.size() != expected_tiles)
            throw std::invalid_argument("Incomplete exact product-tile coverage");
        std::vector<ResidueCiphertext> result;
        result.reserve(products.size());
        for (const auto& cipher : products) {
            for (const auto& poly : cipher) {
                if (poly.size() != ring_.n)
                    throw std::invalid_argument("Incorrect product polynomial length");
                for (const auto& value : poly)
                    if (value < 0 || value >= ring_.q)
                        throw std::invalid_argument("Noncanonical full-Q product coefficient");
            }
            result.push_back({arithmetic_.split(cipher[0]), arithmetic_.split(cipher[1])});
        }
        return result;
    }

    std::vector<Ciphertext> continue_products(std::vector<ResidueCiphertext> products,
                                            std::size_t expected_tiles) const {
        // Bindings reach this only via read_products or split_products, which
        // validate every tensor shape/range. The vector is privately owned.
        product_bytes(expected_tiles);
        if (products.size() != expected_tiles)
            throw std::invalid_argument("Incomplete exact product-tile coverage");
        std::vector<Ciphertext> results;
        results.reserve((products.size() + server_.padded - 1) / server_.padded);
        for (std::size_t start = 0; start < products.size(); start += server_.padded) {
            const auto count = std::min(server_.padded, products.size() - start);
            std::vector<ResidueCiphertext> work;
            work.reserve(count);
            // E13 product outputs are UNSHIFTED. Apply the original trace's
            // shift exactly once, including padded=1 and a partial last group.
            for (std::size_t i = 0; i < count; ++i)
                work.push_back(monomial(products[start + i], 2 * ring_.n + 1 - server_.padded));
            auto shift = server_.padded / 2;
            for (std::size_t level = 0; level < server_.exponents.size(); ++level, shift /= 2) {
                std::vector<ResidueCiphertext> merged;
                merged.reserve(std::min(shift, work.size()));
                for (std::size_t i = 0; i < std::min(shift, work.size()); ++i) {
                    auto plus = work[i], minus = work[i];
                    if (i + shift < work.size()) {
                        const auto right = monomial(work[i + shift], shift);
                        arithmetic_.add(plus, right);
                        subtract(minus, right);
                    }
                    // ResidueArithmetic::rotate reconstructs the ONE canonical
                    // full-Q polynomial before common gadget decomposition.
                    // Independent per-limb digit tapes are never accepted.
                    arithmetic_.add(plus, arithmetic_.rotate(minus, server_.exponents[level],
                                                            *server_.keys[level + 1]));
                    merged.push_back(std::move(plus));
                }
                work = std::move(merged);
            }
            if (work.size() != 1 || shift)
                throw std::logic_error("Incomplete native trusted butterfly");
            results.push_back({arithmetic_.compose(work[0][0]), arithmetic_.compose(work[0][1])});
        }
        return results;
    }

    void compact(std::vector<Ciphertext>& output, const TerminalReduction& reduction) const {
        for (auto& cipher : output) reduction.apply(cipher);
    }
};
} // namespace cuhepy_bgv_lab
