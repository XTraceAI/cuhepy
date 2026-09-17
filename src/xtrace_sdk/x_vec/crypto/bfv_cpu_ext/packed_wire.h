// The existing wire packs each coefficient into q.bit_length() bits, without
// padding individual coefficients to byte boundaries. No Python mpz tuples are
// needed to import or export these buffers.
#pragma once
#include "rns_ntt.h"
#include <cstring>
#include <string>
#include <string_view>

namespace xtrace_bfv {
inline Word load_word(std::string_view data, std::size_t offset) {
    if (offset >= data.size()) return 0;
    Word result = 0;
    std::memcpy(&result, data.data() + offset, std::min<std::size_t>(8, data.size() - offset));
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    result = __builtin_bswap64(result);
#endif
    return result;
}

inline Polynomial import_packed(std::string_view data, const Ring& ring) {
    ProfileScope timing(Phase::wire_import);
    const auto bits = mpz_sizeinbase(ring.q.get_mpz_t(), 2);
    if (data.size() != (ring.n * bits + 7) / 8) throw std::invalid_argument("Incorrect packed polynomial byte length");
    const auto words = (bits + 63) / 64;
    Polynomial result(ring.n);
    for (std::size_t i = 0; i < ring.n; ++i) {
        std::array<Word, 8> limbs{};
        auto offset = (i * bits / 64) * 8, shift = i * bits % 64;
        for (std::size_t j = 0; j < words; ++j) {
            limbs[j] = load_word(data, offset + 8 * j) >> shift;
            if (shift) limbs[j] |= load_word(data, offset + 8 * j + 8) << (64 - shift);
        }
        if (bits % 64) limbs[words - 1] &= (Word(1) << (bits % 64)) - 1;
        mpz_import(result[i].get_mpz_t(), words, -1, sizeof(Word), 0, 0, limbs.data());
        if (result[i] >= ring.q) throw std::invalid_argument("Noncanonical packed polynomial coefficient");
    }
    return result;
}

inline std::string export_packed(const Polynomial& poly, const mpz_class& q) {
    ProfileScope timing(Phase::wire_export);
    const auto bits = mpz_sizeinbase(q.get_mpz_t(), 2), words = (bits + 63) / 64;
    if (bits > 512) throw std::invalid_argument("Unsupported packed modulus");
    std::vector<Word> packed((poly.size() * bits + 63) / 64 + 1);
    for (std::size_t i = 0; i < poly.size(); ++i) {
        if (poly[i] < 0 || poly[i] >= q) throw std::logic_error("Invalid native output coefficient");
        std::array<Word, 8> limbs{};
        mpz_export(limbs.data(), nullptr, -1, sizeof(Word), 0, 0, poly[i].get_mpz_t());
        auto offset = i * bits / 64, shift = i * bits % 64;
        for (std::size_t j = 0; j < words; ++j) {
            packed[offset + j] |= limbs[j] << shift;
            if (shift) packed[offset + j + 1] |= limbs[j] >> (64 - shift);
        }
    }
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    for (auto& word : packed) word = __builtin_bswap64(word);
#endif
    return std::string(reinterpret_cast<const char*>(packed.data()), (poly.size() * bits + 7) / 8);
}
} // namespace xtrace_bfv
