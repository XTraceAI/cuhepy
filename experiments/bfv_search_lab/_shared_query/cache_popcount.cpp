// Q76.4c permitted plaintext cache control. Stateless, bounded, no HE handles.
// Direct callers must supply valid allocated spans; the Python wrapper owns
// immutable inputs and output arrays. Invalid grammar never changes outputs.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

namespace {
constexpr std::uint32_t MAX_ROWS = 32768;
constexpr std::uint32_t MAX_DIMENSION = 512;

struct Span {
    std::uintptr_t begin, end;
};

bool span(const void* pointer, std::size_t length, Span& result) noexcept {
    if (!pointer || !length) return false;
    auto start = reinterpret_cast<std::uintptr_t>(pointer);
    if (length > std::numeric_limits<std::uintptr_t>::max() - start) return false;
    result = {start, start + length};
    return true;
}

bool overlap(const Span& left, const Span& right) noexcept {
    return left.begin < right.end && right.begin < left.end;
}
}

extern "C" std::uint32_t cuhepy_cache_popcount_abi() noexcept { return 1; }

extern "C" int cuhepy_cache_popcount(
    const unsigned char* rows, std::size_t row_bytes,
    std::uint32_t count, std::uint32_t dimension,
    const unsigned char* query, std::size_t query_bytes,
    std::uint16_t* scores, std::size_t score_count,
    std::uint32_t* positions, std::size_t position_count) noexcept {
    if (!count || count > MAX_ROWS || !dimension || dimension > MAX_DIMENSION) return -1;
    const std::size_t width = (dimension + 7) / 8;
    const std::size_t winners = count < 3 ? count : 3;
    if (row_bytes != count * width || query_bytes != width || score_count != count
        || position_count != winners) return -1;
    if (reinterpret_cast<std::uintptr_t>(scores) % alignof(std::uint16_t)
        || reinterpret_cast<std::uintptr_t>(positions) % alignof(std::uint32_t)) return -1;
    Span input, word, distances, top;
    if (!span(rows, row_bytes, input) || !span(query, query_bytes, word)
        || !span(scores, score_count * sizeof(*scores), distances)
        || !span(positions, position_count * sizeof(*positions), top)) return -1;
    if (overlap(distances, input) || overlap(distances, word) || overlap(top, input)
        || overlap(top, word) || overlap(distances, top)) return -1;

    // Check EVERY physical row, including the last one, before writing scores.
    if (dimension % 8) {
        const unsigned char padding = static_cast<unsigned char>(0xffU << (dimension % 8));
        if (query[width - 1] & padding) return -1;
        for (std::size_t i = 0; i < count; ++i)
            if (rows[i * width + width - 1] & padding) return -1;
    }
    const std::size_t whole_words = width / sizeof(std::uint64_t);
    std::array<std::uint64_t, 8> query_words{};
    for (std::size_t j = 0; j < whole_words; ++j)
        std::memcpy(&query_words[j], query + j * sizeof(std::uint64_t), sizeof(std::uint64_t));
    std::array<std::uint16_t, 3> best_scores{65535, 65535, 65535};
    std::array<std::uint32_t, 3> best_positions{};
    for (std::uint32_t i = 0; i < count; ++i) {
        auto row = rows + i * width;
        unsigned distance = 0;
        for (std::size_t j = 0; j < whole_words; ++j) {
            std::uint64_t value;
            std::memcpy(&value, row + j * sizeof(value), sizeof(value));
            distance += __builtin_popcountll(value ^ query_words[j]);
        }
        for (std::size_t j = whole_words * sizeof(std::uint64_t); j < width; ++j)
            distance += __builtin_popcount(static_cast<unsigned>(row[j] ^ query[j]));
        scores[i] = static_cast<std::uint16_t>(distance);
        // Rows are visited in ordinal order. Strict insertion preserves ties;
        // IDs never enter the native selector, so numeric-ID ties cannot leak in.
        for (std::size_t j = 0; j < winners; ++j) {
            if (distance >= best_scores[j]) continue;
            for (std::size_t k = winners - 1; k > j; --k) {
                best_scores[k] = best_scores[k - 1];
                best_positions[k] = best_positions[k - 1];
            }
            best_scores[j] = static_cast<std::uint16_t>(distance);
            best_positions[j] = i;
            break;
        }
    }
    for (std::size_t j = 0; j < winners; ++j) positions[j] = best_positions[j];
    return 0;
}
