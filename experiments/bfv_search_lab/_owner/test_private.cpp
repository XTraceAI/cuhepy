// Dynamic secret-taint, independent arithmetic and wiping tests for BGV.
// Compile -DCUHEPY_BGV_CTGRIND and run under Memcheck; "negative" must fail.
#define CUHEPY_BGV_CT_TEST
#include "bgv_private.h"
#include <cassert>
#include <iostream>
#ifdef CUHEPY_BGV_CTGRIND
#include <valgrind/memcheck.h>
#endif
using namespace cuhepy_bgv_private;

void secret(void* p, std::size_t size) {
#ifdef CUHEPY_BGV_CTGRIND
    VALGRIND_MAKE_MEM_UNDEFINED(p, size);
#else
    (void)p; (void)size;
#endif
}
void declassify(void* p, std::size_t size) {
#ifdef CUHEPY_BGV_CTGRIND
    VALGRIND_MAKE_MEM_DEFINED(p, size);
#else
    (void)p; (void)size;
#endif
}
int main(int argc, char**) {
#ifdef CUHEPY_BGV_CTGRIND
    assert(RUNNING_ON_VALGRIND);
    if (argc > 1) {
        Word input = 1;
        secret(&input, sizeof(input));
        if (input) std::cout << "Deliberate secret branch: negative control\n";
        return 0;
    }
#else
    (void)argc;
#endif
    constexpr Word p0 = 1152921504606584833ULL, p1 = 1152921504598720513ULL, t = 1031;
    for (Word p : {Word(3), t, (Word(1) << 25) - 1, (Word(1) << 60) - 1}) {
        PublicReducer reducer(p);
        for (Word original : {Word(0), p - 1, p, p + 1, UINT64_MAX / 2, UINT64_MAX}) {
            Word value = original;
            secret(&value, sizeof(value));
            Word actual = reducer.reduce(value);
            declassify(&actual, sizeof(actual));
            assert(actual == original % p);
        }
    }
    for (std::size_t n : {std::size_t(16), std::size_t(128), std::size_t(16384), std::size_t(32768)}) {
        for (Word p : {Word(65537), (Word(1) << 25) - 1, (Word(1) << 60) - 1}) {
            std::vector<unsigned char> key(n), output(4 * n);
            std::vector<Word> c0(n), c1(n), expected(n);
            for (unsigned pattern = 0; pattern < 3; ++pattern) {
                SignedWide sum = 0;
                for (std::size_t i = 0; i < n; ++i) {
                    key[i] = pattern == 0 ? 1 : pattern == 1 ? 255 : (i % 3 == 0 ? 0 : i % 3 == 1 ? 1 : 255);
                    c0[i] = i % 4 == 0 ? 0 : i % 4 == 1 ? p / 2 : i % 4 == 2 ? p / 2 + 1 : p - 1;
                    // Dense extrema for uniform keys; sparse for the mixed key.
                    c1[i] = pattern != 2 || i < 3 || i == n - 1 ? p - 1 - (i % 3) : 0;
                    sum += c1[i];
                }
                SignedWide prefix = 0;
                for (std::size_t i = 0; i < n; ++i) {
                    SignedWide phase = c0[i];
                    if (pattern != 2) {
                        prefix += c1[i];
                        phase += (pattern == 0 ? 1 : -1) * (2 * prefix - sum);
                    } else {
                        for (std::size_t j : {std::size_t(0), std::size_t(1), std::size_t(2), n - 1}) {
                            std::size_t at = (i + n - j) % n;
                            int s = key[at] == 255 ? -1 : key[at];
                            phase += (i >= j ? 1 : -1) * SignedWide(c1[j]) * s;
                        }
                    }
                    // Public independent oracle; deliberately normal division.
                    phase %= p;
                    if (phase < 0) phase += p;
                    if (phase > p / 2) phase -= p;
                    phase %= t;
                    if (phase < 0) phase += t;
                    expected[i] = Word(phase);
                }
                Decoder decoder(n, p, t, p0, p1, key.data());
                // No private intermediate/output is declassified inside the kernel.
                secret(decoder.test_secret_spectra(), 2 * n * sizeof(Word));
                decoder.decode(c0.data(), c1.data(), output.data());
                declassify(output.data(), output.size());
                for (std::size_t i = 0; i < n; ++i) {
                    Word value = 0;
                    for (unsigned j = 0; j < 4; ++j) value |= Word(output[4*i+j]) << (8*j);
                    assert(value == expected[i]);
                }
                decoder.close();
                for (std::size_t i = 0; i < 2 * n; ++i) assert(decoder.test_secret_spectra()[i] == 0);
                bool rejected = false;
                try { decoder.decode(c0.data(), c1.data(), output.data()); }
                catch (const std::runtime_error&) { rejected = true; }
                assert(rejected);
            }
        }
    }
    std::cout << "BGV private arithmetic, boundary, wiping and taint checks passed\n";
}
