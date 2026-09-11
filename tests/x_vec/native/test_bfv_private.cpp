// Standalone private-kernel arithmetic, wiping and optional secret-taint checks.
// Compile with -DXTRACE_BFV_CTGRIND and run under Valgrind Memcheck to flag
// secret-dependent branches/addresses in the compiled decoder and NTTs.
#define XTRACE_BFV_CT_TEST
#include "private_decoder.h"
#include <cassert>
#include <iostream>
#ifdef XTRACE_BFV_CTGRIND
#include <valgrind/memcheck.h>
#endif

using namespace xtrace_bfv_private;

void secret(void* data, std::size_t bytes) {
#ifdef XTRACE_BFV_CTGRIND
    VALGRIND_MAKE_MEM_UNDEFINED(data, bytes);
#else
    (void)data; (void)bytes;
#endif
}
void declassify(void* data, std::size_t bytes) {
#ifdef XTRACE_BFV_CTGRIND
    VALGRIND_MAKE_MEM_DEFINED(data, bytes);
#else
    (void)data; (void)bytes;
#endif
}

int main(int argc, char**) {
#ifdef XTRACE_BFV_CTGRIND
    assert(RUNNING_ON_VALGRIND);
    if (argc > 1) {
        // The CI negative control must fail under Memcheck. It demonstrates
        // that the runner actually detects a branch on a marked secret.
        Word value = 1;
        secret(&value, sizeof(value));
        if (value) std::cout << "Deliberate secret branch in negative control\n";
        return 0;
    }
#else
    (void)argc;
#endif
    constexpr Word q = 1125899906842597ULL, t = 65537;
    constexpr Word p0 = 1152921504606830593ULL, p1 = 1152921504606748673ULL;
    // Independent division/modulo oracles are PUBLIC test calculations.
    for (Word modulus : {Word(17), q, 2 * q}) {
        for (unsigned bits : {67U, 82U}) {
            const Wide largest = (Wide(1) << bits) - 1;
            for (Wide value : {Wide(0), Wide(modulus - 1), Wide(modulus), Wide(modulus + 1), largest}) {
                Wide expected = value / modulus;
                auto result = fixed_divide(value, modulus, bits);
                assert(result.second == value % modulus);
                if (expected <= UINT64_MAX) assert(result.first == expected);
            }
        }
    }
    for (Word a : {Word(0), Word(1), p0 / 2, p0 - 1}) {
        for (Word b : {Word(0), Word(1), p0 / 2, p0 - 1}) {
            PublicMultiplier multiplier(a, p0);
            Word input = b;
            secret(&input, sizeof(input));
            Word actual = multiplier.multiply(input, p0);
            declassify(&actual, sizeof(actual));
            assert(actual == Wide(a) * b % p0);
        }
    }
    // Exercise the fixed divider with tainted inputs at both actual widths.
    for (unsigned bits : {67U, 82U}) {
        Wide value = (Wide(1) << (bits - 1)) + 123;
        Wide expected = value / q;
        secret(&value, sizeof(value));
        auto result = fixed_divide(value, q, bits);
        declassify(&result, sizeof(result));
        assert(result.first == expected);
    }
    for (std::size_t n : {std::size_t(16), std::size_t(128), std::size_t(8192)}) {
        FixedNTT transform(n, p0);
        std::vector<Word> input(n), expected(n);
        for (std::size_t i = 0; i < n; ++i) input[i] = expected[i] = i % 3 ? p0 - 1 : 1;
        secret(input.data(), n * sizeof(Word));
        transform.forward(input.data());
        transform.inverse(input.data());
        declassify(input.data(), n * sizeof(Word));
        assert(input == expected);

        std::vector<unsigned char> key(n), output(4 * n);
        std::vector<Word> c0(n), c1(n);
        for (unsigned pattern = 0; pattern < 3; ++pattern) {
            for (std::size_t i = 0; i < n; ++i) {
                key[i] = pattern == 0 ? 1 : pattern == 1 ? 255 : (i % 3 == 0 ? 0 : i % 3 == 1 ? 1 : 255);
                c0[i] = (i & 1) ? q - 1 : q / 2;
                c1[i] = (i & 1) ? 0 : q - 1;
            }
            PrivateDecoder decoder(n, q, t, p0, p1, key.data());
            // Taint the persistent secret AFTER public parameter/import validation.
            // No private output is declassified until the entire kernel returns.
            secret(decoder.test_secret_spectra(), 2 * n * sizeof(Word));
            decoder.decode(c0.data(), c1.data(), output.data());
            declassify(output.data(), output.size());
            for (std::size_t i = 0; i < n; ++i) {
                Word slot = 0;
                for (unsigned byte = 0; byte < 4; ++byte) slot |= Word(output[4 * i + byte]) << (8 * byte);
                assert(slot < t);
            }
            decoder.close();
            for (std::size_t i = 0; i < 2 * n; ++i) assert(decoder.test_secret_spectra()[i] == 0);
            bool rejected = false;
            try { decoder.decode(c0.data(), c1.data(), output.data()); }
            catch (const std::runtime_error&) { rejected = true; }
            assert(rejected);
        }
    }
    std::cout << "Private BFV arithmetic, transform and wiping checks passed\n";
}
