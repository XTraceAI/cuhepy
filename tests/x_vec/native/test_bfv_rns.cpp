// Standalone kernel oracles; also run under address/undefined-behavior sanitizers.
#include "rns_ntt.h"
#include "packed_wire.h"
#include <cassert>
#include <iostream>
#include <random>
using namespace xtrace_bfv;

Polynomial schoolbook(const Polynomial& a, const Polynomial& b) {
    Polynomial result(a.size());
    for (std::size_t i = 0; i < a.size(); ++i)
        for (std::size_t j = 0; j < b.size(); ++j) {
            if (i + j < a.size()) result[i + j] += a[i] * b[j];
            else result[i + j - a.size()] -= a[i] * b[j];
        }
    return result;
}

int main() {
    std::mt19937_64 random(1337);
    gmp_randclass big_random(gmp_randinit_default);
    big_random.seed(1337);
    for (bool fast : {false, true}) {
    for (unsigned q_bits : {31, 100, 180, 512}) {
        for (unsigned bits : {1, 15, 30, 59, 60, 61, 127}) {
            if (bits > q_bits) continue;
            mpz_class q = (mpz_class(1) << q_bits) - 1;
            auto ring = std::make_shared<Ring>(8, q, bits, fast);
            Polynomial a(8), b(8);
            for (auto& value : a) value = big_random.get_z_range(q);
            for (auto& value : b) value = big_random.get_z_range(q);
            for (const auto& transform : ring->transforms) {
                Word p = transform.modulus;
                for (int i = 0; i < 300; ++i) {
                    Word multiplier = i ? random() % p : p - 1;
                    Word input = i ? random() % (4 * p) : 4 * p - 1;
                    assert(Multiplier(multiplier, p).multiply(input, p) == Wide(input) * multiplier % p);
                    assert(Multiplier(multiplier, p).multiply_lazy(input, p) < 2 * p);
                    Wide wide = i ? (Wide(random()) << 64) | random() : ~Wide(0);
                    assert(transform.reduce(wide) == wide % p);
                    Word y = i ? random() % p : p - 1;
                    assert(transform.fraction(y) == (Wide(y) << 64) / p);
                }
                std::vector<Word> values(8);
                for (auto& value : values) value = random() % p;
                auto original = values;
                transform.forward(values);
                transform.inverse(values);
                assert(values == original);
            }
            for (int sample = 0; sample < 3; ++sample) {
                if (sample == 1) { a.assign(8, q - 1); b.assign(8, q - 1); }
                if (sample == 2) a.assign(8, 0);
                assert(ring->product(a, b) == schoolbook(a, b));
            }
            std::vector<std::array<Polynomial, 2>> key(ring->digits);
            for (auto& pair : key) {
                pair[0].assign(8, q - 1);
                pair[1] = b;
            }
            a.assign(8, q - 1);
            SwitchKey prepared(ring, key);
            Ciphertext expected{Polynomial(8), Polynomial(8)};
            for (std::size_t digit = 0; digit < ring->digits; ++digit) {
                Polynomial part(8);
                for (std::size_t i = 0; i < 8; ++i) {
                    part[i] = a[i] >> (digit * bits);
                    mpz_fdiv_r_2exp(part[i].get_mpz_t(), part[i].get_mpz_t(), bits);
                }
                for (std::size_t k = 0; k < 2; ++k) {
                    auto product = schoolbook(part, key[digit][k]);
                    for (std::size_t i = 0; i < 8; ++i) expected[k][i] += product[i];
                }
            }
            for (auto& component : expected)
                for (auto& value : component) mpz_mod(value.get_mpz_t(), value.get_mpz_t(), q.get_mpz_t());
            assert(prepared.apply(a) == expected);
        }
    }
    // Exercise NTT lengths, both signs of X^N=-1, and large transform tables.
    for (std::size_t n : {16, 64, 8192, 32768}) {
        mpz_class q = (mpz_class(1) << 180) - 1;
        Ring ring(n, q, 30, fast);
        Polynomial a(n), b(n);
        a[n - 1] = q - 1;
        b[1] = q - 1;
        auto product = ring.product(a, b);
        assert(product[0] == -(q - 1) * (q - 1));
        for (std::size_t i = 1; i < n; ++i) assert(product[i] == 0);
    }
    }
    // Exercise the certified CRT interval precisely where an approximate
    // rounding decision is insufficient: the two sides of +/-M/2.
    for (unsigned bits : {31, 64, 100, 180, 512}) {
        mpz_class q = (mpz_class(1) << bits) - 1;
        Ring ring(8, q, 15, true);
        mpz_class product = 1;
        for (std::size_t count = 1; count <= ring.transforms.size(); ++count) {
            product *= ring.transforms[count - 1].modulus;
            mpz_class half = product / 2;
            Polynomial values{0, 1, -1, half, half + 1, -half, -half - 1, product - 1};
            NativeProfile profile;
            Polynomial result;
            { ProfileSession session(profile); result = ring.decode_mod_q(ring.encode(values, count)); }
            if (count >= 2) assert(profile.calls[static_cast<std::size_t>(Phase::crt_exact_fallback)] > 0);
            for (std::size_t i = 0; i < values.size(); ++i) {
                mpz_class expected;
                mpz_mod(expected.get_mpz_t(), values[i].get_mpz_t(), product.get_mpz_t());
                if (expected > half) expected -= product;
                mpz_mod(expected.get_mpz_t(), expected.get_mpz_t(), q.get_mpz_t());
                assert(result[i] == expected);
            }
        }
        Polynomial values(8);
        for (auto& c : values) c = big_random.get_z_range(q);
        values[0] = 0; values[7] = q - 1;
        assert(import_packed(export_packed(values, q), ring) == values);
    }
    std::cout << "Native NTT, Shoup, signed CRT and gadget oracles passed\n";
}
