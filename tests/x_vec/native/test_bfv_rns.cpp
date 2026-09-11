// Standalone kernel oracles; also run under address/undefined-behavior sanitizers.
#include "rns_ntt.h"
#include "packed_wire.h"
#include "bfv_residue.h"
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
                    Wide numerator = Wide(y) * (i ? random() % p : p - 1);
                    auto divided = transform.divide(numerator);
                    assert(divided.first == numerator / p && divided.second == numerator % p);
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
    // Persistent RNS: exact canonical Garner lifts and binary gadget digits at
    // every supported Q width, including word boundaries and the widest gadget.
    Ring primes(8, (mpz_class(1) << 480) - 1, 30, true);
    mpz_class q = 1;
    for (std::size_t count = 1; count <= 8; ++count) {
        q *= primes.transforms[count - 1].modulus;
        for (unsigned bits : {1, 15, 30, 60, 61, 127, 480}) {
            if (bits > 60 * count) continue;
            auto ring = std::make_shared<Ring>(8, q, bits, true, true);
            ResidueArithmetic arithmetic(*ring);
            assert(ring->switch_prime_count == count);
            Polynomial a(8);
            for (auto& c : a) c = big_random.get_z_range(q);
            a[0] = 0; a[1] = q - 1; a[2] = q / 2;
            a[3] = primes.transforms[0].modulus % q;
            a[4] = (mpz_class(1) << (60 * count - 1)) % q;
            auto residues = arithmetic.split(a);
            assert(arithmetic.compose(residues) == a);
            auto words = arithmetic.compose_words(residues);
            for (std::size_t digit = 0; digit < ring->digits; ++digit)
                for (std::size_t j = 0; j < count; ++j)
                    for (std::size_t i = 0; i < 8; ++i) {
                        mpz_class expected = a[i] >> (digit * bits);
                        mpz_fdiv_r_2exp(expected.get_mpz_t(), expected.get_mpz_t(), bits);
                        assert(arithmetic.digit_mod(words[i], digit * bits, bits, j) ==
                               mpz_fdiv_ui(expected.get_mpz_t(), ring->transforms[j].modulus));
                    }
            std::vector<Ciphertext> key(ring->digits, Ciphertext{Polynomial(8), Polynomial(8)});
            for (auto& pair : key)
                for (auto& component : pair)
                    for (auto& c : component) c = big_random.get_z_range(q);
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
                for (auto& c : component) mpz_mod(c.get_mpz_t(), c.get_mpz_t(), q.get_mpz_t());
            NativeProfile profile;
            ResidueCiphertext actual;
            { ProfileSession session(profile); actual = arithmetic.apply(residues, prepared); }
            assert(profile.calls[std::size_t(Phase::crt_reconstruct)] == 0);
            assert(profile.calls[std::size_t(Phase::mod_q)] == 0);
            assert(arithmetic.compose(actual[0]) == expected[0]);
            assert(arithmetic.compose(actual[1]) == expected[1]);
            assert(prepared.apply(a) == expected);
            for (Word g : {3, 9, 15}) {
                auto rotated = arithmetic.rotate(actual, g, prepared);
                auto reference = rotate(expected, g, prepared);
                assert(arithmetic.compose(rotated[0]) == reference[0]);
                assert(arithmetic.compose(rotated[1]) == reference[1]);
            }
        }
    }
    // The fused transform must preserve the existing bit-reversed spectrum,
    // including maximal residues, not just invert its own forward operation.
    for (std::size_t n : {8, 16, 64, 8192, 32768}) {
        Ring ring(n, (mpz_class(1) << 180) - 1, 30, true);
        for (const auto& original : ring.transforms) {
            PrimeNTT fused(n, original.modulus, true, true);
            for (int sample = 0; sample < 3; ++sample) {
                std::vector<Word> input(n);
                for (auto& c : input) c = sample == 0 ? 0 : sample == 1 ? original.modulus - 1 : random() % original.modulus;
                auto old = input, next = input;
                original.forward(old); fused.forward(next);
                assert(old == next);
                fused.inverse(next);
                assert(next == input);
            }
        }
    }
    // Independent GMP oracle for exact signed tensor scaling at every Q width.
    // The +/- convolution bounds and half-integer rounding cases exercise the
    // certified fixed-point intervals and their fixed-word exact corrections.
    q = 1;
    for (std::size_t count = 1; count <= 8; ++count) {
        q *= primes.transforms[count - 1].modulus;
        Ring ring(8, q, 30, true, true, 2);
        ResidueArithmetic arithmetic(ring);
        mpz_class bound = 2 * ring.n * (q - 1) * (q - 1);
        auto tensor_count = ring.prime_count(bound);
        for (Word t : {Word(2), Word(97), Word(65537), (Word(1) << (count == 1 ? 59 : 60)) - 1}) {
            RNSScale scaler(ring, t);
            NativeProfile profile;
            for (int sample = 0; sample < 100; ++sample) {
                Polynomial z(8);
                for (auto& c : z) { c = big_random.get_z_range(2 * bound + 1); c -= bound; }
                if (sample == 0) z = {0, 1, -1, mpz_class(q / 2), mpz_class(q / 2 + 1), mpz_class(-q / 2), mpz_class(-q / 2 - 1), bound};
                if (sample == 1) z = {-bound, q, -q, mpz_class(2 * q), mpz_class(-2 * q), mpz_class(q - 1), mpz_class(1 - q), mpz_class(bound - 1)};
                Residues scaled;
                { ProfileSession session(profile); scaled = scaler.scale(ring.encode(z, tensor_count)); }
                auto result = arithmetic.compose(scaled);
                for (std::size_t i = 0; i < z.size(); ++i) {
                    mpz_class expected = 2 * t * z[i] + q, denominator = 2 * q;
                    mpz_fdiv_q(expected.get_mpz_t(), expected.get_mpz_t(), denominator.get_mpz_t());
                    mpz_mod(expected.get_mpz_t(), expected.get_mpz_t(), q.get_mpz_t());
                    assert(result[i] == expected);
                }
            }
            assert(profile.calls[std::size_t(Phase::crt_reconstruct)] == 0);
            if (count > 1) assert(profile.calls[std::size_t(Phase::crt_exact_fallback)] > 0);
            bool rejected = false;
            try { scaler.scale(Residues{}); } catch (const std::invalid_argument&) { rejected = true; }
            assert(rejected);
        }
    }
    std::cout << "Native NTT, signed CRT, gadget, persistent RNS and exact scaling oracles passed\n";
}
