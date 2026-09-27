// Independent BGV circuit oracle using official Microsoft SEAL 4.1.2 APIs.
// Input: N, dimension, count, binary query, then binary rows (whitespace).
// Checks every plaintext coefficient, not merely the selected top-k answers.
// No cuhepy arithmetic, encoders, decoders, or secret keys are imported.
#include <seal/seal.h>
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <vector>

using namespace seal;
int main() {
    try {
        std::size_t n, dimension, count;
        if (!(std::cin >> n >> dimension >> count) || n != 16384 || !dimension ||
            dimension > 512 || count > 2 * n + 1)
            throw std::invalid_argument("Oracle fixture exceeds its fixed limits");
        std::size_t padded = 1;
        while (padded < dimension) padded *= 2;
        const std::uint64_t t = 1031;
        auto bit = []() {
            int value;
            if (!(std::cin >> value) || (value != 0 && value != 1))
                throw std::invalid_argument("Expected binary fixture");
            return value;
        };
        std::vector<int> query(dimension);
        for (auto& value : query) value = bit();
        std::vector<std::vector<int>> rows(count, std::vector<int>(dimension));
        for (auto& row : rows) for (auto& value : row) value = bit();
        EncryptionParameters parameters(scheme_type::bgv);
        parameters.set_poly_modulus_degree(n);
        // Two 48-bit data primes plus SEAL's special key-switch prime. This
        // differs from cuhepy's single-prime Q96; correctness oracle only.
        parameters.set_coeff_modulus(CoeffModulus::Create(n, {48, 48, 48}));
        parameters.set_plain_modulus(t);
        SEALContext context(parameters, true, sec_level_type::tc128);
        if (!context.parameters_set()) throw std::runtime_error(context.parameter_error_message());
        KeyGenerator keygen(context);
        PublicKey public_key;
        RelinKeys relin;
        keygen.create_public_key(public_key);
        keygen.create_relin_keys(relin);
        std::vector<std::uint32_t> exponents;
        std::uint64_t g = 1 + 2 * n / padded;
        for (auto shift = padded / 2; shift; shift /= 2) {
            exponents.push_back(g);
            g = g * g % (2 * n);
        }
        GaloisKeys rotations;
        if (!exponents.empty()) keygen.create_galois_keys(exponents, rotations);
        Encryptor encryptor(context, public_key);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());
        auto monomial = [&](const Ciphertext& ct, std::size_t shift) {
            shift %= 2 * n;
            Plaintext plain(n);
            plain[shift % n] = shift < n ? 1 : t - 1;
            Ciphertext result;
            evaluator.multiply_plain(ct, plain, result);
            return result;
        };
        Plaintext qp(n);
        for (std::size_t j = 0; j < dimension; ++j) qp[padded - 1 - j] = query[j] ? t - 1 : 1;
        Ciphertext encrypted_query;
        encryptor.encrypt(qp, encrypted_query);
        const auto capacity = n / padded;
        std::vector<Ciphertext> products;
        for (std::size_t start = 0; start < count; start += capacity) {
            Plaintext tile(n);
            for (std::size_t i = 0; i < std::min(capacity, count - start); ++i)
                for (std::size_t j = 0; j < dimension; ++j)
                    tile[i * padded + j] = rows[start + i][j] ? t - 1 : 1;
            Ciphertext encrypted_tile, product;
            encryptor.encrypt(tile, encrypted_tile);
            evaluator.multiply(encrypted_query, encrypted_tile, product);
            evaluator.relinearize_inplace(product, relin);
            products.push_back(monomial(product, 2 * n + 1 - padded));
        }
        std::size_t checked = 0;
        for (bool joint : {false, true}) {
            for (std::size_t start = 0; start < products.size(); start += padded) {
                std::vector<Ciphertext> work(products.begin() + start,
                                             products.begin() + std::min(start + padded, products.size()));
                Ciphertext output;
                if (joint) {
                    auto shift = padded / 2;
                    for (auto exponent : exponents) {
                        std::vector<Ciphertext> merged;
                        for (std::size_t i = 0; i < std::min(shift, work.size()); ++i) {
                            auto plus = work[i], minus = work[i];
                            if (i + shift < work.size()) {
                                auto right = monomial(work[i + shift], shift);
                                evaluator.add_inplace(plus, right);
                                evaluator.sub_inplace(minus, right);
                            }
                            Ciphertext rotated;
                            evaluator.apply_galois(minus, exponent, rotations, rotated);
                            evaluator.add_inplace(plus, rotated);
                            merged.push_back(std::move(plus));
                        }
                        work = std::move(merged);
                        shift /= 2;
                    }
                    output = work[0];
                } else {
                    for (std::size_t i = 0; i < work.size(); ++i) {
                        for (auto exponent : exponents) {
                            Ciphertext rotated;
                            evaluator.apply_galois(work[i], exponent, rotations, rotated);
                            evaluator.add_inplace(work[i], rotated);
                        }
                        auto shifted = monomial(work[i], i);
                        if (i == 0) output = std::move(shifted);
                        else evaluator.add_inplace(output, shifted);
                    }
                }
                Plaintext plain;
                decryptor.decrypt(output, plain);
                std::vector<std::uint64_t> expected(n);
                for (std::size_t i = 0; i < std::min(n, count - start * capacity); ++i) {
                    int dot = 0;
                    for (std::size_t j = 0; j < dimension; ++j)
                        dot += query[j] == rows[start * capacity + i][j] ? 1 : -1;
                    auto value = static_cast<std::int64_t>(padded) * dot % static_cast<std::int64_t>(t);
                    expected[(i % capacity) * padded + i / capacity] = (value + t) % t;
                }
                for (std::size_t i = 0; i < n; ++i) {
                    auto value = i < plain.coeff_count() ? plain[i] : 0;
                    if (value != expected[i]) throw std::runtime_error("SEAL plaintext mismatch");
                    ++checked;
                }
            }
        }
        std::cout << "{\"seal_version\":\"" << SEAL_VERSION << "\",\"n\":" << n
                  << ",\"dimension\":" << dimension << ",\"count\":" << count
                  << ",\"coefficients_checked\":" << checked
                  << ",\"both_circuits_correct\":true,\"security_setting\":\"SEAL TC128\"}\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
