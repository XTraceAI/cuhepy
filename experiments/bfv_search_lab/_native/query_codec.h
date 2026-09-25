// Public coefficient codec only: no secret, entropy, encryption or decryption.
// Same mixed-radix mapping as compressed_query_bgv.py, with bounded bit streams.
#pragma once
#include <gmpxx.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <stdexcept>
#include <vector>

namespace cuhepy_bgv_lab {
class QueryCodec {
    const std::size_t n_, drop_;
    const unsigned long t_;
    const mpz_class q_;
    mpz_class radix_, center_, maximum_;
    std::size_t full_bits_, code_bits_;

    static std::size_t width(std::size_t n, std::size_t bits) { return (n*bits+7)/8; }
    static void read(mpz_class& value, const unsigned char* input, std::size_t size,
                     std::size_t at, std::size_t bits) {
        const auto byte = at/8, offset = at%8;
        const auto count = std::min((offset+bits+7)/8,size-byte);
        mpz_import(value.get_mpz_t(),count,-1,1,0,0,input+byte);
        mpz_fdiv_q_2exp(value.get_mpz_t(),value.get_mpz_t(),offset);
        mpz_fdiv_r_2exp(value.get_mpz_t(),value.get_mpz_t(),bits);
    }
    static void write(const mpz_class& value, std::vector<unsigned char>& output,
                      std::size_t at, std::size_t bits) {
        if (value < 0 || mpz_sizeinbase(value.get_mpz_t(),2) > bits)
            throw std::logic_error("Query codec output exceeds fixed width");
        // At most 240 Q bits + 30 plaintext bits + seven shift bits.
        std::array<unsigned char,40> bytes{};
        mpz_class shifted = value << (at%8);
        std::size_t count = 0;
        mpz_export(bytes.data(),&count,-1,1,0,0,shifted.get_mpz_t());
        if (at/8+count > output.size()) throw std::logic_error("Query codec write overflow");
        for (std::size_t i=0;i<count;++i) output[at/8+i] |= bytes[i];
    }
public:
    QueryCodec(std::size_t n, const mpz_class& q, unsigned long t, std::size_t drop)
        : n_(n), drop_(drop), t_(t), q_(q) {
        full_bits_ = mpz_sizeinbase(q_.get_mpz_t(),2);
        if (n<8 || n>32768 || (n&(n-1)) || q<3 || mpz_even_p(q.get_mpz_t())
            || full_bits_<16 || full_bits_>240 || t<3 || t>=(1UL<<30) || !(t&1)
            || q<=t || !drop || drop>=full_bits_)
            throw std::invalid_argument("Invalid public query codec parameters");
        radix_ = mpz_class(1)<<drop;
        mpz_class intervals = (radix_-1)/t;
        center_ = (intervals/2)*t;
        mpz_class last = q-1, high = last>>drop, tail = last%radix_;
        maximum_ = high*t+(tail<t ? tail : mpz_class(t-1));
        code_bits_ = mpz_sizeinbase(maximum_.get_mpz_t(),2);
    }
    std::vector<unsigned char> apply(const unsigned char* input, std::size_t size,
                                     bool expand) const {
        const auto in_bits = expand ? code_bits_ : full_bits_;
        const auto out_bits = expand ? full_bits_ : code_bits_;
        if (size != width(n_,in_bits)) throw std::invalid_argument("Incorrect query codec payload length");
        // N is divisible by eight, so each whole polynomial has no padding bits.
        std::vector<unsigned char> output(width(n_,out_bits),0);
        mpz_class value, high, residue, base, result, remaining;
        for (std::size_t i=0;i<n_;++i) {
            read(value,input,size,i*in_bits,in_bits);
            if (expand) {
                if (value>maximum_) throw std::invalid_argument("Noncanonical compressed query coefficient");
                auto remainder = mpz_fdiv_q_ui(high.get_mpz_t(),value.get_mpz_t(),t_);
                base = high<<drop_;
                remaining = q_-base;
                if (mpz_class(remainder)>=radix_ || mpz_class(remainder)>=remaining)
                    throw std::invalid_argument("Compressed query coefficient has no preimage");
                result = base+remainder+center_;
                mpz_mod(result.get_mpz_t(),result.get_mpz_t(),q_.get_mpz_t());
            } else {
                if (value>=q_) throw std::invalid_argument("Noncanonical seeded query coefficient");
                mpz_fdiv_q_2exp(high.get_mpz_t(),value.get_mpz_t(),drop_);
                mpz_fdiv_r_2exp(residue.get_mpz_t(),value.get_mpz_t(),drop_);
                result = high*t_+mpz_fdiv_ui(residue.get_mpz_t(),t_);
            }
            write(result,output,i*out_bits,out_bits);
        }
        return output;
    }
};
} // namespace cuhepy_bgv_lab
