// Public fixed-width coefficient codec. Existing GMP mapping is the oracle and
// fallback. Only widths <=120 enter here, so a coefficient plus its byte offset
// fits in unsigned __int128; reconstruction is below 2*Q < 2^121.
#pragma once
#include <gmpxx.h>
#include <array>
#include <cstddef>
#include <stdexcept>
#include <vector>

namespace cuhepy_bgv_lab::word_codec {
using Wide = unsigned __int128;

inline Wide integer(const mpz_class& value) {
    if (value < 0 || mpz_sizeinbase(value.get_mpz_t(),2)>120)
        throw std::invalid_argument("Public word codec integer exceeds 120 bits");
    std::array<unsigned char,16> bytes{};
    std::size_t count=0;
    mpz_export(bytes.data(),&count,-1,1,0,0,value.get_mpz_t());
    Wide result=0;
    for (std::size_t i=0;i<count;++i) result|=Wide(bytes[i])<<(8*i);
    return result;
}

inline Wide read(const unsigned char* input,std::size_t size,std::size_t at,std::size_t bits) {
    const auto byte=at/8,offset=at%8,count=(offset+bits+7)/8;
    if (byte>size || count>size-byte) throw std::invalid_argument("Public word codec read overflow");
    Wide value=0;
    for (std::size_t i=0;i<count;++i) value|=Wide(input[byte+i])<<(8*i);
    return (value>>offset)&((Wide(1)<<bits)-1);
}

inline void write(Wide value,std::vector<unsigned char>& output,std::size_t at,std::size_t bits) {
    const auto byte=at/8,offset=at%8,count=(offset+bits+7)/8;
    if ((value>>bits) || byte>output.size() || count>output.size()-byte)
        throw std::logic_error("Public word codec output overflow");
    value<<=offset;
    for (std::size_t i=0;i<count;++i) output[byte+i]|=static_cast<unsigned char>(value>>(8*i));
}

inline std::vector<unsigned char> apply(
    const unsigned char* input,std::size_t size,std::size_t n,
    const mpz_class& q,std::size_t full_bits,std::size_t code_bits,unsigned long t,
    std::size_t drop,const mpz_class& center,const mpz_class& maximum,bool expand) {
    if (full_bits<16 || full_bits>120 || !code_bits || code_bits>120 || !drop || drop>=full_bits)
        throw std::invalid_argument("Public word codec width exceeds fixed bound");
    const auto in_bits=expand ? code_bits : full_bits,out_bits=expand ? full_bits : code_bits;
    if (size!=(n*in_bits+7)/8) throw std::invalid_argument("Incorrect word codec payload length");
    const Wide modulus=integer(q),limit=integer(maximum),bias=integer(center),radix=Wide(1)<<drop;
    std::vector<unsigned char> output((n*out_bits+7)/8,0);
    for (std::size_t i=0;i<n;++i) {
        const Wide value=read(input,size,i*in_bits,in_bits);
        Wide result;
        if (expand) {
            if (value>limit) throw std::invalid_argument("Noncanonical compressed query coefficient");
            const Wide high=value/t,residue=value%t,base=high<<drop;
            if (base>=modulus || residue>=radix || residue>=modulus-base)
                throw std::invalid_argument("Compressed query coefficient has no preimage");
            // The canonical preimage is below Q and center<R/2<=Q/2.
            result=base+residue+bias;
            if (result>=modulus) result-=modulus;
        } else {
            if (value>=modulus) throw std::invalid_argument("Noncanonical seeded query coefficient");
            result=(value>>drop)*t+(value&(radix-1))%t;
        }
        write(result,output,i*out_bits,out_bits);
    }
    return output;
}
} // namespace cuhepy_bgv_lab::word_codec
