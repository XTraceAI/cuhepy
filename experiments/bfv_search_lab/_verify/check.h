// Experimental trusted verification arithmetic. No HE secret key is loaded.
// Challenge weights MUST come from the one-use Python wrapper after output is
// pinned. Direct calls with attacker-chosen weights are not verification.
#pragma once
#include "rns_ntt.h"
#include <cstring>
#include <string_view>

namespace cuhepy_bgv_check {
using namespace xtrace_bfv;
static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "Little-endian fixture required");
inline Word load(const char* input) { Word value;std::memcpy(&value,input,8);return value; }

class Arithmetic {
    friend class ProductArithmetic;
    std::vector<PrimeNTT> transforms_;
    // [limb][digit][component], each already transformed.
    std::array<std::array<std::array<std::vector<Word>,2>,4>,2> key_;
public:
    const std::size_t n;
    std::array<Word,2> primes;
    Arithmetic(std::size_t size,std::string_view key) : n(size) {
        if(n<8||n>16384||(n&(n-1))||key.size()!=16*n*8)
            throw std::invalid_argument("Invalid bounded switch-check key");
        Word p=(Word(1)<<60)-2*n+1;
        for(std::size_t limb=0;limb<2;++limb) {
            mpz_class candidate(p);
            while(!mpz_probab_prime_p(candidate.get_mpz_t(),32)) {
                if(p<=(Word(1)<<59)) throw std::invalid_argument("No suitable check prime");
                p-=2*n;candidate=p;
            }
            primes[limb]=p;
            transforms_.emplace_back(n,p,true,true);
            for(std::size_t j=0;j<4;++j) for(std::size_t k=0;k<2;++k) {
                auto& values=key_[limb][j][k];values.resize(n);
                for(std::size_t i=0;i<n;++i) {
                    values[i]=load(key.data()+8*(((limb*4+j)*2+k)*n+i));
                    if(values[i]>=p) throw std::invalid_argument("Noncanonical check key");
                }
                transforms_.back().forward(values);
            }
            p-=2*n;
        }
    }
    void validate(std::string_view bytes,std::size_t batch,std::size_t components) const {
        if(!batch||batch>64||batch*n>(1U<<20)||(components!=2&&components!=3)
           ||bytes.size()!=batch*components*2*n*8)
            throw std::invalid_argument("Invalid bounded check input/output");
        for(std::size_t b=0;b<batch;++b) for(std::size_t k=0;k<components;++k)
            for(std::size_t limb=0;limb<2;++limb) for(std::size_t i=0;i<n;++i)
                if(load(bytes.data()+8*(((b*components+k)*2+limb)*n+i))>=primes[limb])
                    throw std::invalid_argument("Noncanonical checked residue");
    }
    bool check(std::string_view input,std::string_view output,std::string_view weights,std::size_t batch) const {
        // Revalidate the native boundary even though the wrapper validated
        // complete immutable packets BEFORE generating any private weights.
        validate(input,batch,3);validate(output,batch,2);
        if(weights.size()!=2*3*batch*8) throw std::invalid_argument("Incorrect check weights");
        for(std::size_t l=0;l<2;++l) for(std::size_t h=0;h<3;++h) for(std::size_t b=0;b<batch;++b)
            if(load(weights.data()+8*((l*3+h)*batch+b))>=primes[l])
                throw std::invalid_argument("Noncanonical check weight");
        const Word p0=primes[0],p1=primes[1],mask=(Word(1)<<30)-1;
        const Multiplier inverse(power_mod(p0%p1,p1-2,p1),p1);
        std::vector<Word> digits(batch*4*n);
        for(std::size_t b=0;b<batch;++b) for(std::size_t i=0;i<n;++i) {
            Word first=load(input.data()+8*((b*6+4)*n+i));
            Word second=load(input.data()+8*((b*6+5)*n+i));
            Word reduced=first>=p1?first-p1:first;
            Word delta=second>=reduced?second-reduced:second+p1-reduced;
            Wide canonical=Wide(p0)*inverse.multiply(delta,p1)+first;
            for(std::size_t j=0;j<4;++j) digits[(b*4+j)*n+i]=Word(canonical>>(30*j))&mask;
        }
        bool accepted=true;
        for(std::size_t l=0;l<2;++l) {
            const auto& transform=transforms_[l];const Word p=primes[l];
            for(std::size_t h=0;h<3;++h) {
                std::vector<Word> alpha(batch);
                for(std::size_t b=0;b<batch;++b) alpha[b]=load(weights.data()+8*((l*3+h)*batch+b));
                std::array<std::vector<Word>,4> folded;
                for(std::size_t j=0;j<4;++j) {
                    folded[j].resize(n);
                    for(std::size_t i=0;i<n;++i) {
                        Wide sum=0;
                        for(std::size_t b=0;b<batch;++b) sum+=Wide(alpha[b])*digits[(b*4+j)*n+i];
                        folded[j][i]=sum%p;
                    }
                    transform.forward(folded[j]);
                }
                for(std::size_t k=0;k<2;++k) {
                    std::vector<Word> expected(n);
                    for(std::size_t i=0;i<n;++i) {
                        Wide sum=0;
                        for(std::size_t j=0;j<4;++j) sum+=Wide(folded[j][i])*key_[l][j][k][i];
                        expected[i]=transform.remainder(sum);
                    }
                    transform.inverse(expected);
                    for(std::size_t i=0;i<n;++i) {
                        Wide observed=0;
                        for(std::size_t b=0;b<batch;++b) {
                            Word out=load(output.data()+8*((b*4+k*2+l)*n+i));
                            Word in=load(input.data()+8*((b*6+k*2+l)*n+i));
                            Word difference=out>=in?out-in:out+p-in;
                            observed+=Wide(alpha[b])*difference;
                        }
                        // Up to 64 products of two <2^60 values: sum <2^126.
                        // Use full unsigned-128 remainder, NOT a reduction that
                        // assumes the quotient fits in one machine word.
                        accepted &= expected[i]==Word(observed%p);
                    }
                }
            }
        }
        return accepted;
    }
};
} // namespace cuhepy_bgv_check
