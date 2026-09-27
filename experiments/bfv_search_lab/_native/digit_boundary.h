// E13 public canonical CRT/digit conversion oracle and boundary-cost prototype.
// No HE secret, verifier challenge, receipt or authentication is implemented.
#pragma once
#include "rns_ntt.h"
#include <cstring>
#include <random>
#include <omp.h>

namespace cuhepy_bgv_lab::digit_boundary {
using namespace xtrace_bfv;
enum class Layout { native = 0, shared = 1, packed = 2 };
static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "This fixture uses little-endian byte packing");

inline Wide load120(const unsigned char* source) {
    Word low = 0, high = 0;
    std::memcpy(&low, source, 8); std::memcpy(&high, source+8, 7);
    return Wide(low) | (Wide(high)<<64);
}
inline void store120(unsigned char* out, Wide value) {
    Word low = Word(value), high = Word(value>>64);
    std::memcpy(out, &low, 8); std::memcpy(out+8, &high, 7);
}

class CRT {
    static Word checked_inverse(Word first, Word second) {
        if (first == second || first < (Word(1)<<59) || second < (Word(1)<<59)
            || first >= (Word(1)<<60) || second >= (Word(1)<<60))
            throw std::invalid_argument("Expected two distinct 60-bit RNS primes");
        for (Word p:{first,second}) {
            mpz_class value(p);
            if (!mpz_probab_prime_p(value.get_mpz_t(),32)) throw std::invalid_argument("Composite RNS modulus");
        }
        return power_mod(first%second,second-2,second);
    }
    const Multiplier inverse_;
public:
    const Word p0, p1;
    CRT(Word first, Word second)
        : inverse_(checked_inverse(first,second), second), p0(first), p1(second) {}
    Wide compose(Word first, Word second) const {
        Word reduced = first >= p1 ? first-p1 : first;
        Word delta = second >= reduced ? second-reduced : second+p1-reduced;
        return Wide(p0)*inverse_.multiply(delta,p1)+first;
    }
    Wide oracle(Word first, Word second) const {
        mpz_class a(p0), b(p1), inverse;
        if (!mpz_invert(inverse.get_mpz_t(),a.get_mpz_t(),b.get_mpz_t()))
            throw std::runtime_error("Invalid CRT oracle moduli");
        mpz_class step=(mpz_class(second)-first)*inverse;
        mpz_mod(step.get_mpz_t(),step.get_mpz_t(),b.get_mpz_t());
        mpz_class value=mpz_class(first)+a*step;
        Word words[2]{};
        mpz_export(words,nullptr,-1,sizeof(Word),0,0,value.get_mpz_t());
        return Wide(words[0]) | (Wide(words[1])<<64);
    }
};

inline void convert(const CRT& crt, const void* source, void* destination,
                    int n, int batch, Layout layout, int threads) {
    if (n<8 || n>32768 || (n&(n-1)) || batch<1 || batch>512 || !source || !destination
        || threads<1 || threads>8 || unsigned(layout)>2)
        throw std::invalid_argument("Invalid bounded CRT/digit conversion");
    const auto* words=static_cast<const Word*>(source);
    auto* out=static_cast<Word*>(destination);
    const auto* bytes=static_cast<const unsigned char*>(source);
    auto* packed=static_cast<unsigned char*>(destination);
    unsigned invalid=0;
    const int coefficients=n*batch;
    const unsigned log_n=__builtin_ctz(unsigned(n));
    #pragma omp parallel for schedule(static) num_threads(threads) if(threads>1 && coefficients>=65536) reduction(|:invalid)
    for (int at=0;at<coefficients;++at) {
        int b=at>>log_n,i=at&(n-1);
        Word first,second;
        if (layout==Layout::packed) {
            Wide pair=load120(bytes+15*std::size_t(at));
            first=Word(pair)&((Word(1)<<60)-1); second=Word(pair>>60);
        } else { first=words[(b*2)*n+i]; second=words[(b*2+1)*n+i]; }
        if (first>=crt.p0 || second>=crt.p1) { invalid=1; continue; }
        Wide value=crt.compose(first,second);
        if (layout==Layout::packed) store120(packed+15*std::size_t(at),value);
        else for (int d=0;d<4;++d) {
            Word digit=Word(value>>(30*d))&((Word(1)<<30)-1);
            if (layout==Layout::shared) out[(b*4+d)*n+i]=digit;
            else { out[((b*4+d)*2)*n+i]=digit; out[((b*4+d)*2+1)*n+i]=digit; }
        }
    }
    // Callers must not transmit any partially written output after rejection.
    if (invalid) throw std::invalid_argument("Noncanonical RNS coefficient");
}

inline void self_test(const CRT& crt) {
    omp_set_dynamic(0);
    int workers=1;
    #pragma omp parallel num_threads(8) reduction(max:workers)
    { workers=omp_get_num_threads(); }
    if(workers!=8) throw std::runtime_error("Eight actual OpenMP workers required for this comparison");
    std::mt19937_64 rng(20260927);
    for (int n:{8,2048}) {
        int batch=33;
        std::vector<Word> source(2*batch*n), native(8*batch*n), shared(4*batch*n);
        std::vector<unsigned char> packed(15*batch*n), result(packed.size());
        for (int b=0;b<batch;++b) for (int i=0;i<n;++i) {
            Word first=rng()%crt.p0, second=rng()%crt.p1;
            if (i<4) { first=(i&1)?crt.p0-1:0; second=(i&2)?crt.p1-1:0; }
            source[(b*2)*n+i]=first; source[(b*2+1)*n+i]=second;
            store120(packed.data()+15*(b*n+i),Wide(first)|(Wide(second)<<60));
        }
        for (int threads:{1,8}) {
            convert(crt,source.data(),native.data(),n,batch,Layout::native,threads);
            convert(crt,source.data(),shared.data(),n,batch,Layout::shared,threads);
            convert(crt,packed.data(),result.data(),n,batch,Layout::packed,threads);
            for (int b=0;b<batch;++b) for (int i=0;i<n;++i) {
                Wide expected=crt.oracle(source[(b*2)*n+i],source[(b*2+1)*n+i]);
                if (load120(result.data()+15*(b*n+i))!=expected) throw std::runtime_error("Packed CRT mismatch");
                for (int d=0;d<4;++d) {
                    Word digit=Word(expected>>(30*d))&((Word(1)<<30)-1);
                    if (shared[(b*4+d)*n+i]!=digit || native[((b*4+d)*2)*n+i]!=digit
                        || native[((b*4+d)*2+1)*n+i]!=digit) throw std::runtime_error("Gadget digit mismatch");
                }
            }
        }
        for (int limb:{0,1}) {
            Word old=source[limb*n]; source[limb*n]=limb?crt.p1:crt.p0;
            for (Layout layout:{Layout::native,Layout::shared,Layout::packed}) {
                store120(packed.data(),Wide(source[0])|(Wide(source[n])<<60));
                bool rejected=false;
                try { convert(crt,layout==Layout::packed?static_cast<void*>(packed.data()):source.data(),
                              native.data(),n,batch,layout,8); }
                catch(const std::invalid_argument&) { rejected=true; }
                if (!rejected) throw std::runtime_error("Noncanonical residue accepted");
            }
            source[limb*n]=old;
        }
    }
}
} // namespace cuhepy_bgv_lab::digit_boundary
