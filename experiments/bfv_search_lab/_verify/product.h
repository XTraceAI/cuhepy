// Bound tensor product + canonical switch. No HE secret or SEAL dependency.
// Caller-chosen weights are arithmetic tests only; the Python one-use wrapper
// fixes all output/witness bytes before sampling independent uniform weights.
#pragma once
#include "check.h"
#include <string>

namespace cuhepy_bgv_check {
class ProductArithmetic {
    using Poly = std::vector<Word>;
    using Pair = std::array<std::array<Poly,2>,2>; // [component][limb]
    std::shared_ptr<const Arithmetic> ctx_;
    std::vector<Pair> index_; // Immutable NTT index, prepared once.

    Pair query(std::string_view input) const {
        ctx_->validate(input,1,2);
        Pair out;
        for(std::size_t k=0;k<2;++k) for(std::size_t l=0;l<2;++l) {
            auto& p=out[k][l];p.resize(n);
            for(std::size_t i=0;i<n;++i) p[i]=load(input.data()+8*((k*2+l)*n+i));
            ctx_->transforms_[l].forward(p);
        }
        return out;
    }
    Poly c2(const Pair& q) const {
        Poly out(batch*2*n);
        for(std::size_t b=0;b<batch;++b) for(std::size_t l=0;l<2;++l) {
            const auto& t=ctx_->transforms_[l];Poly p(n);
            for(std::size_t i=0;i<n;++i) p[i]=t.remainder(Wide(index_[b][1][l][i])*q[1][l][i]);
            t.inverse(p);std::copy(p.begin(),p.end(),out.begin()+(b*2+l)*n);
        }
        return out;
    }
    Poly digits(const Poly& z) const {
        const auto p0=ctx_->primes[0],p1=ctx_->primes[1];
        const Multiplier inverse(power_mod(p0%p1,p1-2,p1),p1);
        Poly out(batch*4*n);
        for(std::size_t b=0;b<batch;++b) for(std::size_t i=0;i<n;++i) {
            const Word a=z[(b*2)*n+i],r=z[(b*2+1)*n+i],reduced=a>=p1?a-p1:a;
            const Word delta=r>=reduced?r-reduced:r+p1-reduced;
            const Wide value=Wide(p0)*inverse.multiply(delta,p1)+a;
            for(std::size_t j=0;j<4;++j) out[(b*4+j)*n+i]=Word(value>>(30*j))&((Word(1)<<30)-1);
        }
        return out;
    }
    template<class F> Poly fold(const Poly& alpha,Word p,F&& value) const {
        // Stream each tile instead of striding across all tiles per coefficient.
        // At most 64 products of two <2^60 values: exact sum <2^126.
        std::vector<Wide> sums(n);
        for(std::size_t b=0;b<batch;++b) for(std::size_t i=0;i<n;++i)
            sums[i]+=Wide(alpha[b])*value(b,i);
        Poly out(n);
        for(std::size_t i=0;i<n;++i) out[i]=sums[i]%p; // Full 128-bit remainder.
        return out;
    }
    static void put(std::string& out,std::size_t at,Word value) { std::memcpy(out.data()+8*at,&value,8); }
public:
    const std::size_t n,batch;
    ProductArithmetic(std::shared_ptr<const Arithmetic> ctx,std::string_view input,std::size_t b)
        : ctx_(std::move(ctx)),n(ctx_->n),batch(b) {
        ctx_->validate(input,batch,2);index_.resize(batch);
        for(std::size_t b=0;b<batch;++b) for(std::size_t k=0;k<2;++k) for(std::size_t l=0;l<2;++l) {
            auto& p=index_[b][k][l];p.resize(n);
            for(std::size_t i=0;i<n;++i) p[i]=load(input.data()+8*(((b*2+k)*2+l)*n+i));
            ctx_->transforms_[l].forward(p);
        }
    }
    void validate(std::string_view witness,std::string_view output,bool local) const {
        ctx_->validate(output,batch,2);
        if(local) {
            if(!witness.empty()) throw std::invalid_argument("Local c2 has no witness");
        } else {
            if(witness.size()!=batch*2*n*8) throw std::invalid_argument("Incorrect c2 witness size");
            for(std::size_t b=0;b<batch;++b) for(std::size_t l=0;l<2;++l) for(std::size_t i=0;i<n;++i)
                if(load(witness.data()+8*((b*2+l)*n+i))>=ctx_->primes[l])
                    throw std::invalid_argument("Noncanonical c2 witness");
        }
    }
    // Matched deterministic native baseline: prepared index/key, one query NTT,
    // full output computation, no random check. Fuse c0/c1 and switch products
    // in the NTT domain; no Python/GMP intermediate conversion is charged away.
    std::pair<std::string,std::string> evaluate(std::string_view input,bool witness) const {
        const auto q=query(input);const auto z=c2(q),d=digits(z);
        std::string out(batch*4*n*8,'\0'),proof(witness?batch*2*n*8:0,'\0');
        if(witness) for(std::size_t i=0;i<z.size();++i) put(proof,i,z[i]);
        for(std::size_t b=0;b<batch;++b) for(std::size_t l=0;l<2;++l) {
            const auto& t=ctx_->transforms_[l];std::array<Poly,4> ds;
            for(std::size_t j=0;j<4;++j) {
                ds[j].assign(d.begin()+(b*4+j)*n,d.begin()+(b*4+j+1)*n);t.forward(ds[j]);
            }
            for(std::size_t k=0;k<2;++k) {
                Poly y(n);
                for(std::size_t i=0;i<n;++i) {
                    Wide sum=Wide(index_[b][0][l][i])*q[k][l][i];
                    if(k) sum+=Wide(index_[b][1][l][i])*q[0][l][i];
                    for(std::size_t j=0;j<4;++j) sum+=Wide(ds[j][i])*ctx_->key_[l][j][k][i];
                    // At most six products: quotient <6p<2^63 fits a Word.
                    y[i]=t.remainder(sum);
                }
                t.inverse(y);
                for(std::size_t i=0;i<n;++i) put(out,((b*2+k)*2+l)*n+i,y[i]);
            }
        }
        return {std::move(proof),std::move(out)};
    }
    bool check(std::string_view input,std::string_view witness,std::string_view output,
               std::string_view weights,bool local) const {
        validate(witness,output,local);
        if(weights.size()!=2*3*batch*8) throw std::invalid_argument("Incorrect product weights");
        for(std::size_t l=0;l<2;++l) for(std::size_t h=0;h<3;++h) for(std::size_t b=0;b<batch;++b)
            if(load(weights.data()+8*((l*3+h)*batch+b))>=ctx_->primes[l])
                throw std::invalid_argument("Noncanonical product weight");
        const auto q=query(input);
        Poly z;
        if(local) z=c2(q);
        else {z.resize(batch*2*n);for(std::size_t i=0;i<z.size();++i) z[i]=load(witness.data()+8*i);}
        const auto d=digits(z);bool accepted=true;
        for(std::size_t l=0;l<2;++l) {
            const auto& t=ctx_->transforms_[l];const auto p=ctx_->primes[l];
            for(std::size_t h=0;h<3;++h) {
                Poly alpha(batch);
                for(std::size_t b=0;b<batch;++b) alpha[b]=load(weights.data()+8*((l*3+h)*batch+b));
                std::array<Poly,2> a;
                for(std::size_t k=0;k<2;++k) a[k]=fold(alpha,p,[&](auto b,auto i){return index_[b][k][l][i];});
                if(!local) {
                    auto expected=a[1];
                    for(std::size_t i=0;i<n;++i) expected[i]=t.remainder(Wide(expected[i])*q[1][l][i]);
                    t.inverse(expected);
                    const auto observed=fold(alpha,p,[&](auto b,auto i){return z[(b*2+l)*n+i];});
                    for(std::size_t i=0;i<n;++i) accepted &= expected[i]==observed[i];
                }
                std::array<Poly,4> ds;
                for(std::size_t j=0;j<4;++j) {
                    ds[j]=fold(alpha,p,[&](auto b,auto i){return d[(b*4+j)*n+i];});t.forward(ds[j]);
                }
                for(std::size_t k=0;k<2;++k) {
                    Poly expected(n);
                    for(std::size_t i=0;i<n;++i) {
                        Wide sum=Wide(a[0][i])*q[k][l][i];
                        if(k) sum+=Wide(a[1][i])*q[0][l][i];
                        for(std::size_t j=0;j<4;++j) sum+=Wide(ds[j][i])*ctx_->key_[l][j][k][i];
                        expected[i]=t.remainder(sum);
                    }
                    t.inverse(expected);
                    const auto observed=fold(alpha,p,[&](auto b,auto i){return load(output.data()+8*((b*4+k*2+l)*n+i));});
                    for(std::size_t i=0;i<n;++i) accepted &= expected[i]==observed[i];
                }
            }
        }
        return accepted;
    }
};
} // namespace cuhepy_bgv_check
