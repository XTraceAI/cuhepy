// Q71 isolated public complete-vector residual primitive. No secret or signer.
// This reuses cuhepy's own NTT, not SEAL. The C ABI is for the trusted Python
// research adapter; it is not a wire parser or a production release interface.
#include "rns_ntt.h"
#include <cstring>
#include <limits>

namespace {
using xtrace_bfv::Word;
using xtrace_bfv::Wide;
using Vector = std::vector<Word>;
using Rows = std::array<Vector, 2>;
struct Op { Word kind, a, b, value0, value1; };

struct Program {
    std::size_t n, inputs;
    std::array<Word, 2> primes;
    std::array<std::unique_ptr<xtrace_bfv::PrimeNTT>, 2> transforms;
    std::vector<Op> ops;
    std::vector<std::size_t> roots, uses;
    std::vector<Rows> constants;
    std::vector<std::size_t> reverse;
    std::vector<Vector> maps;
    std::vector<Rows> shifts;
    struct Binding { Word kind, slot, digit; };
    std::vector<Binding> wire_bindings;
    std::array<std::vector<Wide>, 2> owner_query;
    std::size_t wire_polynomials=0;

    static Wide common(const unsigned char* raw) {
        Wide value=0;
        for (unsigned byte=0; byte<15; ++byte) value |= Wide(raw[byte]) << (8*byte);
        return value;
    }

    void enroll_wire(const Word* bindings, std::size_t sources, std::size_t polynomials,
                     const unsigned char* query, std::size_t length) {
        if (!bindings || !query || !sources || sources>=polynomials || polynomials>10000
            || length!=2*n*15 || Wide(polynomials)*n*15>(Wide(1)<<31))
            throw std::invalid_argument("Wrong complete wire enrollment");
        std::vector<unsigned> coverage(polynomials,0);
        unsigned queries=0;
        for (std::size_t i=0; i<inputs; ++i) {
            Binding b{bindings[3*i],bindings[3*i+1],bindings[3*i+2]};
            if (b.kind>2 || (b.kind==0 && (b.slot>=2 || b.digit))
                || (b.kind==1 && (b.slot>=sources || b.digit>=4))
                || (b.kind==2 && (b.slot<sources || b.slot>=polynomials || b.digit)))
                throw std::invalid_argument("Wrong owner source/output binding");
            if (b.kind==0) queries |= 1U<<b.slot;
            else coverage[b.slot] |= b.kind==1 ? 1U<<b.digit : 1U;
            wire_bindings.push_back(b);
        }
        if (queries!=3) throw std::invalid_argument("Both original query components required");
        for (std::size_t i=0; i<polynomials; ++i)
            if (coverage[i]!=(i<sources ? 15U : 1U))
                throw std::invalid_argument("Complete common-Q slot coverage required");
        const Wide q=Wide(primes[0])*primes[1];
        for (std::size_t c=0; c<2; ++c) {
            owner_query[c].resize(n);
            for (std::size_t i=0; i<n; ++i) {
                auto value=common(query+(c*n+i)*15);
                if (value>=q) throw std::invalid_argument("Noncanonical original query");
                owner_query[c][i]=value;
            }
        }
        wire_polynomials=polynomials;
    }

    Program(std::size_t n, Word p0, Word p1, std::size_t inputs,
            const Word* descriptions, std::size_t count,
            const Word* roots_data, std::size_t root_count,
            const Word* public_data, std::size_t public_count)
        : n(n), inputs(inputs), primes{p0,p1}, uses(count,0), reverse(n) {
        if (n < 8 || n > 16384 || (n & (n-1)) || !inputs || inputs > 10000
            || !count || count > 200000 || !root_count || root_count > 10000
            || public_count > 100000 || p0 == p1 || !descriptions || !roots_data
            || (public_count && !public_data)
            || Wide(public_count) * n * 16 > (Wide(1) << 30))
            throw std::invalid_argument("Invalid bounded kernel dimensions");
        for (std::size_t p=0; p<2; ++p) {
            auto prime=primes[p];
            mpz_class integer(prime);
            if (prime < 3 || prime >= (Word(1)<<60) || (prime-1)%(2*n)
                || !mpz_probab_prime_p(integer.get_mpz_t(),50))
                throw std::invalid_argument("Actual compatible prime required");
        }
        for (std::size_t i=0; i<count; ++i) {
            const auto* d=descriptions+5*i;
            Op op{d[0],d[1],d[2],d[3],d[4]};
            if (op.kind>6 || (op.kind>=2 && op.a>=i)
                || ((op.kind==2 || op.kind==3) && op.b>=i)
                || (op.kind==1 && op.value0>=inputs)
                || (op.kind==5 && op.value0>=public_count)
                || (op.kind==4 && (op.value0>=p0 || op.value1>=p1))
                || (op.kind==6 && (!(op.value0&1) || op.value0>=2*n || op.value1>=2*n)))
                throw std::invalid_argument("Wrong acyclic enrolled operation");
            if (op.kind>=2) ++uses[op.a];
            if (op.kind==2 || op.kind==3) ++uses[op.b];
            ops.push_back(op);
        }
        for (std::size_t i=0; i<root_count; ++i) {
            if (roots_data[i]>=count) throw std::invalid_argument("Wrong residual root");
            roots.push_back(roots_data[i]); ++uses[roots.back()];
        }
        // Validate all public rows before constructing/using an NTT.
        for (std::size_t c=0; c<public_count; ++c)
            for (std::size_t p=0; p<2; ++p)
                for (std::size_t i=0; i<n; ++i)
                    if (public_data[(2*c+p)*n+i]>=primes[p])
                        throw std::invalid_argument("Noncanonical public residue");
        unsigned bits=0;
        for (auto x=n; x>1; x/=2) ++bits;
        for (std::size_t i=0; i<n; ++i) {
            std::size_t index=i, result=0;
            for (unsigned bit=0; bit<bits; ++bit) { result=2*result+(index&1); index/=2; }
            reverse[i]=result;
        }
        for (std::size_t p=0; p<2; ++p)
            transforms[p]=std::make_unique<xtrace_bfv::PrimeNTT>(n,primes[p],true,true);
        for (std::size_t c=0; c<public_count; ++c) {
            Rows value;
            for (std::size_t p=0; p<2; ++p) {
                value[p].assign(public_data+(2*c+p)*n,public_data+(2*c+p+1)*n);
                transforms[p]->forward(value[p]);
            }
            constants.push_back(std::move(value));
        }
        maps.resize(count); shifts.resize(count);
        for (std::size_t a=0; a<count; ++a) {
            const auto& op=ops[a];
            if (op.kind!=6) continue;
            maps[a].resize(n);
            for (std::size_t i=0; i<n; ++i) {
                auto odd=(op.value0*(2*reverse[i]+1))%(2*n);
                maps[a][i]=reverse[(odd-1)/2];
            }
            if (op.value1) for (std::size_t p=0; p<2; ++p) {
                shifts[a][p].assign(n,0);
                shifts[a][p][op.value1%n]=op.value1>=n ? primes[p]-1 : 1;
                transforms[p]->forward(shifts[a][p]);
            }
        }
    }

    template<class BindingReader>
    bool run(BindingReader&& binding, Word* diagnostic) const {
        auto remaining=uses;
        std::vector<Rows> values(ops.size());
        std::vector<std::vector<std::size_t>> at_root(ops.size());
        for (std::size_t i=0; i<roots.size(); ++i) at_root[roots[i]].push_back(i);
        bool exact=true;
        auto consume=[&](std::size_t a) {
            if (!--remaining[a]) for (auto& p:values[a]) Vector().swap(p);
        };
        for (std::size_t a=0; a<ops.size(); ++a) {
            const auto& op=ops[a];
            auto& value=values[a];
            for (std::size_t p=0; p<2; ++p) {
                auto modulus=primes[p]; value[p].resize(n);
                if (!op.kind) std::fill(value[p].begin(),value[p].end(),0);
                else if (op.kind==1) {
                    binding(op.value0,p,value[p]);
                    transforms[p]->forward(value[p]);
                } else for (std::size_t i=0; i<n; ++i) {
                    auto x=values[op.a][p][i];
                    if (op.kind==2) { auto sum=x+values[op.b][p][i]; value[p][i]=sum>=modulus ? sum-modulus : sum; }
                    else if (op.kind==3) { auto y=values[op.b][p][i]; value[p][i]=x>=y ? x-y : x+modulus-y; }
                    else if (op.kind==4) value[p][i]=transforms[p]->remainder(Wide(x)*(p ? op.value1 : op.value0));
                    else if (op.kind==5) value[p][i]=transforms[p]->remainder(Wide(x)*constants[op.value0][p][i]);
                    else {
                        x=values[op.a][p][maps[a][i]];
                        value[p][i]=op.value1 ? transforms[p]->remainder(Wide(x)*shifts[a][p][i]) : x;
                    }
                }
                for (auto root:at_root[a]) {
                    // Checking the ENTIRE NTT vector is exact by invertibility.
                    // One vanishing evaluation coordinate never grants success.
                    for (auto x:value[p]) exact &= x==0;
                    if (diagnostic) {
                        auto coefficients=value[p]; transforms[p]->inverse(coefficients);
                        std::copy(coefficients.begin(),coefficients.end(),diagnostic+(2*root+p)*n);
                    }
                }
            }
            if (op.kind>=2) consume(op.a);
            if (op.kind==2 || op.kind==3) consume(op.b);
            for (auto root:at_root[a]) { (void)root; consume(a); }
            if (!remaining[a]) for (auto& p:value) Vector().swap(p);
        }
        return exact;
    }

    bool evaluate(const Word* data, std::size_t input_count, Word* diagnostic) const {
        if (!data || input_count!=inputs) throw std::invalid_argument("Wrong complete input coverage");
        // Full immutable binding grammar is checked by Python; check EVERY
        // limb range here too before arithmetic, including a malformed last row.
        for (std::size_t a=0; a<inputs; ++a)
            for (std::size_t p=0; p<2; ++p)
                for (std::size_t i=0; i<n; ++i)
                    if (data[(2*a+p)*n+i]>=primes[p])
                        throw std::invalid_argument("Noncanonical input residue");
        return run([&](std::size_t a,std::size_t p,Vector& value) {
            std::copy(data+(2*a+p)*n,data+(2*a+p+1)*n,value.begin());
        },diagnostic);
    }

    bool evaluate_wire(const unsigned char* body, std::size_t length, Word* diagnostic) const {
        if (!wire_polynomials || !body || length!=wire_polynomials*n*15)
            throw std::invalid_argument("Wrong immutable whole wire coverage");
        const Wide q=Wide(primes[0])*primes[1];
        // Full grammar first, including every unused physical coordinate.
        for (std::size_t i=0; i<wire_polynomials*n; ++i)
            if (common(body+15*i)>=q) throw std::invalid_argument("Noncanonical common-Q source/output");
        return run([&](std::size_t a,std::size_t p,Vector& value) {
            const auto& b=wire_bindings[a];
            for (std::size_t i=0; i<n; ++i) {
                Wide x=b.kind==0 ? owner_query[b.slot][i] : common(body+(b.slot*n+i)*15);
                if (b.kind==1) x=(x>>(30*b.digit))&((Wide(1)<<30)-1);
                value[i]=x%primes[p];
            }
        },diagnostic);
    }
};
}

extern "C" {
void* cuhepy_noise_cut_create(std::size_t n, Word p0, Word p1, std::size_t inputs,
                            const Word* ops, std::size_t count, const Word* roots,
                            std::size_t residuals, const Word* constants, std::size_t public_count) noexcept {
    try { return new Program(n,p0,p1,inputs,ops,count,roots,residuals,constants,public_count); }
    catch (...) { return nullptr; }
}
void cuhepy_noise_cut_destroy(void* raw) noexcept { delete static_cast<Program*>(raw); }
void* cuhepy_noise_cut_create_wire(std::size_t n, Word p0, Word p1, std::size_t inputs,
                                const Word* ops, std::size_t count, const Word* roots,
                                std::size_t residuals, const Word* constants, std::size_t public_count,
                                const Word* bindings, std::size_t sources, std::size_t polynomials,
                                const unsigned char* query, std::size_t length) noexcept {
    try {
        auto result=std::make_unique<Program>(n,p0,p1,inputs,ops,count,roots,residuals,constants,public_count);
        result->enroll_wire(bindings,sources,polynomials,query,length);
        return result.release();
    } catch (...) { return nullptr; }
}
int cuhepy_noise_cut_check(void* raw, const Word* inputs, std::size_t count) noexcept {
    try { if (!raw) return -1; return static_cast<Program*>(raw)->evaluate(inputs,count,nullptr) ? 1 : 0; }
    catch (...) { return -1; }
}
int cuhepy_noise_cut_residuals(void* raw, const Word* inputs, std::size_t count, Word* output) noexcept {
    try { if (!raw || !output) return -1; static_cast<Program*>(raw)->evaluate(inputs,count,output); return 0; }
    catch (...) { return -1; }
}
int cuhepy_noise_cut_check_wire(void* raw, const unsigned char* body, std::size_t length) noexcept {
    try { if (!raw) return -1; return static_cast<Program*>(raw)->evaluate_wire(body,length,nullptr) ? 1 : 0; }
    catch (...) { return -1; }
}
int cuhepy_noise_cut_residuals_wire(void* raw, const unsigned char* body, std::size_t length, Word* output) noexcept {
    try { if (!raw || !output) return -1; static_cast<Program*>(raw)->evaluate_wire(body,length,output); return 0; }
    catch (...) { return -1; }
}
}
