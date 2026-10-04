// Q76 public canonical shared-query BGV evaluator and complete relation check.
// This core does not authenticate enrollment/requests or authorize release.
// Homemade exact NTT/RNS, no SEAL, HE secret, signer or challenge entropy.
// The context compiles its graph internally. Public preparation is immutable
// and shared across requests; request wire inputs are full common-Q integers.
#include "rns_ntt.h"
#include <cstring>
#include <map>
#include <tuple>
#include <limits>

namespace {
using namespace xtrace_bfv;
using Vector = std::vector<Word>;
using Rows = std::array<Vector, 2>;
using Pair = std::array<Rows, 2>;
constexpr unsigned WIDTH=15, DIGITS=4;

Wide common(const unsigned char* raw) {
    Wide x=0; for (unsigned i=0;i<WIDTH;++i) x |= Wide(raw[i])<<(8*i); return x;
}
void write_common(Wide x,unsigned char* raw) {
    for (unsigned i=0;i<WIDTH;++i) raw[i]=static_cast<unsigned char>(x>>(8*i));
}
mpz_class integer(Wide x) {
    Word limbs[2]{Word(x),Word(x>>64)};mpz_class out;
    mpz_import(out.get_mpz_t(),2,-1,sizeof(Word),0,0,limbs);return out;
}
struct Op { unsigned kind; std::size_t a=0,b=0,v0=0,v1=0; };
struct Binding { unsigned kind;std::size_t slot,digit; };

struct Context {
    std::size_t n,d,padded,levels,records,groups,sources,body_size;
    Word t,eta,p;
    std::array<Word,2> primes;
    Wide q;
    Word inverse0;
    std::array<std::unique_ptr<PrimeNTT>,2> fft;
    std::vector<Rows> constants, shifts;
    std::vector<std::vector<std::size_t>> maps;
    std::vector<std::array<std::size_t,DIGITS*2>> key_at;
    std::vector<std::array<std::size_t,3>> index_at;
    std::vector<Op> ops;
    std::vector<Binding> bindings;
    std::vector<std::size_t> roots,uses;
    std::map<std::tuple<unsigned,std::size_t,std::size_t,std::size_t,std::size_t>,std::size_t> interned;
    std::size_t public_ntts=0;

    Context(std::size_t degree,std::size_t dimension,std::size_t count,
            Word p0,Word p1,Word plaintext,Word support,Word terminal,
            const unsigned char* keys,std::size_t keys_size,
            const unsigned char* index,std::size_t index_size)
        :n(degree),d(dimension),records(count),t(plaintext),eta(support),p(terminal),primes{p0,p1},q(Wide(p0)*p1) {
        if (n<8 || n>16384 || (n&(n-1)) || d<3 || d>512 || d>n/2
            || !records || records>2*n || t>=(Word(1)<<30) || !(t&1)
            || !eta || eta>64 || p<(Word(1)<<15) || p>=(Word(1)<<60)
            || p0==p1 || !keys || !index)
            throw std::invalid_argument("Wrong bounded native enrollment");
        padded=1;levels=0;while(padded<d){padded*=2;++levels;}
        groups=(records+n-1)/n;sources=padded-1+groups;
        body_size=(sources+2*groups)*n*WIDTH;
        if(t<=2*padded || keys_size!=(levels+1)*DIGITS*2*n*WIDTH || index_size!=2*d*groups*n*WIDTH
            || Wide(3*d*groups+2*DIGITS*(levels+1))*n*16>(Wide(1)<<30))
            throw std::invalid_argument("Wrong full key/index coverage or cache cap");
        for(auto prime:primes) {
            mpz_class z(prime);
            if(prime<(Word(1)<<59) || prime>=(Word(1)<<60) || (prime-1)%(2*n)
                || !mpz_probab_prime_p(z.get_mpz_t(),50)) throw std::invalid_argument("Wrong actual prime");
        }
        mpz_class modulus=integer(q), small(p);
        if(mpz_sizeinbase(modulus.get_mpz_t(),2)!=120 || p>=q || (modulus-p)%t!=0
            || !mpz_probab_prime_p(small.get_mpz_t(),50)) throw std::invalid_argument("Wrong Q/P contract");
        // Independent deterministic owner-origin box, before any NTT.
        mpz_class fresh=t/2+mpz_class(t)*eta;
        mpz_class error=mpz_class(t)*eta*n*DIGITS*((Word(1)<<30)-1),phase=fresh;
        for(std::size_t l=0;l<levels;++l) {
            phase=2*phase+error;
            if(2*phase>=modulus) throw std::invalid_argument("Unsafe expansion box");
        }
        phase=n*mpz_class(d)*fresh*phase+error;
        mpz_class rounded=(p*phase+modulus-1)/modulus+((mpz_class(n+1)*t+1)/2);
        if(2*phase>=modulus || 2*rounded>=p) throw std::invalid_argument("Unsafe complete Q/P box");
        // Every coordinate is validated before preparation, including last.
        for(auto item:{std::make_pair(keys,keys_size),std::make_pair(index,index_size)})
            for(std::size_t i=0;i<item.second;i+=WIDTH)
                if(common(item.first+i)>=q) throw std::invalid_argument("Noncanonical enrollment coefficient");
        inverse0=power_mod(p0%p1,p1-2,p1);
        for(std::size_t k=0;k<2;++k) fft[k]=std::make_unique<PrimeNTT>(n,primes[k],true,true);
        auto prepare=[&](const unsigned char* bytes) {
            Rows row;
            for(std::size_t k=0;k<2;++k) {
                row[k].resize(n);
                for(std::size_t i=0;i<n;++i) row[k][i]=common(bytes+WIDTH*i)%primes[k];
                fft[k]->forward(row[k]);++public_ntts;
            }
            auto at=constants.size();constants.push_back(std::move(row));return at;
        };
        for(std::size_t l=0;l<=levels;++l) {
            std::array<std::size_t,DIGITS*2> at{};
            for(std::size_t j=0;j<DIGITS*2;++j) at[j]=prepare(keys+(l*DIGITS*2+j)*n*WIDTH);
            key_at.push_back(at);
        }
        for(std::size_t tile=0;tile<d*groups;++tile) {
            std::array<std::size_t,3> at{prepare(index+2*tile*n*WIDTH),prepare(index+(2*tile+1)*n*WIDTH),constants.size()};
            Rows sum=constants[at[0]];add(sum,constants[at[1]]);constants.push_back(std::move(sum));index_at.push_back(at);
        }
        unsigned bits=0;for(auto x=n;x>1;x/=2)++bits;
        auto reverse=[&](std::size_t x){std::size_t out=0;for(unsigned i=0;i<bits;++i){out=2*out+(x&1);x/=2;}return out;};
        for(std::size_t l=0;l<levels;++l) {
            const auto exponent=1+n/(std::size_t(1)<<l);std::vector<std::size_t> map(n);
            for(std::size_t i=0;i<n;++i) map[i]=reverse(((exponent*(2*reverse(i)+1))%(2*n)-1)/2);
            maps.push_back(std::move(map));
            Rows shift;
            for(std::size_t k=0;k<2;++k) {
                shift[k].assign(n,0);shift[k][n-(std::size_t(1)<<l)]=primes[k]-1;
                fft[k]->forward(shift[k]);++public_ntts;
            }
            shifts.push_back(std::move(shift));
        }
        compile();
    }

    void add(Rows& a,const Rows& b,bool subtract=false) const {
        for(std::size_t k=0;k<2;++k)for(std::size_t i=0;i<n;++i) {
            auto x=a[k][i],y=b[k][i];
            a[k][i]=subtract ? (x>=y?x-y:x+primes[k]-y) : (x+y>=primes[k]?x+y-primes[k]:x+y);
        }
    }
    Rows zero() const { return {Vector(n),Vector(n)}; }
    Wide compose(Word a,Word b) const {
        auto x=a>=primes[1]?a-primes[1]:a;
        auto delta=b>=x?b-x:b+primes[1]-x;
        return Wide(a)+Wide(primes[0])*(Wide(delta)*inverse0%primes[1]);
    }
    Rows permute(const Rows& input,std::size_t level,bool shifted=false) const {
        Rows out=zero();
        for(std::size_t k=0;k<2;++k)for(std::size_t i=0;i<n;++i)
            out[k][i]=shifted ? fft[k]->remainder(Wide(input[k][i])*shifts[level][k][i]) : input[k][maps[level][i]];
        return out;
    }
    std::size_t op(unsigned kind,std::size_t a=0,std::size_t b=0,std::size_t v0=0,std::size_t v1=0) {
        auto key=std::make_tuple(kind,a,b,v0,v1);auto old=interned.find(key);
        if(old!=interned.end())return old->second;
        auto at=ops.size();ops.push_back({kind,a,b,v0,v1});interned[key]=at;return at;
    }
    std::size_t input(unsigned kind,std::size_t slot,std::size_t digit=0) {
        auto at=bindings.size();bindings.push_back({kind,slot,digit});return op(1,0,0,at);
    }
    std::size_t plus(std::size_t a,std::size_t b){if(!a)return b;if(!b)return a;return op(2,std::min(a,b),std::max(a,b));}
    std::size_t minus(std::size_t a,std::size_t b){if(a==b)return 0;return op(3,a,b);}
    std::size_t product(std::size_t a,std::size_t c){return op(5,a,0,c);}
    std::array<std::size_t,DIGITS> source(std::size_t slot,std::size_t expression) {
        std::array<std::size_t,DIGITS> digits{};std::size_t composed=0;
        for(std::size_t j=0;j<DIGITS;++j) {
            digits[j]=input(1,slot,j);auto power=Wide(1)<<(30*j);
            composed=plus(composed,op(4,digits[j],0,power%primes[0],power%primes[1]));
        }
        roots.push_back(minus(expression,composed));return digits;
    }
    std::array<std::size_t,2> switching(const std::array<std::size_t,DIGITS>& ds,std::size_t key) {
        std::array<std::size_t,2> out{};
        for(std::size_t j=0;j<DIGITS;++j)for(std::size_t c=0;c<2;++c)out[c]=plus(out[c],product(ds[j],key_at[key][2*j+c]));
        return out;
    }
    void compile() {
        op(0);std::vector<std::array<std::size_t,2>> work{{input(0,0),input(0,1)}};std::size_t slot=0;
        for(std::size_t l=0;l<levels;++l) {
            std::vector<std::array<std::size_t,2>> even,odd;
            for(auto pair:work) {
                std::array<std::size_t,2> rotated{op(6,pair[0],0,l),op(6,pair[1],0,l)};
                auto digits=source(slot++,rotated[1]);auto sw=switching(digits,l+1);
                rotated={plus(rotated[0],sw[0]),sw[1]};
                even.push_back({plus(pair[0],rotated[0]),plus(pair[1],rotated[1])});
                odd.push_back({op(6,minus(pair[0],rotated[0]),0,l,1),op(6,minus(pair[1],rotated[1]),0,l,1)});
            }
            even.insert(even.end(),odd.begin(),odd.end());work=std::move(even);
        }
        for(std::size_t g=0;g<groups;++g) {
            std::array<std::size_t,3> total{};
            for(std::size_t j=0;j<d;++j) {
                auto pair=work[j];const auto& idx=index_at[g*d+j];
                auto a=product(pair[0],idx[0]),b=product(pair[1],idx[1]);
                auto cross=minus(minus(product(plus(pair[0],pair[1]),idx[2]),a),b);
                total[0]=plus(total[0],a);total[1]=plus(total[1],cross);total[2]=plus(total[2],b);
            }
            auto digits=source(slot++,total[2]);auto sw=switching(digits,0);
            for(std::size_t c=0;c<2;++c)roots.push_back(minus(plus(total[c],sw[c]),input(2,sources+2*g+c)));
        }
        if(slot!=sources || roots.size()!=sources+2*groups)throw std::logic_error("Incomplete native graph");
        uses.assign(ops.size(),0);
        for(auto x:ops) {if(x.kind>=2)++uses[x.a];if(x.kind==2 || x.kind==3)++uses[x.b];}
        for(auto r:roots)++uses[r];
        interned.clear();
    }
};

struct Query {
    std::shared_ptr<const Context> ctx;
    std::array<std::vector<Wide>,2> original;
    Query(std::shared_ptr<const Context> c,const unsigned char* raw,std::size_t length):ctx(std::move(c)) {
        if(!raw || length!=2*ctx->n*WIDTH)throw std::invalid_argument("Wrong original query coverage");
        for(std::size_t i=0;i<2*ctx->n;++i)if(common(raw+WIDTH*i)>=ctx->q)throw std::invalid_argument("Noncanonical original query");
        for(std::size_t c=0;c<2;++c) {
            original[c].resize(ctx->n);for(std::size_t i=0;i<ctx->n;++i)original[c][i]=common(raw+(c*ctx->n+i)*WIDTH);
        }
    }
    bool check(const unsigned char* body,std::size_t length,Word* diagnostic=nullptr) const {
        const auto& c=*ctx;
        if(!body || length!=c.body_size)throw std::invalid_argument("Wrong complete proof body");
        for(std::size_t i=0;i<length;i+=WIDTH)if(common(body+i)>=c.q)throw std::invalid_argument("Noncanonical final/source coefficient");
        std::vector<Rows> values(c.ops.size());auto remaining=c.uses;
        std::vector<std::vector<std::size_t>> at_root(c.ops.size());
        for(std::size_t r=0;r<c.roots.size();++r)at_root[c.roots[r]].push_back(r);
        auto consume=[&](std::size_t a){if(!--remaining[a])for(auto& row:values[a])Vector().swap(row);};bool exact=true;
        for(std::size_t a=0;a<c.ops.size();++a) {
            const auto& op=c.ops[a];auto& value=values[a];
            for(std::size_t k=0;k<2;++k) {
                auto modulus=c.primes[k];value[k].resize(c.n);
                if(!op.kind)std::fill(value[k].begin(),value[k].end(),0);
                else if(op.kind==1) {
                    const auto& b=c.bindings[op.v0];
                    for(std::size_t i=0;i<c.n;++i) {
                        Wide x=b.kind==0?original[b.slot][i]:common(body+(b.slot*c.n+i)*WIDTH);
                        if(b.kind==1)x=(x>>(30*b.digit))&((Wide(1)<<30)-1);
                        value[k][i]=x%modulus;
                    }
                    c.fft[k]->forward(value[k]);
                } else for(std::size_t i=0;i<c.n;++i) {
                    auto x=values[op.a][k][i];
                    if(op.kind==2) {auto sum=x+values[op.b][k][i];value[k][i]=sum>=modulus?sum-modulus:sum;}
                    else if(op.kind==3) {auto y=values[op.b][k][i];value[k][i]=x>=y?x-y:x+modulus-y;}
                    else if(op.kind==4)value[k][i]=c.fft[k]->remainder(Wide(x)*(k?op.v1:op.v0));
                    else if(op.kind==5)value[k][i]=c.fft[k]->remainder(Wide(x)*c.constants[op.v0][k][i]);
                    else value[k][i]=op.v1?c.fft[k]->remainder(Wide(x)*c.shifts[op.v0][k][i]):values[op.a][k][c.maps[op.v0][i]];
                }
                for(auto root:at_root[a]) {
                    for(auto x:value[k])exact &= x==0;
                    if(diagnostic) {auto copy=value[k];c.fft[k]->inverse(copy);std::copy(copy.begin(),copy.end(),diagnostic+(2*root+k)*c.n);}
                }
            }
            if(op.kind>=2)consume(op.a);
            if(op.kind==2 || op.kind==3)consume(op.b);
            for(auto r:at_root[a]){(void)r;consume(a);}
            if(!remaining[a])for(auto& row:value)Vector().swap(row);
        }
        return exact;
    }
    std::array<Rows,DIGITS> digits(Rows source,unsigned char* output) const {
        const auto& c=*ctx;
        for(std::size_t k=0;k<2;++k)c.fft[k]->inverse(source[k]);
        std::array<Rows,DIGITS> rows;
        for(auto& row:rows)row=c.zero();
        for(std::size_t i=0;i<c.n;++i) {
            Wide x=c.compose(source[0][i],source[1][i]);write_common(x,output+WIDTH*i);
            for(std::size_t j=0;j<DIGITS;++j)for(std::size_t k=0;k<2;++k)rows[j][k][i]=Word(x>>(30*j))&((Word(1)<<30)-1);
        }
        for(auto& row:rows)for(std::size_t k=0;k<2;++k)c.fft[k]->forward(row[k]);
        return rows;
    }
    Pair switching(const std::array<Rows,DIGITS>& ds,std::size_t key) const {
        const auto& c=*ctx;Pair out{c.zero(),c.zero()};
        for(std::size_t a=0;a<2;++a)for(std::size_t k=0;k<2;++k)for(std::size_t i=0;i<c.n;++i) {
            Wide sum=0;for(std::size_t j=0;j<DIGITS;++j)sum+=Wide(ds[j][k][i])*c.constants[c.key_at[key][2*j+a]][k][i];
            out[a][k][i]=c.fft[k]->remainder(sum);
        }
        return out;
    }
    void produce(unsigned char* body,std::size_t length) const {
        const auto& c=*ctx;if(!body || length!=c.body_size)throw std::invalid_argument("Wrong producer buffer");
        Pair query{c.zero(),c.zero()};
        for(std::size_t a=0;a<2;++a)for(std::size_t k=0;k<2;++k) {
            for(std::size_t i=0;i<c.n;++i)query[a][k][i]=original[a][i]%c.primes[k];
            c.fft[k]->forward(query[a][k]);
        }
        std::vector<Pair> work{std::move(query)};std::size_t slot=0;
        for(std::size_t l=0;l<c.levels;++l) {
            std::vector<Pair> even,odd;even.reserve(work.size());odd.reserve(work.size());
            for(const auto& pair:work) {
                Pair rotated{c.permute(pair[0],l),c.permute(pair[1],l)};
                auto ds=digits(rotated[1],body+slot++*c.n*WIDTH);auto sw=switching(ds,l+1);
                c.add(rotated[0],sw[0]);rotated[1]=std::move(sw[1]);
                Pair plus=pair,minus=pair;
                for(std::size_t a=0;a<2;++a){c.add(plus[a],rotated[a]);c.add(minus[a],rotated[a],true);minus[a]=c.permute(minus[a],l,true);}
                even.push_back(std::move(plus));odd.push_back(std::move(minus));
            }
            for(auto& pair:odd)even.push_back(std::move(pair));
            work=std::move(even);
        }
        for(std::size_t g=0;g<c.groups;++g) {
            std::array<Rows,3> total{c.zero(),c.zero(),c.zero()};
            for(std::size_t j=0;j<c.d;++j)for(std::size_t k=0;k<2;++k)for(std::size_t i=0;i<c.n;++i) {
                const auto& idx=c.index_at[g*c.d+j];auto a=work[j][0][k][i],b=work[j][1][k][i],modulus=c.primes[k];
                auto x=c.fft[k]->remainder(Wide(a)*c.constants[idx[0]][k][i]);
                auto z=c.fft[k]->remainder(Wide(b)*c.constants[idx[1]][k][i]);
                auto sum=a+b>=modulus?a+b-modulus:a+b;
                auto y=c.fft[k]->remainder(Wide(sum)*c.constants[idx[2]][k][i]);
                y=y>=x?y-x:y+modulus-x;y=y>=z?y-z:y+modulus-z;
                std::array<Word,3> products{x,y,z};
                for(std::size_t part=0;part<3;++part){auto value=total[part][k][i]+products[part];total[part][k][i]=value>=modulus?value-modulus:value;}
            }
            auto ds=digits(total[2],body+slot++*c.n*WIDTH);auto sw=switching(ds,0);
            for(std::size_t a=0;a<2;++a) {
                c.add(total[a],sw[a]);for(std::size_t k=0;k<2;++k)c.fft[k]->inverse(total[a][k]);
                for(std::size_t i=0;i<c.n;++i)write_common(c.compose(total[a][0][i],total[a][1][i]),body+((c.sources+2*g+a)*c.n+i)*WIDTH);
            }
        }
        if(slot!=c.sources)throw std::logic_error("Incomplete source producer");
    }
    void terminal(const unsigned char* body,std::size_t length,unsigned char* output,std::size_t output_size) const {
        const auto& c=*ctx;unsigned bits=0;for(auto x=c.p;x;x/=2)++bits;
        auto width=(c.n*bits+7)/8;
        if(!body || length!=c.body_size || !output || output_size!=2*c.groups*width)throw std::invalid_argument("Wrong terminal buffers");
        std::memset(output,0,output_size);
        mpz_class modulus=integer(c.q),qt=modulus*c.t,denominator=2*qt,numerator,rounded;
        for(std::size_t row=0;row<2*c.groups;++row)for(std::size_t i=0;i<c.n;++i) {
            auto wide=common(body+((c.sources+row)*c.n+i)*WIDTH);
            if(wide>=c.q)throw std::invalid_argument("Noncanonical terminal source");
            auto x=integer(wide);Word residue=mpz_fdiv_ui(x.get_mpz_t(),c.t);
            numerator=2*(c.p*x-modulus*residue)+qt;
            mpz_fdiv_q(rounded.get_mpz_t(),numerator.get_mpz_t(),denominator.get_mpz_t());
            rounded=rounded*c.t+residue;Word result=mpz_fdiv_ui(rounded.get_mpz_t(),c.p);
            auto at=i*bits,byte=at/8,offset=at%8;Wide packed=Wide(result)<<offset;
            for(std::size_t b=0;b<(offset+bits+7)/8;++b)output[row*width+byte+b]|=static_cast<unsigned char>(packed>>(8*b));
        }
    }
};
using Handle=std::shared_ptr<const Context>;
}

extern "C" {
unsigned cuhepy_shared_abi() noexcept{return 1202;}
void* cuhepy_shared_create(std::size_t n,std::size_t d,std::size_t records,Word p0,Word p1,Word t,Word eta,Word p,
                          const unsigned char* keys,std::size_t kl,const unsigned char* index,std::size_t il) noexcept {
    try{return new Handle(std::make_shared<Context>(n,d,records,p0,p1,t,eta,p,keys,kl,index,il));}catch(...){return nullptr;}
}
void cuhepy_shared_destroy(void* raw) noexcept{delete static_cast<Handle*>(raw);}
void* cuhepy_shared_query(void* raw,const unsigned char* query,std::size_t length) noexcept {
    try{if(!raw)return nullptr;return new Query(*static_cast<Handle*>(raw),query,length);}catch(...){return nullptr;}
}
void cuhepy_shared_query_destroy(void* raw) noexcept{delete static_cast<Query*>(raw);}
int cuhepy_shared_check(void* raw,const unsigned char* body,std::size_t length) noexcept {
    try{if(!raw)return -1;return static_cast<Query*>(raw)->check(body,length)?1:0;}catch(...){return -1;}
}
int cuhepy_shared_residuals(void* raw,const unsigned char* body,std::size_t length,Word* output,std::size_t output_words) noexcept {
    try{
        if(!raw || !output)return -1;
        const auto& query=*static_cast<Query*>(raw);
        if(output_words!=2*query.ctx->roots.size()*query.ctx->n)return -1;
        query.check(body,length,output);
        return 0;
    }catch(...){return -1;}
}
int cuhepy_shared_produce(void* raw,unsigned char* body,std::size_t length) noexcept {
    try{if(!raw)return -1;static_cast<Query*>(raw)->produce(body,length);return 0;}catch(...){return -1;}
}
int cuhepy_shared_terminal(void* raw,const unsigned char* body,std::size_t length,unsigned char* out,std::size_t size) noexcept {
    try{if(!raw)return -1;static_cast<Query*>(raw)->terminal(body,length,out,size);return 0;}catch(...){return -1;}
}
int cuhepy_shared_stats(void* raw,Word* out,std::size_t size) noexcept {
    try{if(!raw || !out || size!=8)return -1;const auto& c=**static_cast<Handle*>(raw);
        out[0]=c.body_size;out[1]=c.sources;out[2]=c.roots.size();out[3]=c.ops.size();out[4]=c.constants.size();out[5]=c.public_ntts;
        out[6]=c.constants.size()*2*c.n*sizeof(Word);out[7]=c.maps.size()*c.n*sizeof(std::size_t)+c.shifts.size()*2*c.n*sizeof(Word);return 0;
    }catch(...){return -1;}
}
}
