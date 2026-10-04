// Exact matched product control; compile this translation unit alone. It
// preserves full-witness/replay ABIs and shares their genuine prefix/suffix.
#include "shared_query_replay.cpp"

namespace {
std::size_t compact_size(const Context& c) {
    unsigned bits=0;for(auto p=c.p;p;p/=2)++bits;
    return 2*c.groups*((c.n*bits+7)/8);
}
void aggregate_buffers(const Context& c,const unsigned char* body,std::size_t length,
                       const unsigned char* output,std::size_t size) {
    if(!body || length!=3*c.groups*c.n*WIDTH || !output || size!=compact_size(c))
        throw std::invalid_argument("Wrong complete aggregate/terminal coverage");
}
}
extern "C" {
unsigned cuhepy_shared_aggregate_abi() {return 1;}
int cuhepy_shared_aggregate_produce(void* h,unsigned char* body,std::size_t length,
                                  unsigned char* output,std::size_t size) {
    try {
        if(!h)return -1;
        const auto& query=*static_cast<Query*>(h);const auto& c=*query.ctx;
        aggregate_buffers(c,body,length,output,size);
        auto work=query.expand();std::vector<unsigned char> final(2*c.groups*c.n*WIDTH);
        for(std::size_t g=0;g<c.groups;++g) {
            auto total=query.aggregate(work,g);
            for(std::size_t part=0;part<3;++part) {
                auto row=total[part];for(std::size_t k=0;k<2;++k)c.fft[k]->inverse(row[k]);
                for(std::size_t i=0;i<c.n;++i)write_common(c.compose(row[0][i],row[1][i]),body+((3*g+part)*c.n+i)*WIDTH);
            }
            query.finish_aggregate(std::move(total),final.data()+2*g*c.n*WIDTH);
        }
        query.terminal(final.data(),final.size(),output,size,false);
        return 0;
    } catch(...) {return -1;}
}
int cuhepy_shared_aggregate_finish(void* h,const unsigned char* body,std::size_t length,
                                 unsigned char* output,std::size_t size) {
    try {
        if(!h)return -1;
        const auto& query=*static_cast<Query*>(h);const auto& c=*query.ctx;
        aggregate_buffers(c,body,length,output,size);
        // Validate the ENTIRE canonical common-Q claim before any prefix NTT.
        for(std::size_t at=0;at<length;at+=WIDTH)
            if(common(body+at)>=c.q)throw std::invalid_argument("Noncanonical aggregate coordinate");
        auto work=query.expand();std::vector<unsigned char> final(2*c.groups*c.n*WIDTH);
        for(std::size_t g=0;g<c.groups;++g) {
            auto expected=query.aggregate(work,g);
            std::array<Rows,3> claimed{c.zero(),c.zero(),c.zero()};bool equal=true;
            for(std::size_t part=0;part<3;++part)for(std::size_t k=0;k<2;++k) {
                for(std::size_t i=0;i<c.n;++i)
                    claimed[part][k][i]=common(body+((3*g+part)*c.n+i)*WIDTH)%c.primes[k];
                c.fft[k]->forward(claimed[part][k]);
                for(std::size_t i=0;i<c.n;++i)equal &= claimed[part][k][i]==expected[part][k][i];
            }
            // Direct coefficient equality is the cheaper paired-product form
            // of the known exact three-point identity. No scalar sampling or
            // hidden challenge, and no peer-supplied expanded query, is used.
            if(!equal)return 0;
            query.finish_aggregate(std::move(claimed),final.data()+2*g*c.n*WIDTH);
        }
        // Terminal bytes are written only after every group/limb/coordinate
        // passes. The Python caller authorizes only a complete-frame match.
        query.terminal(final.data(),final.size(),output,size,false);
        return 1;
    } catch(...) {return -1;}
}
}
