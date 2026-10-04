// Matched prepared replay. Build this translation unit alone: it retains the
// original ABI and shares all arithmetic with the full-witness producer.
// Nothing accepts a peer-chosen mode, executable, graph or plaintext secret.
#include "shared_query.cpp"

extern "C" {
unsigned cuhepy_shared_replay_abi() {return 1;}
int cuhepy_shared_replay(void* h,unsigned char* output,std::size_t length) {
    try {
        if(!h || !output)throw std::invalid_argument("Null replay buffer/handle");
        const auto& query=*static_cast<Query*>(h);const auto& c=*query.ctx;
        unsigned bits=0;for(auto x=c.p;x;x/=2)++bits;
        if(length!=2*c.groups*((c.n*bits+7)/8))throw std::invalid_argument("Wrong replay output coverage");
        // This is only the final two components per group (<=983040 bytes in
        // the registered profile), never the ~127 MB expansion/source witness.
        std::vector<unsigned char> final(2*c.groups*c.n*WIDTH);
        query.produce(final.data(),final.size(),false);
        query.terminal(final.data(),final.size(),output,length,false);
        return 0;
    } catch(...) {return -1;}
}
}
