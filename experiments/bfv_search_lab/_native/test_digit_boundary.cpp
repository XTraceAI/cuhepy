// Host-only sanitizer entry point for the public CRT/digit prototype.
#include "digit_boundary.h"
#include <iostream>
int main() {
    try {
        xtrace_bfv::Ring ring(2048,(mpz_class(1)<<120)-119,30,true);
        using cuhepy_bgv_lab::digit_boundary::CRT;
        auto a=ring.transforms[0].modulus,b=ring.transforms[1].modulus;
        cuhepy_bgv_lab::digit_boundary::self_test(CRT(a,b));
        for(auto pair:std::vector<std::pair<xtrace_bfv::Word,xtrace_bfv::Word>>{{0,0},{a,a},{a,0},{a,4}}) {
            bool rejected=false;
            try { CRT invalid(pair.first,pair.second); } catch(const std::invalid_argument&) { rejected=true; }
            if(!rejected) throw std::runtime_error("Invalid CRT context accepted");
        }
        std::cout<<"Canonical CRT, all transfer layouts, thread counts and GMP oracle passed\n";
    } catch(const std::exception& error) {std::cerr<<error.what()<<'\n';return 1;}
}
