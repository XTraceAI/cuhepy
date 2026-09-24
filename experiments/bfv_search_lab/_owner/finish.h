// Plaintext-only local result handling. LUT/heap access is variable-time.
// Canonicality and correlation checks do not authenticate a server response.
#pragma once
#include "packed_wire.h"
#include <queue>

namespace cuhepy_bgv_owner {
using namespace xtrace_bfv;

inline void put32(std::string& data, std::size_t offset, Word value) {
    for (unsigned j = 0; j < 4; ++j) data[offset+j] = static_cast<unsigned char>(value>>(8*j));
}

class Finisher {
    using Ranked = std::pair<Word,Word>; // distance, original index
    const std::size_t n_, count_, dimension_, k_;
    const Word t_;
    std::size_t padded_ = 1, seen_ = 0, groups_ = 0;
    Word inverse_ = 1;
    std::vector<Word> table_;
    std::priority_queue<Ranked> best_;
    std::string distances_;
    const bool all_;
public:
    Finisher(std::size_t n, Word t, std::size_t count, std::size_t dimension,
             std::size_t k, bool all) : n_(n), count_(count), dimension_(dimension), k_(k), t_(t), all_(all) {
        if (n < 8 || n > 32768 || (n&(n-1)) || t < 3 || t >= (Word(1)<<30) || !(t&1) ||
            count > 64*n || !dimension || dimension > n/2 || 2*dimension >= t || k > 64)
            throw std::invalid_argument("Invalid native result layout");
        while (padded_ < dimension) {
            padded_ *= 2;
            inverse_ = inverse_*((t+1)/2)%t; // Invert a power of two for ANY odd t.
        }
        if (t <= 65536) {
            table_.assign(t,~Word(0));
            for (std::size_t distance = 0; distance <= dimension; ++distance) {
                auto dot = static_cast<long>(dimension)-2*static_cast<long>(distance);
                auto residue = (static_cast<long>(padded_)*dot)%static_cast<long>(t);
                if (residue < 0) residue += static_cast<long>(t);
                table_[residue] = distance;
            }
        }
        if (all) distances_.resize(count*4);
    }
    std::size_t groups() const { return (count_+n_-1)/n_; }
    void consume(const std::vector<Word>& plain) {
        if (groups_ >= groups() || plain.size() != n_ ||
            std::any_of(plain.begin(),plain.end(),[&](Word v) { return v >= t_; }))
            throw std::invalid_argument("Invalid native plaintext shape/coefficient");
        auto capacity = n_/padded_, used = std::min(n_,count_-seen_);
        for (std::size_t i = 0; i < used; ++i) {
            Word value = plain[(i%capacity)*padded_+i/capacity], distance;
            if (!table_.empty()) {
                distance = table_[value];
                if (distance == ~Word(0)) throw std::invalid_argument("Invalid trace correlation");
            } else {
                long dot = value*inverse_%t_;
                if (Word(dot) > t_/2) dot -= static_cast<long>(t_);
                auto delta = static_cast<long>(dimension_)-dot;
                if (dot < -static_cast<long>(dimension_) || dot > static_cast<long>(dimension_) || delta%2)
                    throw std::invalid_argument("Invalid trace correlation");
                distance = delta/2;
            }
            Ranked candidate{distance,seen_+i};
            if (k_ && (best_.size() < k_ || candidate < best_.top())) {
                if (best_.size() == k_) best_.pop();
                best_.push(candidate);
            }
            if (all_) put32(distances_,(seen_+i)*4,distance);
        }
        seen_ += used; ++groups_;
    }
    std::pair<std::string,std::string> result() {
        if (seen_ != count_ || groups_ != groups()) throw std::invalid_argument("Incomplete native response");
        std::string top(best_.size()*8,'\0');
        while (!best_.empty()) {
            auto at = (best_.size()-1)*8;
            auto candidate = best_.top();
            put32(top,at,candidate.second); put32(top,at+4,candidate.first); best_.pop();
        }
        return {std::move(distances_),std::move(top)};
    }
};
} // namespace cuhepy_bgv_owner
