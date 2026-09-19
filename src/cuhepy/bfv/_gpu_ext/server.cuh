// Batched CUDA implementation of the existing public Hamming circuit. Host GMP
// is limited to plan preparation, wire import/export and terminal compaction.
#pragma once
#include "kernels.cuh"
#include "../_cpu_ext/bfv_residue.h"
#include "../_cpu_ext/packed_wire.h"
#include <utility>

namespace xtrace_bfv::gpu {
using PackedCipher = std::array<std::string_view,2>;
inline void check(cudaError_t error) {
    if (error != cudaSuccess) throw std::runtime_error(std::string("BFV CUDA: ")+cudaGetErrorString(error));
}
struct DeviceScope {
    int previous;
    explicit DeviceScope(int device) { check(cudaGetDevice(&previous)); check(cudaSetDevice(device)); }
    ~DeviceScope() { cudaSetDevice(previous); }
};
struct Stream {
    cudaStream_t value;
    Stream() { check(cudaStreamCreateWithFlags(&value, cudaStreamNonBlocking)); }
    ~Stream() { cudaStreamSynchronize(value); cudaStreamDestroy(value); }
};
template<class T> class Buffer {
    T* pointer_ = nullptr;
    std::size_t size_ = 0;
    int device_ = 0;
public:
    Buffer() = default;
    explicit Buffer(std::size_t size) : size_(size) {
        check(cudaGetDevice(&device_));
        if (size) check(cudaMalloc(reinterpret_cast<void**>(&pointer_), size*sizeof(T)));
    }
    explicit Buffer(const std::vector<T>& values) : Buffer(values.size()) {
        // If copying fails, delegating-constructor destruction frees the buffer.
        check(cudaMemcpy(pointer_, values.data(), size_*sizeof(T), cudaMemcpyHostToDevice));
    }
    Buffer(const Buffer&) = delete;
    Buffer& operator=(const Buffer&) = delete;
    Buffer(Buffer&& other) noexcept { swap(other); }
    Buffer& operator=(Buffer&& other) noexcept { swap(other); return *this; }
    void swap(Buffer& other) noexcept {
        std::swap(pointer_, other.pointer_); std::swap(size_, other.size_); std::swap(device_, other.device_);
    }
    ~Buffer() {
        if (pointer_) { int previous = 0; cudaGetDevice(&previous); cudaSetDevice(device_); cudaFree(pointer_); cudaSetDevice(previous); }
    }
    T* data() const { return pointer_; }
    std::size_t bytes() const { return size_*sizeof(T); }
};
inline Mul multiplier(Word value, Word p) {
    return {value, Word((Wide(value)<<64)/p)};
}
inline void export_words(const mpz_class& value, U* out) {
    if (value < 0 || mpz_sizeinbase(value.get_mpz_t(), 2) > 256)
        throw std::invalid_argument("CUDA CRT value exceeds four limbs");
    std::fill(out, out+4, 0);
    mpz_export(out, nullptr, -1, sizeof(U), 0, 0, value.get_mpz_t());
}
inline int blocks(std::size_t count) { return static_cast<int>((count+255)/256); }

// Opt-in diagnostic wall timings. Synchronize each measured phase so queued GPU
// work is not charged to the next CPU phase. Exclude these runs from benchmarks.
template<class Function>
void measured(Phase phase, cudaStream_t stream, Function function) {
    if (active_profile) check(cudaStreamSynchronize(stream));
    ProfileScope timing(phase);
    function();
    if (active_profile) check(cudaStreamSynchronize(stream));
}

class CudaServer final : public HammingServer {
    int device_;
    Parameters host_{};
    Buffer<Parameters> parameters_;
    Buffer<Mul> roots_, inverse_roots_, inverse_n_, mask_;
    std::map<Word, Buffer<Mul>> keys_ntt_;
    // Public experiment controls; immutable after plan construction.
    const unsigned kernel_level_;
    const std::size_t batch_limit_;

    class Uploader {
        const CudaServer& server_;
        const std::size_t batch_, stride_;
        Buffer<U> packed_;
        Buffer<unsigned> invalid_{1};
    public:
        Uploader(const CudaServer& server, std::size_t batch)
            : server_(server), batch_(batch), stride_((server.ring->n*180+63)/64+1), packed_(batch*2*stride_) {}
        void copy(const PackedCipher* input, std::size_t batch, U* out, cudaStream_t stream) {
            if (batch > batch_) throw std::invalid_argument("CUDA upload exceeds batch capacity");
            std::vector<U> packed(batch*2*stride_,0);
            { ProfileScope timing(Phase::wire_import);
              for (std::size_t b = 0; b < batch; ++b)
                  for (int c = 0; c < 2; ++c) {
                      if (input[b][c].size() != server_.ring->n*180/8)
                          throw std::invalid_argument("Incorrect CUDA packed polynomial byte length");
                      std::memcpy(packed.data()+(2*b+c)*stride_,input[b][c].data(),input[b][c].size());
                  }
            }
            unsigned invalid = 0;
            measured(Phase::to_residues,stream,[&] {
                check(cudaMemcpyAsync(packed_.data(),packed.data(),packed.size()*sizeof(U),cudaMemcpyHostToDevice,stream));
                check(cudaMemsetAsync(invalid_.data(),0,sizeof(unsigned),stream));
                unpack_residues<<<blocks(batch*2*server_.ring->n),256,0,stream>>>(packed_.data(),out,invalid_.data(),server_.parameters_.data(),batch,stride_);
                check(cudaGetLastError());
                check(cudaMemcpyAsync(&invalid,invalid_.data(),sizeof(unsigned),cudaMemcpyDeviceToHost,stream));
                check(cudaStreamSynchronize(stream)); // Host bytes/flag are alive until completion.
            });
            if (invalid) throw std::invalid_argument("Noncanonical packed polynomial coefficient");
        }
    };

    template<int Primes, bool Inverse>
    void fused_transform(U* data, int polys, cudaStream_t stream) const {
        dim3 grid(std::max<std::size_t>(1,ring->n/1024),polys*Primes);
        const auto* roots = Inverse ? inverse_roots_.data() : roots_.data();
        if constexpr (Inverse) {
            ntt_fused<Primes,true,false><<<grid,256,0,stream>>>(data,roots,inverse_n_.data(),parameters_.data());
            if (ring->n > 1024)
                ntt_fused<Primes,true,true><<<grid,256,0,stream>>>(data,roots,inverse_n_.data(),parameters_.data());
        } else {
            if (ring->n > 1024)
                ntt_fused<Primes,false,true><<<grid,256,0,stream>>>(data,roots,inverse_n_.data(),parameters_.data());
            ntt_fused<Primes,false,false><<<grid,256,0,stream>>>(data,roots,inverse_n_.data(),parameters_.data());
        }
    }

    Buffer<Mul> prepare_mask(std::size_t count) const {
        auto encoded = ring->encode(mask(count), 3);
        std::vector<Mul> values;
        for (int j = 0; j < 3; ++j)
            for (Word v : encoded[j]) values.push_back(multiplier(v, host_.primes[j].p));
        return Buffer<Mul>(values);
    }
    void transform(U* data, int primes, int polys, bool inverse, cudaStream_t stream) const {
        measured(inverse ? Phase::inverse_ntt : Phase::forward_ntt, stream, [&] {
        if (kernel_level_) {
            if (primes == 3) {
                if (inverse) fused_transform<3,true>(data,polys,stream);
                else fused_transform<3,false>(data,polys,stream);
            } else {
                if (inverse) fused_transform<7,true>(data,polys,stream);
                else fused_transform<7,false>(data,polys,stream);
            }
            check(cudaGetLastError());
            return;
        }
        auto count = std::size_t(polys)*primes*ring->n/2;
        if (inverse) {
            for (int groups = ring->n/2; groups; groups /= 2)
                ntt_stage<<<blocks(count),256,0,stream>>>(data, inverse_roots_.data(), parameters_.data(), primes, polys, groups, true);
            normalize<<<blocks(count*2),256,0,stream>>>(data, inverse_n_.data(), parameters_.data(), primes, count*2);
        } else {
            for (std::size_t groups = 1; groups < ring->n; groups *= 2)
                ntt_stage<<<blocks(count),256,0,stream>>>(data, roots_.data(), parameters_.data(), primes, polys, groups, false);
        }
        check(cudaGetLastError());
        });
    }
    void switch_key(const U* src, int components, int component, U* digits, U* out,
                    std::size_t batch, Word key, cudaStream_t stream) const {
        measured(Phase::gadget_decompose, stream, [&] {
            decompose<<<blocks(batch*ring->n),256,0,stream>>>(src, digits, parameters_.data(), batch, components, component);
        });
        transform(digits, 3, batch*6, false, stream);
        measured(Phase::pointwise, stream, [&] {
            if (kernel_level_ >= 3 && ring->n >= 32) {
                dim3 grid(ring->n/32,(batch+7)/8,3);
                key_product_tiled<<<grid,256,0,stream>>>(digits,keys_ntt_.at(key).data(),out,parameters_.data(),batch);
            } else {
                key_product<<<blocks(batch*6*ring->n),256,0,stream>>>(digits, keys_ntt_.at(key).data(), out, parameters_.data(), batch);
            }
        });
        transform(out, 3, batch*2, true, stream);
    }
    std::vector<U> residues(const Ciphertext& ct) const {
        ProfileScope timing(Phase::to_residues);
        std::vector<U> result(6*ring->n);
        for (int c = 0; c < 2; ++c)
            for (int j = 0; j < 3; ++j)
                for (std::size_t i = 0; i < ring->n; ++i)
                    result[(c*3+j)*ring->n+i] = mpz_fdiv_ui(ct[c][i].get_mpz_t(), host_.primes[j].p);
        return result;
    }
public:
    CudaServer(KeyHandle relin, std::map<Word, KeyHandle> keys, std::size_t padded, Word t,
               const mpz_class& target, unsigned kernel_level = 3, std::size_t batch_limit = 32)
        : HammingServer(relin, std::move(keys), padded, t, target, false),
          kernel_level_(kernel_level), batch_limit_(batch_limit) {
        if (kernel_level > 3 || batch_limit < 1 || batch_limit > 256)
            throw std::invalid_argument("Invalid CUDA kernel level or tile batch limit");
        // Deliberately bounded first backend. Never silently change cryptographic
        // parameters or fall back to CPU when CUDA was explicitly requested.
        if (ring->residue_prime_count != 3 || ring->digit_bits != 30 || ring->digits != 6 ||
            ring->kernel_level != 2 || t >= (Word(1)<<30) || padded > 512)
            throw std::invalid_argument("CUDA requires three RNS primes, 30-bit gadget digits, kernel_level=2, t<2^30 and padded dimension<=512");
        if (ring->prime_count(2*ring->n*(ring->q-1)*(ring->q-1)) != 7)
            throw std::invalid_argument("CUDA tensor requires exactly seven auxiliary primes");
        check(cudaGetDevice(&device_));
        host_.n = ring->n; host_.t = t;
        for (Word v = t; v; v >>= 1) ++host_.t_bits;
        std::vector<Mul> roots, inverse_roots, inverse_n;
        mpz_class b_product = 1;
        for (int j = 0; j < 7; ++j) {
            Word p = ring->transforms[j].modulus;
            mpz_class reciprocal = (mpz_class(1)<<128)/p;
            host_.primes[j] = {p, mpz_getlimbn(reciprocal.get_mpz_t(),0), mpz_getlimbn(reciprocal.get_mpz_t(),1)};
            if (j >= 3) b_product *= p;
            Word psi = 0;
            for (Word candidate = 2; !psi; ++candidate) {
                Word w = power_mod(candidate, (p-1)/(2*ring->n), p);
                if (power_mod(w, ring->n, p) == p-1) psi = w;
            }
            Word inv_psi = power_mod(psi, p-2, p);
            for (std::size_t i = 0; i < ring->n; ++i) {
                std::size_t reversed = 0, v = i;
                for (std::size_t size = ring->n; size > 1; size /= 2) { reversed = 2*reversed+(v&1); v >>= 1; }
                roots.push_back(multiplier(power_mod(psi, reversed, p), p));
                inverse_roots.push_back(multiplier(power_mod(inv_psi, reversed, p), p));
            }
            inverse_n.push_back(multiplier(power_mod(ring->n, p-2, p), p));
            for (int k = 0; k < 7; ++k) {
                Word other = ring->transforms[k].modulus % p;
                host_.prime_mod[j][k] = multiplier(other, p);
                if (j != k) host_.inverse[j][k] = multiplier(power_mod(other,p-2,p),p);
            }
            if (j >= 3) host_.inverse_q[j-3] = multiplier(power_mod(mpz_fdiv_ui(ring->q.get_mpz_t(),p),p-2,p),p);
        }
        // The centered B lift of the tensor quotient must be unique.
        if (b_product <= 2*(2*ring->n*(ring->q-1)*(ring->q-1)/ring->q+1))
            throw std::invalid_argument("Insufficient CUDA auxiliary base");
        export_words((b_product+1)/2, host_.half_b);
        export_words(ring->q/2, host_.half_q);
        export_words(ring->q, host_.q_words);
        for (int j = 0; j < 3; ++j) {
            Word p = host_.primes[j].p;
            host_.radix64[j] = multiplier(Word((Wide(1)<<64)%p),p);
        }
        for (int bit = 0; bit < host_.t_bits; ++bit) export_words(ring->q<<bit, host_.shifted_q[bit]);
        for (int j = 0; j < 3; ++j) host_.b_mod_q[j] = mpz_fdiv_ui(b_product.get_mpz_t(),host_.primes[j].p);
        parameters_ = Buffer<Parameters>(std::vector<Parameters>{host_});
        roots_ = Buffer<Mul>(roots); inverse_roots_ = Buffer<Mul>(inverse_roots); inverse_n_ = Buffer<Mul>(inverse_n);
        auto prepare = [&](Word exponent, const SwitchKey& key) {
            std::vector<Mul> transformed;
            for (const auto& pair : key.transformed())
                for (const auto& component : pair)
                    for (int j = 0; j < 3; ++j)
                        for (Word v : component[j]) transformed.push_back(multiplier(v,host_.primes[j].p));
            keys_ntt_.emplace(exponent, Buffer<Mul>(transformed));
        };
        prepare(0,*relin_);
        for (const auto& entry : keys_) prepare(entry.first,*entry.second);
        mask_ = prepare_mask(capacity);
    }

    void search(const Ciphertext& query, std::size_t count, ReadTile read_tile, Emit emit, bool compact_result) const override {
        if (!count) return;
        DeviceScope device(device_);
        Buffer<U> query_rns(residues(query));
        evaluate(query_rns.data(),count,[&](std::size_t at, std::size_t batch, U* scratch, cudaStream_t stream) {
            std::vector<U> imported;
            imported.reserve(batch*6*ring->n);
            for (std::size_t i = 0; i < batch; ++i) {
                auto r = residues(read_tile(at+i)); imported.insert(imported.end(),r.begin(),r.end());
            }
            check(cudaMemcpyAsync(scratch,imported.data(),imported.size()*sizeof(U),cudaMemcpyHostToDevice,stream));
            check(cudaStreamSynchronize(stream));
            return scratch;
        },emit,compact_result);
    }

    void search_packed(const PackedCipher& query, const std::vector<PackedCipher>& index,
                       std::size_t count, Emit emit, bool compact_result) const {
        if (kernel_level_ < 2) {
            Ciphertext q{import_packed(query[0],*ring),import_packed(query[1],*ring)};
            search(q,count,[&](std::size_t at) -> Ciphertext {
                return {import_packed(index.at(at)[0],*ring),import_packed(index.at(at)[1],*ring)};
            },emit,compact_result);
            return;
        }
        DeviceScope device(device_);
        Buffer<U> query_rns(6*ring->n);
        Uploader uploader(*this,std::max<std::size_t>(1,std::min(batch_limit_,index.size())));
        Stream upload_stream;
        uploader.copy(&query,1,query_rns.data(),upload_stream.value);
        evaluate(query_rns.data(),count,[&](std::size_t at, std::size_t batch, U* scratch, cudaStream_t stream) {
            uploader.copy(index.data()+at,batch,scratch,stream);
            return scratch;
        },emit,compact_result);
    }

    Buffer<U> prepare_index(const std::vector<PackedCipher>& index) const {
        if (index.size() > SIZE_MAX/(6*ring->n)) throw std::invalid_argument("CUDA index exceeds addressable size");
        DeviceScope device(device_);
        Buffer<U> result(index.size()*6*ring->n);
        if (index.empty()) return result;
        Uploader uploader(*this,std::min(batch_limit_,index.size()));
        Stream stream;
        for (std::size_t at = 0; at < index.size(); at += batch_limit_) {
            auto batch = std::min(batch_limit_,index.size()-at);
            uploader.copy(index.data()+at,batch,result.data()+at*6*ring->n,stream.value);
        }
        return result;
    }

    void search_prepared(const PackedCipher& query, const U* index, std::size_t count,
                          Emit emit, bool compact_result) const {
        DeviceScope device(device_);
        Buffer<U> query_rns(6*ring->n);
        Uploader uploader(*this,1);
        Stream upload_stream;
        uploader.copy(&query,1,query_rns.data(),upload_stream.value);
        evaluate(query_rns.data(),count,[&](std::size_t at, std::size_t, U*, cudaStream_t) -> const U* {
            return index+at*6*ring->n;
        },emit,compact_result);
    }

private:
    using LoadBatch = std::function<const U*(std::size_t,std::size_t,U*,cudaStream_t)>;
    void evaluate(const U* query_rns, std::size_t count, LoadBatch load, Emit emit, bool compact_result) const {
        if (!count) return;
        std::size_t tiles = (count+capacity-1)/capacity, n = ring->n;
        std::size_t batch_max = std::min(batch_limit_, tiles), group_max = std::min(padded,tiles);
        // Allocation is per call: immutable plans are safe to share between
        // Python threads, and concurrent searches have independent streams.
        Buffer<U> input(batch_max*6*n), lifted(batch_max*14*n), tensor(batch_max*21*n);
        Buffer<U> scaled(batch_max*9*n), digits(batch_max*18*n), value(batch_max*6*n), permuted(batch_max*6*n), switched(batch_max*6*n);
        Buffer<U> group(group_max*6*n);
        Buffer<Mul> partial;
        if (count%capacity) partial = prepare_mask(count%capacity);
        // Construct the stream last so outstanding work is joined before any
        // scratch buffer is freed, including exception paths.
        Stream stream;
        auto rotate_add = [&](const U* source, U* destination, std::size_t batch, Word g,
                              int from, int from_step, int to, int to_step) {
            measured(Phase::automorphism, stream.value, [&] {
                permute<<<blocks(batch*6*n),256,0,stream.value>>>(source,permuted.data(),parameters_.data(),batch,g,from,from_step);
            });
            switch_key(permuted.data(),2,1,digits.data(),switched.data(),batch,g,stream.value);
            measured(Phase::add_sub, stream.value, [&] {
                add_rotation<<<blocks(batch*6*n),256,0,stream.value>>>(destination,switched.data(),permuted.data(),parameters_.data(),batch,to,to_step);
            });
        };
        for (std::size_t start = 0; start < tiles; start += padded) {
            auto group_size = std::min(padded,tiles-start);
            for (std::size_t at = 0; at < group_size; at += batch_max) {
                auto batch = std::min(batch_max,group_size-at);
                const U* indexed = load(start+at,batch,input.data(),stream.value);
                measured(Phase::to_residues, stream.value, [&] {
                    difference<<<blocks(batch*2*n),256,0,stream.value>>>(query_rns,indexed,lifted.data(),parameters_.data(),batch);
                });
                transform(lifted.data(),7,batch*2,false,stream.value);
                measured(Phase::pointwise, stream.value, [&] {
                    square<<<blocks(batch*7*n),256,0,stream.value>>>(lifted.data(),tensor.data(),parameters_.data(),batch);
                });
                transform(tensor.data(),7,batch*3,true,stream.value);
                measured(Phase::rns_scale, stream.value, [&] {
                    scale_round<<<blocks(batch*3*n),256,0,stream.value>>>(tensor.data(),scaled.data(),parameters_.data(),batch);
                });
                switch_key(scaled.data(),3,2,digits.data(),value.data(),batch,0,stream.value);
                measured(Phase::add_sub, stream.value, [&] {
                    add_linear<<<blocks(batch*6*n),256,0,stream.value>>>(value.data(),scaled.data(),parameters_.data(),batch);
                });
                for (auto g : left_) rotate_add(value.data(),value.data(),batch,g,0,1,0,1);
                transform(value.data(),3,batch*2,false,stream.value);
                measured(Phase::pointwise, stream.value, [&] {
                    mask_product<<<blocks(batch*6*n),256,0,stream.value>>>(value.data(),mask_.data(),partial.data(),parameters_.data(),batch,
                                                                     count%capacity && start+at+batch==tiles);
                });
                transform(value.data(),3,batch*2,true,stream.value);
                check(cudaMemcpyAsync(group.data()+at*6*n,value.data(),batch*6*n*sizeof(U),cudaMemcpyDeviceToDevice,stream.value));
            }
            // Same complete-subtree merges and tail fold as merge_hamming_tiles.
            std::size_t level = 0;
            for (std::size_t size = 1; 2*size <= group_size; size *= 2, ++level) {
                auto pairs = group_size/(2*size);
                for (std::size_t at = 0; at < pairs; at += batch_max) {
                    auto batch = std::min(batch_max,pairs-at);
                    rotate_add(group.data(),group.data(),batch,right_[level],(2*at+1)*size,2*size,2*at*size,2*size);
                }
            }
            std::size_t tail = group_size, accumulated = 0;
            for (std::size_t bit = 0; (std::size_t(1)<<bit) <= group_size; ++bit) {
                auto size = std::size_t(1)<<bit;
                if (!(group_size & size)) continue;
                tail -= size;
                if (accumulated) rotate_add(group.data(),group.data(),1,right_[bit],tail+size,1,tail,1);
                accumulated += size;
            }
            std::vector<U> output(6*n);
            check(cudaGetLastError());
            check(cudaMemcpyAsync(output.data(),group.data(),output.size()*sizeof(U),cudaMemcpyDeviceToHost,stream.value));
            check(cudaStreamSynchronize(stream.value));
            ResidueArithmetic arithmetic(*ring);
            Ciphertext result;
            for (int c = 0; c < 2; ++c) {
                Residues r(3,std::vector<Word>(n));
                for (int j = 0; j < 3; ++j) std::copy_n(output.data()+(c*3+j)*n,n,r[j].begin());
                result[c] = arithmetic.compose(r);
            }
            if (compact_result) compact(result);
            emit(result);
        }
    }
public:
    std::size_t bytes() const override {
        std::size_t total = parameters_.bytes()+roots_.bytes()+inverse_roots_.bytes()+inverse_n_.bytes()+mask_.bytes();
        for (const auto& key : keys_ntt_) total += key.second.bytes();
        return total;
    }
};

// The snapshot owns its exact plan, including device and public keys. A fresh
// plan cannot accidentally reuse an index uploaded under different parameters.
struct PreparedIndex {
    const std::shared_ptr<const CudaServer> server;
    const std::size_t count;
    const Buffer<U> values;
    PreparedIndex(std::shared_ptr<const CudaServer> server, const std::vector<PackedCipher>& index, std::size_t count)
        : server(std::move(server)), count(count), values(this->server->prepare_index(index)) {}
};
} // namespace xtrace_bfv::gpu
