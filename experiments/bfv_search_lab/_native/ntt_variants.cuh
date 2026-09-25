// Homemade public NTT experiments. Same roots, modulus and butterfly order as
// the package baseline; only indexing, shared tiles and warp communication vary.
#pragma once
#include "../_gpu_ext/server.cuh"

namespace cuhepy_bgv_lab::ntt_experiment {
using namespace xtrace_bfv::gpu;

template<bool Inverse>
__device__ U warp_tail(U value, int i, int log_size, int rows, int chunk,
                       U p, const Mul* roots) {
    // Called only for complete 32-lane groups. N and tile sizes are powers of
    // two >=32. All named lanes execute each shuffle with the same XOR distance.
    for (int gap_log = Inverse ? 0 : 4; Inverse ? gap_log < 5 : gap_log >= 0;
         gap_log += Inverse ? 1 : -1) {
        int gap = 1<<gap_log, stage = log_size-1-gap_log;
        Mul root = roots[((rows+chunk)<<stage)+(i>>(gap_log+1))];
        bool upper = (i&gap) != 0;
        if constexpr (Inverse) {
            U peer = __shfl_xor_sync(0xffffffffU,value,gap);
            value = upper ? mul(sub(peer,value,p),root,p) : add(value,peer,p);
        } else {
            if (upper) value = mul(value,root,p);
            U peer = __shfl_xor_sync(0xffffffffU,value,gap);
            value = upper ? sub(peer,value,p) : add(value,peer,p);
        }
    }
    return value;
}

template<int LogTile, bool Warp, bool Inverse, bool Outer>
__global__ void transform(U* data, const Mul* roots, const Mul* inverse_n,
                          const Parameters* plan) {
    constexpr int tile = 1<<LogTile;
    __shared__ U values[tile];
    int n = plan->n, log_n = __ffs(n)-1, row_log = min(log_n,LogTile);
    int rows = n>>row_log, column_log = LogTile-(log_n-row_log);
    int poly = blockIdx.y, chunk = blockIdx.x, prime = poly&1;
    int log_size = Outer ? LogTile : row_log, size = 1<<log_size;
    int stages = Outer ? log_n-row_log : row_log;
    bool warp = Warp && !Outer && size>=32;
    U p = plan->primes[prime].p;
    const Mul* local_roots = roots+prime*n;
    for (int i = threadIdx.x; i < size; i += blockDim.x) {
        int at = Outer ? ((i>>column_log)<<row_log)+(chunk<<column_log)+(i&((1<<column_log)-1))
                       : (chunk<<row_log)+i;
        U value = data[poly*n+at];
        if constexpr (Inverse) if (warp) value = warp_tail<true>(value,i,log_size,rows,chunk,p,local_roots);
        values[i] = value;
    }
    __syncthreads();
    int first = Inverse ? stages-1-(warp ? 5 : 0) : 0;
    int last = Inverse ? 0 : stages-1-(warp ? 5 : 0);
    for (int stage = first; Inverse ? stage>=last : stage<=last; stage += Inverse ? -1 : 1) {
        int gap_log = log_size-1-stage, gap = 1<<gap_log;
        for (int at = threadIdx.x; at < size/2; at += blockDim.x) {
            int group = at>>gap_log, position = (group<<(gap_log+1))+(at&(gap-1));
            int root_index = (Outer ? 1<<stage : (rows+chunk)<<stage)+group;
            U a = values[position], b = values[position+gap];
            Mul root = local_roots[root_index];
            if constexpr (Inverse) {
                values[position] = add(a,b,p);
                values[position+gap] = mul(sub(a,b,p),root,p);
            } else {
                b = mul(b,root,p);
                values[position] = add(a,b,p); values[position+gap] = sub(a,b,p);
            }
        }
        __syncthreads();
    }
    for (int i = threadIdx.x; i < size; i += blockDim.x) {
        int at = Outer ? ((i>>column_log)<<row_log)+(chunk<<column_log)+(i&((1<<column_log)-1))
                       : (chunk<<row_log)+i;
        U value = values[i];
        if constexpr (!Inverse) if (warp) value = warp_tail<false>(value,i,log_size,rows,chunk,p,local_roots);
        if constexpr (Inverse) if (Outer || n<=tile) value = mul(value,inverse_n[prime],p);
        data[poly*n+at] = value;
    }
}

template<int LogTile, bool Warp, bool Inverse>
void launch(U* data, const Mul* roots, const Mul* inverse_n, const Parameters* plan,
            std::size_t n, std::size_t polys, cudaStream_t stream) {
    dim3 grid(std::max<std::size_t>(1,n>>LogTile),polys*2);
    if constexpr (Inverse) {
        transform<LogTile,Warp,true,false><<<grid,256,0,stream>>>(data,roots,inverse_n,plan);
        if (n>(1U<<LogTile)) transform<LogTile,Warp,true,true><<<grid,256,0,stream>>>(data,roots,inverse_n,plan);
    } else {
        if (n>(1U<<LogTile)) transform<LogTile,Warp,false,true><<<grid,256,0,stream>>>(data,roots,inverse_n,plan);
        transform<LogTile,Warp,false,false><<<grid,256,0,stream>>>(data,roots,inverse_n,plan);
    }
}

template<bool Inverse>
void run(unsigned variant, U* data, const Mul* roots, const Mul* inverse_n, const Parameters* plan,
         std::size_t n, std::size_t polys, cudaStream_t stream) {
    switch (variant) {
    case 0: {
        dim3 grid(std::max<std::size_t>(1,n/1024),polys*2);
        if constexpr (Inverse) {
            ntt_fused<2,true,false><<<grid,256,0,stream>>>(data,roots,inverse_n,plan);
            if (n>1024) ntt_fused<2,true,true><<<grid,256,0,stream>>>(data,roots,inverse_n,plan);
        } else {
            if (n>1024) ntt_fused<2,false,true><<<grid,256,0,stream>>>(data,roots,inverse_n,plan);
            ntt_fused<2,false,false><<<grid,256,0,stream>>>(data,roots,inverse_n,plan);
        }
        break;
    }
    case 1: launch<10,false,Inverse>(data,roots,inverse_n,plan,n,polys,stream); break;
    case 2: launch<10,true,Inverse>(data,roots,inverse_n,plan,n,polys,stream); break;
    case 3: launch<9,true,Inverse>(data,roots,inverse_n,plan,n,polys,stream); break;
    case 4: launch<11,true,Inverse>(data,roots,inverse_n,plan,n,polys,stream); break;
    default: throw std::invalid_argument("Unknown experimental NTT variant");
    }
    check(cudaGetLastError());
}
} // namespace cuhepy_bgv_lab::ntt_experiment
