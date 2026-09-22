// Share the audited wire validation and ownership boundary with the CPU module.
// Only packed-server entry points are exposed by this optional CUDA build.
#define XTRACE_BFV_CUDA 1
#include "../_cpu_ext/bindings.cpp"
