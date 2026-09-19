# Build the CPU extension first with the same host C++ toolchain. CUDA 12.0
# supports GCC 12; override CUDA_CXX for a compiler supported by your toolkit.
PYTHON ?= python3
NVCC ?= nvcc
CUDA_CXX ?= g++-12
CUDA_ARCH ?= 86
NVCCFLAGS ?= -O3
PY_INC := $(shell $(PYTHON) -c 'import sysconfig; print(sysconfig.get_paths()["include"])')
EXT := $(shell $(PYTHON) -c 'import sysconfig; print(sysconfig.get_config_var("EXT_SUFFIX"))')
TARGET := _bfv_cuda$(EXT)

.PHONY: all clean
all: $(TARGET)

$(TARGET): bindings.cu kernels.cuh server.cuh ../_cpu_ext/bindings.cpp $(wildcard ../_cpu_ext/*.h) Makefile
	$(NVCC) $(NVCCFLAGS) -std=c++17 -ccbin $(CUDA_CXX) -Xcompiler -fPIC -shared \
		-gencode arch=compute_$(CUDA_ARCH),code=sm_$(CUDA_ARCH) \
		-gencode arch=compute_$(CUDA_ARCH),code=compute_$(CUDA_ARCH) \
		-I$(PY_INC) bindings.cu -lgmpxx -lgmp -o $@

clean:
	rm -f $(TARGET)
