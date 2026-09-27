# Isolated research extension. No change to the package's default backends.
PYTHON ?= python3
CXX ?= c++
CXXFLAGS ?= -O3
NVCC ?= nvcc
CUDA_CXX ?= g++-12
CUDA_ARCH ?= 86
NVCCFLAGS ?= -O3
ROOT := ../../..
CPU := $(ROOT)/src/cuhepy/bfv/_cpu_ext
PY_INC := $(shell $(PYTHON) -c 'import sysconfig; print(sysconfig.get_paths()["include"])')
EXT := $(shell $(PYTHON) -c 'import sysconfig; print(sysconfig.get_config_var("EXT_SUFFIX"))')
TARGET := _bgv_trace$(EXT)
CUDA_TARGET := _bgv_trace_cuda$(EXT)
BOUNDARY_TARGET ?= /tmp/cuhepy-bgv-digit-boundary
.PHONY: all cuda clean
all: $(TARGET)
cuda: $(CUDA_TARGET)
.PHONY: digit-boundary
digit-boundary: digit_boundary.cu digit_boundary.h test_digit_boundary.cpp
	$(NVCC) $(NVCCFLAGS) -std=c++17 -ccbin $(CUDA_CXX) -Xcompiler=-fopenmp \
		-gencode arch=compute_$(CUDA_ARCH),code=sm_$(CUDA_ARCH) \
		-I$(CPU) digit_boundary.cu -lgmpxx -lgmp -o $(BOUNDARY_TARGET)
$(TARGET): bindings.cpp trace_server.h residue_trace.h compact.h query_codec.h word_codec.h $(wildcard $(CPU)/*.h) Makefile
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -std=c++17 -Wall -Wextra -fPIC -shared \
		-I$(PY_INC) -I$(CPU) bindings.cpp $(LDFLAGS) -lgmpxx -lgmp -o $@
$(CUDA_TARGET): bindings.cu bindings.cpp trace_server.h residue_trace.h compact.h query_codec.h word_codec.h cuda_trace.cuh cuda_batch.cuh ntt_variants.cuh terminal_cuda.cuh $(wildcard $(CPU)/*.h) $(wildcard $(CPU)/../_gpu_ext/*.cuh) Makefile
	$(NVCC) $(NVCCFLAGS) -std=c++17 -ccbin $(CUDA_CXX) -Xcompiler -fPIC -shared \
		-gencode arch=compute_$(CUDA_ARCH),code=sm_$(CUDA_ARCH) \
		-gencode arch=compute_$(CUDA_ARCH),code=compute_$(CUDA_ARCH) \
		-I$(PY_INC) -I$(CPU) bindings.cu -lgmpxx -lgmp -o $@
clean:
	rm -f $(TARGET) $(CUDA_TARGET)
