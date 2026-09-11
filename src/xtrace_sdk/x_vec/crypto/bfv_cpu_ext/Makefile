# Optional CPU BFV extension; no SEAL, CUDA, pybind11 or Python build dependency.
# From the repository root:
#   make -C src/xtrace_sdk/x_vec/crypto/bfv_cpu_ext PYTHON="$(pwd)/.venv/bin/python"
# Requires a C++17 compiler, Python development headers, and GMP development files.
PYTHON ?= python3
CXX ?= c++
PY_INC := $(shell $(PYTHON) -c 'import sysconfig; print(sysconfig.get_paths()["include"])')
EXT := $(shell $(PYTHON) -c 'import sysconfig; print(sysconfig.get_config_var("EXT_SUFFIX"))')
TARGET := _bfv_rns$(EXT)
CXXFLAGS ?= -O3
CPPFLAGS ?=
LDFLAGS ?=
LDLIBS ?= -lgmpxx -lgmp

.PHONY: all clean
all: $(TARGET)

$(TARGET): bindings.cpp rns_ntt.h profile.h bfv_server.h bfv_residue.h packed_wire.h Makefile
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -std=c++17 -Wall -Wextra -fPIC -shared \
		-I$(PY_INC) bindings.cpp $(LDFLAGS) $(LDLIBS) -o $@

clean:
	rm -f $(TARGET)
