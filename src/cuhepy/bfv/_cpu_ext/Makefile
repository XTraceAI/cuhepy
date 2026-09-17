# Optional CPU BFV extension; no SEAL, CUDA, pybind11 or Python build dependency.
# From the repository root:
#   make -C src/cuhepy/bfv/_cpu_ext PYTHON="$(pwd)/.venv/bin/python"
# Requires a C++17 compiler, Python development headers, and GMP development files.
PYTHON ?= python3
CXX ?= c++
PY_INC := $(shell $(PYTHON) -c 'import sysconfig; print(sysconfig.get_paths()["include"])')
EXT := $(shell $(PYTHON) -c 'import sysconfig; print(sysconfig.get_config_var("EXT_SUFFIX"))')
TARGET := _bfv_rns$(EXT)
PRIVATE_TARGET := _bfv_private$(EXT)
CXXFLAGS ?= -O3
CPPFLAGS ?=
LDFLAGS ?=
LDLIBS ?= -lgmpxx -lgmp

.PHONY: all clean
all: $(TARGET) $(PRIVATE_TARGET)

$(TARGET): bindings.cpp rns_ntt.h profile.h bfv_server.h bfv_residue.h rns_scale.h packed_wire.h Makefile
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -std=c++17 -Wall -Wextra -fPIC -shared \
		-I$(PY_INC) bindings.cpp $(LDFLAGS) $(LDLIBS) -o $@

$(PRIVATE_TARGET): private_bindings.cpp private_decoder.h rns_ntt.h profile.h Makefile
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -std=c++17 -Wall -Wextra -fPIC -shared \
		-fstack-protector-strong -D_FORTIFY_SOURCE=3 -I$(PY_INC) private_bindings.cpp \
		$(LDFLAGS) -Wl,-z,relro,-z,now,-z,noexecstack $(LDLIBS) -o $@

clean:
	rm -f $(TARGET) $(PRIVATE_TARGET)
