# Isolated research extension. No change to the package's default backends.
PYTHON ?= python3
CXX ?= c++
CXXFLAGS ?= -O3
ROOT := ../../..
CPU := $(ROOT)/src/cuhepy/bfv/_cpu_ext
PY_INC := $(shell $(PYTHON) -c 'import sysconfig; print(sysconfig.get_paths()["include"])')
EXT := $(shell $(PYTHON) -c 'import sysconfig; print(sysconfig.get_config_var("EXT_SUFFIX"))')
TARGET := _bgv_trace$(EXT)
.PHONY: all clean
all: $(TARGET)
$(TARGET): bindings.cpp trace_server.h $(CPU)/rns_ntt.h $(CPU)/profile.h Makefile
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -std=c++17 -Wall -Wextra -fPIC -shared \
		-I$(PY_INC) -I$(CPU) bindings.cpp $(LDFLAGS) -lgmpxx -lgmp -o $@
clean:
	rm -f $(TARGET)
