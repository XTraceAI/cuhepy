# Private owner experiment, separate from the public C++/CUDA server extensions.
PYTHON ?= python3
CXX ?= c++
CXXFLAGS ?= -O3
CPU := ../../../src/cuhepy/bfv/_cpu_ext
PY_INC := $(shell $(PYTHON) -c 'import sysconfig; print(sysconfig.get_paths()["include"])')
EXT := $(shell $(PYTHON) -c 'import sysconfig; print(sysconfig.get_config_var("EXT_SUFFIX"))')
TARGET := _bgv_owner$(EXT)
.PHONY: all clean
all: $(TARGET)
$(TARGET): bindings.cpp owner.h $(wildcard $(CPU)/*.h) Makefile
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -std=c++17 -Wall -Wextra -fPIC -shared -pthread \
		-I$(PY_INC) -I$(CPU) bindings.cpp $(LDFLAGS) -lgmpxx -lgmp -o $@
clean:
	rm -f $(TARGET)
