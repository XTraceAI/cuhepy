PYTHON ?= python3
CXX ?= g++-12
CXXFLAGS ?= -O3
CPU := ../../../src/cuhepy/bfv/_cpu_ext
PY_INC := $(shell $(PYTHON) -c 'import sysconfig; print(sysconfig.get_paths()["include"])')
EXT := $(shell $(PYTHON) -c 'import sysconfig; print(sysconfig.get_config_var("EXT_SUFFIX"))')
TARGET := _bgv_checked$(EXT)
.PHONY: all clean
all: $(TARGET)
$(TARGET): bindings.cpp check.h $(wildcard $(CPU)/*.h) Makefile
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -std=c++17 -Wall -Wextra -fPIC -shared \
		-I$(PY_INC) -I$(CPU) bindings.cpp $(LDFLAGS) -lgmpxx -lgmp -o $@
clean:
	rm -f $(TARGET)
