# Separate output path; never rebuild a company or historical extension.
PYTHON ?= python3
CXX ?= c++
ROOT := ../../..
CPU := $(ROOT)/src/cuhepy/bfv/_cpu_ext
NATIVE := ../_native
PY_INC := $(shell $(PYTHON) -c 'import sysconfig; print(sysconfig.get_paths()["include"])')
EXT := $(shell $(PYTHON) -c 'import sysconfig; print(sysconfig.get_config_var("EXT_SUFFIX"))')
TARGET ?= /tmp/cuhepy-bgv-propagated/_bgv_propagated$(EXT)
.PHONY: all
all: $(TARGET)
$(TARGET): bindings.cpp propagated_server.h $(wildcard $(NATIVE)/*.h) $(wildcard $(CPU)/*.h) Makefile
	mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -O3 -std=c++17 -Wall -Wextra -fPIC -shared \
		-I$(PY_INC) -I$(CPU) -I$(NATIVE) bindings.cpp $(LDFLAGS) -lgmpxx -lgmp -o $@
