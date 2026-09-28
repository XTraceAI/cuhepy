# Optional, isolated E29 public arithmetic. No production backend is changed.
PYTHON ?= python3
CXX ?= c++
CXXFLAGS ?= -O3
PY_INC := $(shell $(PYTHON) -c 'import sysconfig; print(sysconfig.get_paths()["include"])')
EXT := $(shell $(PYTHON) -c 'import sysconfig; print(sysconfig.get_config_var("EXT_SUFFIX"))')
TARGET := _crt_subring$(EXT)
.PHONY: all
all: $(TARGET)
$(TARGET): bindings.cpp Makefile
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -std=c++17 -Wall -Wextra -fPIC -shared -I$(PY_INC) bindings.cpp $(LDFLAGS) -o $@
