# Isolated research integrity-key arithmetic; no HE private key enters here.
PYTHON ?= python3
CXX ?= c++
CXXFLAGS ?= -O3
PY_INC := $(shell $(PYTHON) -c 'import sysconfig; print(sysconfig.get_paths()["include"])')
EXT := $(shell $(PYTHON) -c 'import sysconfig; print(sysconfig.get_config_var("EXT_SUFFIX"))')
TARGET := _fingerprint$(EXT)
.PHONY: all
all: $(TARGET)
$(TARGET): bindings.cpp Makefile
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -std=c++17 -Wall -Wextra -fPIC -shared -I$(PY_INC) bindings.cpp $(LDFLAGS) -o $@
