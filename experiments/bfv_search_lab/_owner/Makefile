# Private owner experiment, separate from the public C++/CUDA server extensions.
PYTHON ?= python3
CXX ?= c++
CXXFLAGS ?= -O3
CPU := ../../../src/cuhepy/bfv/_cpu_ext
PY_INC := $(shell $(PYTHON) -c 'import sysconfig; print(sysconfig.get_paths()["include"])')
EXT := $(shell $(PYTHON) -c 'import sysconfig; print(sysconfig.get_config_var("EXT_SUFFIX"))')
TARGET := _bgv_owner$(EXT)
PRIVATE_TARGET := _bgv_private$(EXT)
.PHONY: all clean
all: $(TARGET) $(PRIVATE_TARGET)
$(TARGET): bindings.cpp owner.h finish.h rns_product.h $(wildcard $(CPU)/*.h) Makefile
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -std=c++17 -Wall -Wextra -fPIC -shared -pthread \
		-I$(PY_INC) -I$(CPU) bindings.cpp $(LDFLAGS) -lgmpxx -lgmp -o $@
$(PRIVATE_TARGET): private_bindings.cpp bgv_private.h $(wildcard $(CPU)/*.h) Makefile
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -std=c++17 -Wall -Wextra -fPIC -shared -pthread \
		-fstack-protector-strong -D_FORTIFY_SOURCE=3 -I$(PY_INC) -I$(CPU) private_bindings.cpp \
		$(LDFLAGS) -Wl,-z,relro,-z,now,-z,noexecstack -lgmpxx -lgmp -o $@
clean:
	rm -f $(TARGET) $(PRIVATE_TARGET)
