# Isolated public research library; never overwrite delivered extensions.
CXX ?= c++
CPU := ../../../src/cuhepy/bfv/_cpu_ext
TARGET ?= /tmp/cuhepy-shared-query/libshared_query_native.so
SOURCE ?= shared_query.cpp
.PHONY: all
all: $(TARGET)
$(TARGET): $(SOURCE) shared_query.cpp $(wildcard $(CPU)/*.h) Makefile
	mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -O3 -std=c++17 -Wall -Wextra -fPIC -shared -I$(CPU) $(SOURCE) $(LDFLAGS) -lgmpxx -lgmp -o $@
