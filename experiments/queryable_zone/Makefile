CXX ?= g++
CXXFLAGS ?= -O3 -std=c++17 -Wall -Wextra -Wpedantic
LDLIBS = -lldns -llz4 -lzstd -lcrypto

all: native_zone

native_zone: native_zone.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f native_zone

.PHONY: all clean
