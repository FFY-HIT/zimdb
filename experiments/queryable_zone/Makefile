CXX ?= g++
CXXFLAGS ?= -O3 -std=c++17 -Wall -Wextra -Wpedantic
LDLIBS = -lldns -llz4 -lzstd -lcrypto

all: native_zone

native_zone: native_zone.cpp rrset_page_codec.inc hierarchy_sorter.inc ns_pool.inc flat_zone.inc column_page.inc column_page_v2.inc column_page_v3.inc
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f native_zone

.PHONY: all clean
