# Standalone BOGI-v2.3 reader + Dig API + optional auth answer library.
CC ?= gcc
AR ?= ar
ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
CFLAGS ?= -O2 -g -fPIC -Wall -Wextra -Wno-unused-parameter -I$(ROOT)include
BUILD := $(ROOT)build

.PHONY: all clean smoke install

all: $(BUILD)/libbogi23.a $(BUILD)/libbogi23.so $(BUILD)/dump_zone

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/bogi23_reader.o: $(ROOT)src/bogi23_reader.c $(ROOT)include/bogi23_reader.h $(ROOT)include/bogi23_export.h $(ROOT)include/bogi23_dig.h $(ROOT)include/bogi23_binary_pool.h | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)/bogi23_binary_pool.o: $(ROOT)src/bogi23_binary_pool.c $(ROOT)include/bogi23_binary_pool.h | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)/bogi_auth_answer.o: $(ROOT)src/bogi_auth_answer.c $(ROOT)include/bogi_auth_answer.h $(ROOT)include/bogi23_export.h $(ROOT)include/bogi23_reader.h | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)/libbogi23.a: $(BUILD)/bogi23_reader.o $(BUILD)/bogi23_binary_pool.o $(BUILD)/bogi_auth_answer.o
	$(AR) rcs $@ $^

$(BUILD)/libbogi23.so: $(BUILD)/bogi23_reader.o $(BUILD)/bogi23_binary_pool.o $(BUILD)/bogi_auth_answer.o
	$(CC) -shared -o $@ $^

$(BUILD)/dump_zone: $(ROOT)smoke/dump_zone.c $(BUILD)/libbogi23.a
	$(CC) $(CFLAGS) -o $@ $< $(BUILD)/libbogi23.a

$(BUILD)/soa_smoke: $(ROOT)smoke/soa_smoke.c $(BUILD)/libbogi23.a
	$(CC) $(CFLAGS) -o $@ $< $(BUILD)/libbogi23.a

$(BUILD)/answer_smoke: $(ROOT)smoke/answer_smoke.c $(BUILD)/libbogi23.a
	$(CC) $(CFLAGS) -o $@ $< $(BUILD)/libbogi23.a

smoke: $(BUILD)/soa_smoke $(BUILD)/answer_smoke
	$(BUILD)/soa_smoke /home/administrator/agentdns-czds/prepared/czds_page/image.bogi
	$(BUILD)/answer_smoke /home/administrator/agentdns-czds/prepared/czds_page/image.bogi

clean:
	rm -rf $(BUILD)

install: all
	mkdir -p /home/administrator/agentdns-multiauth/libbogi23/build
	cp -a $(BUILD)/libbogi23.a $(BUILD)/libbogi23.so $(BUILD)/dump_zone /home/administrator/agentdns-multiauth/libbogi23/build/
	cp -a $(ROOT)include/*.h /home/administrator/agentdns-multiauth/libbogi23/include/
