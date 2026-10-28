# BIND 9.20 dyndb module → bogi_zonedb.so (mmap-direct ZimDB).
# Requires BIND development headers / libs. Override paths as needed:
#   make BIND_INC=/usr/include BIND_DEPS=/usr
CC ?= gcc
BIND_INC ?= /usr/include
BIND_DEPS ?= /usr
CFLAGS := -fPIC -O2 -g -Wall -Wextra -Wno-unused-parameter \
	-Iinclude -Iinclude-overlay -I$(BIND_INC) \
	-I$(BIND_DEPS)/include -I$(BIND_DEPS)/include/x86_64-linux-gnu \
	-DZONEDB_DEFAULT=\"qpzone\" -DRCU_MEMBARRIER -D_GNU_SOURCE
LIBS := -ldns -lisc -lurcu -lpthread
LDFLAGS := -shared -Wl,-z,relro -L$(BIND_DEPS)/lib -L$(BIND_DEPS)/lib/x86_64-linux-gnu

SRCS := src/driver.c src/instance.c src/zone.c src/db.c src/log.c \
	src/bogi23_reader.c
OBJS := $(SRCS:.c=.o)

.PHONY: all clean

all: bogi_zonedb.so

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

bogi_zonedb.so: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

clean:
	rm -f $(OBJS) bogi_zonedb.so
