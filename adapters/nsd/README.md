# NSD ← ZimDB (BOGI-v2.3)

## Files
- `bogi_nsd.c` / `bogi_nsd.h` — drop into NSD source root (tested with NSD 4.14.0)

## Build
1. Build `../../libbogi23` (`make -C ../../libbogi23`).
2. Copy these two files into the NSD tree.
3. Add to NSD `Makefile`:
   - `CPPFLAGS += -I/path/to/zimdb/libbogi23/include`
   - `LDFLAGS  += -L/path/to/zimdb/libbogi23/build`
   - `LIBS     += -lbogi23`
   - add `bogi_nsd.o` next to `query.o`
4. Apply hooks below, then `make`.

## Hooks (NSD 4.14.0)
**`query.c`** — include + early answer + release:

```c
#include "bogi_nsd.h"
/* in authoritative answer path: */
if (bogi_nsd_try_answer(nsd, q))
    /* return the same "already answered" code used by neighbouring branches */;
/* on zone release path: */
bogi_nsd_release_zone(q->zone);
```

**`server.c`** — open images after config load:

```c
#include "bogi_nsd.h"
bogi_nsd_open_all(nsd);
```

## Runtime
Set `BOGI_IMAGE=/path/to/image.bogi` (or multi-zone map as documented in `bogi_nsd.c`).
