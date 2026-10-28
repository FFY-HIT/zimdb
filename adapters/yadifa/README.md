# YADIFA ← ZimDB (BOGI-v2.3)

## Files
- `bogi_yadifa.c` / `bogi_yadifa.h` → `sbin/yadifad/` (tested with YADIFA 3.0.9)

## Hooks (`server_process_message_udp.c`)
```c
#include "bogi_yadifa.h"
/* once: */ bogi_yadifa_open_all();
bogi_yadifa_lazy(mesg);
if (bogi_yadifa_try_answer(mesg)) { /* reply */ }
```

Link `-lbogi23`. Runtime: `BOGI_IMAGE=...`
