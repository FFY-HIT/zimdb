# Unbound ← ZimDB (BOGI-v2.3)

## Files
- `bogi_unbound.c` / `bogi_unbound.h` → `daemon/` (tested with Unbound 1.24.2)

## Hooks (`daemon/worker.c`)
```c
#include "daemon/bogi_unbound.h"
/* once: */ bogi_unbound_open_all();
bogi_unbound_lazy(worker->env.auth_zones, &qinfo);
if (bogi_unbound_try_answer(c->buffer)) { /* send buffer */ }
bogi_unbound_release(worker->env.auth_zones);
```

Link `-lbogi23`. Runtime: `BOGI_IMAGE=...`
