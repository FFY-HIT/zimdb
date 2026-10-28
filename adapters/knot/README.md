# Knot DNS ← ZimDB (BOGI-v2.3)

## Files
- `bogi_knot.c` / `bogi_knot.h` → `src/knot/nameserver/` (tested with Knot 3.5.3)

## Build
Link `-lbogi23` and compile `bogi_knot.c` into the nameserver objects.

## Hooks
1. `src/knot/server/server.c` — `#include "knot/nameserver/bogi_knot.h"`; `bogi_knot_open_all()` after zones are ready; `bogi_knot_close_all()` on shutdown.
2. `src/knot/nameserver/process_query.c` — when `next_state == KNOT_STATE_PRODUCE`, try `bogi_knot_try_answer(pkt, qdata)`.
3. `src/knot/nameserver/internet.c` — `bogi_knot_release_contents(...)` on cleanup.

## Runtime
`BOGI_IMAGE=/path/to/image.bogi`
